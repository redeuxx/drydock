"""Storage targets: where archives go.

A local root must resolve inside DRYDOCK_LOCAL_STORAGE_ROOTS and must not overlap
drydock's own directories (storage.local.validate_root). Admins manage local targets.

A remote target (sftp, smb, webdav or drive) makes drydock, through rclone, connect wherever
its settings point, from a container that can reach the unauthenticated Docker socket
proxy. Like notification targets, only a superadmin with a recent password check may create,
change or remove one, and admins see it read-only (they may test it and back up to it). Its
fields are checked against storage.options' allowlist, and its secrets are never rendered.
Transfers go through storage.rclone, for the kinds in its KINDS so far.

Every target's settings are stored encrypted.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.crypto import CryptoError
from drydock.db import get_db
from drydock.models import Backup, Job, StorageTarget
from drydock.routes.auth import client_ip
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.storage import options
from drydock.storage.base import StorageError
from drydock.storage.local import LocalStorage, validate_root
from drydock.storage.rclone import KINDS as REMOTE_KINDS
from drydock.storage.rclone import RcloneBackend
from drydock.storage.rclone_rc import RcloneError, RcloneUnavailable
from drydock.templating import render, see_other

router = APIRouter(prefix="/storage")

Admin = Annotated[Auth, Depends(require_role(Role.admin))]

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_PATH = 1024
KINDS = ("local", *options.BACKENDS)
KIND_LABELS = {"local": "Local directory"} | {k: b.label for k, b in options.BACKENDS.items()}
UNREADABLE = "(cannot be decrypted with the configured secret keys)"
REMOTE_LATER = "Transfers to this kind of storage arrive in a later release."


@dataclass
class StorageForm:
    name: str = ""
    path: str = ""
    enabled: bool = True


@dataclass
class RemoteForm:
    """A remote target's form: never a secret, only the names of stored ones."""

    name: str = ""
    enabled: bool = True
    values: dict[str, str] = field(default_factory=dict)  # non-secret options and folder
    stored: frozenset[str] = frozenset()  # secret options that hold a value


async def form_items(request: Request) -> list[tuple[str, Any]]:
    """Every submitted field in order, repeats and file fields included, so that
    storage.options can refuse them."""
    return list((await request.form()).multi_items())


FormItems = Annotated[list[tuple[str, Any]], Depends(form_items)]


def last(items: list[tuple[str, Any]], key: str) -> str:
    value = next((v for k, v in reversed(items) if k == key), "")
    return value if isinstance(value, str) else ""


def load_config(request: Request, target: StorageTarget) -> dict[str, Any] | None:
    try:
        config = json.loads(request.app.state.crypto.decrypt(target.config_enc))
    except CryptoError, ValueError:
        return None
    return config if isinstance(config, dict) else None


def location(request: Request, target: StorageTarget) -> str:
    """The local root or the remote location, or a placeholder when it cannot be read."""
    config = load_config(request, target)
    if config is None:
        return UNREADABLE
    if target.kind == "local":
        return str(config.get("path", UNREADABLE))
    return options.location(target.kind, config)


def summary(request: Request, target: StorageTarget) -> dict[str, Any]:
    where = "path" if target.kind == "local" else "location"
    return {
        "name": target.name,
        "kind": target.kind,
        where: location(request, target),
        "enabled": target.enabled,
    }


def require_remote_editor(auth: Auth) -> None:
    """Remote targets are changed by a superadmin with recent auth (see the docstring)."""
    if auth.user.role < Role.superadmin:
        raise HTTPException(status_code=403, detail="Only a superadmin can change remote storage.")
    require_recent_auth(auth)


def help_texts(request: Request) -> dict[str, dict[str, str]]:
    """rclone's help for the allowlisted options, cached. A mismatch with the allowlist
    disables remote forms; while rclone is down they render without help."""
    state = request.app.state
    if getattr(state, "storage_help", None) is None:
        try:
            state.storage_help = options.help_texts(state.rclone.call("config/providers"))
        except RcloneUnavailable, RcloneError:
            return {}
        except options.OptionsError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from None
    return state.storage_help


def name_errors(db: Session, name: str, storage_id: int | None = None) -> list[str]:
    if not NAME_RE.fullmatch(name):
        return ["Name must be 1 to 64 letters, digits, dots, dashes or underscores."]
    query = select(StorageTarget.id).where(StorageTarget.name == name)
    if storage_id is not None:
        query = query.where(StorageTarget.id != storage_id)
    if db.scalar(query) is not None:
        return ["A storage target with that name exists."]
    return []


def validate_local(request: Request, form: StorageForm) -> tuple[list[str], str | None]:
    """Returns the path errors and, when the path is valid, the resolved root to store."""
    if len(form.path) > MAX_PATH:
        return ["The storage path is too long."], None
    try:
        return [], str(validate_root(form.path, request.app.state.settings))
    except StorageError as exc:
        return [str(exc)], None


def get_target(db: Session, storage_id: int) -> StorageTarget:
    target = db.get(StorageTarget, storage_id)
    if target is None:
        raise HTTPException(status_code=404)
    return target


def remote_form(target: StorageTarget, config: dict[str, Any] | None) -> RemoteForm:
    backend = options.BACKENDS[target.kind]
    stored = dict((config or {}).get("options", {}))
    values = {o.name: stored.get(o.name, o.default) for o in backend.options if not o.secret}
    values["folder"] = str((config or {}).get("folder", ""))
    secrets = frozenset(o.name for o in backend.secrets if stored.get(o.name))
    return RemoteForm(target.name, target.enabled, values, secrets)


def new_page(
    request: Request, auth: Auth, kind: str, status_code: int = 200, **context: Any
) -> Response:
    remote = kind != "local"
    context.setdefault("errors", [])
    context.setdefault("form", RemoteForm() if remote else StorageForm())
    return render(
        request,
        "storage/new.html",
        status_code,
        auth=auth,
        kind=kind,
        kind_labels=KIND_LABELS,
        transfer_kinds=REMOTE_KINDS,
        backend=options.BACKENDS.get(kind),
        helps=help_texts(request).get(kind, {}) if remote else {},
        roots=request.app.state.settings.local_storage_roots,
        **context,
    )


def edit_page(
    request: Request,
    db: Session,
    auth: Auth,
    target: StorageTarget,
    status_code: int = 200,
    **context: Any,
) -> Response:
    remote = target.kind != "local"
    if remote:
        context.setdefault("form", remote_form(target, load_config(request, target)))
    else:
        context.setdefault(
            "form", StorageForm(target.name, location(request, target), target.enabled)
        )
    context.setdefault("errors", [])
    context.setdefault("test", None)
    editor = not remote or auth.user.role >= Role.superadmin
    helps: dict[str, str] = {}
    options_error = None
    if remote and editor:
        try:
            helps = help_texts(request).get(target.kind, {})
        except HTTPException as exc:  # the form is disabled; viewing and removing still work
            options_error = exc.detail
    jobs = db.scalars(select(Job).where(Job.storage_target_id == target.id).order_by(Job.name))
    return render(
        request,
        "storage/edit.html",
        status_code,
        auth=auth,
        target=target,
        kind_labels=KIND_LABELS,
        backend=options.BACKENDS.get(target.kind),
        helps=helps,
        options_error=options_error,
        editor=editor,
        transfers=target.kind in REMOTE_KINDS,
        location=location(request, target),
        jobs=list(jobs),
        roots=request.app.state.settings.local_storage_roots,
        **context,
    )


def store(request: Request, config: dict[str, Any]) -> str:
    return request.app.state.crypto.encrypt(json.dumps(config))


# LIST AND CREATE


@router.get("")
def list_storage(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    targets = db.scalars(select(StorageTarget).order_by(StorageTarget.name)).all()
    rows = [(t, location(request, t)) for t in targets]
    return render(request, "storage/list.html", auth=auth, rows=rows, kind_labels=KIND_LABELS)


@router.get("/new")
def new_storage_form(
    request: Request,
    auth: Admin,
    kind: str = Query(default="local", alias="type", max_length=16),
) -> Response:
    if kind not in KINDS:
        raise HTTPException(status_code=404)
    if kind == "local":
        roots = request.app.state.settings.local_storage_roots
        return new_page(request, auth, kind, form=StorageForm(path=str(roots[0]) if roots else ""))
    if auth.user.role < Role.superadmin:
        raise HTTPException(status_code=403, detail="Only a superadmin can add remote storage.")
    backend = options.BACKENDS[kind]
    values = {o.name: o.default for o in backend.options if not o.secret} | {"folder": ""}
    return new_page(request, auth, kind, form=RemoteForm(values=values))


@router.post("")
def create_storage(
    request: Request, auth: Admin, items: FormItems, db: Session = Depends(get_db)
) -> Response:
    kind = last(items, "kind") or "local"
    if kind not in KINDS:
        raise HTTPException(status_code=422, detail="Unknown storage kind.")
    name, enabled = last(items, "name").strip(), last(items, "enabled") == "1"
    if kind == "local":
        form = StorageForm(name, last(items, "path").strip(), enabled)
        path_errors, root = validate_local(request, form)
        errors = name_errors(db, name) + path_errors
        if errors or root is None:
            db.rollback()
            return new_page(request, auth, kind, 422, form=form, errors=errors)
        config: dict[str, Any] = {"path": root}
    else:
        require_remote_editor(auth)
        help_texts(request)  # refuses while rclone's options do not match the allowlist
        parsed = options.parse(kind, items, None)
        errors = name_errors(db, name) + parsed.errors
        if errors or parsed.config is None:
            db.rollback()
            form = RemoteForm(name, enabled, parsed.shown)
            return new_page(request, auth, kind, 422, form=form, errors=errors)
        config = parsed.config
    target = StorageTarget(name=name, kind=kind, config_enc=store(request, config), enabled=enabled)
    db.add(target)
    db.flush()
    audit.record(
        db,
        actor=auth.user.username,
        action="storage.create",
        target=f"storage:{target.id}",
        ip=client_ip(request),
        details=summary(request, target),
    )
    db.commit()
    return see_other(request, f"/storage/{target.id}")


# EDIT


@router.get("/{storage_id}")
def edit_storage(
    request: Request, storage_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    return edit_page(request, db, auth, get_target(db, storage_id))


@router.post("/{storage_id}")
def update_storage(
    request: Request,
    storage_id: int,
    auth: Admin,
    items: FormItems,
    db: Session = Depends(get_db),
) -> Response:
    target = get_target(db, storage_id)
    name, enabled = last(items, "name").strip(), last(items, "enabled") == "1"
    changed: list[str] = []
    if target.kind == "local":
        form = StorageForm(name, last(items, "path").strip(), enabled)
        path_errors, root = validate_local(request, form)
        errors = name_errors(db, name, target.id) + path_errors
        if errors or root is None:
            db.rollback()
            return edit_page(request, db, auth, target, 422, form=form, errors=errors)
        config: dict[str, Any] = {"path": root}
    else:
        require_remote_editor(auth)
        help_texts(request)  # refuses while rclone's options do not match the allowlist
        stored = load_config(request, target) or {}
        parsed = options.parse(target.kind, items, stored)
        errors = name_errors(db, name, target.id) + parsed.errors
        if last(items, "kind") not in ("", target.kind):
            errors.append("The kind of a storage target cannot be changed.")
        if errors or parsed.config is None:
            db.rollback()
            secrets = remote_form(target, stored).stored
            form = RemoteForm(name, enabled, parsed.shown, secrets)
            return edit_page(request, db, auth, target, 422, form=form, errors=errors)
        config, changed = parsed.config, parsed.changed
    before = summary(request, target)
    target.name = name
    target.enabled = enabled
    target.config_enc = store(request, config)
    after = summary(request, target)
    details: dict[str, Any] = {
        k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]
    }
    if changed:
        details["options_changed"] = changed  # names only, never values
    audit.record(
        db,
        actor=auth.user.username,
        action="storage.update",
        target=f"storage:{target.id}",
        ip=client_ip(request),
        details=details,
    )
    db.commit()
    return see_other(request, f"/storage/{target.id}")


@router.post("/{storage_id}/delete")
def delete_storage(
    request: Request, storage_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    target = get_target(db, storage_id)
    if target.kind != "local":
        require_remote_editor(auth)
    users = db.scalars(select(Job.name).where(Job.storage_target_id == target.id)).all()
    if users:
        db.rollback()
        error = f"Jobs still use this storage: {', '.join(users)}. Move or delete them first."
        return edit_page(request, db, auth, target, 409, errors=[error])
    catalogued = db.scalar(
        select(func.count()).select_from(Backup).where(Backup.storage_target_id == target.id)
    )
    audit.record(
        db,
        actor=auth.user.username,
        action="storage.delete",
        target=f"storage:{target.id}",
        ip=client_ip(request),
        details=summary(request, target) | {"catalog_entries_removed": catalogued},
    )
    # The archives stay where they are; only drydock's catalog entries go.
    db.execute(delete(Backup).where(Backup.storage_target_id == target.id))
    db.delete(target)
    db.commit()
    return see_other(request, "/storage")


def remote_backend(request: Request, target: StorageTarget) -> RcloneBackend:
    """A remote target's backend. Raises StorageError (safe to show)."""
    config = load_config(request, target)
    if config is None:
        raise StorageError(f"The settings {UNREADABLE}.")
    state = request.app.state
    return RcloneBackend(state.rclone, target.kind, config, state.settings.staging_dir)


@router.post("/{storage_id}/test")
def test_storage(
    request: Request, storage_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    """Writes and removes a probe file: in a local root, or on remote storage (through
    rclone, which also proves the host key and the login)."""
    target = get_target(db, storage_id)
    where = location(request, target)
    username = auth.user.username  # read before the rollback expires auth.user
    error: str | None = None
    try:
        if target.kind == "local":
            LocalStorage(where, request.app.state.settings).test()
        elif target.kind in REMOTE_KINDS:
            backend = remote_backend(request, target)
            db.rollback()  # no write lock while on the network
            backend.test()
            target = get_target(db, storage_id)
        else:
            error = REMOTE_LATER
    except StorageError as exc:
        error = str(exc)
        target = get_target(db, storage_id)
    key = "path" if target.kind == "local" else "location"
    audit.record(
        db,
        actor=username,
        action="storage.test",
        target=f"storage:{target.id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={key: where} if error is None else {key: where, "error": error},
    )
    db.commit()
    return edit_page(request, db, auth, target, test={"error": error})
