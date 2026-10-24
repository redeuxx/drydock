"""Restore from storage: the wizard. Admin and above only.

1. GET /restore lists the storage targets. GET /restore/storage/{storage_id} lists one
   target's archives straight from the storage, so it works without the backup catalog,
   with what each archive's first bytes say. That preview is not verified and is only
   shown; an encrypted archive shows its name, size and time only. Remote storage is
   listed too, but restores from it arrive in a later release.
2. POST /restore/from-storage creates a restore run, and the dispatcher verifies the
   archive (pass 1) without touching any host. The plan page follows its log meanwhile.
3. POST /restore/runs/{restore_id}/plan plans the restore against the chosen host's
   current state (read-only Docker calls) and stores the choice and a summary without
   secrets. The plan page then shows that summary for confirmation.
4. POST /restore/runs/{restore_id}/execute runs it, once. The dispatcher plans again and
   refuses anything that differs from the summary confirmed here. The confirm form
   carries a digest of the plan it shows, so a plan stored again meanwhile (by anyone)
   is refused rather than run under the confirmation given for another.

Beyond the admin role, the bodies check: an archive this drydock did not sign, and any
risk-flagged field (signed or not), need a superadmin, a per-field acknowledgement and the
password from the last 10 minutes. Overwrite needs the container name (a stack's project
name) typed and recent auth, data-only recent auth. A compose output directory needs
nothing more by itself; a sensitive one is a flagged field. The host-path denylist applies
to every role (restore.plan).

Routes that wait on the dispatcher or a host release the database lock first, because
every transaction takes SQLite's write lock up front.
"""

import dataclasses
import functools
import hashlib
import hmac
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import anyio.from_thread
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.archive import manifest as m
from drydock.archive.verify import VerifyError
from drydock.crypto import CryptoError
from drydock.db import get_db
from drydock.jobs.dispatcher import (
    ACTIVE_STATUSES,
    UNDECRYPTABLE_STORAGE,
    Dispatcher,
    DispatchError,
    archive_facts,
    json_object,
)
from drydock.jobs.runlog import log_path, read_log
from drydock.models import Host, Run, StorageTarget
from drydock.restore import apply as restore_apply
from drydock.restore import plan as restore_plan
from drydock.restore import verify as restore_verify
from drydock.routes.auth import FormStr, client_ip
from drydock.routes.hosts import DOCKER_ERRORS, INVENTORY_TIMEOUT, open_host
from drydock.routes.jobs import as_id
from drydock.routes.runs import PAGE_LOG_LIMIT
from drydock.routes.storage import KIND_LABELS, get_target, remote_backend
from drydock.security.hostpaths import HostPathError
from drydock.security.rbac import Role, has_recent_auth, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.storage.base import (
    ENCRYPTED_SUFFIX,
    StorageBackend,
    StorageError,
    StoredObject,
    check_name,
    parse_name,
)
from drydock.storage.local import LocalStorage
from drydock.storage.rclone import KINDS as REMOTE_KINDS
from drydock.storage.rclone import REMOTE_RESTORE_LATER
from drydock.templating import render, see_other

router = APIRouter(prefix="/restore")

Admin = Annotated[Auth, Depends(require_role(Role.admin))]

AWAITING = "awaiting_confirmation"
LISTING_LIMIT = 200  # archives a storage listing page shows
REMOTE_PREVIEW_BUDGET = 20.0  # seconds a remote listing spends reading archive heads
SLOW_STORAGE = "not read, the storage is slow to answer"
MAX_LISTING_PAGE = 100_000
RECENT_RESTORES = 20
MAX_AUDITED_ERRORS = 10
UNSIGNED = "Only a superadmin can restore an archive that is not signed by this drydock."
FLAGGED = "Flagged fields need a superadmin."
PLAN_CHANGED = "The plan changed since you viewed it. Review it again."
MODE_LABELS = {
    "new-name": "New name: restore beside the original under a new name",
    "overwrite": "Overwrite: replace the original container and the data it uses",
    "data-only": "Data only: write the volume and bind mount data into existing volumes",
    "image-only": "Images only: load or pull the images and nothing else",
}
OLDEST = datetime.min.replace(tzinfo=UTC)


# FORM


@dataclass
class PlanForm:
    """The plan form as submitted, or as the stored choice fills it."""

    host_id: str = ""
    mode: str = ""
    new_name: str = ""
    remaps: dict[int, str] = field(default_factory=dict)  # bind n: host path as entered
    skip: set[int] = field(default_factory=set)
    share: set[int] = field(default_factory=set)
    wipe: set[int] = field(default_factory=set)
    bind_volumes: dict[int, str] = field(default_factory=dict)  # bind n: target volume
    volumes: dict[int, str] = field(default_factory=dict)  # archive volume index: target
    data_container: str = ""
    compose_dir: str = ""

    @classmethod
    def initial(cls, manifest: m.Manifest, choice: restore_plan.Choice | None) -> PlanForm:
        remaps = {b.n: b.source for b in manifest.binds}
        if choice is None:
            return cls(remaps=remaps)
        index = {v.name: i for i, v in enumerate(manifest.volumes)}
        return cls(
            host_id=str(choice.host_id),
            mode=choice.mode,
            new_name=choice.new_name,
            remaps=remaps | choice.bind_remaps,
            skip=set(choice.skip_binds),
            share=set(choice.share_binds),
            wipe=set(choice.wipe_binds),
            bind_volumes=dict(choice.bind_volume_map),
            volumes={index[n]: t for n, t in choice.volume_map.items() if n in index},
            data_container=choice.data_container,
            compose_dir=choice.compose_dir,
        )

    @classmethod
    def submitted(cls, manifest: m.Manifest, fields: dict[str, str]) -> PlanForm:
        """Reads only the fields the archive's binds and volumes name."""

        def value(name: str) -> str:
            return fields.get(name, "").strip()

        binds = [b.n for b in manifest.binds]
        return cls(
            host_id=value("host_id"),
            mode=value("mode"),
            new_name=value("new_name"),
            remaps={n: value(f"remap_{n}") for n in binds},
            skip={n for n in binds if value(f"skip_{n}") == "1"},
            share={n for n in binds if value(f"share_{n}") == "1"},
            wipe={n for n in binds if value(f"wipe_{n}") == "1"},
            bind_volumes={n: v for n in binds if (v := value(f"bind_volume_{n}"))},
            volumes={i: v for i in range(len(manifest.volumes)) if (v := value(f"volmap_{i}"))},
            data_container=value("data_container"),
            compose_dir=value("compose_dir"),
        )

    def choice(self, manifest: m.Manifest, host_id: int) -> restore_plan.Choice:
        """The Choice for the chosen mode. Fields of other modes are left out, so a value
        left in a field the mode does not use cannot fail the plan."""
        mode = self.mode
        if mode not in restore_plan.MODES:
            raise restore_plan.PlanError("Choose a restore mode.")
        fields: dict[str, Any] = {}
        if mode in ("new-name", "overwrite"):
            sources = {b.n: b.source for b in manifest.binds}
            fields = {
                "bind_remaps": {n: p for n, p in self.remaps.items() if p and p != sources[n]},
                "skip_binds": frozenset(self.skip),
                "share_binds": frozenset(self.share),
                "wipe_binds": frozenset(self.wipe),
                "compose_dir": self.compose_dir,
            }
        elif mode == "data-only":
            fields = {
                "volume_map": {manifest.volumes[i].name: t for i, t in self.volumes.items()},
                "bind_volume_map": dict(self.bind_volumes),
                "data_container": self.data_container,
            }
        new_name = self.new_name if mode == "new-name" else ""
        return restore_plan.Choice(host_id=host_id, mode=mode, new_name=new_name, **fields)


async def form_fields(request: Request) -> dict[str, str]:
    """The submitted form, already parsed by the CSRF check. The plan form's field names
    depend on the archive (remap_<n>, volmap_<i>), so they are read from here."""
    form = await request.form()
    return {key: value for key, value in form.items() if isinstance(value, str)}


# HELPERS


def dispatcher(request: Request) -> Dispatcher:
    return request.app.state.dispatcher


def get_restore(db: Session, restore_id: int) -> Run:
    run = db.get(Run, restore_id)
    if run is None or run.kind != "restore":
        raise HTTPException(status_code=404)
    return run


def run_doc(run: Run) -> dict[str, Any]:
    """The run's plan document: source, signed, encrypted, choice and summary."""
    return json_object(run.plan)


def summary_of(doc: dict[str, Any]) -> dict[str, Any] | None:
    summary = doc.get("summary")
    return summary if isinstance(summary, dict) else None


def risk_flags(summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    risk = (summary or {}).get("risk")
    if not isinstance(risk, list):
        return []
    return [r for r in risk if isinstance(r, dict) and isinstance(r.get("key"), str)]


def stored_choice(doc: dict[str, Any]) -> restore_plan.Choice | None:
    try:
        return restore_plan.Choice.from_dict(doc.get("choice"))
    except restore_plan.PlanError:
        return None


def signed(doc: dict[str, Any]) -> bool:
    return doc.get("signed") is True


def needs_superadmin(doc: dict[str, Any]) -> bool:
    return not signed(doc) or bool(risk_flags(summary_of(doc)))


def plan_digest(doc: dict[str, Any]) -> str:
    """Identifies the stored choice and summary, the plan a confirm form shows."""
    plan = {"choice": doc.get("choice"), "summary": doc.get("summary")}
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def form_id(value: str) -> int | None:
    """as_id for form input; str.isdigit() also accepts non-ASCII digits int() rejects."""
    return as_id(value) if value.isascii() else None


def needs_reauth(doc: dict[str, Any], summary: dict[str, Any]) -> bool:
    mode = summary.get("mode")
    return not signed(doc) or bool(risk_flags(summary)) or mode in ("overwrite", "data-only")


def target_root(request: Request, target: StorageTarget) -> str | None:
    """The storage directory, decrypted like Dispatcher._root; None if it cannot be."""
    if target.kind != "local":
        return None
    try:
        return str(json.loads(request.app.state.crypto.decrypt(target.config_enc))["path"])
    except CryptoError, ValueError, KeyError, TypeError:
        return None


def release[T](db: Session, obj: T) -> T:
    """Ends the transaction (and its write lock) but keeps obj usable, detached."""
    if obj in db:
        db.expunge(obj)
    db.rollback()
    return obj


def deny(db: Session, auth: Auth, request: Request, action: str, run: Run, reason: str) -> NoReturn:
    audit.record(
        db,
        actor=auth.user.username,
        action=action,
        target=f"run:{run.id}",
        outcome="denied",
        ip=client_ip(request),
        details={"reason": reason},
    )
    db.commit()
    raise HTTPException(status_code=403, detail=reason)


def allowed_modes(manifest: m.Manifest) -> list[str]:
    """The modes this archive can be restored in. Several containers go under a new name
    only as a stack (a new Compose project)."""
    modes = []
    containers = manifest.containers
    if containers and all(c.config_member is not None for c in containers):
        if len(containers) == 1 or restore_plan.is_stack(manifest):
            modes.append("new-name")
        modes.append("overwrite")
    if any(v.data_member for v in manifest.volumes) or any(b.data_member for b in manifest.binds):
        modes.append("data-only")
    if manifest.images:
        modes.append("image-only")
    return modes


def created_at(obj: StoredObject) -> datetime:
    try:
        return parse_name(obj.name).created_at
    except StorageError:
        return OLDEST


def staged_dir(request: Request, run: Run) -> Path:
    return restore_verify.restore_dir(request.app.state.settings.staging_dir, run.id)


def index_page(
    request: Request, db: Session, auth: Auth, status_code: int = 200, errors: Sequence[str] = ()
) -> Response:
    targets = db.scalars(select(StorageTarget).order_by(StorageTarget.name)).all()
    runs = db.scalars(
        select(Run).where(Run.kind == "restore").order_by(Run.id.desc()).limit(RECENT_RESTORES)
    ).all()
    return render(
        request,
        "restore/index.html",
        status_code,
        auth=auth,
        targets=targets,
        listed_kinds=("local", *REMOTE_KINDS),
        kind_labels=KIND_LABELS,
        runs=runs,
        errors=list(errors),
    )


def plan_page(
    request: Request,
    db: Session,
    auth: Auth,
    run: Run,
    status_code: int = 200,
    *,
    errors: Sequence[str] = (),
    form: PlanForm | None = None,
    staged: restore_verify.Staged | None = None,
) -> Response:
    """The wizard page of a restore run. A submitted form (form set) hides the stored
    summary: it no longer matches what the form shows."""
    enabled = select(Host).where(Host.enabled.is_(True)).order_by(Host.name)
    hosts = [(host.id, host.name) for host in db.scalars(enabled)]
    run = release(db, run)
    doc = run_doc(run)
    context: dict[str, Any] = {
        "run": run,
        "doc": doc,
        "signed": signed(doc),
        "errors": list(errors),
        "active": run.status in ACTIVE_STATUSES,
        "awaiting": run.status == AWAITING,
        "log_text": "",
        "offset": 0,
        "stage_error": None,
        "manifest": None,
        "stack": False,
        "hosts": hosts,
        "form": form,
        "modes": [],
        "mode_labels": MODE_LABELS,
        "summary": None,
        "flags": [],
        "reauth_hint": False,
        "may_execute": False,
        "plan_digest": "",
    }
    if context["active"]:
        path = log_path(request.app.state.settings.data_dir, run.id)
        context["log_text"], context["offset"] = read_log(path, 0, PAGE_LOG_LIMIT)
    elif context["awaiting"]:
        try:
            staged = staged or restore_verify.load_staged(
                staged_dir(request, run), request.app.state.crypto
            )
        except VerifyError as exc:
            context["stage_error"] = str(exc)
        else:
            manifest = staged.manifest
            context["manifest"] = manifest
            context["stack"] = restore_plan.is_stack(manifest)
            context["modes"] = allowed_modes(manifest)
            context["form"] = form or PlanForm.initial(manifest, stored_choice(doc))
            summary = summary_of(doc) if form is None else None
            if summary is not None:
                flags = risk_flags(summary)
                superadmin = auth.user.role >= Role.superadmin
                context["summary"] = summary
                context["flags"] = flags
                context["reauth_hint"] = needs_reauth(doc, summary) and not has_recent_auth(auth)
                context["may_execute"] = superadmin or not needs_superadmin(doc)
                context["plan_digest"] = plan_digest(doc)
    return render(request, "restore/run.html", status_code, auth=auth, **context)


# STORAGE


@router.get("")
def restore_index(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    return index_page(request, db, auth)


@router.get("/storage/{storage_id}")
def storage_archives(
    request: Request,
    storage_id: int,
    auth: Admin,
    page: int = Query(default=1, ge=1, le=MAX_LISTING_PAGE),
    db: Session = Depends(get_db),
) -> Response:
    """The archives in the storage itself, newest first, LISTING_LIMIT a page,
    with an unverified preview of each manifest. Reads the directory only: no catalog, no
    writes."""
    target = release(db, get_target(db, storage_id))
    rows: list[tuple[StoredObject, datetime | None, restore_verify.Preview]] = []
    total = 0
    error = None
    first = (page - 1) * LISTING_LIMIT
    root = target_root(request, target)
    if target.kind not in ("local", *REMOTE_KINDS):
        error = REMOTE_RESTORE_LATER
    elif target.kind == "local" and root is None:
        error = UNDECRYPTABLE_STORAGE
    else:
        try:
            storage: StorageBackend = (
                LocalStorage(root, request.app.state.settings)
                if root is not None
                else remote_backend(request, target)
            )
            # By time, then name: a stable order, so pages neither repeat nor skip.
            objects = sorted(storage.list(), key=lambda o: (created_at(o), o.name), reverse=True)
            total = len(objects)
            # Remote previews are network reads, one after another: the page gets a budget.
            deadline = time.monotonic() + REMOTE_PREVIEW_BUDGET
            for obj in objects[first : first + LISTING_LIMIT]:
                stamp = created_at(obj)
                when = None if stamp == OLDEST else stamp
                if root is not None:
                    shown = restore_verify.preview(storage, obj.name)
                elif obj.name.endswith(ENCRYPTED_SUFFIX):  # all an encrypted head would say
                    shown = restore_verify.Preview("encrypted")
                elif time.monotonic() > deadline:
                    shown = restore_verify.Preview("unreadable", reason=SLOW_STORAGE)
                else:
                    shown = restore_verify.preview(storage, obj.name)
                rows.append((obj, when, shown))
        except StorageError as exc:
            error = str(exc)
    return render(
        request,
        "restore/storage.html",
        auth=auth,
        target=target,
        rows=rows,
        total=total,
        first=first,
        page=page,
        more=first + LISTING_LIMIT < total,
        error=error,
    )


@router.post("/from-storage")
def restore_from_storage(
    request: Request,
    auth: Admin,
    storage_id: FormStr = "",
    name: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    """Starts a restore run: the archive is verified before anything else happens."""
    archive = name.strip()
    target_id = form_id(storage_id.strip())

    def record(outcome: str, target: str | None, **details: Any) -> None:
        audit.record(
            db,
            actor=auth.user.username,
            action="restore.verify",
            target=target,
            outcome=outcome,
            ip=client_ip(request),
            details=details,
        )
        db.commit()

    try:
        check_name(archive)
    except StorageError:
        target_id = None
    if target_id is None:
        error = "Choose an archive from a storage listing."
        record("failure", None, storage_id=storage_id[:32], archive=archive[:255], error=error)
        return index_page(request, db, auth, 422, [error])
    username = auth.user.username  # read before the release expires auth.user
    if release(db, get_target(db, target_id)).kind != "local":
        record("failure", None, storage_id=target_id, archive=archive, error=REMOTE_RESTORE_LATER)
        return index_page(request, db, auth, 409, [REMOTE_RESTORE_LATER])
    try:
        run_id = anyio.from_thread.run(
            dispatcher(request).submit_restore, target_id, archive, username
        )
    except DispatchError as exc:
        record("failure", None, storage_id=target_id, archive=archive, error=str(exc))
        return index_page(request, db, auth, 409, [str(exc)])
    record("success", f"run:{run_id}", storage_id=target_id, archive=archive)
    return see_other(request, f"/restore/runs/{run_id}/plan")


# PLAN AND CONFIRM


@router.get("/runs/{restore_id}/plan")
def plan_form(
    request: Request, restore_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    return plan_page(request, db, auth, get_restore(db, restore_id))


@router.post("/runs/{restore_id}/plan")
def plan_restore(
    request: Request,
    restore_id: int,
    auth: Admin,
    fields: Annotated[dict[str, str], Depends(form_fields)],
    db: Session = Depends(get_db),
) -> Response:
    """Plans the restore against the host's current state and stores the choice and its
    summary. Nothing on the host changes: inspect_target makes read-only calls."""
    settings = request.app.state.settings
    run = get_restore(db, restore_id)

    def record(outcome: str, **details: Any) -> None:
        audit.record(
            db,
            actor=auth.user.username,
            action="restore.plan",
            target=f"run:{restore_id}",
            outcome=outcome,
            ip=client_ip(request),
            details=details,
        )
        db.commit()

    if run.status != AWAITING:
        error = "This restore is not awaiting confirmation."
        record("failure", error=error, status=run.status)
        return plan_page(request, db, auth, run, 409, errors=[error])
    if not signed(run_doc(run)) and auth.user.role < Role.superadmin:
        deny(db, auth, request, "restore.plan", run, UNSIGNED)
    run = release(db, run)
    try:
        staged = restore_verify.load_staged(staged_dir(request, run), request.app.state.crypto)
    except VerifyError as exc:
        record("failure", error=str(exc))
        return plan_page(request, db, auth, run, 409, errors=[str(exc)])
    manifest = staged.manifest
    form = PlanForm.submitted(manifest, fields)
    errors: list[str] = []
    host_id = form_id(form.host_id)
    host = db.get(Host, host_id) if host_id is not None else None
    if host is None or not host.enabled:
        errors.append("Choose an enabled host.")
    if form.mode not in allowed_modes(manifest):
        errors.append("Choose a restore mode this archive supports.")
    if host is not None and not errors:
        host = release(db, host)
        try:
            choice = form.choice(manifest, host.id)
            # Validates every archive-supplied name before a Docker call can see it.
            lookup = restore_plan.lookups(manifest, staged.configs, choice)
            with open_host(request, host, INVENTORY_TIMEOUT) as handle:
                target = restore_apply.inspect_target(
                    handle,
                    lookup,
                    host_id=host.id,
                    host_name=host.name,
                    helper_image=settings.helper_image,
                )
            plan = restore_plan.build_plan(
                manifest, staged.configs, target, choice, archive_facts(staged)
            )
        except restore_plan.PlanError as exc:
            errors += exc.errors
        except HostPathError as exc:
            errors.append(str(exc))
        except DOCKER_ERRORS as exc:
            errors.append(str(exc) or type(exc).__name__)
    if errors:
        record("failure", mode=form.mode[:32], errors=errors[:MAX_AUDITED_ERRORS])
        return plan_page(request, db, auth, run, 422, errors=errors, form=form, staged=staged)
    summary = restore_plan.summary(plan, host.name)
    run = get_restore(db, restore_id)
    if run.status != AWAITING:  # compare-and-set: this transaction holds the write lock
        error = "This restore is not awaiting confirmation."
        record("failure", error=error, status=run.status)
        return plan_page(request, db, auth, run, 409, errors=[error])
    doc = run_doc(run)
    doc["choice"] = choice.to_dict()
    doc["summary"] = summary
    run.plan = json.dumps(doc)
    audit.record(
        db,
        actor=auth.user.username,
        action="restore.plan",
        target=f"run:{run.id}",
        ip=client_ip(request),
        details={
            "mode": choice.mode,
            "host_id": host.id,
            "flags": [flag.key for flag in plan.risk],
            "signed": signed(doc),
            **stack_details(summary),
        },
    )
    db.commit()
    return see_other(request, f"/restore/runs/{run.id}/plan")


def stack_details(summary: dict[str, Any]) -> dict[str, Any]:
    """The project and compose directory of a summary, for audit details, when set."""
    details: dict[str, Any] = {}
    if isinstance(summary.get("project"), str):
        details["project"] = summary["project"]
    compose = summary.get("compose")
    if isinstance(compose, dict) and isinstance(compose.get("dir"), str):
        details["compose_dir"] = compose["dir"]
    return details


@router.post("/runs/{restore_id}/execute")
def execute_restore(
    request: Request,
    restore_id: int,
    auth: Admin,
    confirm_name: FormStr = "",
    plan_digest_seen: Annotated[str, Form(alias="plan_digest")] = "",
    ack: Annotated[list[str] | None, Form()] = None,
    db: Session = Depends(get_db),
) -> Response:
    """Runs the confirmed plan, once: the one whose digest the confirm form carries. The
    dispatcher plans again against the host and refuses to run anything but the summary
    confirmed here."""
    run = get_restore(db, restore_id)
    doc = run_doc(run)
    acknowledged = set(ack or [])

    def refuse(status_code: int, error: str, **details: Any) -> Response:
        audit.record(
            db,
            actor=auth.user.username,
            action="restore.execute",
            target=f"run:{restore_id}",
            outcome="failure",
            ip=client_ip(request),
            details={"error": error, **details},
        )
        db.commit()
        return plan_page(
            request, db, auth, get_restore(db, restore_id), status_code, errors=[error]
        )

    # First, whatever the plan state: an admin never gets past an unsigned or flagged archive.
    if needs_superadmin(doc) and auth.user.role < Role.superadmin:
        deny(db, auth, request, "restore.execute", run, UNSIGNED if not signed(doc) else FLAGGED)
    summary = summary_of(doc)
    choice = stored_choice(doc)
    if summary is None or choice is None:
        return refuse(409, "Plan the restore first.")
    # The dispatcher compares the stored choice and summary with the ones this digest
    # covers again, inside the transaction that queues the run.
    if not hmac.compare_digest(plan_digest_seen.encode(), plan_digest(doc).encode()):
        return refuse(409, PLAN_CHANGED, mode=choice.mode)
    flags = risk_flags(summary)
    overwrite = choice.mode == "overwrite"
    if not signed(doc) or flags or overwrite or choice.mode == "data-only":
        require_recent_auth(auth)
    if overwrite:
        containers = summary.get("containers")
        project = summary.get("project")
        if project is not None:  # a stack: its project name
            expected = project
            error = "Type the project name to confirm."
        else:
            expected = containers[0] if isinstance(containers, list) and containers else None
            error = "Type the container name to confirm."
        if not isinstance(expected, str) or confirm_name.strip() != expected:
            return refuse(422, error, mode=choice.mode)
    missing = [flag for flag in flags if flag["key"] not in acknowledged]
    if missing:
        fields = ", ".join(f"{flag.get('subject')} {flag.get('field')}" for flag in missing)
        return refuse(422, f"Acknowledge every flagged field first: {fields}.", mode=choice.mode)
    keys = sorted(flag["key"] for flag in flags)
    seen = {"choice": doc.get("choice"), "summary": summary}
    choice = dataclasses.replace(choice, acknowledged=frozenset(keys))
    username = auth.user.username  # read before the release expires auth.user
    run = release(db, run)
    try:
        anyio.from_thread.run(
            functools.partial(dispatcher(request).execute_restore, seen=seen),
            run.id,
            choice,
            username,
        )
    except DispatchError as exc:
        return refuse(409, str(exc), mode=choice.mode)
    audit.record(
        db,
        actor=auth.user.username,
        action="restore.execute",
        target=f"run:{run.id}",
        ip=client_ip(request),
        details={
            "mode": choice.mode,
            "host_id": choice.host_id,
            "acknowledged": keys,
            "signed": signed(doc),
            **stack_details(summary),
        },
    )
    db.commit()
    return see_other(request, f"/runs/{run.id}")
