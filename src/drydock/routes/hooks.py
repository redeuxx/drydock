"""The hook library: commands that jobs run with exec in a container before and after their
data read (jobs/hooks.py runs them).

A hook runs arbitrary commands inside containers, so only a superadmin with the password
from the last 10 minutes creates, edits or deletes one (Decisions 2 and 5), and every
change is audited with before and after values. The superadmin also binds each hook to one
host entry and to one container or Compose project (hooks.check_binding): admins attach
hooks to jobs by name but never choose where they run, and an edit that would move a hook
away from a job it is attached to is refused. Admins see the library, argv included, so
they know what they attach; viewers and operators see only hook names on job pages.
"""

import json
import types
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.jobs import hooks
from drydock.models import Hook, Host, Job, utcnow
from drydock.routes.auth import FormStr, client_ip
from drydock.routes.jobs import PHASES, as_id, hook_ids
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter(prefix="/hooks")

Admin = Annotated[Auth, Depends(require_role(Role.admin))]
Superadmin = Annotated[Auth, Depends(require_role(Role.superadmin))]


@dataclass
class HookForm:
    """The hook form as typed (argv is the JSON text)."""

    name: str = ""
    host_id: str = ""
    project: str = ""
    container: str = ""
    argv: str = ""
    user: str = ""
    workdir: str = ""
    timeout_s: str = str(hooks.DEFAULT_TIMEOUT)
    log_output: bool = False

    @classmethod
    def from_hook(cls, row: Hook) -> HookForm:
        return cls(
            name=row.name,
            host_id=str(row.host_id),
            project=row.project or "",
            container=row.container,
            argv=argv_text(row),
            user=row.user,
            workdir=row.workdir,
            timeout_s=str(row.timeout_s),
            log_output=row.log_output,
        )


def argv_text(row: Hook) -> str:
    """The stored argv as readable JSON (the stored text itself if it is not JSON)."""
    try:
        return json.dumps(json.loads(row.argv_json), ensure_ascii=False)
    except ValueError, RecursionError:
        return row.argv_json


def used_by(db: Session, hook_id: int) -> list[tuple[Job, str]]:
    """The jobs that list this hook, as (job, "before" or "after"), by job name. A job whose
    list is not valid JSON is skipped (job saves write it, so this is defensive)."""
    result = []
    for job in db.scalars(select(Job).order_by(Job.name)):
        for column, phase in PHASES:
            if hook_id in hook_ids(getattr(job, column)):
                result.append((job, phase))
    return result


def get_hook(db: Session, hook_id: int) -> Hook:
    row = db.get(Hook, hook_id)
    if row is None:
        raise HTTPException(status_code=404)
    return row


def name_taken(db: Session, name: str, hook_id: int | None = None) -> bool:
    query = select(Hook.id).where(Hook.name == name)  # NOCASE, like the column
    if hook_id is not None:
        query = query.where(Hook.id != hook_id)
    return db.scalar(query) is not None


def check_form(
    db: Session, form: HookForm, hook_id: int | None = None
) -> tuple[hooks.HookFields | None, int | None, list[str]]:
    """Validates the form: the fields, the host ID and the errors."""
    fields, errors = hooks.validate_form(
        form.name,
        form.container,
        form.argv,
        form.user,
        form.workdir,
        form.timeout_s,
        form.project,
        "1" if form.log_output else "",
    )
    host_id = as_id(form.host_id)
    if host_id is None or db.get(Host, host_id) is None:
        host_id = None
        errors.append("Choose a host.")
    if fields is not None and name_taken(db, fields.name, hook_id):
        errors.append("A hook with that name exists.")
    return fields, host_id, errors


def apply(row: Hook, fields: hooks.HookFields, host_id: int) -> None:
    row.name = fields.name
    row.host_id = host_id
    row.project = fields.project
    row.container = fields.container
    row.argv_json = hooks.argv_json(fields.argv)
    row.user = fields.user
    row.workdir = fields.workdir
    row.timeout_s = fields.timeout_s
    row.log_output = fields.log_output
    row.updated_at = utcnow()


def submitted(**values: str) -> HookForm:
    return HookForm(
        name=values["name"],
        host_id=values["host_id"].strip(),
        project=values["project"],
        container=values["container"],
        argv=values["argv"],
        user=values["user"],
        workdir=values["workdir"],
        timeout_s=values["timeout_s"],
        log_output=values["log_output"] in ("1", "on"),
    )


def hosts_list(db: Session) -> list[Host]:
    return list(db.scalars(select(Host).order_by(Host.name)))


def hook_page(
    request: Request,
    db: Session,
    auth: Auth,
    row: Hook,
    status_code: int = 200,
    **context: Any,
) -> Response:
    context.setdefault("form", HookForm.from_hook(row))
    context.setdefault("errors", [])
    context.setdefault("error", None)
    return render(
        request,
        "hooks/detail.html",
        status_code,
        auth=auth,
        hook=row,
        host=db.get(Host, row.host_id),
        argv=argv_text(row),
        jobs=used_by(db, row.id),
        hosts=hosts_list(db),
        **context,
    )


# LIST AND CREATE


@router.get("")
def list_hooks(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    rows = db.scalars(select(Hook).order_by(Hook.name)).all()
    host_names = {h.id: h.name for h in db.scalars(select(Host))}
    users: dict[int, set[int]] = {}
    for job in db.scalars(select(Job)):
        for column, _phase in PHASES:
            for hook_id in hook_ids(getattr(job, column)):
                users.setdefault(hook_id, set()).add(job.id)
    listing = [(row, host_names.get(row.host_id), len(users.get(row.id, ()))) for row in rows]
    return render(request, "hooks/list.html", auth=auth, rows=listing)


@router.get("/new")
def new_hook_form(request: Request, auth: Superadmin, db: Session = Depends(get_db)) -> Response:
    return render(
        request, "hooks/new.html", auth=auth, form=HookForm(), errors=[], hosts=hosts_list(db)
    )


@router.post("")
def create_hook(
    request: Request,
    auth: Superadmin,
    name: FormStr = "",
    host_id: FormStr = "",
    project: FormStr = "",
    container: FormStr = "",
    argv: FormStr = "",
    user: FormStr = "",
    workdir: FormStr = "",
    timeout_s: FormStr = "",
    log_output: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    form = submitted(
        name=name,
        host_id=host_id,
        project=project,
        container=container,
        argv=argv,
        user=user,
        workdir=workdir,
        timeout_s=timeout_s,
        log_output=log_output,
    )
    fields, bound_host, errors = check_form(db, form)
    if errors or fields is None or bound_host is None:
        db.rollback()
        return render(
            request,
            "hooks/new.html",
            422,
            auth=auth,
            form=form,
            errors=errors,
            hosts=hosts_list(db),
        )
    row = Hook()
    apply(row, fields, bound_host)
    db.add(row)
    db.flush()
    audit.record(
        db,
        actor=auth.user.username,
        action="hook.create",
        target=f"hook:{row.id}",
        ip=client_ip(request),
        details=hooks.summary(row),
    )
    db.commit()
    return see_other(request, f"/hooks/{row.id}")


# VIEW AND EDIT


@router.get("/{hook_id}")
def view_hook(
    request: Request, hook_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    return hook_page(request, db, auth, get_hook(db, hook_id))


@router.post("/{hook_id}")
def update_hook(
    request: Request,
    hook_id: int,
    auth: Superadmin,
    name: FormStr = "",
    host_id: FormStr = "",
    project: FormStr = "",
    container: FormStr = "",
    argv: FormStr = "",
    user: FormStr = "",
    workdir: FormStr = "",
    timeout_s: FormStr = "",
    log_output: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    row = get_hook(db, hook_id)
    form = submitted(
        name=name,
        host_id=host_id,
        project=project,
        container=container,
        argv=argv,
        user=user,
        workdir=workdir,
        timeout_s=timeout_s,
        log_output=log_output,
    )
    fields, bound_host, errors = check_form(db, form, row.id)
    if not errors and fields is not None and bound_host is not None:
        # Every job that has this hook attached must still accept it where it now runs.
        bound = types.SimpleNamespace(
            name=fields.name,
            host_id=bound_host,
            project=fields.project,
            container=fields.container,
        )
        refused = set()
        for job, _phase in used_by(db, row.id):
            try:
                hooks.check_binding(
                    bound, host_id=job.host_id, target_type=job.target_type, target=job.target
                )
            except hooks.HookError:
                refused.add(job.name)
        if refused:
            names = ", ".join(sorted(refused))
            errors.append(
                f"Jobs {names} would no longer match this hook. Detach it from them first."
            )
    if errors or fields is None or bound_host is None:
        db.rollback()
        return hook_page(request, db, auth, get_hook(db, hook_id), 422, form=form, errors=errors)
    before = hooks.summary(row)
    apply(row, fields, bound_host)
    after = hooks.summary(row)
    audit.record(
        db,
        actor=auth.user.username,
        action="hook.update",
        target=f"hook:{row.id}",
        ip=client_ip(request),
        details={k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]},
    )
    db.commit()
    return see_other(request, f"/hooks/{row.id}")


@router.post("/{hook_id}/delete")
def delete_hook(
    request: Request, hook_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    require_recent_auth(auth)
    row = get_hook(db, hook_id)
    users = sorted({job.name for job, _phase in used_by(db, row.id)})
    if users:
        error = f"Hook {row.name} is attached to jobs {', '.join(users)}. Detach it first."
        audit.record(
            db,
            actor=auth.user.username,
            action="hook.delete",
            target=f"hook:{row.id}",
            outcome="failure",
            ip=client_ip(request),
            details={"name": row.name, "error": error},
        )
        db.commit()
        return hook_page(request, db, auth, get_hook(db, hook_id), 409, error=error)
    audit.record(
        db,
        actor=auth.user.username,
        action="hook.delete",
        target=f"hook:{row.id}",
        ip=client_ip(request),
        details=hooks.summary(row),
    )
    db.delete(row)
    db.commit()
    return see_other(request, "/hooks")
