"""Update policies: scheduled updates of a container or a Compose stack (updates/apply.py),
optionally after a backup by one of the jobs, telling a notification target how it went.

Operators see the policies and may run one now; admins create, edit and delete them.
Every change and every run started here is audited.
"""

from dataclasses import dataclass
from typing import Annotated, Any

import anyio.from_thread
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.jobs import scheduler
from drydock.jobs import targets as job_targets
from drydock.jobs.dispatcher import DispatchError
from drydock.models import Host, Job, NotificationTarget, UpdatePolicy, utcnow
from drydock.routes.auth import client_ip
from drydock.routes.containers import CONTAINER_ID_RE
from drydock.routes.jobs import (
    JOB_NAME_RE,
    SCHEDULE_PRESETS,
    as_id,
    check_one,
    schedule_label,
    scheduled,
    sorted_zones,
)
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter(prefix="/updates")

Operator = Annotated[Auth, Depends(require_role(Role.operator))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]
# A policy runs on a schedule: "only by hand" is the containers page's Update button.
PRESETS = {k: v for k, v in SCHEDULE_PRESETS.items() if k != "manual"}
DEFAULT_CRON = "0 4 * * 0"
PRESETS.setdefault(DEFAULT_CRON, "Every Sunday at 04:00")


@dataclass
class PolicyForm:
    name: str = ""
    host_id: str = ""
    target_type: str = "container"
    target: str = ""
    cron_preset: str = DEFAULT_CRON
    cron: str = DEFAULT_CRON
    timezone: str = ""
    backup_job_id: str = ""
    stop_on_failed_backup: bool = True
    notify_target_id: str = ""
    notify_success: bool = False
    enabled: bool = True

    @classmethod
    def from_policy(cls, policy: UpdatePolicy) -> PolicyForm:
        return cls(
            name=policy.name,
            host_id=str(policy.host_id),
            target_type=policy.target_type,
            target=policy.target,
            cron_preset=policy.cron if policy.cron in PRESETS else "custom",
            cron=policy.cron,
            timezone=policy.timezone or "",
            backup_job_id=str(policy.backup_job_id or ""),
            stop_on_failed_backup=policy.stop_on_failed_backup,
            notify_target_id=str(policy.notify_target_id or ""),
            notify_success=policy.notify_success,
            enabled=policy.enabled,
        )

    @classmethod
    async def read(cls, request: Request) -> PolicyForm:
        form = await request.form()

        def text(key: str, default: str = "") -> str:
            value = form.get(key, default)
            return value.strip()[:300] if isinstance(value, str) else default

        preset = text("cron_preset", DEFAULT_CRON)
        # A preset wins over the (hidden) cron field; "custom" uses what was typed.
        if preset in PRESETS and preset != "custom":
            cron = preset
        else:
            cron = scheduled(text("cron"), "custom")
        return cls(
            name=text("name"),
            host_id=text("host_id"),
            target_type=text("target_type", "container"),
            target=text("target"),
            cron_preset=preset if preset in PRESETS else "custom",
            cron=cron,
            timezone=text("timezone"),
            backup_job_id=text("backup_job_id"),
            stop_on_failed_backup=form.get("stop_on_failed_backup") == "1",
            notify_target_id=text("notify_target_id"),
            notify_success=form.get("notify_success") == "1",
            enabled=form.get("enabled") == "1",
        )


def validate(db: Session, form: PolicyForm, default_tz: str, policy_id: int | None) -> list[str]:
    errors = []
    if not JOB_NAME_RE.fullmatch(form.name):
        errors.append("Name must be 1 to 64 characters.")
    else:
        query = select(UpdatePolicy.id).where(UpdatePolicy.name == form.name)
        if policy_id is not None:
            query = query.where(UpdatePolicy.id != policy_id)
        if db.scalar(query) is not None:
            errors.append("An update policy with that name exists.")
    host_id = as_id(form.host_id)
    if host_id is None or db.get(Host, host_id) is None:
        errors.append("Choose a host.")
    if (target_error := check_one(form.target_type, form.target)) is not None:
        errors.append(target_error.replace("back up", "update"))
    elif form.target_type == "container" and CONTAINER_ID_RE.fullmatch(form.target):
        # An update makes the container again with a new ID: only its name stays.
        errors.append("Enter the container's name, not its ID: an update gives it a new ID.")
    if not form.cron:
        errors.append("Choose a schedule.")
    else:
        try:
            if form.timezone:
                scheduler.zone(form.timezone)
            scheduler.checked(form.cron, form.timezone or default_tz, utcnow())
        except scheduler.CronError as exc:
            errors.append(str(exc))
    if form.backup_job_id:
        job = db.get(Job, as_id(form.backup_job_id) or 0)
        if job is None:
            errors.append("Choose an existing job for the backup first.")
        elif job.host_id != host_id or (form.target_type, form.target) not in {
            (t.target_type, t.target) for t in job_targets.of(db, job)
        }:
            errors.append("The backup job must back up this container or stack on this host.")
    if (
        form.notify_target_id
        and db.get(NotificationTarget, as_id(form.notify_target_id) or 0) is None
    ):
        errors.append("Choose an existing notification target.")
    return errors


def apply_form(policy: UpdatePolicy, form: PolicyForm) -> None:
    policy.name = form.name
    policy.host_id = as_id(form.host_id) or 0
    policy.target_type = form.target_type
    policy.target = form.target
    policy.cron = form.cron
    policy.timezone = form.timezone or None
    policy.backup_job_id = as_id(form.backup_job_id) if form.backup_job_id else None
    policy.stop_on_failed_backup = form.stop_on_failed_backup
    policy.notify_target_id = as_id(form.notify_target_id) if form.notify_target_id else None
    policy.notify_success = form.notify_success
    policy.enabled = form.enabled
    policy.updated_at = utcnow()


def summary(policy: UpdatePolicy) -> dict[str, Any]:
    return {
        "name": policy.name,
        "host_id": policy.host_id,
        "target": f"{policy.target_type}:{policy.target}",
        "cron": policy.cron,
        "timezone": policy.timezone,
        "backup_job_id": policy.backup_job_id,
        "enabled": policy.enabled,
    }


def get_policy(db: Session, policy_id: int) -> UpdatePolicy:
    policy = db.get(UpdatePolicy, policy_id)
    if policy is None:
        raise HTTPException(status_code=404)
    return policy


def edit_page(
    request: Request,
    auth: Auth,
    db: Session,
    form: PolicyForm,
    policy: UpdatePolicy | None,
    errors: list[str] | None = None,
    status_code: int = 200,
) -> Response:
    return render(
        request,
        "updates/edit.html",
        status_code,
        auth=auth,
        form=form,
        policy=policy,
        errors=errors or [],
        presets=PRESETS,
        hosts=list(db.scalars(select(Host).order_by(Host.name))),
        jobs=list(db.scalars(select(Job).order_by(Job.name))),
        targets=list(db.scalars(select(NotificationTarget).order_by(NotificationTarget.name))),
        default_tz=request.app.state.settings.tz,
        zones=sorted_zones(),
    )


def rebuild(request: Request) -> None:
    anyio.from_thread.run(request.app.state.scheduler.rebuild)


@router.get("")
def list_policies(request: Request, auth: Operator, db: Session = Depends(get_db)) -> Response:
    policies = list(db.scalars(select(UpdatePolicy).order_by(UpdatePolicy.name)))
    sched = request.app.state.scheduler
    return render(
        request,
        "updates/list.html",
        auth=auth,
        rows=[
            (p, schedule_label(p.cron), sched.next_update_time(p.id) if p.enabled else None)
            for p in policies
        ],
        hosts={h.id: h.name for h in db.scalars(select(Host))},
        jobs={j.id: j.name for j in db.scalars(select(Job))},
    )


@router.get("/new")
def new_policy(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    host = request.query_params.get("host", "")
    kind = request.query_params.get("type", "container")
    form = PolicyForm(
        host_id=host if host.isdigit() else "",
        target_type=kind if kind in ("container", "stack") else "container",
        target=request.query_params.get("target", "")[:255],
    )
    return edit_page(request, auth, db, form, None)


async def read_form(request: Request) -> PolicyForm:
    return await PolicyForm.read(request)


Form = Annotated[PolicyForm, Depends(read_form)]


@router.post("")
def create_policy(
    request: Request, auth: Admin, form: Form, db: Session = Depends(get_db)
) -> Response:
    errors = validate(db, form, request.app.state.settings.tz, None)
    if errors:
        db.rollback()
        return edit_page(request, auth, db, form, None, errors, 422)
    policy = UpdatePolicy()
    apply_form(policy, form)
    db.add(policy)
    db.flush()
    audit.record(
        db,
        actor=auth.user.username,
        action="update_policy.create",
        target=f"update_policy:{policy.id}",
        ip=client_ip(request),
        details=summary(policy),
    )
    db.commit()
    rebuild(request)
    return see_other(request, "/updates")


@router.get("/{policy_id}")
def edit_policy(
    request: Request, policy_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    policy = get_policy(db, policy_id)
    return edit_page(request, auth, db, PolicyForm.from_policy(policy), policy)


@router.post("/{policy_id}")
def update_policy(
    request: Request, policy_id: int, auth: Admin, form: Form, db: Session = Depends(get_db)
) -> Response:
    policy = get_policy(db, policy_id)
    errors = validate(db, form, request.app.state.settings.tz, policy_id)
    if errors:
        db.rollback()
        return edit_page(request, auth, db, form, get_policy(db, policy_id), errors, 422)
    apply_form(policy, form)
    audit.record(
        db,
        actor=auth.user.username,
        action="update_policy.update",
        target=f"update_policy:{policy.id}",
        ip=client_ip(request),
        details=summary(policy),
    )
    db.commit()
    rebuild(request)
    return see_other(request, "/updates")


@router.post("/{policy_id}/delete")
def delete_policy(
    request: Request, policy_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    policy = get_policy(db, policy_id)
    audit.record(
        db,
        actor=auth.user.username,
        action="update_policy.delete",
        target=f"update_policy:{policy.id}",
        ip=client_ip(request),
        details=summary(policy),
    )
    db.delete(policy)
    db.commit()
    rebuild(request)
    return see_other(request, "/updates")


@router.post("/{policy_id}/run")
def run_policy(
    request: Request, policy_id: int, auth: Operator, db: Session = Depends(get_db)
) -> Response:
    """Runs the policy's update now (its backup first included). Audited."""
    policy = get_policy(db, policy_id)
    name = policy.name
    db.rollback()
    try:
        run_id = anyio.from_thread.run(
            request.app.state.dispatcher.submit_policy, policy_id, auth.user.username
        )
        error = None
    except DispatchError as exc:
        run_id, error = None, str(exc)
    audit.record(
        db,
        actor=auth.user.username,
        action="update_policy.run",
        target=f"update_policy:{policy_id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"name": name} | ({"run_id": run_id} if run_id else {"error": error}),
    )
    db.commit()
    if run_id is None:
        raise HTTPException(status_code=409, detail=error)
    return see_other(request, f"/runs/{run_id}")
