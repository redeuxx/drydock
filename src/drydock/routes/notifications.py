"""Notification targets: where run results go (notify.py). Every change is audited.

Like the hook library (Decision 2), only superadmins add, change, test or delete targets,
with recent auth: a target makes drydock send requests from its own container, to
internal hosts too. Admins see the list and attach targets to jobs on the job form.

A target's Apprise URL is built here from the form and stored only encrypted. No page or
form ever shows it again, nor does the audit log: they show the name, the kind and the
jobs that use it. Editing keeps the destination unless values for it are entered (then
the whole destination is entered again), and destination fields are never filled back
into a form, even after a validation error.
"""

import re
from dataclasses import dataclass, fields, replace
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from drydock import audit, notify
from drydock.db import get_db
from drydock.models import Host, Job, JobNotification, NotificationTarget
from drydock.routes.auth import client_ip
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter(prefix="/notifications")

Admin = Annotated[Auth, Depends(require_role(Role.admin))]
Superadmin = Annotated[Auth, Depends(require_role(Role.superadmin))]

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,63}")
KIND_LABELS = {
    "webhook": "Webhook (JSON POST)",
    "email": "Email (SMTP)",
    "ntfy": "ntfy",
    "gotify": "Gotify",
    "url": "Other Apprise URL",
}
# Each kind's destination fields: any of them filled on edit replaces the destination.
DESTINATION = {
    "webhook": ("webhook_url",),
    "email": ("smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from", "smtp_to"),
    "ntfy": ("ntfy_server", "ntfy_topic", "ntfy_token"),
    "gotify": ("gotify_server", "gotify_token"),
    "url": ("raw_url",),
}
# Never rendered back: anything that can hold a credential.
SECRET_FIELDS = (
    "webhook_url",
    "smtp_user",
    "smtp_password",
    "ntfy_server",
    "ntfy_token",
    "gotify_server",
    "gotify_token",
    "raw_url",
)
NEW_DESTINATION = "Enter the new destination, or keep the kind it has."


@dataclass
class TargetForm:
    name: str = ""
    kind: str = "webhook"
    enabled: bool = True
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: str = ""
    smtp_security: str = "starttls"
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    ntfy_server: str = ""
    ntfy_topic: str = ""
    ntfy_token: str = ""
    gotify_server: str = ""
    gotify_token: str = ""
    raw_url: str = ""

    def shown(self) -> TargetForm:
        """The form as it may be rendered: secrets left out."""
        return replace(self, **dict.fromkeys(SECRET_FIELDS, ""))


def submitted(values: dict[str, str]) -> TargetForm:
    form = TargetForm(enabled=values.get("enabled") == "1")
    for field in fields(TargetForm):
        if field.name != "enabled":
            value = values.get(field.name, "")
            # Passwords and tokens are taken as typed; everything else is trimmed.
            setattr(form, field.name, value if field.name == "smtp_password" else value.strip())
    return form


def destination(form: TargetForm) -> str:
    """The Apprise URL the form describes. Raises notify.NotifyError."""
    if form.kind == "webhook":
        return notify.webhook_url(form.webhook_url)
    if form.kind == "email":
        return notify.email_url(
            form.smtp_host,
            form.smtp_port,  # empty: the usual port for the security chosen
            form.smtp_security,
            form.smtp_user,
            form.smtp_password,
            form.smtp_from,
            form.smtp_to,
        )
    if form.kind == "ntfy":
        return notify.ntfy_url(form.ntfy_server, form.ntfy_topic, form.ntfy_token)
    if form.kind == "gotify":
        return notify.gotify_url(form.gotify_server, form.gotify_token)
    return notify.check_url(form.raw_url)


def validate(
    db: Session, form: TargetForm, target: NotificationTarget | None = None
) -> tuple[list[str], str | None]:
    """The errors, and the new URL (None: keep the stored one)."""
    errors = []
    if not NAME_RE.fullmatch(form.name):
        errors.append("Name must be 1 to 64 letters, digits, spaces, dots, dashes or underscores.")
    else:
        query = select(NotificationTarget.id).where(NotificationTarget.name == form.name)
        if target is not None:
            query = query.where(NotificationTarget.id != target.id)
        if db.scalar(query) is not None:
            errors.append("A notification target with that name exists.")
    if form.kind not in notify.KINDS:
        errors.append("Choose the kind of target.")
        return errors, None
    url = None
    keep = target is not None and not any(getattr(form, f) for f in DESTINATION[form.kind])
    if keep and target is not None and form.kind != target.kind:
        errors.append(NEW_DESTINATION)
    elif not keep:
        try:
            url = destination(form)
        except notify.NotifyError as exc:
            errors.append(str(exc))
    return errors, url


def users(db: Session, target: NotificationTarget) -> list[str]:
    return list(
        db.scalars(
            select(Job.name)
            .join(JobNotification, JobNotification.job_id == Job.id)
            .where(JobNotification.target_id == target.id)
            .order_by(Job.name)
        )
    )


def summary(target: NotificationTarget) -> dict[str, Any]:
    """Audit details: never the URL."""
    return {"name": target.name, "kind": target.kind, "enabled": target.enabled}


def get_target(db: Session, target_id: int) -> NotificationTarget:
    target = db.get(NotificationTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404)
    return target


def edit_page(
    request: Request,
    db: Session,
    auth: Auth,
    target: NotificationTarget,
    status_code: int = 200,
    **context: Any,
) -> Response:
    context.setdefault("form", TargetForm(target.name, target.kind, target.enabled))
    context.setdefault("errors", [])
    context.setdefault("test", None)
    return render(
        request,
        "notifications/edit.html",
        status_code,
        auth=auth,
        target=target,
        jobs=users(db, target),
        kind_labels=KIND_LABELS,
        **context,
    )


# LIST AND CREATE


@router.get("")
def list_targets(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    targets = db.scalars(select(NotificationTarget).order_by(NotificationTarget.name)).all()
    rows = [(t, users(db, t)) for t in targets]
    return render(request, "notifications/list.html", auth=auth, rows=rows, kind_labels=KIND_LABELS)


@router.get("/new")
def new_target_form(request: Request, auth: Superadmin) -> Response:
    return render(
        request,
        "notifications/new.html",
        auth=auth,
        form=TargetForm(),
        errors=[],
        kind_labels=KIND_LABELS,
    )


async def form_values(request: Request) -> dict[str, str]:
    """The submitted fields as strings: the last value of a repeated field, as the CSRF
    check reads it; file fields are dropped."""
    values = await request.form()
    return {k: v for k, v in values.items() if isinstance(v, str)}


FormValues = Annotated[dict[str, str], Depends(form_values)]


@router.post("")
def create_target(
    request: Request, auth: Superadmin, values: FormValues, db: Session = Depends(get_db)
) -> Response:
    require_recent_auth(auth)
    form = submitted(values)
    errors, url = validate(db, form)
    if errors or url is None:
        db.rollback()
        return render(
            request,
            "notifications/new.html",
            422,
            auth=auth,
            form=form.shown(),
            errors=errors,
            kind_labels=KIND_LABELS,
        )
    target = NotificationTarget(
        name=form.name,
        kind=form.kind,
        url_enc=request.app.state.crypto.encrypt(url),
        enabled=form.enabled,
    )
    db.add(target)
    db.flush()
    audit.record(
        db,
        actor=auth.user.username,
        action="notification.create",
        target=f"notification:{target.id}",
        ip=client_ip(request),
        details=summary(target),
    )
    db.commit()
    return see_other(request, f"/notifications/{target.id}")


# EDIT


@router.get("/{target_id}")
def edit_target(
    request: Request, target_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    return edit_page(request, db, auth, get_target(db, target_id))


@router.post("/{target_id}")
def update_target(
    request: Request,
    target_id: int,
    auth: Superadmin,
    values: FormValues,
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    target = get_target(db, target_id)
    form = submitted(values)
    errors, url = validate(db, form, target)
    if errors:
        db.rollback()
        return edit_page(request, db, auth, target, 422, form=form.shown(), errors=errors)
    before = summary(target)
    target.name = form.name
    target.kind = form.kind
    target.enabled = form.enabled
    if url is not None:
        target.url_enc = request.app.state.crypto.encrypt(url)
    details: dict[str, Any] = {
        k: {"from": before[k], "to": v} for k, v in summary(target).items() if before[k] != v
    }
    if url is not None:
        details["destination"] = "replaced"
    audit.record(
        db,
        actor=auth.user.username,
        action="notification.update",
        target=f"notification:{target.id}",
        ip=client_ip(request),
        details=details,
    )
    db.commit()
    return see_other(request, f"/notifications/{target.id}")


@router.post("/{target_id}/delete")
def delete_target(
    request: Request, target_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    require_recent_auth(auth)
    target = get_target(db, target_id)
    audit.record(
        db,
        actor=auth.user.username,
        action="notification.delete",
        target=f"notification:{target.id}",
        ip=client_ip(request),
        details=summary(target) | {"detached_from": users(db, target)},
    )
    db.delete(target)  # its job attachments go with it (ON DELETE CASCADE)
    db.execute(update(Host).where(Host.alert_target_id == target_id).values(alert_target_id=None))
    db.commit()
    return see_other(request, "/notifications")


@router.post("/{target_id}/test")
def test_target(
    request: Request, target_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    """Sends a test message now, from the drydock container. The transaction (and so the
    database write lock) ends before the send, which can take NOTIFY_TIMEOUT."""
    require_recent_auth(auth)
    target = get_target(db, target_id)
    name, url_enc = target.name, target.url_enc
    db.rollback()
    outcome = request.app.state.notifier.test(name, url_enc)
    target = get_target(db, target_id)
    audit.record(
        db,
        actor=auth.user.username,
        action="notification.test",
        target=f"notification:{target.id}",
        outcome="success" if outcome.ok else "failure",
        ip=client_ip(request),
        details={"name": target.name, "result": outcome.detail},
    )
    db.commit()
    return edit_page(request, db, auth, target, test=outcome)
