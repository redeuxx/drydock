"""The bell: what happened lately, per user.

Nothing is stored for it but each user's feed_read_at. Items come from what drydock records
anyway: finished runs (backups for every role, restores for admins, as their pages allow)
and a few audit events admins should see. An item is unread when it is newer than the
user's feed_read_at, or than the account itself before the first "Mark all read".
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from drydock.models import AuditEvent, Job, Run, User
from drydock.security.rbac import Role

DROPDOWN = 8
PAGE = 100
MAX_COUNT = 99  # the badge shows "99+" above this
LEVELS = {"done": "success", "cancelled": "warning"}  # every other end is an error
# Audit events worth a bell for admins: title and the page that helps.
ALERTS = {
    "host.hostkey_mismatch": ("Host key mismatch on host {id}", "/hosts/{id}"),
    "job.schedule_missed": ("A scheduled run of job {id} was missed", "/jobs/{id}"),
    "storage.oauth_revoked": ("Google Drive storage {id} needs reconnecting", "/storage/{id}"),
}


@dataclass(frozen=True)
class Item:
    when: datetime
    level: str  # success, warning or error
    title: str
    link: str
    unread: bool


def read_since(user: User) -> datetime:
    return user.feed_read_at or user.created_at


def run_query(user: User):
    query = select(Run, Job.name).outerjoin(Job, Run.job_id == Job.id)
    query = query.where(Run.finished_at.is_not(None))
    if user.role < Role.admin:
        query = query.where(Run.kind == "backup")
    return query


def alert_query(user: User):
    if user.role < Role.admin:
        return None
    return select(AuditEvent).where(AuditEvent.action.in_(ALERTS))


def run_item(run: Run, job_name: str | None, since: datetime) -> Item:
    level = LEVELS.get(run.status, "error")
    if run.kind == "restore":
        title, link = f"Restore #{run.id}: {run.status}", f"/restore/runs/{run.id}"
    else:
        title, link = f"Backup of {job_name or 'a deleted job'}: {run.status}", f"/runs/{run.id}"
    when = run.finished_at or run.created_at
    return Item(when, level, title, link, when > since)


def alert_item(event: AuditEvent, since: datetime) -> Item:
    title, link = ALERTS[event.action]
    _, _, ident = (event.target or "").partition(":")
    ident = ident if ident.isdigit() else "?"
    level = "warning" if event.action == "job.schedule_missed" else "error"
    return Item(
        event.ts,
        level,
        title.format(id=ident),
        link.format(id=ident) if ident != "?" else "/",
        event.ts > since,
    )


def items(db: Session, user: User, limit: int) -> list[Item]:
    since = read_since(user)
    found = [
        run_item(run, name, since)
        for run, name in db.execute(run_query(user).order_by(Run.finished_at.desc()).limit(limit))
    ]
    if (alerts := alert_query(user)) is not None:
        events = db.scalars(alerts.order_by(AuditEvent.ts.desc()).limit(limit))
        found += [alert_item(event, since) for event in events]
    return sorted(found, key=lambda item: item.when, reverse=True)[:limit]


def unread(db: Session, user: User) -> int:
    since = read_since(user)
    runs = run_query(user).where(Run.finished_at > since).limit(MAX_COUNT + 1).subquery()
    count = db.scalar(select(func.count()).select_from(runs)) or 0
    if (alerts := alert_query(user)) is not None:
        recent = alerts.where(AuditEvent.ts > since).limit(MAX_COUNT + 1).subquery()
        count += db.scalar(select(func.count()).select_from(recent)) or 0
    return count


def summary(db: Session, user: User) -> dict[str, Any]:
    """What base.html's bell shows on every page."""
    return {"items": items(db, user, DROPDOWN), "unread": unread(db, user), "max": MAX_COUNT}
