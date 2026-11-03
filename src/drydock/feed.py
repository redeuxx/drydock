"""The bell: what happened lately, per user, and the job runs the dashboard lists.

Nothing is stored for it but each user's feed_read_at. Items come from what drydock records
anyway: finished runs (backups for every role, restores for admins, as their pages allow)
and a few audit events admins should see. The runs a job started together, one per target,
are one item (a JobRun) that tells how each ended. An item is unread when it changed after
the user's feed_read_at, or after the account was made before the first "Mark all read".
"""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from drydock.jobs.targets import MAX_TARGETS
from drydock.models import AuditEvent, Job, Run, User
from drydock.security.rbac import Role

DROPDOWN = 8
PAGE = 100
MAX_COUNT = 99  # the badge shows "99+" above this
# Worst first: the status a job run shows, and the order its counts are told in.
WORST = ("failed", "interrupted", "running", "queued", "cancelled", "done")
OPEN = ("queued", "verifying", "running", "awaiting_confirmation")
# Audit events worth a bell for admins: title and the page that helps.
ALERTS = {
    "host.hostkey_mismatch": ("Host key mismatch on host {id}", "/hosts/{id}"),
    "job.schedule_missed": ("A scheduled run of job {id} was missed", "/jobs/{id}"),
    "storage.oauth_revoked": ("Google Drive storage {id} needs reconnecting", "/storage/{id}"),
}

# JOB RUNS


@dataclass(frozen=True)
class JobRun:
    """The runs a job started together, one per target and oldest first; or one restore."""

    runs: list[Run]
    job_name: str | None

    @property
    def first(self) -> Run:
        return self.runs[0]

    @property
    def worst(self) -> Run:
        return min(
            self.runs, key=lambda r: WORST.index(r.status) if r.status in WORST else len(WORST)
        )

    @property
    def counts(self) -> list[tuple[str, int]]:
        """(status, how many runs), worst first."""
        found = Counter(r.status for r in self.runs)
        order = [*WORST, *sorted(s for s in found if s not in WORST)]
        return [(status, found[status]) for status in order if found[status]]

    @property
    def level(self) -> str:
        """error, warning, success, or info while a target has not ended."""
        statuses = {r.status for r in self.runs}
        if statuses - {"done", "cancelled", *OPEN}:
            return "error"
        if "cancelled" in statuses:
            return "warning"
        return "success" if statuses == {"done"} else "info"

    @property
    def size(self) -> int | None:
        sizes = [r.size for r in self.runs if r.size is not None]
        return sum(sizes) if sizes else None

    @property
    def when(self) -> datetime:
        """When it last changed: its newest end, or when it was created."""
        return max(r.finished_at or r.created_at for r in self.runs)

    @property
    def took(self) -> timedelta | None:
        starts = [r.started_at for r in self.runs if r.started_at is not None]
        if not starts or any(r.finished_at is None for r in self.runs):
            return None
        return self.when - min(starts)

    @property
    def error(self) -> str | None:
        return self.worst.error or next((r.error for r in self.runs if r.error), None)

    @property
    def title(self) -> str:
        if self.first.kind == "restore":
            return f"Restore #{self.first.id}: {self.first.status.replace('_', ' ')}"
        name = self.job_name or "a deleted job"
        if len(self.runs) == 1:
            return f"Backup of {name}: {self.first.status}"
        counts = self.counts
        told = ", ".join(
            status if len(counts) == 1 else f"{count} {status}" for status, count in counts
        )
        return f"Backup of {name}, {len(self.runs)} targets: {told}"

    @property
    def link(self) -> str:
        if self.first.kind == "restore":
            return f"/restore/runs/{self.first.id}"
        return f"/runs/{self.worst.id}"


def job_runs(db: Session, runs: list[Run], limit: int) -> list[JobRun]:
    """The first limit job runs that runs (in the order wanted) belong to, each with all
    of its runs, also those not in runs."""
    keys = list(dict.fromkeys(r.first_run_id or r.id for r in runs))[:limit]
    grouped: dict[int, dict[int, Run]] = {key: {} for key in keys}
    for run in [*runs, *db.scalars(select(Run).where(Run.first_run_id.in_(keys)))]:
        if (key := run.first_run_id or run.id) in grouped:
            grouped[key][run.id] = run
    groups = [sorted(grouped[key].values(), key=lambda r: r.id) for key in keys]
    job_ids = {group[0].job_id for group in groups if group[0].job_id is not None}
    names = dict(db.execute(select(Job.id, Job.name).where(Job.id.in_(job_ids))).all())
    return [JobRun(group, names.get(group[0].job_id)) for group in groups]


# THE BELL


@dataclass(frozen=True)
class Item:
    when: datetime
    level: str  # success, info, warning or error
    title: str
    link: str
    unread: bool
    job_run: JobRun | None = None


def read_since(user: User) -> datetime:
    return user.feed_read_at or user.created_at


def run_filters(user: User) -> list[Any]:
    filters = [Run.finished_at.is_not(None)]
    if user.role < Role.admin:
        filters.append(Run.kind == "backup")
    return filters


def alert_query(user: User):
    if user.role < Role.admin:
        return None
    return select(AuditEvent).where(AuditEvent.action.in_(ALERTS))


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
    # ponytail: reads limit * MAX_TARGETS runs to find limit job runs; fewer items show
    # only when most recent job runs have close to MAX_TARGETS targets.
    runs = db.scalars(
        select(Run)
        .where(*run_filters(user))
        .order_by(Run.finished_at.desc())
        .limit(limit * MAX_TARGETS)
    ).all()
    found = [
        Item(j.when, j.level, j.title, j.link, j.when > since, j)
        for j in job_runs(db, list(runs), limit)
    ]
    if (alerts := alert_query(user)) is not None:
        events = db.scalars(alerts.order_by(AuditEvent.ts.desc()).limit(limit))
        found += [alert_item(event, since) for event in events]
    return sorted(found, key=lambda item: item.when, reverse=True)[:limit]


def unread(db: Session, user: User) -> int:
    since = read_since(user)
    runs = (
        select(func.coalesce(Run.first_run_id, Run.id))
        .where(*run_filters(user), Run.finished_at > since)
        .distinct()
        .limit(MAX_COUNT + 1)
        .subquery()
    )
    count = db.scalar(select(func.count()).select_from(runs)) or 0
    if (alerts := alert_query(user)) is not None:
        recent = alerts.where(AuditEvent.ts > since).limit(MAX_COUNT + 1).subquery()
        count += db.scalar(select(func.count()).select_from(recent)) or 0
    return count


def summary(db: Session, user: User) -> dict[str, Any]:
    """What base.html's bell shows on every page."""
    return {"items": items(db, user, DROPDOWN), "unread": unread(db, user), "max": MAX_COUNT}
