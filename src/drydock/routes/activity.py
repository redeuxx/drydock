"""The activity page: container events from every host, as hosts/events.py stored them,
and backup runs, newest first in one list. A run sits at the time it was queued, so its
place never moves while its status changes; it is filtered by its job's host and by its
job's name or target. Clearing removes container events only; runs have their own history.

Every role may view it: it shows what the containers page already shows (names, images),
plus what happened to them and when. Filters, the time range and the page are GET
parameters, so the address keeps a view. The newest page refreshes itself every 5
seconds; older pages (keyset pagination on time and id, so rows arriving meanwhile never
shift them) stay still. Admins can clear the record, for one host or all, after entering
their password again; that is audited.
"""

import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import and_, delete, false, func, or_, select, true
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.hosts.events import NS
from drydock.models import DockerEvent, Host, Job, Run
from drydock.routes.auth import client_ip
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other

router = APIRouter()

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]
PAGE = 50
MAX_INT = 2**63 - 1
MAX_QUERY = 100
# Docker's container actions, as the filter offers them.
ACTIONS = {
    "create": "Create",
    "start": "Start",
    "restart": "Restart",
    "stop": "Stop",
    "kill": "Kill",
    "die": "Die",
    "oom": "Out of memory",
    "pause": "Pause",
    "unpause": "Unpause",
    "destroy": "Destroy",
    "rename": "Rename",
    "update": "Update",
    "health_status": "Health",
    "attach": "Attach",
    "detach": "Detach",
    "commit": "Commit",
    "copy": "Copy",
    "export": "Export",
    "resize": "Resize",
    "top": "Top",
}
BACKUP = "backup"  # the action filter's value for backup runs (not a Docker action)
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
RANGES = {
    "1h": ("Last hour", 3600),
    "24h": ("Last 24 hours", 86400),
    "7d": ("Last 7 days", 7 * 86400),
    "30d": ("Last 30 days", 30 * 86400),
    "all": ("All", None),
}


@dataclass(frozen=True)
class View:
    """The filters, as the query string gives them (cleaned)."""

    host: int | None = None
    container: str = ""
    action: str = ""
    range: str = "24h"

    @property
    def query(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in ("", None)}


def view_of(host: str, container: str, action: str, span: str) -> View:
    """host is text: "All hosts" sends it empty."""
    return View(
        host=int(host) if re.fullmatch(r"[0-9]{1,9}", host) else None,
        container=container.strip()[:MAX_QUERY],
        action=action if action in ACTIONS or action == BACKUP else "",
        range=span if span in RANGES else "24h",
    )


def at_us(us: int) -> datetime:
    return EPOCH + timedelta(microseconds=us)


def filtered(view: View, now_ns: int) -> list[Any]:
    """The WHERE clauses of a view, for container events."""
    clauses: list[Any] = []
    if view.action == BACKUP:
        clauses.append(false())
    if view.host is not None:
        clauses.append(DockerEvent.host_id == view.host)
    if view.container:
        # Substring of the name, or the start of the ID; LIKE's wildcards are matched as text.
        text = view.container.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append(
            or_(
                DockerEvent.name.like(f"%{text}%", escape="\\"),
                DockerEvent.container_id.like(f"{text.lower()}%", escape="\\"),
            )
        )
    if view.action:
        clauses.append(DockerEvent.action == view.action)
    seconds = RANGES[view.range][1]
    if seconds is not None:
        clauses.append(DockerEvent.time_ns >= now_ns - seconds * NS)
    return clauses


def run_filtered(view: View, now_ns: int) -> list[Any]:
    """The WHERE clauses of a view, for backup runs (outer-joined to their job)."""
    clauses: list[Any] = [Run.kind == "backup"]
    if view.action and view.action != BACKUP:
        clauses.append(false())
    if view.host is not None:
        clauses.append(Job.host_id == view.host)
    if view.container:
        # The job's name or the run's target; LIKE's wildcards are matched as text.
        text = view.container.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append(
            or_(
                Job.name.like(f"%{text}%", escape="\\"),
                Run.target_label.like(f"%{text}%", escape="\\"),
            )
        )
    seconds = RANGES[view.range][1]
    if seconds is not None:
        clauses.append(Run.created_at >= at_us((now_ns - seconds * NS) // 1000))
    return clauses


# The list is newest first by (time, rank, id): at one instant events (rank 1) come
# before runs (rank 0). A run's time is when it was queued, in whole microseconds.
EVENT, RUN = 1, 0


def parse_before(value: str) -> tuple[int, int, int] | None:
    """The keyset cursor of the last row of the page before: "<time_ns>-<id>" for an
    event, "<time_ns>-r<id>" for a run."""
    stamp, _, row = value.partition("-")
    rank = RUN if row.startswith("r") else EVENT
    row = row.removeprefix("r")
    if not (re.fullmatch(r"[0-9]{1,19}", stamp) and re.fullmatch(r"[0-9]{1,19}", row)):
        return None
    if max(int(stamp), int(row)) > MAX_INT:
        return None  # SQLite's integers end there
    return int(stamp), rank, int(row)


def older(before: tuple[int, int, int]) -> Any:
    """The events after the cursor in the list's order."""
    stamp, rank, row = before
    same = DockerEvent.id < row if rank == EVENT else false()
    return or_(DockerEvent.time_ns < stamp, and_(DockerEvent.time_ns == stamp, same))


def runs_older(before: tuple[int, int, int]) -> Any:
    """The runs after the cursor in the list's order."""
    stamp, rank, row = before
    clause = Run.created_at < at_us(-(-stamp // 1000))  # queued before the cursor's instant
    if stamp % 1000 == 0:  # an instant a run can share
        same = true() if rank == EVENT else Run.id < row
        clause = or_(clause, and_(Run.created_at == at_us(stamp // 1000), same))
    return clause


@dataclass(frozen=True)
class Entry:
    """One row of the list: a container event, or a backup run with its job."""

    time_ns: int
    rank: int
    id: int
    event: DockerEvent | None = None
    run: Run | None = None
    job_name: str | None = None
    host_id: int | None = None

    @property
    def cursor(self) -> str:
        return f"{self.time_ns}-{'r' if self.rank == RUN else ''}{self.id}"


@router.get("/activity")
def activity(
    request: Request,
    auth: Viewer,
    db: Session = Depends(get_db),
    host: str = "",
    container: str = "",
    action: str = "",
    range: str = "24h",
    before: str = "",
) -> Response:
    view = view_of(host, container, action, range)
    now_ns = int(datetime.now(UTC).timestamp() * NS)
    clauses = filtered(view, now_ns)
    run_clauses = run_filtered(view, now_ns)
    cursor = parse_before(before)
    query = select(DockerEvent).where(*clauses)
    runs = select(Run, Job.name, Job.host_id).outerjoin(Job, Run.job_id == Job.id)
    runs = runs.where(*run_clauses)
    if cursor is not None:
        query = query.where(older(cursor))
        runs = runs.where(runs_older(cursor))
    events = db.scalars(
        query.order_by(DockerEvent.time_ns.desc(), DockerEvent.id.desc()).limit(PAGE)
    )
    entries = [Entry(e.time_ns, EVENT, e.id, event=e, host_id=e.host_id) for e in events]
    for run, job_name, job_host in db.execute(
        runs.order_by(Run.created_at.desc(), Run.id.desc()).limit(PAGE)
    ):
        stamp = (run.created_at - EPOCH) // timedelta(microseconds=1) * 1000
        entries.append(Entry(stamp, RUN, run.id, run=run, job_name=job_name, host_id=job_host))
    rows = sorted(entries, key=lambda e: (e.time_ns, e.rank, e.id), reverse=True)[:PAGE]
    # ponytail: four counts per page and per 5 s poll, a scan of up to 200,000 rows with a
    # container search. Milliseconds in SQLite; cache them like the cards' if many tabs
    # stay open on a full table.
    event_count = select(func.count()).select_from(DockerEvent)
    run_count = select(func.count()).select_from(Run).outerjoin(Job, Run.job_id == Job.id)
    total = (db.scalar(event_count.where(*clauses)) or 0) + (
        db.scalar(run_count.where(*run_clauses)) or 0
    )
    # Where this page starts among all matching rows: those newer than its first row.
    first = 1
    if cursor is not None:
        first += (db.scalar(event_count.where(*clauses).where(~older(cursor))) or 0) + (
            db.scalar(run_count.where(*run_clauses).where(~runs_older(cursor))) or 0
        )
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    last = rows[-1] if len(rows) == PAGE else None
    context = {
        "rows": rows,
        "view": view,
        "hosts": hosts,
        "host_names": {h.id: h.name for h in hosts},
        "actions": ACTIONS | {BACKUP: "Backup run"},
        "ranges": RANGES,
        "total": total,
        "first": first,
        "live": cursor is None,
        "newest_url": "/activity?" + urlencode(view.query),
        "older_url": (
            "/activity?" + urlencode(view.query | {"before": last.cursor})
            if last is not None
            else None
        ),
    }
    # The region's own requests (its poll, the filters) take the region alone.
    partial = is_htmx(request) and request.headers.get("hx-target", "").endswith("#activity")
    template = "activity/_events.html" if partial else "activity/index.html"
    return render(request, template, auth=auth, **context)


@router.post("/activity/clear")
def clear(
    request: Request,
    auth: Admin,
    host: Annotated[int, Form()],
    db: Session = Depends(get_db),
) -> Response:
    """Deletes the stored events of one host, or of all hosts (host 0). The form has no
    default: clearing all hosts is chosen, never fallen into."""
    require_recent_auth(auth)
    target_host = None
    if host:
        target_host = db.get(Host, host)
        if target_host is None:
            raise HTTPException(status_code=404)
    statement = delete(DockerEvent)
    if target_host is not None:
        statement = statement.where(DockerEvent.host_id == target_host.id)
    deleted = db.execute(statement).rowcount
    audit.record(
        db,
        actor=auth.user.username,
        action="activity.clear",
        target=f"host:{target_host.id}" if target_host is not None else "all hosts",
        ip=client_ip(request),
        details={"host": target_host.name if target_host else "all", "deleted": deleted},
    )
    db.commit()
    request.app.state.events.forget_counts()  # the cards show the clear at once
    return see_other(request, "/activity?range=all")
