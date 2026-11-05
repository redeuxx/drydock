"""The activity page: container events from every host, as hosts/events.py stored them.

Every role may view it: it shows what the containers page already shows (names, images),
plus what happened to them and when. Filters, the time range and the page are GET
parameters, so the address keeps a view. The newest page refreshes itself every 5
seconds; older pages (keyset pagination on time and id, so rows arriving meanwhile never
shift them) stay still. Admins can clear the record, for one host or all, after entering
their password again; that is audited.
"""

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.hosts.events import NS
from drydock.models import DockerEvent, Host
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
    "exec_create": "Exec create",
    "exec_start": "Exec start",
    "exec_die": "Exec end",
    "attach": "Attach",
    "detach": "Detach",
    "commit": "Commit",
    "copy": "Copy",
    "export": "Export",
    "resize": "Resize",
    "top": "Top",
}
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
        host=int(host) if host.isdigit() and len(host) < 10 else None,
        container=container.strip()[:MAX_QUERY],
        action=action if action in ACTIONS else "",
        range=span if span in RANGES else "24h",
    )


def filtered(view: View, now_ns: int) -> list[Any]:
    """The WHERE clauses of a view."""
    clauses: list[Any] = []
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


def parse_before(value: str) -> tuple[int, int] | None:
    """The keyset cursor "<time_ns>-<id>" of the last row of the page before."""
    stamp, _, row = value.partition("-")
    if not (stamp.isdigit() and row.isdigit()) or len(stamp) > 19 or len(row) > 19:
        return None
    if max(int(stamp), int(row)) > MAX_INT:
        return None  # SQLite's integers end there
    return int(stamp), int(row)


def older(before: tuple[int, int]) -> Any:
    stamp, row = before
    return or_(
        DockerEvent.time_ns < stamp, and_(DockerEvent.time_ns == stamp, DockerEvent.id < row)
    )


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
    cursor = parse_before(before)
    query = select(DockerEvent).where(*clauses)
    if cursor is not None:
        query = query.where(older(cursor))
    rows = list(
        db.scalars(query.order_by(DockerEvent.time_ns.desc(), DockerEvent.id.desc()).limit(PAGE))
    )
    # ponytail: two counts per page and per 5 s poll, a scan of up to 200,000 rows with a
    # container search. Milliseconds in SQLite; cache them like the cards' if many tabs
    # stay open on a full table.
    total = db.scalar(select(func.count()).select_from(DockerEvent).where(*clauses)) or 0
    # Where this page starts among all matching rows: those newer than its first row.
    first = 1
    if cursor is not None:
        first += (
            db.scalar(
                select(func.count()).select_from(DockerEvent).where(*clauses).where(~older(cursor))
            )
            or 0
        )
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    last = rows[-1] if len(rows) == PAGE else None
    context = {
        "rows": rows,
        "view": view,
        "hosts": hosts,
        "host_names": {h.id: h.name for h in hosts},
        "actions": ACTIONS,
        "ranges": RANGES,
        "total": total,
        "first": first,
        "live": cursor is None,
        "newest_url": "/activity?" + urlencode(view.query),
        "older_url": (
            "/activity?" + urlencode(view.query | {"before": f"{last.time_ns}-{last.id}"})
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
