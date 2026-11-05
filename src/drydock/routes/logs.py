"""The logs page: one container's log, live, for admins only. Application logs routinely
hold tokens, email addresses and stack traces with secrets, so no other role reads them.

The page itself reads only the status collector's cache (its container list). Its log
loads through /logs/lines, which reads Docker: first the last lines, then every 2 seconds
whatever came after them (hosts/logs.py has the cursor). Those reads run on threads of
their own (app.state.log_limiter), so a slow host never holds the threads that the app's
sync routes run on. A read is not audited: drydock audits changes, not reads.
"""

import functools
import re
from typing import Annotated, Any
from urllib.parse import urlencode

import anyio.to_thread
import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock.db import get_db
from drydock.hosts import logs
from drydock.hosts.client import run_blocking
from drydock.models import Host
from drydock.routes.containers import ACTION_ERRORS, CONTAINER_ID_RE, daemon_error
from drydock.routes.hosts import DOCKER_ERRORS, open_host, release, target
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render

router = APIRouter()

Admin = Annotated[Auth, Depends(require_role(Role.admin))]
MAX_NS = 2**63 - 1
MAX_SEEN = 10**6
NOT_PRINTABLE_RE = re.compile(r"[^ -~]")


def tail_of(value: int) -> int:
    return value if value in logs.TAILS else logs.DEFAULT_TAIL


@router.get("/logs")
def logs_page(
    request: Request,
    auth: Admin,
    db: Session = Depends(get_db),
    host: int | None = None,
    container: str = "",
    tail: int = logs.DEFAULT_TAIL,
) -> Response:
    collector = request.app.state.status
    collector.touch()
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = next((h for h in hosts if h.id == host), None) or next(
        (h for h in hosts if h.enabled), hosts[0] if hosts else None
    )
    context: dict[str, Any] = {
        "hosts": hosts,
        "chosen": chosen,
        "containers": [],
        "selected": None,
        "tail": tail_of(tail),
        "tails": logs.TAILS,
    }
    if chosen is not None:
        snap = collector.snapshot(chosen.id)
        context |= {
            "state": request.app.state.hosts.status(chosen),
            "snap": snap,
            "where": target(chosen),
            "containers": list(snap.containers) if snap is not None else [],
        }
        if CONTAINER_ID_RE.fullmatch(container):
            # The cache may not have it yet (or any more): the log says if it is gone.
            found = next((c for c in context["containers"] if c.id == container), None)
            context["selected"] = (container, found.name if found else container[:12])
    return render(request, "logs/index.html", auth=auth, **context)


def load_host(db: Session, host_id: int) -> Host:
    """Blocking (every transaction takes SQLite's write lock): never on the event loop,
    which serves the SSH tunnels."""
    found = db.get(Host, host_id)
    if found is None:
        raise HTTPException(status_code=404)
    return release(db, found)


def read_lines(
    request: Request, host: Host, container: str, tty: bool | None, tail: int, cursor: logs.Cursor
) -> tuple[logs.Batch | None, bool, str | None]:
    """Blocking. The batch, whether the container has a TTY (inspected when unknown), and
    an error that is safe to show instead of the batch.

    ponytail: a client per poll, like the other routes, costs a /version round trip every
    2 seconds per open log. Keep one per host (as the status collector does) if that
    shows on slow SSH links.
    """
    if not host.enabled:
        return None, False, "The host is disabled."
    try:
        handle = open_host(request, host, logs.TIMEOUT)
    except DOCKER_ERRORS as exc:
        return None, False, str(exc)
    try:
        api = handle.client.api
        if tty is None:
            tty = bool((api.inspect_container(container).get("Config") or {}).get("Tty"))
        return logs.read(api, container, tty, tail, cursor), tty, None
    except requests.exceptions.ReadTimeout:
        return None, False, "Docker did not answer in time."
    except ACTION_ERRORS as exc:
        return None, False, daemon_error(exc)
    finally:
        handle.close()


@router.get("/logs/lines")
async def log_lines(
    request: Request,
    auth: Admin,
    db: Session = Depends(get_db),
    host: int = 0,
    container: str = "",
    tail: int = logs.DEFAULT_TAIL,
    after: Annotated[int, Query(ge=0, le=MAX_NS)] = 0,
    seen: Annotated[int, Query(ge=0, le=MAX_SEEN)] = 0,
    tty: Annotated[int | None, Query(ge=0, le=1)] = None,
) -> Response:
    """The log's next lines and a poller for the ones after them. The first request (tty
    unknown) always answers, so the poller starts; later ones answer 204 when nothing is
    new, and the poller keeps its cursor. Failures answer 502 with the reason, which the
    page shows once while the poller keeps trying."""
    if not CONTAINER_ID_RE.fullmatch(container):
        raise HTTPException(status_code=404)
    chosen = await run_blocking(load_host, db, host)
    tail = tail_of(tail)
    batch, has_tty, error = await anyio.to_thread.run_sync(
        functools.partial(
            read_lines,
            request,
            chosen,
            container,
            None if tty is None else bool(tty),
            tail,
            logs.Cursor(after, seen),
        ),
        limiter=request.app.state.log_limiter,
    )
    if batch is None:
        # The page shows the reason (frontend/app.ts). A header takes printable ASCII only.
        reason = NOT_PRINTABLE_RE.sub("?", error or "")
        return PlainTextResponse(reason, 502, headers={"X-Drydock-Reason": reason})
    if tty is not None and not batch.lines and is_htmx(request):
        return Response(status_code=204)
    query = urlencode(
        {
            "host": chosen.id,
            "container": container,
            "tail": tail,
            "after": batch.cursor.ns,
            "seen": batch.cursor.seen,
            "tty": int(has_tty),
        }
    )
    # No bell (feed=None): it reads the database, and this runs on the event loop.
    return render(
        request,
        "logs/_lines.html",
        auth=auth,
        feed=None,
        lines=batch.lines,
        cut=batch.cut,
        next_url=f"/logs/lines?{query}",
    )
