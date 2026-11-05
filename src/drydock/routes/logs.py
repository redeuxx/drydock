"""The logs page: container logs, live, for admins only. Application logs routinely hold
tokens, email addresses and stack traces with secrets, so no other role reads them.

The page shows one container's log, or up to MAX_SELECTED containers' logs merged into one
stream (each line named) or side by side. It reads only the status collector's cache (its
container list). The logs load through /logs/lines, which reads Docker: first the last
lines, then every 2 seconds whatever came after them, one cursor per container (hosts/
logs.py). Those reads run on threads of their own (app.state.log_limiter), so a slow host
never holds the threads that the app's sync routes run on. /logs/download hands the same
lines over as a text file. Reads are not audited: drydock audits changes, not reads.
"""

import functools
import re
from dataclasses import dataclass
from typing import Annotated, Any
from urllib.parse import urlencode

import anyio
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
MAX_SELECTED = 10
MODES = ("merged", "grouped")
DOWNLOAD_BYTES = 8 * logs.MAX_BYTES  # one download, all its containers together
# A container and its cursor in a poll's URL: the ID alone (the first request), or
# ID~newest timestamp (ns)~lines at it~TTY.
CURSOR_RE = re.compile(r"([0-9a-f]{12,64})(?:~(\d{1,19})~(\d{1,7})~([01]))?")
MAX_NS = 2**63 - 1
NOT_PRINTABLE_RE = re.compile(r"[^ -~]")
FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def tail_of(value: int) -> int:
    return value if value in logs.TAILS else logs.DEFAULT_TAIL


def chosen_ids(values: list[str]) -> list[str]:
    """Container IDs as given, once each and at most MAX_SELECTED; anything else is left
    out."""
    return list(dict.fromkeys(v for v in values if CONTAINER_ID_RE.fullmatch(v)))[:MAX_SELECTED]


def names_on(request: Request, host_id: int) -> dict[str, str]:
    """Container ID to name, from the status collector's cache."""
    snap = request.app.state.status.snapshot(host_id)
    return {c.id: c.name for c in snap.containers} if snap is not None else {}


@router.get("/logs")
def logs_page(
    request: Request,
    auth: Admin,
    db: Session = Depends(get_db),
    host: int | None = None,
    c: Annotated[list[str], Query()] = [],  # noqa: B006 (FastAPI copies it)
    mode: str = "merged",
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
        "selected": [],
        "stacks": [],
        "mode": mode if mode in MODES else "merged",
        "tail": tail_of(tail),
        "tails": logs.TAILS,
        "max_selected": MAX_SELECTED,
        "dropped": len({v for v in c if CONTAINER_ID_RE.fullmatch(v)}) > MAX_SELECTED,
    }
    if chosen is not None:
        snap = collector.snapshot(chosen.id)
        containers = list(snap.containers) if snap is not None else []
        stacks: dict[str, list[str]] = {}
        for found in containers:
            if found.project:
                stacks.setdefault(found.project, []).append(found.id)
        names = {found.id: found.name for found in containers}
        context |= {
            "state": request.app.state.hosts.status(chosen),
            "snap": snap,
            "where": target(chosen),
            "containers": containers,
            # The cache may not have one yet (or any more): its log says if it is gone.
            "selected": [(cid, names.get(cid, cid[:12])) for cid in chosen_ids(c)],
            # (name, the first MAX_SELECTED members, how many it has)
            "stacks": sorted((name, ids[:MAX_SELECTED], len(ids)) for name, ids in stacks.items()),
        }
    return render(request, "logs/index.html", auth=auth, **context)


# READING LOGS


@dataclass(frozen=True)
class Want:
    """One container's part of a poll."""

    container: str
    cursor: logs.Cursor
    tty: bool | None  # None: not known yet (the first request), so inspected


def wants_of(values: list[str]) -> list[Want]:
    wants: dict[str, Want] = {}
    for value in values:
        found = CURSOR_RE.fullmatch(value)
        if found is None:
            raise HTTPException(status_code=404)
        cid, ns, seen, tty = found.groups()
        if ns is not None and int(ns) > MAX_NS:
            raise HTTPException(status_code=404)
        cursor = logs.Cursor(int(ns), int(seen)) if ns is not None else logs.Cursor()
        wants.setdefault(cid, Want(cid, cursor, None if tty is None else tty == "1"))
    if not wants or len(wants) > MAX_SELECTED:
        raise HTTPException(status_code=404)
    return list(wants.values())


def load_host(db: Session, host_id: int) -> Host:
    """Blocking (every transaction takes SQLite's write lock): never on the event loop,
    which serves the SSH tunnels."""
    found = db.get(Host, host_id)
    if found is None:
        raise HTTPException(status_code=404)
    return release(db, found)


@dataclass(frozen=True)
class Got:
    want: Want
    batch: logs.Batch | None
    tty: bool
    error: str | None


def read_one(request: Request, host: Host, want: Want, tail: int, limit: int) -> Got:
    """Blocking. One container's lines, or an error that is safe to show.

    ponytail: a client per container and poll, like the other routes, costs a /version
    round trip every 2 seconds per log shown. Keep one per host (as the status collector
    does) if that shows on slow SSH links.
    """
    if not host.enabled:
        return Got(want, None, False, "The host is disabled.")
    try:
        handle = open_host(request, host, logs.TIMEOUT)
    except DOCKER_ERRORS as exc:
        return Got(want, None, False, str(exc))
    try:
        api = handle.client.api
        tty = want.tty
        if tty is None:
            tty = bool((api.inspect_container(want.container).get("Config") or {}).get("Tty"))
        batch = logs.read(api, want.container, tty, tail, want.cursor, limit)
        return Got(want, batch, tty, None)
    except requests.exceptions.ReadTimeout:
        return Got(want, None, False, "Docker did not answer in time.")
    except ACTION_ERRORS as exc:
        return Got(want, None, False, daemon_error(exc))
    finally:
        handle.close()


async def read_all(
    request: Request, host: Host, wants: list[Want], tail: int, budget: int
) -> list[Got]:
    """Every container's lines, read at once (as many as the log threads allow), each
    within its share of budget bytes."""
    got: list[Got | None] = [None] * len(wants)
    limit = budget // len(wants)

    async def one(i: int) -> None:
        got[i] = await anyio.to_thread.run_sync(
            functools.partial(read_one, request, host, wants[i], tail, limit),
            limiter=request.app.state.log_limiter,
        )

    async with anyio.create_task_group() as group:
        for i in range(len(wants)):
            group.start_soon(one, i)
    return [g for g in got if g is not None]


def failure(got: list[Got], names: dict[str, str]) -> str | None:
    """The first error, named after its container when there are several."""
    for g in got:
        if g.error is not None:
            if len(got) == 1:
                return g.error
            return f"{name_of(g, names)}: {g.error}"
    return None


def name_of(got: Got, names: dict[str, str]) -> str:
    return names.get(got.want.container, got.want.container[:12])


def failed(reason: str) -> Response:
    # The page shows the reason (frontend/app.ts). A header takes printable ASCII only.
    reason = NOT_PRINTABLE_RE.sub("?", reason)
    return PlainTextResponse(reason, 502, headers={"X-Drydock-Reason": reason})


def merged(got: list[Got]) -> list[tuple[int, logs.Line]]:
    """(container's place, line) by time; lines at the same time keep their order."""
    lines = [(i, line) for i, g in enumerate(got) if g.batch for line in g.batch.lines]
    return sorted(lines, key=lambda pair: pair[1].ns)


@router.get("/logs/lines")
async def log_lines(
    request: Request,
    auth: Admin,
    db: Session = Depends(get_db),
    host: int = 0,
    c: Annotated[list[str], Query()] = [],  # noqa: B006 (FastAPI copies it)
    tail: int = logs.DEFAULT_TAIL,
) -> Response:
    """The logs' next lines, merged by time, and a poller for the ones after them. The
    first request (a container without a cursor) always answers, so the poller starts;
    later ones answer 204 when nothing is new, and the poller keeps its cursors.

    When every read fails (the host is down), the answer is 502 with the reason, which the
    page shows once while the poller keeps trying. When only some fail (a container was
    removed or recreated), the log says so and stops following those; the rest go on."""
    wants = wants_of(c)
    chosen = await run_blocking(load_host, db, host)
    tail = tail_of(tail)
    got = await read_all(request, chosen, wants, tail, logs.MAX_BYTES)
    names = names_on(request, chosen.id)
    if all(g.error is not None for g in got):
        return failed(failure(got, names) or "")
    lost = [f"{name_of(g, names)}: {g.error} Reload to follow it again." for g in got if g.error]
    lines = merged(got)
    first = any(w.tty is None for w in wants)
    if not first and not lines and not lost and is_htmx(request):
        return Response(status_code=204)
    cursors = [
        f"{g.want.container}~{g.batch.cursor.ns}~{g.batch.cursor.seen}~{int(g.tty)}"
        for g in got
        if g.batch is not None
    ]
    query = urlencode({"host": chosen.id, "tail": tail, "c": cursors}, doseq=True)
    # No bell (feed=None): it reads the database, and this runs on the event loop.
    return render(
        request,
        "logs/_lines.html",
        auth=auth,
        feed=None,
        lines=lines,
        lost=lost,
        named=len(got) > 1,
        names=[name_of(g, names) for g in got],
        next_url=f"/logs/lines?{query}",
    )


@router.get("/logs/download")
async def download(
    request: Request,
    auth: Admin,
    db: Session = Depends(get_db),
    host: int = 0,
    c: Annotated[list[str], Query()] = [],  # noqa: B006 (FastAPI copies it)
    tail: int = logs.DEFAULT_TAIL,
) -> Response:
    """The last tail lines of each container as a text file, merged by time, in UTC. At
    most DOWNLOAD_BYTES of Docker's answers are read (built in memory; ponytail: stream it
    if larger downloads are wanted)."""
    wants = [Want(w.container, logs.Cursor(), None) for w in wants_of(c)]
    chosen = await run_blocking(load_host, db, host)
    got = await read_all(request, chosen, wants, tail_of(tail), DOWNLOAD_BYTES)
    names = names_on(request, chosen.id)
    if (reason := failure(got, names)) is not None:
        # Saved as the file all the same (a download link cannot show a page): say so.
        return failed(f"Drydock could not read the logs. {reason}")
    shown = [name_of(g, names) for g in got]
    text = "".join(
        f"{line.when.isoformat(timespec='microseconds') if line.when else '-'}"
        f"{' ' + shown[i] if len(got) > 1 else ''} {line.stream} {line.text}\n"
        for i, line in merged(got)
    )
    if any(g.batch is not None and g.batch.cut for g in got):
        text += "[cut: the download reached its size limit; choose fewer lines]\n"
    stem = shown[0] if len(got) == 1 else chosen.name
    filename = (FILENAME_RE.sub("-", stem).strip("-.") or "container") + "-logs.txt"
    return PlainTextResponse(
        text, headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
