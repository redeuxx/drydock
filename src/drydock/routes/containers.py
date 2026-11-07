"""The containers page: one host's containers as the status collector last read them
(hosts/status.py). Showing them reads only its cache and never calls Docker; operators'
actions (start, stop and the like) and admins' inspect do.

Filtering, searching and sorting happen here, not in the browser, so the table's polls
(which send the toolbar's fields) keep them. Every role may view the page; label values
are searched for admins only, since labels can carry credentials (basic auth hashes,
tokens) that a viewer's searches could otherwise probe for.
"""

import copy
import functools
import ipaddress
import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from typing import Annotated, Any
from urllib.parse import urlencode, urlsplit

import anyio.from_thread
import docker.errors
import requests
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.audit import SECRET_KEY_RE
from drydock.db import get_db
from drydock.hosts import inventory
from drydock.hosts.helper import HELPER_LABEL
from drydock.hosts.inventory import PROJECT_LABEL
from drydock.hosts.status import ContainerStatus, HostSnapshot
from drydock.jobs.dispatcher import DispatchError, lock_scope, name_key
from drydock.models import EVERY_STACK, HealthAck, Host, Job, JobTarget, UpdatePolicy, utcnow
from drydock.routes.auth import client_ip
from drydock.routes.hosts import DOCKER_ERRORS, open_host, release, target
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other
from drydock.updates import switch as tag_switch
from drydock.updates.switch import TAG_ERROR, TAG_RE

router = APIRouter()

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Operator = Annotated[Auth, Depends(require_role(Role.operator))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]
MAX_QUERY = 100


def first_ip(c: ContainerStatus) -> tuple[int, int] | None:
    for _, address in c.ips:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        return ip.version, int(ip)
    return None


def total(a: int | None, b: int | None) -> int | None:
    return None if a is None and b is None else (a or 0) + (b or 0)


# Column to sort key. A key of None (unknown) sorts last in either direction.
SORTS: dict[str, Callable[[ContainerStatus], Any]] = {
    "name": lambda c: c.name.lower(),
    "image": lambda c: c.image.lower(),
    "state": lambda c: c.state,
    "uptime": lambda c: c.started_at if c.state == "running" else None,
    "restarts": lambda c: c.restarts,
    "cpu": lambda c: c.cpu_percent,
    "memory": lambda c: c.mem_bytes,
    "net": lambda c: total(c.net_rx, c.net_tx),
    "disk": lambda c: total(c.block_read, c.block_write),
    "ip": first_ip,
    "stack": lambda c: c.project.lower() if c.project else None,
}
# Uptime sorts by when the container started: the longest up comes first ascending.
Verdicts = dict[str, Any]  # the update checker's, by container ID


def is_newer(verdicts: Verdicts, c: ContainerStatus) -> bool:
    return c.id in verdicts and verdicts[c.id].state == "update"


# The status filter: the dashboard cards' counters link here with these keys. Each test
# takes the row and the update checker's verdicts by container ID.
STATUSES: dict[str, tuple[str, Callable[[ContainerStatus, Verdicts], bool]]] = {
    "running": ("Running", lambda c, v: c.state == "running"),
    "exited": ("Stopped (exited or dead)", lambda c, v: c.state in ("exited", "dead")),
    "paused": ("Paused", lambda c, v: c.state == "paused"),
    "restarting": ("Restarting", lambda c, v: c.state == "restarting"),
    "created": ("Created", lambda c, v: c.state == "created"),
    "unhealthy": ("Unhealthy", lambda c, v: c.health == "unhealthy"),
    "updates": ("Update available", lambda c, v: is_newer(v, c)),
}


Found = tuple[Host, ContainerStatus]


def sort_rows(rows: list[Found], key: str, descending: bool) -> list[Found]:
    def by(row: Found) -> Any:
        return SORTS[key](row[1])

    known = [r for r in rows if by(r) is not None]
    unknown = [r for r in rows if by(r) is None]
    # Ties keep name order (rows arrive sorted by name), whichever way the column sorts.
    known.sort(key=by, reverse=descending)
    return known + unknown


# EVERY HOST AND PAGES (the containers, stacks and images pages)
#
# A Docker page shows one host, or every enabled host when none is chosen (the host
# picker's All hosts, and a host that does not exist). Its rows come PAGE_SIZE at a time.

PAGE_SIZE = 100  # as many as MAX_SELECTED, so a page's checkboxes are one valid selection


def pick_host(hosts: list[Host], host: str) -> Host | None:
    """The host to show, or None for every host."""
    return next((h for h in hosts if str(h.id) == host), None)


def shown_hosts(hosts: list[Host], chosen: Host | None) -> list[Host]:
    return [chosen] if chosen is not None else [h for h in hosts if h.enabled]


def page_number(text: str) -> int:
    """The ?page= value; anything but a plain number is the first page."""
    return int(text) if text.isascii() and text.isdigit() and len(text) < 7 else 1


def back_url(path: str, back: str, number: int) -> str:
    """Where an action on a Docker page returns to: back is the host the page showed (an
    ID, or anything else for every host), number its page."""
    query = ({"host": back} if back.isdigit() else {}) | ({"page": number} if number > 1 else {})
    return f"{path}?{urlencode(query)}" if query else path


def paginate[T](rows: list[T], number: int) -> tuple[list[T], int, int]:
    """(the rows on that page, that page, how many pages). Past the end is the last page."""
    pages = max(1, -(-len(rows) // PAGE_SIZE))
    number = min(max(number, 1), pages)
    return rows[(number - 1) * PAGE_SIZE : number * PAGE_SIZE], number, pages


def matches(c: ContainerStatus, query: str, values: bool) -> bool:
    if query in c.name.lower() or query in c.image.lower():
        return True
    return any(query in k.lower() or (values and query in v.lower()) for k, v in c.labels)


def covering_jobs(db: Session, host_id: int) -> dict[tuple[str, str], list[Job]]:
    """("container", name) or ("stack", project) to the host's jobs that back it up."""
    jobs = {j.id: j for j in db.scalars(select(Job).where(Job.host_id == host_id))}
    covers: dict[tuple[str, str], list[Job]] = defaultdict(list)
    for job in jobs.values():
        covers[(job.target_type, job.target)].append(job)
    extra = db.execute(
        select(JobTarget.job_id, JobTarget.target_type, JobTarget.target).where(
            JobTarget.job_id.in_(jobs)
        )
    )
    for job_id, kind, name in extra:
        if jobs[job_id] not in covers[(kind, name)]:
            covers[(kind, name)].append(jobs[job_id])
    for found in covers.values():
        found.sort(key=lambda j: j.name.lower())
    return covers


def port_base(request: Request, host: Host, admin: bool) -> str | None:
    """Where a published port is reached from the browser: drydock's own address (the
    BASE_URL setting, never the request's Host header) for the local host, an SSH host's
    address for admins (only they see it)."""
    if host.kind == "local":
        name = urlsplit(request.app.state.settings.base_url).hostname
    elif admin:
        name = host.address
    else:
        return None
    if not name:
        return None
    return f"http://[{name}]" if ":" in name else f"http://{name}"


@router.get("/containers")
def containers(
    request: Request,
    auth: Viewer,
    db: Session = Depends(get_db),
    host: str = "",
    sort: str = "name",
    order: str = "asc",
    status: str = "",
    stack: str = "",
    q: str = "",
    number: Annotated[str, Query(alias="page")] = "1",
) -> Response:
    view = View(host, sort, order, status, stack, q, page_number(number))
    return page(request, auth, db, view)


@dataclass(frozen=True)
class View:
    """What the page shows: the host ("" for every host), sort, filters and page, as the
    query string gives them."""

    host: str = ""
    sort: str = "name"
    order: str = "asc"
    status: str = ""
    stack: str = ""
    q: str = ""
    page: int = 1

    @property
    def url(self) -> str:
        shown = {k: v for k, v in asdict(self).items() if v not in ("", 1)}
        return "/containers?" + urlencode(shown)


@dataclass(frozen=True)
class Row:
    """A container on the page, with what its row shows besides the container itself."""

    host: Host
    c: ContainerStatus
    verdict: Any  # the update checker's (updates/check.py), or None
    lines: tuple[list[float | None], list[int | None]]  # its CPU and memory sparklines
    jobs: list[Job]  # the backup jobs that cover it
    policies: list[tuple[UpdatePolicy, datetime | None]]  # its update policies, next run
    port_base: str | None


def page(
    request: Request,
    auth: Auth,
    db: Session,
    view: View,
    outcomes: list[Outcome] | None = None,
    notice: tuple[str, bool] | None = None,
) -> Response:
    collector = request.app.state.status
    collector.touch()
    updates = request.app.state.updates
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = pick_host(hosts, view.host)
    sort = view.sort if view.sort in SORTS else "name"
    order = "desc" if view.order == "desc" else "asc"
    status = view.status if view.status in STATUSES else ""
    stack = view.stack
    query = view.q.strip()[:MAX_QUERY]
    admin = auth.user.role >= Role.admin

    verdicts: dict[int, Verdicts] = {}
    snaps: dict[int, HostSnapshot | None] = {}
    found: list[Found] = []
    for h in shown_hosts(hosts, chosen):
        snaps[h.id] = snap = collector.snapshot(h.id)
        checks = updates.result(h.id)
        verdicts[h.id] = checks.verdicts if checks is not None else {}
        if snap is not None:
            found += [(h, c) for c in snap.containers]
    total = len(found)
    stacks = sorted({c.project for _, c in found if c.project})
    if chosen is None:
        found.sort(key=lambda r: (r[1].name, r[0].name))  # as one host's arrive, then by host
    stack_newer = sum(  # members of the filtered stack with a newer image (one host only)
        1
        for h, c in found
        if chosen is not None and stack and c.project == stack and is_newer(verdicts[h.id], c)
    )
    if status:
        found = [r for r in found if STATUSES[status][1](r[1], verdicts[r[0].id])]
    if stack:
        found = [r for r in found if r[1].project == stack]
    if query:
        found = [r for r in found if matches(r[1], query.lower(), admin)]
    shown, number, pages = paginate(sort_rows(found, sort, order == "desc"), view.page)

    scheduler = request.app.state.scheduler
    facts: dict[int, Any] = {}  # per host of a row: its jobs, policies, sparklines, ports
    rows = []
    for h, c in shown:
        if h.id not in facts:
            facts[h.id] = (
                covering_jobs(db, h.id),
                [
                    (p, scheduler.next_update_time(p.id) if p.enabled else None)
                    for p in db.scalars(select(UpdatePolicy).where(UpdatePolicy.host_id == h.id))
                ],
                collector.history(h.id),
                port_base(request, h, admin),
            )
        covers, policies, history, base = facts[h.id]
        mine = (("container", c.name), ("stack", c.project))
        mine += (("stack", EVERY_STACK),) if c.project else ()
        jobs = covers[("container", c.name)] + (covers[("stack", c.project)] if c.project else [])
        rows.append(
            Row(
                h,
                c,
                verdicts[h.id].get(c.id),
                history.containers.get(c.id, ([], [])),
                list({j.id: j for j in jobs}.values()),
                [(p, when) for p, when in policies if (p.target_type, p.target) in mine],
                base,
            )
        )
    host_value = str(chosen.id) if chosen is not None else ""
    shown_view = View(host_value, sort, order, status, stack, query)
    context: dict[str, Any] = {
        "hosts": hosts,
        "chosen": chosen,
        "host_value": host_value,  # the host field of the page's forms
        "sort": sort,
        "order": order,
        "status": status,
        "stack": stack,
        "q": query,
        "statuses": STATUSES,
        "rows": rows,
        "matched": len(found),
        "total": total,
        "page": number,
        "pages": pages,
        "page_url": shown_view.url + "&page=",
        "stacks": stacks,
        # Every host's page: the hosts that were not read cleanly, with their reading.
        "unread": [],
        "outcomes": outcomes or [],
        "verbs": ACTIONS,
        "checks": None,
        "notice": notice,  # (text, whether it went well) after a check for updates
        "stack_newer": stack_newer,
    }
    if chosen is None:
        context["unread"] = [
            (h, snaps[h.id])
            for h in shown_hosts(hosts, chosen)
            if snaps[h.id] is None or snaps[h.id].taken_at is None or snaps[h.id].error
        ]
    else:
        context |= {
            "checks": updates.result(chosen.id),
            "state": request.app.state.hosts.status(chosen),
            "snap": snaps[chosen.id],
            "where": target(chosen) if admin else None,
        }
    # The table's own requests (its poll, the toolbar) take the table alone; the host
    # picker swaps #main, so it takes the page.
    partial = (
        outcomes is None
        and notice is None
        and is_htmx(request)
        and request.headers.get("hx-target", "").endswith("#containers")
    )
    template = "containers/_table.html" if partial else "containers/index.html"
    return render(request, template, auth=auth, **context)


# ACTIONS (OPERATORS) AND INSPECT (ADMINS)
#
# Each action inspects the container first and refuses drydock's own containers (itself
# and its Compose project, the socket proxy among them) and its helpers. While it acts it
# holds the dispatcher's keys for the container, its name and its project (try_hold): a
# container that a backup or restore holds is refused, and a run that starts meanwhile
# waits. Every container selected is audited, acted on or not, once the request itself is
# valid. Then the page waits for the host's next reading, so it shows the result.
#
# ponytail: one container after another, inside the request. A stop waits up to the
# container's stop timeout (10 s by default), so stopping many containers that ignore
# SIGTERM can outlast a reverse proxy's timeout; the actions still finish and are audited.
# Run them concurrently, or as a background run, if that matters.

ACTIONS = {
    "start": "started",
    "stop": "stopped",
    "restart": "restarted",
    "pause": "paused",
    "unpause": "unpaused",
    "remove": "removed",  # admins only, with a recent password; volumes are kept
    "acknowledge": "acknowledged",  # an exited, unhealthy container; no Docker call
}
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}")
MAX_SELECTED = 100
# A stop or restart waits the container's own stop timeout (10 s unless it sets one, at
# most MAX_GRACE) before Docker kills it; the request may take that much longer.
ACTION_TIMEOUT = 30
MAX_GRACE = 300
INSPECT_TIMEOUT = 20
ACTION_ERRORS = (docker.errors.DockerException, requests.RequestException)


@dataclass(frozen=True)
class Outcome:
    action: str
    name: str
    error: str | None = None
    host: str | None = None  # its host's name, when the page shows more than one host


def daemon_error(exc: BaseException) -> str:
    """Safe to show: the daemon's own text is not quoted (it can name paths)."""
    if isinstance(exc, docker.errors.NotFound):
        return "No such container any more."
    if isinstance(exc, docker.errors.APIError):
        if exc.status_code == 409:
            return "Docker refused: the container is not in a state for that."
        return f"The Docker daemon answered HTTP {exc.status_code or 'an error'}."
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "Docker did not answer in time. The table shows what happened."
    return "Cannot reach the Docker daemon."


def refusal(info: dict[str, Any], own: frozenset[str]) -> str | None:
    labels = (info.get("Config") or {}).get("Labels") or {}
    if info.get("Id") in own:
        return "Drydock does not act on itself or its own Compose project."
    if labels.get(HELPER_LABEL):
        return "Drydock's helper containers are left to drydock."
    return None


def lock_keys(info: dict[str, Any], scope: str) -> list[str]:
    """The keys a backup or restore of the container takes (dispatcher.backup_keys)."""
    name = str(info.get("Name", "")).lstrip("/")
    keys = {str(info["Id"]), name_key(scope, "container", name)}
    project = ((info.get("Config") or {}).get("Labels") or {}).get(PROJECT_LABEL)
    if project:
        keys.add(name_key(scope, "project", str(project)))
    return sorted(keys)


def act_on(
    dispatcher: Any,
    api: Any,
    action: str,
    container_id: str,
    own: frozenset[str],
    scope: str,
    owner: str,
) -> Outcome:
    """Blocking, on the route's worker thread: one action on one container."""
    try:
        info = api.inspect_container(container_id)
    except ACTION_ERRORS as exc:
        return Outcome(action, container_id[:12], daemon_error(exc))
    name = str(info.get("Name", "")).lstrip("/") or container_id[:12]
    if (reason := refusal(info, own)) is not None:
        return Outcome(action, name, reason)
    keys = lock_keys(info, scope)
    if not anyio.from_thread.run(dispatcher.try_hold, keys, owner):
        return Outcome(action, name, "A backup or restore is using it. Try again when it ends.")
    try:
        if action in ("stop", "restart", "remove"):
            # Its own stop timeout, as `docker stop` uses; docker-py needs a number.
            grace = (info.get("Config") or {}).get("StopTimeout")
            grace = grace if isinstance(grace, int) and 0 <= grace <= MAX_GRACE else 10
            getattr(api, "stop" if action == "remove" else action)(info["Id"], timeout=grace)
            if action == "remove":
                # Stopped first, so it shuts down as `docker stop` would; its volumes stay.
                api.remove_container(info["Id"], v=False)
        else:
            getattr(api, action)(info["Id"])
    except ACTION_ERRORS as exc:
        return Outcome(action, name, daemon_error(exc))
    finally:
        anyio.from_thread.run_sync(dispatcher.release_held, keys)
    return Outcome(action, name)


def run_actions(
    request: Request, auth: Auth, host: Host, verb: str, chosen: list[str]
) -> list[Outcome]:
    def every(error: str) -> list[Outcome]:
        return [Outcome(verb, cid[:12], error) for cid in chosen]

    if not host.enabled:
        return every("The host is disabled.")
    if not request.app.state.primary:  # its dispatcher knows nothing of the runs
        return every("This drydock process is not the one that runs backups.")
    owner = f"{auth.user.username}'s {verb} on the containers page"
    try:
        handle = open_host(request, host, ACTION_TIMEOUT)
    except DOCKER_ERRORS as exc:
        return every(str(exc))
    try:
        api = handle.client.api
        own = inventory.own_ids(api)
        scope = lock_scope(api.info(), host.id)
        dispatcher = request.app.state.dispatcher
        return [act_on(dispatcher, api, verb, cid, own, scope, owner) for cid in chosen]
    except ACTION_ERRORS as exc:
        return every(daemon_error(exc))
    finally:
        handle.close()


def acknowledge(
    request: Request, db: Session, auth: Auth, host: Host, chosen: list[str]
) -> tuple[list[Outcome], list[tuple[str, datetime]]]:
    """Marks exited, unhealthy containers (as the cache has them) as seen, so they no longer
    count as unhealthy until they start again (StatusCollector.snapshot). The caller
    commits, then tells the collector the (container ID, time) pairs returned."""
    snap = request.app.state.status.snapshot(host.id)
    rows = snap.containers if snap is not None else ()
    now = utcnow()
    outcomes, acked = [], []
    for cid in chosen:
        c = next((c for c in rows if c.id.startswith(cid)), None)
        if c is None:
            outcomes.append(Outcome("acknowledge", cid[:12], "No such container any more."))
        elif c.state != "exited" or c.health != "unhealthy":
            outcomes.append(Outcome("acknowledge", c.name, "It is not an exited, unhealthy one."))
        else:
            db.merge(
                HealthAck(
                    host_id=host.id, container_id=c.id, acked_at=now, acked_by=auth.user.username
                )
            )
            acked.append((c.id, now))
            outcomes.append(Outcome("acknowledge", c.name))
    return outcomes, acked


def targets(items: list[str], host: str) -> dict[int, list[str]]:
    """Host ID to container IDs, from "<host ID>:<container ID>" values (a bare container
    ID is on host, the form's own). 422 for anything else."""
    by_host: dict[int, list[str]] = {}
    for item in items:
        where, _, container_id = item.rpartition(":")
        where = where or host
        if not (
            CONTAINER_ID_RE.fullmatch(container_id)
            and where.isascii()
            and where.isdigit()
            and len(where) < 10
        ):
            raise HTTPException(status_code=422)
        found = by_host.setdefault(int(where), [])
        if container_id not in found:
            found.append(container_id)
    return by_host


async def refresh_all(collector: Any, host_ids: list[int]) -> None:
    """The collector's refresh of each host, at the same time."""
    async with anyio.create_task_group() as group:
        for host_id in host_ids:
            group.start_soon(collector.refresh, host_id)


@router.post("/containers/actions")
def container_actions(
    request: Request,
    auth: Operator,
    action: Annotated[str, Form()],
    db: Session = Depends(get_db),
    host: Annotated[str, Form()] = "",
    ids: Annotated[list[str] | None, Form(alias="id")] = None,
    sort: Annotated[str, Form()] = "name",
    order: Annotated[str, Form()] = "asc",
    status: Annotated[str, Form()] = "",
    stack: Annotated[str, Form()] = "",
    q: Annotated[str, Form()] = "",
    number: Annotated[str, Form(alias="page")] = "1",
) -> Response:
    """action is "stop" for the selected containers (id), or "stop:<id>" for one row's.
    Each id is "<host ID>:<container ID>", or a container ID on host; host is also the
    page's own ("" for every host)."""
    view = View(host, sort, order, status, stack, q, page_number(number))
    verb, _, one = action.partition(":")
    if verb not in ACTIONS:
        raise HTTPException(status_code=422)
    picked = targets([one] if one else ids or [], host)
    if verb == "remove":
        require_admin_reauth(auth)
    target_hosts = [db.get(Host, host_id) for host_id in picked]
    if any(h is None for h in target_hosts):
        raise HTTPException(status_code=404)
    acted_on = [release(db, h) for h in target_hosts if h is not None]
    count = sum(len(chosen) for chosen in picked.values())
    if not count:
        outcomes = [Outcome(verb, "Nothing", "Select containers first.")]
    elif count > MAX_SELECTED:
        outcomes = [Outcome(verb, "Nothing", f"Select at most {MAX_SELECTED} containers.")]
    else:
        outcomes = []
        acked: list[tuple[int, str, datetime]] = []
        named = not host or len(acted_on) > 1  # the outcomes say which host
        for target_host in acted_on:
            chosen = picked[target_host.id]
            if verb == "acknowledge":
                done, seen = acknowledge(request, db, auth, target_host, chosen)
                acked += [(target_host.id, container_id, at) for container_id, at in seen]
            else:
                done = run_actions(request, auth, target_host, verb, chosen)
            for outcome in done:
                audit.record(
                    db,
                    actor=auth.user.username,
                    action=f"container.{verb}",
                    target=f"container:{outcome.name}",
                    outcome="success" if outcome.error is None else "failure",
                    ip=client_ip(request),
                    details={"host": target_host.name}
                    | ({} if outcome.error is None else {"error": outcome.error}),
                )
            outcomes += [replace(o, host=target_host.name) for o in done] if named else done
        db.commit()
        for host_id, container_id, at in acked:
            request.app.state.status.acknowledge(host_id, container_id, at)
        if verb != "acknowledge":
            anyio.from_thread.run(refresh_all, request.app.state.status, [h.id for h in acted_on])
    if not is_htmx(request):
        # A form without script: redirect, so reloading the page never acts again. The
        # outcomes are in the audit log and the table.
        return see_other(request, view.url)
    response = page(request, auth, db, view, outcomes)
    response.headers["HX-Replace-Url"] = view.url  # the POST's own URL is no page
    return response


def require_admin_reauth(auth: Auth) -> None:
    """Removing cannot be undone: admins only, with the password from the last 10 minutes."""
    if auth.user.role < Role.admin:
        raise HTTPException(status_code=403, detail="Only admins remove containers.")
    require_recent_auth(auth)


def redacted(info: dict[str, Any]) -> dict[str, Any]:
    """Environment values, labels whose key looks secret and log driver options (tokens,
    URLs with passwords) as ***. Names stay. Command lines stay as they are."""
    info = copy.deepcopy(info)
    log_config = (info.get("HostConfig") or {}).get("LogConfig")
    if isinstance(log_config, dict) and isinstance(log_config.get("Config"), dict):
        log_config["Config"] = {k: "***" for k in log_config["Config"]}
    config = info.get("Config")
    if isinstance(config, dict):
        if isinstance(config.get("Env"), list):
            config["Env"] = [
                f"{str(e).partition('=')[0]}=***" if "=" in str(e) else str(e)
                for e in config["Env"]
            ]
        if isinstance(config.get("Labels"), dict):
            config["Labels"] = {
                k: "***" if SECRET_KEY_RE.search(str(k)) else v for k, v in config["Labels"].items()
            }
    return info


@router.post("/containers/check-updates")
def check_updates(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    db: Session = Depends(get_db),
    sort: Annotated[str, Form()] = "name",
    order: Annotated[str, Form()] = "asc",
    status: Annotated[str, Form()] = "",
    stack: Annotated[str, Form()] = "",
    q: Annotated[str, Form()] = "",
) -> Response:
    """Asks the registries now which containers of the host have a newer image (at most
    once a minute per host). Audited: it makes drydock contact registries."""
    view = View(str(host), sort, order, status, stack, q)
    target_host, notice, error = ask_registries(request, db, host)
    audit.record(
        db,
        actor=auth.user.username,
        action="container.check_updates",
        target=f"host:{target_host.id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"host": target_host.name} | ({} if error is None else {"error": error}),
    )
    db.commit()
    if not is_htmx(request):
        return see_other(request, view.url)
    response = page(request, auth, db, view, notice=notice)
    response.headers["HX-Replace-Url"] = view.url
    return response


def ask_registries(
    request: Request, db: Session, host: int
) -> tuple[Host, tuple[str, bool], str | None]:
    """The check behind every page's Check for updates: (the host, the notice to show as
    its text and whether it went well, the error to audit). 404 for a host that does not
    exist. Each route audits it as container.check_updates."""
    target_host = db.get(Host, host)
    if target_host is None:
        raise HTTPException(status_code=404)
    release(db, target_host)
    checker = request.app.state.updates
    wait = checker.wait_before_asking(target_host.id)
    if not target_host.enabled:
        notice, error = ("The host is disabled.", False), "disabled"
    elif not request.app.state.primary:
        notice = ("This drydock process is not the one that reaches the hosts.", False)
        error = "not primary"
    elif wait:
        notice, error = (f"Checked moments ago; try again in {wait} s.", False), "too soon"
    else:
        # ponytail: the request waits for the whole check, one registry lookup after
        # another (each at most 10 s). Run it in the background if hosts with many images
        # on slow registries outlast a reverse proxy's timeout.
        checks = anyio.from_thread.run(checker.check_now, target_host)
        error = checks.error
        if checks.error:
            notice = (f"Checking for updates failed: {checks.error}", False)
        else:
            found, failed = checks.count("update"), checks.count("error")
            text = f"{found} container{'' if found == 1 else 's'} with a newer image."
            if failed:
                text += f" {failed} could not be checked (see each row)."
            notice = (text, True)
    return target_host, notice, error


@router.post("/containers/update")
def update_container(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    container: Annotated[str, Form()],
    db: Session = Depends(get_db),
    shown: Annotated[str | None, Form(alias="view")] = None,
    tag: Annotated[str, Form()] = "",
) -> Response:
    """Starts an update run of one container to what its tag names on the registry now
    (updates/apply.py), or with tag a switch to that tag (updates/switch.py), and opens its
    run page. Audited. A refusal shows view, the host the page showed ("all" for every
    host), or else the container's host."""
    if not CONTAINER_ID_RE.fullmatch(container):
        raise HTTPException(status_code=422)
    target_host = db.get(Host, host)
    if target_host is None:
        raise HTTPException(status_code=404)
    release(db, target_host)
    snap = request.app.state.status.snapshot(target_host.id)
    found = next((c for c in snap.containers if c.id == container), None) if snap else None
    label = found.name if found else container[:12]
    tag = tag.strip()[:129]  # longer is no tag; audited as given, up to here
    error = None
    run_id = None
    if not target_host.enabled:
        error = "The host is disabled."
    elif tag and not TAG_RE.fullmatch(tag):
        error = TAG_ERROR
    elif tag and found is not None and tag_switch.switched_ref(found.image, tag) is None:
        error = "It was made from an image ID, so it has no repository to switch the tag of."
    else:
        try:
            run_id = anyio.from_thread.run(
                functools.partial(
                    request.app.state.dispatcher.submit_update,
                    target_host.id,
                    [container],
                    auth.user.username,
                    f"{label} to tag {tag}" if tag else label,
                    **({"tag": tag} if tag else {}),
                )
            )
        except DispatchError as exc:
            error = str(exc)
    audit.record(
        db,
        actor=auth.user.username,
        action="container.update",
        target=f"container:{label}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"host": target_host.name}
        | ({"tag": tag} if tag else {})
        | ({"run_id": run_id} if run_id else {})
        | ({"error": error} if error else {}),
    )
    db.commit()
    if run_id is None:
        back = shown or str(target_host.id)
        view = View(back if back.isdigit() else "")
        if not is_htmx(request):
            return see_other(request, view.url)
        response = page(request, auth, db, view, notice=(f"{label}: {error}", False))
        response.headers["HX-Replace-Url"] = view.url
        return response
    return see_other(request, f"/runs/{run_id}")


@router.post("/containers/update-stack")
def update_stack(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    stack: Annotated[str, Form()],
    db: Session = Depends(get_db),
    tag: Annotated[str, Form()] = "",
    main: Annotated[str, Form()] = "",
) -> Response:
    """Starts an update run of a Compose project's containers that have a newer image, in
    dependency order and all or nothing (updates/apply.py), and opens its run page. With
    tag, its main service (main, or the one updates/switch.py finds) and the members that
    follow it switch to that tag. Audited."""
    target_host = db.get(Host, host)
    snap = request.app.state.status.snapshot(host)
    known = {c.project for c in snap.containers if c.project} if snap is not None else set()
    if target_host is None or stack not in known:
        raise HTTPException(status_code=404)
    release(db, target_host)
    services = {c.service for c in snap.containers if c.project == stack} if snap else set()
    tag, main = tag.strip()[:129], main.strip()[:64]  # longer is no tag or service
    error = None
    run_id = None
    if not target_host.enabled:
        error = "The host is disabled."
    elif tag and not TAG_RE.fullmatch(tag):
        error = TAG_ERROR
    elif main and (not tag or main not in services):
        listed = ", ".join(sorted(str(n) for n in services if n))
        error = f"Choose a tag and one of the stack's services ({listed})."
    else:
        try:
            run_id = anyio.from_thread.run(
                functools.partial(
                    request.app.state.dispatcher.submit_update,
                    target_host.id,
                    [],
                    auth.user.username,
                    f"stack {stack} to tag {tag}" if tag else f"stack {stack}",
                    project=stack,
                    **({"tag": tag, "main": main or None} if tag else {}),
                )
            )
        except DispatchError as exc:
            error = str(exc)
    audit.record(
        db,
        actor=auth.user.username,
        action="stack.update",
        target=f"stack:{stack}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"host": target_host.name}
        | ({"tag": tag} if tag else {})
        | ({"main": main} if main else {})
        | ({"run_id": run_id} if run_id else {})
        | ({"error": error} if error else {}),
    )
    db.commit()
    if run_id is None:
        view = View(str(target_host.id), stack=stack)
        if not is_htmx(request):
            return see_other(request, view.url)
        response = page(request, auth, db, view, notice=(f"Stack {stack}: {error}", False))
        response.headers["HX-Replace-Url"] = view.url
        return response
    return see_other(request, f"/runs/{run_id}")


@router.get("/containers/{host_id}/{container_id}/inspect")
def inspect(
    request: Request,
    host_id: int,
    container_id: str,
    auth: Admin,
    db: Session = Depends(get_db),
) -> Response:
    """The container's inspect JSON for its row's dialog. A read: not audited."""
    if not CONTAINER_ID_RE.fullmatch(container_id):
        raise HTTPException(status_code=404)
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404)
    release(db, host)
    text = error = None
    if not host.enabled:
        error = "The host is disabled."
        return render(request, "containers/_inspect.html", auth=auth, text=text, error=error)
    try:
        handle = open_host(request, host, INSPECT_TIMEOUT)
    except DOCKER_ERRORS as exc:
        error = str(exc)
    else:
        try:
            info = handle.client.api.inspect_container(container_id)
            text = json.dumps(redacted(info), indent=2, sort_keys=True)
        except ACTION_ERRORS as exc:
            error = daemon_error(exc)
        finally:
            handle.close()
    return render(request, "containers/_inspect.html", auth=auth, text=text, error=error)
