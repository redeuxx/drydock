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
from dataclasses import asdict, dataclass
from typing import Annotated, Any
from urllib.parse import urlencode, urlsplit

import anyio.from_thread
import docker.errors
import requests
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.audit import SECRET_KEY_RE
from drydock.db import get_db
from drydock.hosts import inventory
from drydock.hosts.helper import HELPER_LABEL
from drydock.hosts.inventory import PROJECT_LABEL
from drydock.hosts.status import ContainerStatus
from drydock.jobs.dispatcher import DispatchError, lock_scope, name_key
from drydock.models import Host, Job, JobTarget, UpdatePolicy
from drydock.routes.auth import client_ip
from drydock.routes.hosts import DOCKER_ERRORS, open_host, release, target
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other

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
# The status filter: the dashboard cards' counters link here with these keys. Each test
# takes the row and the update checker's verdicts by container ID.
Verdicts = dict[str, Any]
STATUSES: dict[str, tuple[str, Callable[[ContainerStatus, Verdicts], bool]]] = {
    "running": ("Running", lambda c, v: c.state == "running"),
    "exited": ("Stopped (exited or dead)", lambda c, v: c.state in ("exited", "dead")),
    "paused": ("Paused", lambda c, v: c.state == "paused"),
    "restarting": ("Restarting", lambda c, v: c.state == "restarting"),
    "created": ("Created", lambda c, v: c.state == "created"),
    "unhealthy": ("Unhealthy", lambda c, v: c.health == "unhealthy"),
    "updates": ("Update available", lambda c, v: c.id in v and v[c.id].state == "update"),
}


def sort_rows(rows: list[ContainerStatus], key: str, descending: bool) -> list[ContainerStatus]:
    by = SORTS[key]
    known = [c for c in rows if by(c) is not None]
    unknown = [c for c in rows if by(c) is None]
    # Ties keep name order (rows arrive sorted by name), whichever way the column sorts.
    known.sort(key=by, reverse=descending)
    return known + unknown


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
    host: int | None = None,
    sort: str = "name",
    order: str = "asc",
    status: str = "",
    stack: str = "",
    q: str = "",
) -> Response:
    return page(request, auth, db, View(host, sort, order, status, stack, q))


@dataclass(frozen=True)
class View:
    """What the page shows: the host, sort and filters, as the query string gives them."""

    host: int | None = None
    sort: str = "name"
    order: str = "asc"
    status: str = ""
    stack: str = ""
    q: str = ""

    @property
    def url(self) -> str:
        shown = {k: v for k, v in asdict(self).items() if v not in ("", None)}
        return "/containers?" + urlencode(shown)


def page(
    request: Request,
    auth: Auth,
    db: Session,
    view: View,
    outcomes: list[Outcome] | None = None,
    notice: tuple[str, bool] | None = None,
) -> Response:
    host, sort, order, status, stack, q = (
        view.host,
        view.sort,
        view.order,
        view.status,
        view.stack,
        view.q,
    )
    collector = request.app.state.status
    collector.touch()
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = next((h for h in hosts if h.id == host), None) or next(
        (h for h in hosts if h.enabled), hosts[0] if hosts else None
    )
    sort = sort if sort in SORTS else "name"
    order = "desc" if order == "desc" else "asc"
    status = status if status in STATUSES else ""
    query = q.strip()[:MAX_QUERY]
    admin = auth.user.role >= Role.admin
    context: dict[str, Any] = {
        "hosts": hosts,
        "chosen": chosen,
        "sort": sort,
        "order": order,
        "status": status,
        "stack": stack,
        "q": query,
        "statuses": STATUSES,
        "rows": [],
        "stacks": [],
        "jobs_of": {},
        "outcomes": outcomes or [],
        "verbs": ACTIONS,
        "checks": None,
        "verdicts": {},
        "notice": notice,  # (text, whether it went well) after a check for updates
        "stack_newer": 0,  # members of the filtered stack with a newer image
        "auto_update": {},  # container ID: [(update policy, its next run)]
    }
    if chosen is not None:
        snap = collector.snapshot(chosen.id)
        checks = request.app.state.updates.result(chosen.id)
        verdicts = checks.verdicts if checks is not None else {}
        context |= {
            "checks": checks,
            "verdicts": verdicts,
            "state": request.app.state.hosts.status(chosen),
            "snap": snap,
            "where": target(chosen) if admin else None,
            "port_base": port_base(request, chosen, admin),
        }
        if snap is not None:
            context["stacks"] = sorted({c.project for c in snap.containers if c.project})
            if stack:
                context["stack_newer"] = sum(
                    1
                    for c in snap.containers
                    if c.project == stack and c.id in verdicts and verdicts[c.id].state == "update"
                )
            rows = list(snap.containers)
            if status:
                rows = [c for c in rows if STATUSES[status][1](c, verdicts)]
            if stack:
                rows = [c for c in rows if c.project == stack]
            if query:
                rows = [c for c in rows if matches(c, query.lower(), admin)]
            context["rows"] = sort_rows(rows, sort, order == "desc")
            policies = list(
                db.scalars(select(UpdatePolicy).where(UpdatePolicy.host_id == chosen.id))
            )
            scheduler = request.app.state.scheduler
            context["auto_update"] = {
                c.id: [
                    (p, scheduler.next_update_time(p.id) if p.enabled else None)
                    for p in policies
                    if (p.target_type, p.target) in (("container", c.name), ("stack", c.project))
                ]
                for c in context["rows"]
            }
            covers = covering_jobs(db, chosen.id)
            context["jobs_of"] = {
                c.id: list(
                    {
                        j.id: j
                        for j in covers[("container", c.name)]
                        + (covers[("stack", c.project)] if c.project else [])
                    }.values()
                )
                for c in context["rows"]
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
        if action in ("stop", "restart"):
            # Its own stop timeout, as `docker stop` uses; docker-py needs a number.
            grace = (info.get("Config") or {}).get("StopTimeout")
            grace = grace if isinstance(grace, int) and 0 <= grace <= MAX_GRACE else 10
            getattr(api, action)(info["Id"], timeout=grace)
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


@router.post("/containers/actions")
def container_actions(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    action: Annotated[str, Form()],
    db: Session = Depends(get_db),
    ids: Annotated[list[str] | None, Form(alias="id")] = None,
    sort: Annotated[str, Form()] = "name",
    order: Annotated[str, Form()] = "asc",
    status: Annotated[str, Form()] = "",
    stack: Annotated[str, Form()] = "",
    q: Annotated[str, Form()] = "",
) -> Response:
    """action is "stop" for the selected containers (id), or "stop:<id>" for one row's."""
    view = View(host, sort, order, status, stack, q)
    verb, _, one = action.partition(":")
    chosen = list(dict.fromkeys([one] if one else ids or []))
    if verb not in ACTIONS or not all(CONTAINER_ID_RE.fullmatch(i) for i in chosen):
        raise HTTPException(status_code=422)
    target_host = db.get(Host, host)
    if target_host is None:
        raise HTTPException(status_code=404)
    release(db, target_host)
    if not chosen:
        outcomes = [Outcome(verb, "Nothing", "Select containers first.")]
    elif len(chosen) > MAX_SELECTED:
        outcomes = [Outcome(verb, "Nothing", f"Select at most {MAX_SELECTED} containers.")]
    else:
        outcomes = run_actions(request, auth, target_host, verb, chosen)
        for outcome in outcomes:
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
        db.commit()
        anyio.from_thread.run(request.app.state.status.refresh, target_host.id)
    if not is_htmx(request):
        # A form without script: redirect, so reloading the page never acts again. The
        # outcomes are in the audit log and the table.
        return see_other(request, view.url)
    response = page(request, auth, db, view, outcomes)
    response.headers["HX-Replace-Url"] = view.url  # the POST's own URL is no page
    return response


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
    view = View(host, sort, order, status, stack, q)
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


@router.post("/containers/update")
def update_container(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    container: Annotated[str, Form()],
    db: Session = Depends(get_db),
) -> Response:
    """Starts an update run of one container to what its tag names on the registry now
    (updates/apply.py) and opens its run page. Audited."""
    if not CONTAINER_ID_RE.fullmatch(container):
        raise HTTPException(status_code=422)
    target_host = db.get(Host, host)
    if target_host is None:
        raise HTTPException(status_code=404)
    release(db, target_host)
    snap = request.app.state.status.snapshot(target_host.id)
    name = next((c.name for c in snap.containers if c.id == container), None) if snap else None
    label = name or container[:12]
    error = None
    run_id = None
    if not target_host.enabled:
        error = "The host is disabled."
    else:
        try:
            run_id = anyio.from_thread.run(
                request.app.state.dispatcher.submit_update,
                target_host.id,
                [container],
                auth.user.username,
                label,
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
        | ({"run_id": run_id} if run_id else {})
        | ({"error": error} if error else {}),
    )
    db.commit()
    if run_id is None:
        view = View(target_host.id)
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
) -> Response:
    """Starts an update run of a Compose project's containers that have a newer image, in
    dependency order and all or nothing (updates/apply.py), and opens its run page.
    Audited."""
    target_host = db.get(Host, host)
    snap = request.app.state.status.snapshot(host)
    known = {c.project for c in snap.containers if c.project} if snap is not None else set()
    if target_host is None or stack not in known:
        raise HTTPException(status_code=404)
    release(db, target_host)
    error = None
    run_id = None
    if not target_host.enabled:
        error = "The host is disabled."
    else:
        try:
            run_id = anyio.from_thread.run(
                functools.partial(
                    request.app.state.dispatcher.submit_update,
                    target_host.id,
                    [],
                    auth.user.username,
                    f"stack {stack}",
                    project=stack,
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
        | ({"run_id": run_id} if run_id else {})
        | ({"error": error} if error else {}),
    )
    db.commit()
    if run_id is None:
        view = View(target_host.id, stack=stack)
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
