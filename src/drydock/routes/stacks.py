"""The stacks page: one host's Compose projects, grouped from the status collector's cache
(hosts/status.py) as the containers page reads it. Showing them never calls Docker.

Operators start, stop and restart a whole stack and update it (the containers page's
update-stack route); admins remove one, with the password from the last 10 minutes. Each
action is the containers page's action on every member (routes/containers.py act_on), so
drydock's own project and containers a backup or restore holds are refused the same way.
Removing deletes the containers only: volumes and networks stay, and drydock has no
Compose file to make them again (`docker compose up` on the host does).

ponytail: members are acted on in name order, not Compose's dependency order. Restart
policies and health checks usually cover a start; follow depends_on if that falls short.
"""

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Annotated, Any
from urllib.parse import urlencode

import anyio.from_thread
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.hosts.status import HostSnapshot
from drydock.models import EVERY_STACK, Host, Job, UpdatePolicy
from drydock.routes import containers as container_routes
from drydock.routes.auth import client_ip
from drydock.routes.hosts import release
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other
from drydock.updates import switch as tag_switch
from drydock.updates.check import followed_tag

router = APIRouter()

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Operator = Annotated[Auth, Depends(require_role(Role.operator))]

STACK_ACTIONS = ("start", "stop", "restart", "remove")

# The state filter, as the containers page's: each test takes (running, total, newer).
STATUSES: dict[str, tuple[str, Callable[[int, int, int], bool]]] = {
    "running": ("Running", lambda running, total, newer: running == total),
    "partial": ("Partly running", lambda running, total, newer: 0 < running < total),
    "stopped": ("Stopped", lambda running, total, newer: running == 0),
    "updates": ("Update available", lambda running, total, newer: newer > 0),
}


def filters(status: str, q: str) -> dict[str, str]:
    """The state filter and search as the page applies them: an unknown state is none, the
    search trimmed and capped. The actions carry them back, so the page stays filtered."""
    return {
        "status": status if status in STATUSES else "",
        "q": q.strip()[: container_routes.MAX_QUERY],
    }


@dataclass(frozen=True)
class Stack:
    host: Host
    name: str
    total: int
    running: int
    newer: int  # members with a newer image, as the update checker last saw
    moves: list[str]  # "member: old -> new" for each of them
    tags: list[str]  # the tags its members follow; "pinned" for a digest or image ID
    main: str | None  # its main service (updates/switch.py), as the cache shows it
    main_tag: str | None  # the tag main follows; None when pinned
    version: str  # main's image version (hosts/status.py), "" when unknown
    follow: list[str]  # the other members that switch tags with main
    services: list[str]
    jobs: list[Job]
    policies: list[tuple[UpdatePolicy, datetime | None]]  # its update policies, next run


def page(
    request: Request,
    auth: Auth,
    db: Session,
    host: str,
    number: int = 1,
    outcomes: list[container_routes.Outcome] | None = None,
    notice: tuple[str, bool] | None = None,
    status: str = "",
    q: str = "",
) -> Response:
    """One host's stacks, or every enabled host's when host names none (routes/containers.py
    pick_host), a page at a time. status (STATUSES) and q (in the stack's name, its services
    or images) filter them."""
    shown_filters = filters(status, q)
    status, query = shown_filters["status"], shown_filters["q"]
    collector = request.app.state.status
    collector.touch()
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = container_routes.pick_host(hosts, host)
    snaps: dict[int, HostSnapshot | None] = {}
    found = []  # (host, stack, its members, the host's update verdicts)
    for h in container_routes.shown_hosts(hosts, chosen):
        snaps[h.id] = snap = collector.snapshot(h.id)
        checks = request.app.state.updates.result(h.id)
        verdicts = checks.verdicts if checks is not None else {}
        groups = defaultdict(list)
        for c in snap.containers if snap is not None else ():
            if c.project:
                groups[c.project].append(c)
        found += [(h, name, members, verdicts) for name, members in groups.items()]
    found.sort(key=lambda f: (f[1], f[0].name))
    total = len(found)
    newer = sum(  # stacks with a newer image, on every page
        any(container_routes.is_newer(verdicts, c) for c in members)
        for _, _, members, verdicts in found
    )
    if status:
        test = STATUSES[status][1]
        found = [
            f
            for f in found
            if test(
                sum(c.state == "running" for c in f[2]),
                len(f[2]),
                sum(container_routes.is_newer(f[3], c) for c in f[2]),
            )
        ]
    if query:
        needle = query.lower()
        found = [
            f
            for f in found
            if needle in f[1].lower()
            or any(needle in (c.service or "").lower() or needle in c.image.lower() for c in f[2])
        ]
    shown, number, pages = container_routes.paginate(found, number)

    scheduler = request.app.state.scheduler
    facts: dict[int, Any] = {}  # per host: the jobs that cover its stacks, its stack policies

    def of(h: Host) -> Any:
        if h.id not in facts:
            policies = defaultdict(list)
            for p in db.scalars(
                select(UpdatePolicy)
                .where(UpdatePolicy.host_id == h.id, UpdatePolicy.target_type == "stack")
                .order_by(UpdatePolicy.name)
            ):
                policies[p.target].append(
                    (p, scheduler.next_update_time(p.id) if p.enabled else None)
                )
            facts[h.id] = (container_routes.covering_jobs(db, h.id), policies)
        return facts[h.id]

    stacks = []
    for h, name, members, verdicts in shown:
        parts = tag_switch.from_cache(members)
        main = tag_switch.main_service(parts)
        moving = tag_switch.followers(parts, main, "next") if main is not None else {}
        names = {c.id: c.name for c in members}
        versions = {c.id: c.version for c in members}
        stacks.append(
            Stack(
                h,
                name,
                len(members),
                sum(c.state == "running" for c in members),
                sum(container_routes.is_newer(verdicts, c) for c in members),
                [
                    f"{c.name}: {verdicts[c.id].moves}"
                    for c in sorted(members, key=lambda c: c.name)
                    if container_routes.is_newer(verdicts, c)
                ],
                sorted({followed_tag(c.image) or "pinned" for c in members}),
                (main.service or names[main.id]) if main is not None else None,
                followed_tag(main.image) if main is not None else None,
                versions[main.id] if main is not None else "",
                sorted(names[i] for i in moving if main is not None and i != main.id),
                sorted({c.service for c in members if c.service}),
                of(h)[0][("stack", name)],
                of(h)[1][name] + of(h)[1][EVERY_STACK],
            )
        )
    host_value = str(chosen.id) if chosen is not None else ""
    single = chosen is not None and chosen.enabled
    return render(
        request,
        "stacks/index.html",
        auth=auth,
        hosts=hosts,
        chosen=chosen,
        host_value=host_value,
        snap=snaps.get(chosen.id) if chosen is not None else None,
        unread=[
            (h, snap)
            for h in container_routes.shown_hosts(hosts, None)
            if (snap := snaps[h.id]) is None or snap.taken_at is None or snap.error
        ]
        if chosen is None
        else [],
        stacks=stacks,
        total=total,
        matched=len(found),
        newer=newer,
        status=status,
        q=query,
        statuses=STATUSES,
        page=number,
        pages=pages,
        page_url="/stacks?"
        + urlencode(
            {k: v for k, v in (("host", host_value), ("status", status), ("q", query)) if v}
            | {"page": ""}
        ),
        # A policy updates every stack on the (one) host.
        every=single and bool(of(chosen)[1][EVERY_STACK]),
        checks=request.app.state.updates.result(chosen.id) if chosen is not None else None,
        notice=notice,
        outcomes=outcomes or [],
        verbs=container_routes.ACTIONS,
    )


@router.get("/stacks")
def stacks(
    request: Request,
    auth: Viewer,
    db: Session = Depends(get_db),
    host: str = "",
    status: str = "",
    q: str = "",
    number: Annotated[str, Query(alias="page")] = "1",
) -> Response:
    return page(request, auth, db, host, container_routes.page_number(number), status=status, q=q)


@router.post("/stacks/check-updates")
def check_updates(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    db: Session = Depends(get_db),
    status: Annotated[str, Form()] = "",
    q: Annotated[str, Form()] = "",
) -> Response:
    """The containers page's Check for updates, shown on this page with its filters."""
    shown = filters(status, q)
    target_host, notice, error = container_routes.ask_registries(request, db, host)
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
    url = container_routes.back_url("/stacks", str(host), 1, **shown)
    if not is_htmx(request):
        return see_other(request, url)
    response = page(
        request, auth, db, str(host), notice=notice, status=shown["status"], q=shown["q"]
    )
    response.headers["HX-Replace-Url"] = url
    return response


@router.post("/stacks/actions")
def stack_actions(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    stack: Annotated[str, Form()],
    action: Annotated[str, Form()],
    db: Session = Depends(get_db),
    shown: Annotated[str | None, Form(alias="view")] = None,
    number: Annotated[str, Form(alias="page")] = "1",
    status: Annotated[str, Form()] = "",
    q: Annotated[str, Form()] = "",
) -> Response:
    """Runs action on every container of the stack, as the cache last saw them. Audited
    once for the stack, with each container's outcome. view is the host the page showed
    ("all" for every host), the stack's own host if not given; page, status and q are its
    page and filters, so the answer is that same page."""
    if action not in STACK_ACTIONS:
        raise HTTPException(status_code=422)
    if action == "remove":
        container_routes.require_admin_reauth(auth)
    target_host = db.get(Host, host)
    snap = request.app.state.status.snapshot(host)
    members = [c.id for c in snap.containers if c.project == stack] if snap is not None else []
    if target_host is None or not members:
        raise HTTPException(status_code=404)
    release(db, target_host)
    outcomes = container_routes.run_actions(request, auth, target_host, action, members)
    failed = {o.name: o.error for o in outcomes if o.error}
    audit.record(
        db,
        actor=auth.user.username,
        action=f"stack.{action}",
        target=f"stack:{stack}",
        outcome="failure" if failed else "success",
        ip=client_ip(request),
        details={"host": target_host.name, "containers": [o.name for o in outcomes]}
        | ({"errors": failed} if failed else {}),
    )
    db.commit()
    anyio.from_thread.run(request.app.state.status.refresh, target_host.id)
    back = shown or str(target_host.id)
    shown_page = container_routes.page_number(number)
    url = container_routes.back_url("/stacks", back, shown_page, **filters(status, q))
    if not is_htmx(request):
        return see_other(request, url)
    if not back.isdigit():  # every host: the outcomes say which host
        outcomes = [replace(o, host=target_host.name) for o in outcomes]
    response = page(request, auth, db, back, shown_page, outcomes=outcomes, status=status, q=q)
    response.headers["HX-Replace-Url"] = url
    return response
