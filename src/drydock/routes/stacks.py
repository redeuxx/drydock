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
from dataclasses import dataclass
from typing import Annotated

import anyio.from_thread
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import Host, Job
from drydock.routes import containers as container_routes
from drydock.routes.auth import client_ip
from drydock.routes.hosts import release
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other

router = APIRouter()

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Operator = Annotated[Auth, Depends(require_role(Role.operator))]

STACK_ACTIONS = ("start", "stop", "restart", "remove")


@dataclass(frozen=True)
class Stack:
    name: str
    total: int
    running: int
    newer: int  # members with a newer image, as the update checker last saw
    jobs: list[Job]


def page(
    request: Request,
    auth: Auth,
    db: Session,
    host: int | None,
    outcomes: list[container_routes.Outcome] | None = None,
) -> Response:
    collector = request.app.state.status
    collector.touch()
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = next((h for h in hosts if h.id == host), None) or next(
        (h for h in hosts if h.enabled), hosts[0] if hosts else None
    )
    snap = None
    stacks: list[Stack] = []
    if chosen is not None:
        snap = collector.snapshot(chosen.id)
        checks = request.app.state.updates.result(chosen.id)
        verdicts = checks.verdicts if checks is not None else {}
        if snap is not None:
            groups = defaultdict(list)
            for c in snap.containers:
                if c.project:
                    groups[c.project].append(c)
            covers = container_routes.covering_jobs(db, chosen.id)
            stacks = [
                Stack(
                    name,
                    len(members),
                    sum(c.state == "running" for c in members),
                    sum(c.id in verdicts and verdicts[c.id].state == "update" for c in members),
                    covers[("stack", name)],
                )
                for name, members in sorted(groups.items())
            ]
    return render(
        request,
        "stacks/index.html",
        auth=auth,
        hosts=hosts,
        chosen=chosen,
        snap=snap,
        stacks=stacks,
        outcomes=outcomes or [],
        verbs=container_routes.ACTIONS,
    )


@router.get("/stacks")
def stacks(
    request: Request, auth: Viewer, db: Session = Depends(get_db), host: int | None = None
) -> Response:
    return page(request, auth, db, host)


@router.post("/stacks/actions")
def stack_actions(
    request: Request,
    auth: Operator,
    host: Annotated[int, Form()],
    stack: Annotated[str, Form()],
    action: Annotated[str, Form()],
    db: Session = Depends(get_db),
) -> Response:
    """Runs action on every container of the stack, as the cache last saw them. Audited
    once for the stack, with each container's outcome."""
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
    url = f"/stacks?host={target_host.id}"
    if not is_htmx(request):
        return see_other(request, url)
    response = page(request, auth, db, target_host.id, outcomes)
    response.headers["HX-Replace-Url"] = url
    return response
