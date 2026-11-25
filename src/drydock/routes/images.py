"""The images page: one host's images, read from its daemon when the page loads, with the
containers that use each one. Admins remove an unused image, with the password from the
last 10 minutes.

An image is removed tag by tag (`docker rmi <tag>` for each), so one with several tags
goes in one click; the last tag takes the image with it. One without tags is removed by
ID. An image any container uses, stopped ones included, is refused before anything is
untagged; nothing is ever forced.

Admins also prune a host's images, or every enabled host's: the untagged ones no
container uses (`docker image prune`), or every image no container uses, stopped ones
included (`docker image prune -a`). A prune is refused while any run is active: an update
or restore may have pulled an image that no container uses yet.

ponytail: no lock against a restore that loads the same image meanwhile; the daemon
refuses to remove an image a new container already uses. Add a dispatcher key if needed.
A run that starts while a prune is under way is not waited for either.
"""

import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import urlencode

import docker.errors
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.jobs.dispatcher import ACTIVE_STATUSES
from drydock.models import Host, Run
from drydock.routes import containers as container_routes
from drydock.routes.auth import client_ip
from drydock.routes.containers import ACTION_ERRORS
from drydock.routes.hosts import DOCKER_ERRORS, open_host, release
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import filesize, is_htmx, render, see_other

router = APIRouter()

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Operator = Annotated[Auth, Depends(require_role(Role.operator))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]

IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_TIMEOUT = 30
PRUNE_TIMEOUT = 300  # a daemon with many images takes a while
# Mode: (what the outcome calls the images, Docker's prune filters).
PRUNES: dict[str, tuple[str, dict[str, Any]]] = {
    "dangling": ("untagged", {"dangling": True}),
    "unused": ("unused", {"dangling": False}),
}
READERS = 8  # hosts read at the same time on every host's page
NO_TAG = "<none>:<none>"


@dataclass(frozen=True)
class Image:
    id: str
    tags: list[str]
    size: int
    created: datetime
    users: list[str]  # names of the containers that use it
    newer: bool = False  # a container using it has a newer image, as last checked
    host: Any = None  # the Host it is on


def image_error(exc: BaseException) -> str:
    """Safe to show: the daemon's own text is not quoted (it can name paths)."""
    if isinstance(exc, docker.errors.NotFound):
        return "No such image any more."
    if isinstance(exc, docker.errors.APIError):
        if exc.status_code == 409:
            return "Docker refused: a container uses it or another image depends on it."
        return f"The Docker daemon answered HTTP {exc.status_code or 'an error'}."
    return "Cannot reach the Docker daemon."


def users_by_image(containers: list[dict[str, Any]]) -> dict[str, list[str]]:
    users: dict[str, list[str]] = defaultdict(list)
    for c in containers:
        names = c.get("Names") or [str(c.get("Id", ""))[:12]]
        users[str(c.get("ImageID", ""))].append(str(names[0]).lstrip("/"))
    return users


def read_images(request: Request, host: Host, newer: set[str]) -> tuple[list[Image], str | None]:
    """Blocking. (the images, an error that is safe to show or None). newer: the IDs of
    the containers with a newer image."""
    try:
        handle = open_host(request, host, IMAGE_TIMEOUT)
    except DOCKER_ERRORS as exc:
        return [], str(exc)
    try:
        api = handle.client.api
        containers = api.containers(all=True)
        users = users_by_image(containers)
        behind = {str(c.get("ImageID", "")) for c in containers if c.get("Id") in newer}
        images = [
            Image(
                str(i["Id"]),
                sorted(t for t in i.get("RepoTags") or [] if t != NO_TAG),
                int(i.get("Size") or 0),
                datetime.fromtimestamp(int(i.get("Created") or 0), UTC),
                sorted(users.get(str(i["Id"]), [])),
                str(i["Id"]) in behind,
                host,
            )
            for i in api.images()
        ]
    except ACTION_ERRORS as exc:
        return [], image_error(exc)
    finally:
        handle.close()
    # Tagged images by tag, then the untagged ones.
    return sorted(images, key=lambda i: (not i.tags, i.tags[0] if i.tags else "", i.id)), None


def remove_image(request: Request, host: Host, image_id: str) -> tuple[str, str | None]:
    """Blocking. (what was removed, as shown, and an error or None)."""
    try:
        handle = open_host(request, host, IMAGE_TIMEOUT)
    except DOCKER_ERRORS as exc:
        return image_id[:19], str(exc)
    try:
        api = handle.client.api
        info = api.inspect_image(image_id)
        tags = sorted(t for t in info.get("RepoTags") or [] if t != NO_TAG)
        label = tags[0] if tags else image_id[:19]
        users = users_by_image(api.containers(all=True)).get(image_id)
        if users:
            return label, f"Used by {', '.join(sorted(users))}. Remove those containers first."
        for ref in tags or [image_id]:
            api.remove_image(ref)
        return label, None
    except ACTION_ERRORS as exc:
        return image_id[:19], image_error(exc)
    finally:
        handle.close()


def prune_host(request: Request, host: Host, mode: str) -> tuple[int, int, str | None]:
    """Blocking. (images removed, bytes reclaimed, an error that is safe to show or None)."""
    try:
        handle = open_host(request, host, PRUNE_TIMEOUT)
    except DOCKER_ERRORS as exc:
        return 0, 0, str(exc)
    try:
        api = handle.client.api
        # Docker lists layers among what it deleted: count the images instead.
        before = {str(i.get("Id")) for i in api.images()}
        found = api.prune_images(filters=PRUNES[mode][1])
        after = {str(i.get("Id")) for i in api.images()}
    except docker.errors.APIError as exc:
        if exc.status_code == 409:
            return 0, 0, "Docker is pruning already."
        return 0, 0, image_error(exc)
    except ACTION_ERRORS as exc:
        return 0, 0, image_error(exc)
    finally:
        handle.close()
    reclaimed = found.get("SpaceReclaimed") if isinstance(found, dict) else None
    return len(before - after), reclaimed if isinstance(reclaimed, int) else 0, None


def page(
    request: Request,
    auth: Auth,
    db: Session,
    host: str,
    number: int = 1,
    notice: tuple[str, bool] | None = None,
) -> Response:
    """One host's images, or every enabled host's when host names none (routes/containers.py
    pick_host), read from each daemon at the same time, a page at a time."""
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = container_routes.pick_host(hosts, host)
    read = [h for h in container_routes.shown_hosts(hosts, chosen) if h.enabled]
    updates = request.app.state.updates
    checks = {h.id: updates.result(h.id) for h in read}
    for h in hosts:
        db.expunge(h)
    db.rollback()  # no lock while waiting on the network (routes/hosts.py release)

    def one(h: Host) -> tuple[list[Image], str | None]:
        verdicts = checks[h.id].verdicts if checks[h.id] is not None else {}
        return read_images(request, h, {cid for cid, v in verdicts.items() if v.state == "update"})

    # ponytail: one thread per host, at most READERS at once; a slow host holds the page
    # up to IMAGE_TIMEOUT. Cache the images (as hosts/status.py does containers) if that hurts.
    with ThreadPoolExecutor(max_workers=READERS) as pool:
        results = list(pool.map(one, read))
    images = [i for found, _ in results for i in found]
    errors = [(h, error) for h, (_, error) in zip(read, results, strict=True) if error]
    if chosen is None:
        images.sort(key=lambda i: (not i.tags, i.tags[0] if i.tags else "", i.host.name, i.id))
    shown, number, pages = container_routes.paginate(images, number)
    host_value = str(chosen.id) if chosen is not None else ""
    return render(
        request,
        "images/index.html",
        auth=auth,
        hosts=hosts,
        chosen=chosen,
        host_value=host_value,
        # Its containers as last read: "could not be checked" counts only those there.
        snap=request.app.state.status.snapshot(chosen.id) if chosen is not None else None,
        images=shown,
        count=len(images),
        size=sum(i.size for i in images),
        newer=sum(i.newer for i in images),
        page=number,
        pages=pages,
        page_url=f"/images?{urlencode({'host': host_value, 'page': ''})}",
        errors=errors,  # (host, an error that is safe to show)
        checks=checks.get(chosen.id) if chosen is not None else None,
        notice=notice,
    )


@router.get("/images")
def images(
    request: Request,
    auth: Viewer,
    db: Session = Depends(get_db),
    host: str = "",
    number: Annotated[str, Query(alias="page")] = "1",
) -> Response:
    return page(request, auth, db, host, container_routes.page_number(number))


@router.post("/images/check-updates")
def check_updates(
    request: Request, auth: Operator, host: Annotated[int, Form()], db: Session = Depends(get_db)
) -> Response:
    """The containers page's Check for updates, shown on this page."""
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
    url = f"/images?host={host}"
    if not is_htmx(request):
        return see_other(request, url)
    response = page(request, auth, db, str(host), notice=notice)
    response.headers["HX-Replace-Url"] = url
    return response


@router.post("/images/remove")
def remove(
    request: Request,
    auth: Admin,
    host: Annotated[int, Form()],
    image: Annotated[str, Form()],
    db: Session = Depends(get_db),
    shown: Annotated[str | None, Form(alias="view")] = None,
    number: Annotated[str, Form(alias="page")] = "1",
) -> Response:
    """Audited, removed or not, once the request itself is valid. view is the host the
    page showed ("all" for every host); the image's own host if not given."""
    require_recent_auth(auth)
    if not IMAGE_ID_RE.fullmatch(image):
        raise HTTPException(status_code=422)
    target_host = db.get(Host, host)
    if target_host is None:
        raise HTTPException(status_code=404)
    release(db, target_host)
    if target_host.enabled:
        label, error = remove_image(request, target_host, image)
    else:
        label, error = image[:19], "The host is disabled."
    audit.record(
        db,
        actor=auth.user.username,
        action="image.remove",
        target=f"image:{label}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"host": target_host.name, "id": image} | ({"error": error} if error else {}),
    )
    db.commit()
    back = shown or str(target_host.id)
    shown_page = container_routes.page_number(number)
    url = container_routes.back_url("/images", back, shown_page)
    if not is_htmx(request):
        return see_other(request, url)
    where = "" if back.isdigit() else f" on {target_host.name}"
    notice = (f"{label}{where}: {error or 'removed'}", not error)
    response = page(request, auth, db, back, shown_page, notice=notice)
    response.headers["HX-Replace-Url"] = url
    return response


@router.post("/images/prune")
def prune(
    request: Request,
    auth: Admin,
    host: Annotated[str, Form()],
    mode: Annotated[str, Form()],
    db: Session = Depends(get_db),
) -> Response:
    """Prunes the host's images, or every enabled host's for host "all" (mode: PRUNES).
    Audited per host, pruned or not, once the request itself is valid."""
    require_recent_auth(auth)
    if mode not in PRUNES:
        raise HTTPException(status_code=422)
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = container_routes.pick_host(hosts, host)
    if chosen is None and host != "all":
        raise HTTPException(status_code=404)
    targets = container_routes.shown_hosts(hosts, chosen)
    busy = db.scalar(select(Run.id).where(Run.status.in_(ACTIVE_STATUSES)).limit(1))
    for h in hosts:
        release(db, h)

    def one(h: Host) -> tuple[int, int, str | None]:
        if not h.enabled:
            return 0, 0, "The host is disabled."
        if busy is not None:
            return 0, 0, "A backup, restore or update is running. Prune when it ends."
        return prune_host(request, h, mode)

    # ponytail: the request waits for every host's prune, READERS at a time.
    with ThreadPoolExecutor(max_workers=READERS) as pool:
        results = list(pool.map(one, targets))
    lines = []
    for h, (removed, reclaimed, error) in zip(targets, results, strict=True):
        audit.record(
            db,
            actor=auth.user.username,
            action="image.prune",
            target=f"host:{h.id}",
            outcome="success" if error is None else "failure",
            ip=client_ip(request),
            details={"host": h.name, "mode": mode}
            | ({"error": error} if error else {"removed": removed, "reclaimed": reclaimed}),
        )
        noun = PRUNES[mode][0]
        lines.append(
            f"{h.name}: {error}"
            if error
            else f"{h.name}: {removed} {noun} image{'' if removed == 1 else 's'} removed, "
            f"{filesize(reclaimed) or '0 bytes'} reclaimed."
        )
    db.commit()
    back = "all" if chosen is None else str(chosen.id)
    url = "/images" if chosen is None else f"/images?host={chosen.id}"
    if not is_htmx(request):
        return see_other(request, url)
    failed = any(error for _, _, error in results)
    notice = (" ".join(lines), not failed) if lines else ("No enabled host to prune.", False)
    response = page(request, auth, db, back, notice=notice)
    response.headers["HX-Replace-Url"] = url
    return response
