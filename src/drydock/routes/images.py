"""The images page: one host's images, read from its daemon when the page loads, with the
containers that use each one. Admins remove an unused image, with the password from the
last 10 minutes.

An image is removed tag by tag (`docker rmi <tag>` for each), so one with several tags
goes in one click; the last tag takes the image with it. One without tags is removed by
ID. An image any container uses, stopped ones included, is refused before anything is
untagged; nothing is ever forced.

ponytail: no lock against a restore that loads the same image meanwhile; the daemon
refuses to remove an image a new container already uses. Add a dispatcher key if needed.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Any

import docker.errors
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import Host
from drydock.routes.auth import client_ip
from drydock.routes.containers import ACTION_ERRORS
from drydock.routes.hosts import DOCKER_ERRORS, open_host, release
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other

router = APIRouter()

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]

IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_TIMEOUT = 30
NO_TAG = "<none>:<none>"


@dataclass(frozen=True)
class Image:
    id: str
    tags: list[str]
    size: int
    created: datetime
    users: list[str]  # names of the containers that use it


def image_error(exc: BaseException) -> str:
    """Safe to show: the daemon's own text is not quoted (it can name paths)."""
    if isinstance(exc, docker.errors.NotFound):
        return "No such image any more."
    if isinstance(exc, docker.errors.APIError):
        if exc.status_code == 409:
            return "Docker refused: a container uses it or another image depends on it."
        return f"The Docker daemon answered HTTP {exc.status_code or 'an error'}."
    return "Cannot reach the Docker daemon."


def users_by_image(api: Any) -> dict[str, list[str]]:
    users: dict[str, list[str]] = defaultdict(list)
    for c in api.containers(all=True):
        names = c.get("Names") or [str(c.get("Id", ""))[:12]]
        users[str(c.get("ImageID", ""))].append(str(names[0]).lstrip("/"))
    return users


def read_images(request: Request, host: Host) -> tuple[list[Image], str | None]:
    """Blocking. (the images, an error that is safe to show or None)."""
    try:
        handle = open_host(request, host, IMAGE_TIMEOUT)
    except DOCKER_ERRORS as exc:
        return [], str(exc)
    try:
        api = handle.client.api
        users = users_by_image(api)
        images = [
            Image(
                str(i["Id"]),
                sorted(t for t in i.get("RepoTags") or [] if t != NO_TAG),
                int(i.get("Size") or 0),
                datetime.fromtimestamp(int(i.get("Created") or 0), UTC),
                sorted(users.get(str(i["Id"]), [])),
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
        users = users_by_image(api).get(image_id)
        if users:
            return label, f"Used by {', '.join(sorted(users))}. Remove those containers first."
        for ref in tags or [image_id]:
            api.remove_image(ref)
        return label, None
    except ACTION_ERRORS as exc:
        return image_id[:19], image_error(exc)
    finally:
        handle.close()


def page(
    request: Request,
    auth: Auth,
    db: Session,
    host: int | None,
    notice: tuple[str, bool] | None = None,
) -> Response:
    hosts = list(db.scalars(select(Host).order_by(Host.name)))
    chosen = next((h for h in hosts if h.id == host), None) or next(
        (h for h in hosts if h.enabled), hosts[0] if hosts else None
    )
    images: list[Image] = []
    error = None
    if chosen is not None and chosen.enabled:
        for h in hosts:
            db.expunge(h)
        db.rollback()  # no lock while waiting on the network (routes/hosts.py release)
        images, error = read_images(request, chosen)
    return render(
        request,
        "images/index.html",
        auth=auth,
        hosts=hosts,
        chosen=chosen,
        images=images,
        error=error,
        notice=notice,
    )


@router.get("/images")
def images(
    request: Request, auth: Viewer, db: Session = Depends(get_db), host: int | None = None
) -> Response:
    return page(request, auth, db, host)


@router.post("/images/remove")
def remove(
    request: Request,
    auth: Admin,
    host: Annotated[int, Form()],
    image: Annotated[str, Form()],
    db: Session = Depends(get_db),
) -> Response:
    """Audited, removed or not, once the request itself is valid."""
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
    url = f"/images?host={target_host.id}"
    if not is_htmx(request):
        return see_other(request, url)
    response = page(
        request, auth, db, target_host.id, (f"{label}: {error or 'removed'}", not error)
    )
    response.headers["HX-Replace-Url"] = url
    return response
