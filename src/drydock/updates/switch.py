"""Switching the tag a container, or a Compose stack's main service, follows.

A switch is an update (updates/apply.py) to another tag of the same repository: the new
tag's image is pulled by the digest the registry names, and the container is made again
from repository:tag with its own configuration. Compose files are never edited, so a
later `docker compose up` on the host puts the Compose file's tag back.

A stack's main service is the one the others are there for: no other member depends on
it (Compose's depends_on label), preferring one that binds a host port, then by service
name. The Stacks page and a run judge it from the same two facts.

Switching it switches its replicas, and the members of the same app: images from the
same publisher (registry and path, say ghcr.io/immich-app) whose names start like the
main's (immich-server, immich-machine-learning), on the main's tag or that tag with a
suffix (v1.2-cuda becomes v1.3-cuda). Never across Docker Hub's official images, which
are many publishers' (nextcloud, mariadb and redis are all library/), and never when the
main follows latest, which every image has; then only the main service moves. Everything
else, a database or a cache, keeps its tag.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

import docker.utils

from drydock.engine.stacks import DEPENDS_ON_LABEL, parse_depends_on
from drydock.hosts.inventory import SERVICE_LABEL
from drydock.hosts.status import ContainerStatus
from drydock.updates.check import IMAGE_ID_RE, followed_tag

# Docker's tag grammar.
TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
TAG_ERROR = "A tag is up to 128 letters, digits, _ . and -, not starting with . or -."
DEFAULT_REGISTRY = "docker.io"
LIBRARY = f"{DEFAULT_REGISTRY}/library"  # Docker Hub's official images: many publishers


@dataclass(frozen=True)
class Part:
    """A stack member as a switch sees it."""

    id: str
    service: str | None
    image: str  # the reference it was created from (Config.Image)
    depends_on: frozenset[str]  # the IDs of the members it needs
    ports: bool  # it publishes a port


def repository(image: str) -> str | None:
    """The repository an image reference names, without tag or digest; None for an image
    ID."""
    if not image or IMAGE_ID_RE.fullmatch(image):
        return None
    name, _ = docker.utils.parse_repository_tag(image.partition("@")[0])
    return name or None


def namespace(repo: str) -> str:
    """The registry and path of a repository, its last component left out: nginx and
    docker.io/library/nginx are both docker.io/library."""
    first, _, rest = repo.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = DEFAULT_REGISTRY, repo
    if registry == DEFAULT_REGISTRY and "/" not in path:
        path = "library/" + path
    return f"{registry}/{path.rpartition('/')[0]}"


def switched_ref(image: str, tag: str) -> str | None:
    """repository:tag for the container's repository; None for an image ID."""
    repo = repository(image)
    return f"{repo}:{tag}" if repo else None


def family(repo: str) -> str:
    """The first word of a repository's name: immich for ghcr.io/immich-app/immich-server."""
    return re.split(r"[-_.]", repo.rpartition("/")[2], maxsplit=1)[0]


def main_service(parts: Iterable[Part]) -> Part | None:
    """The member no other one depends on, preferring one that binds a host port, then the
    first by service name and ID."""
    found = list(parts)
    needed = {d for p in found for d in p.depends_on}
    roots = [p for p in found if p.id not in needed] or found
    roots.sort(key=lambda p: (not p.ports, p.service or "", p.id))
    return roots[0] if roots else None


def followers(parts: Iterable[Part], main: Part, tag: str) -> dict[str, str]:
    """Member ID: the reference it switches to, when main switches to tag (the module's
    rules). Main itself and its replicas always; nothing for one made from an image ID."""
    found = list(parts)
    main_repo = repository(main.image)
    if main_repo is None:
        return {}
    switch = {main.id: f"{main_repo}:{tag}"}
    for part in found:
        repo = repository(part.image)
        if part.id != main.id and main.service and part.service == main.service and repo:
            switch[part.id] = f"{repo}:{tag}"
    current = followed_tag(main.image)
    home = namespace(main_repo)
    if current is None or current == "latest" or home == LIBRARY:
        return switch
    for part in found:
        repo = repository(part.image)
        theirs = followed_tag(part.image)
        if part.id in switch or repo is None or theirs is None:
            continue
        if repo != main_repo and (namespace(repo) != home or family(repo) != family(main_repo)):
            continue
        if theirs == current:
            switch[part.id] = f"{repo}:{tag}"
        elif theirs.startswith(current + "-"):
            switch[part.id] = f"{repo}:{tag}{theirs[len(current) :]}"
    return switch


def parts_of(rows: Iterable[tuple[str, str | None, str, object, bool]]) -> list[Part]:
    """Parts from (ID, service, image reference, depends_on label, binds a port)."""
    found = list(rows)
    by_service: dict[str, list[str]] = {}
    for cid, service, *_ in found:
        if service:
            by_service.setdefault(service, []).append(cid)
    parts = []
    for cid, service, image, label, bound in found:
        needs = {i for d in parse_depends_on(label) for i in by_service.get(d.service, [])}
        parts.append(Part(cid, service, image, frozenset(needs - {cid}), bound))
    return parts


def from_cache(members: Iterable[ContainerStatus]) -> list[Part]:
    """A stack's members as the status collector last read them (hosts/status.py)."""
    return parts_of(
        (c.id, c.service, c.image, dict(c.labels).get(DEPENDS_ON_LABEL), c.bound or bool(c.ports))
        for c in members
    )


def from_inspect(infos: Iterable[dict]) -> list[Part]:
    """A stack's members from their inspect output."""
    rows = []
    for info in infos:
        config = info.get("Config") or {}
        labels = config.get("Labels") or {}
        bindings = (info.get("HostConfig") or {}).get("PortBindings")
        service = labels.get(SERVICE_LABEL)
        rows.append(
            (
                str(info["Id"]),
                service if isinstance(service, str) and service else None,
                str(config.get("Image") or ""),
                labels.get(DEPENDS_ON_LABEL),
                isinstance(bindings, dict) and any(bindings.values()),
            )
        )
    return parts_of(rows)
