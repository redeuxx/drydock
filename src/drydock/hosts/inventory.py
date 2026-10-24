"""Container inventory of one host, grouped by Compose project, and the container facts
that backups and restores share (stop timeouts, liveness, drydock's own deployment).

Blocking (docker-py). Call from async code through hosts.client.run_blocking.
"""

import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker
import docker.errors

from drydock.hosts.helper import is_helper

PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"
DEFAULT_STOP_TIMEOUT = 10  # Docker's own default
MAX_STOP_TIMEOUT = 600  # a container may ask for more (or for no limit); drydock caps it
# States in which a container's process may touch its mounts. in_use() treats every state
# except created, exited and dead as live, so a state Docker adds later counts as live too.
LIVE_STATES = frozenset({"running", "paused", "restarting", "removing"})
HEX_PREFIX_RE = re.compile(r"[0-9a-f]{12,64}", re.ASCII)  # a hostname Docker derived from an ID
MOUNTINFO = "/proc/self/mountinfo"
MAX_MOUNTINFO = 1 << 20
# <data-root>/containers/<id>/hostname and the like, as mountinfo shows their roots.
CONTAINER_DIR_RE = re.compile(r"/containers/([0-9a-f]{64})/", re.ASCII)


@dataclass(frozen=True)
class MountInfo:
    type: str  # volume, bind or tmpfs
    name: str | None  # volume name
    source: str | None  # host path, for binds
    destination: str
    read_only: bool


@dataclass(frozen=True)
class ContainerInfo:
    id: str
    name: str
    image: str
    state: str
    status: str
    service: str | None
    mounts: tuple[MountInfo, ...]
    networks: tuple[str, ...]


@dataclass(frozen=True)
class ProjectGroup:
    project: str | None  # None for containers outside Compose
    containers: tuple[ContainerInfo, ...]


def container_info(raw: dict[str, Any]) -> ContainerInfo:
    labels = raw.get("Labels") or {}
    names = raw.get("Names") or []
    networks = (raw.get("NetworkSettings") or {}).get("Networks") or {}
    mounts = tuple(
        MountInfo(
            type=m.get("Type", ""),
            name=m.get("Name") or None,
            source=m.get("Source") or None,
            destination=m.get("Destination", ""),
            read_only=not m.get("RW", True),
        )
        for m in raw.get("Mounts") or []
    )
    return ContainerInfo(
        id=raw["Id"],
        name=names[0].lstrip("/") if names else raw["Id"][:12],
        image=raw.get("Image", ""),
        state=raw.get("State", ""),
        status=raw.get("Status", ""),
        service=labels.get(SERVICE_LABEL),
        mounts=tuple(sorted(mounts, key=lambda m: m.destination)),
        networks=tuple(sorted(networks)),
    )


def list_inventory(client: docker.DockerClient, instance_id: str) -> list[ProjectGroup]:
    """All containers (running or not) in one API call; this drydock's helpers are left out."""
    groups: dict[str | None, list[ContainerInfo]] = {}
    for raw in client.api.containers(all=True):
        labels = raw.get("Labels") or {}
        if is_helper(labels, instance_id):
            continue
        groups.setdefault(labels.get(PROJECT_LABEL), []).append(container_info(raw))
    # Compose projects by name, then standalone containers.
    return [
        ProjectGroup(
            project=project,
            containers=tuple(sorted(groups[project], key=lambda c: (c.service or "", c.name))),
        )
        for project in sorted(groups, key=lambda p: (p is None, p or ""))
    ]


# SHARED CONTAINER FACTS


def stop_timeout(info: dict[str, Any]) -> int:
    """The container's own stop timeout (Compose stop_grace_period), capped."""
    value = (info.get("Config") or {}).get("StopTimeout")
    if not isinstance(value, int) or isinstance(value, bool):
        return DEFAULT_STOP_TIMEOUT
    return MAX_STOP_TIMEOUT if value < 0 else min(value, MAX_STOP_TIMEOUT)


def in_use(state: str) -> bool:
    """Whether a container in this State.Status may be using its mounts."""
    return state not in ("created", "exited", "dead")


def own_id_candidates() -> list[str]:
    """The IDs (or ID prefixes) of the container this process may run in: the hostname
    Docker derives from the ID, then the container directory Docker bind-mounts
    /etc/hostname, /etc/hosts and /etc/resolv.conf from. The second survives a compose
    'hostname:' and the host's UTS or network namespace."""
    candidates = []
    hostname = socket.gethostname()
    if HEX_PREFIX_RE.fullmatch(hostname):
        candidates.append(hostname)
    try:
        with Path(MOUNTINFO).open(encoding="utf-8", errors="replace") as file:
            text = file.read(MAX_MOUNTINFO)
    except OSError:
        text = ""
    candidates += CONTAINER_DIR_RE.findall(text)
    return list(dict.fromkeys(candidates))


def own_container(api) -> dict[str, Any] | None:
    """Drydock's own container on this daemon, if it runs there.

    Found by ID only: Docker resolves a reference by exact name before ID prefix, so a
    container named like drydock's short ID would otherwise stand in for it.
    """
    for candidate in own_id_candidates():
        try:
            # The id filter is a pattern matched anywhere in the ID; keep true prefixes only.
            found = [
                raw["Id"]
                for raw in api.containers(all=True, filters={"id": candidate})
                if raw["Id"].startswith(candidate)
            ]
            if len(found) != 1:
                continue
            info = api.inspect_container(found[0])
        except docker.errors.APIError:
            continue
        if info["Id"] == found[0]:
            return info
    return None


def own_ids(api) -> frozenset[str]:
    """The IDs of drydock's own container and of every container in its Compose project
    (the socket proxy among them). Empty when drydock does not run on this daemon."""
    own = own_container(api)
    if own is None:
        return frozenset()
    ids = {own["Id"]}
    project = ((own.get("Config") or {}).get("Labels") or {}).get(PROJECT_LABEL)
    if project:
        filters = {"label": f"{PROJECT_LABEL}={project}"}
        ids.update(raw["Id"] for raw in api.containers(all=True, filters=filters))
    return frozenset(ids)
