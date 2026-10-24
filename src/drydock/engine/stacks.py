"""Stacks: the containers of one Compose project on one Docker daemon.

Membership is found at run time by the exact label com.docker.compose.project=<project>.
One-off containers (`compose run`), this installation's helpers and originals an overwrite
restore renamed to '<name>-drydock-old' are not members. Containers drydock restored keep
their drydock.restore.run label for good, so they are members like any other.

Order comes from the containers themselves: the com.docker.compose.depends_on label
(Compose v2 writes `service:condition:restart` entries), NetworkMode, IpcMode and PidMode
`container:<ref>`, VolumesFrom and Links (HostConfig.Links on the default bridge, the
endpoint Links on user-defined networks). A dependency starts first and stops last.
Archived inspect documents give the same order as live ones, so backups (jobs.dispatcher)
and restores (restore.plan) share this module.

Pure except discover() and wait_healthy(), which make blocking docker-py calls: run them
on a worker thread.
"""

import bisect
import heapq
import re
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

import docker
import docker.errors
import requests

from drydock.hosts.helper import is_helper
from drydock.hosts.inventory import PROJECT_LABEL, SERVICE_LABEL

DEPENDS_ON_LABEL = "com.docker.compose.depends_on"
ONEOFF_LABEL = "com.docker.compose.oneoff"
NUMBER_LABEL = "com.docker.compose.container-number"
VOLUME_LABEL = "com.docker.compose.volume"
NETWORK_LABEL = "com.docker.compose.network"
# The name an overwrite restore gives the original while it runs (restore.plan.OLD_SUFFIX).
OLD_SUFFIX = "-drydock-old"
# Compose's own rule for project names: 1 to 63 characters.
PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}", re.ASCII)
SERVICE_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", re.ASCII)
# A container reference by ID prefix needs 12 hex characters (dispatcher.CONTAINER_ID_RE).
ID_PREFIX_RE = re.compile(r"[0-9a-f]{12,64}", re.ASCII)
NUMBER_RE = re.compile(r"[0-9]{1,9}", re.ASCII)
MAX_DEPENDENCIES = 256  # entries parsed from one label; the rest are ignored
MAX_REFS = 256  # container references read from one inspect document; the rest are ignored
# Edges in one stack. Real stacks have far fewer; archived documents are attacker-influenced
# and depends_on edges grow with the square of the member count, so order() stops here.
MAX_EDGES = 100_000
MAX_CYCLE_NAMES = 10  # names a cycle error lists before "and N more"
HEALTH_WAIT = 120
HEALTH_POLL = 1.0
CONDITIONS = ("service_started", "service_healthy", "service_completed_successfully")
CONTAINER_MODE_KEYS = ("NetworkMode", "IpcMode", "PidMode")


class StackError(Exception):
    """The stack cannot be ordered. The message is safe to show."""


@dataclass(frozen=True)
class Dependency:
    service: str
    condition: str  # "" when the label names none or one drydock does not know


@dataclass(frozen=True)
class Member:
    id: str
    name: str
    service: str | None
    after: tuple[str, ...]  # member IDs that must start before this one, sorted
    healthy: tuple[str, ...]  # those of after that must be healthy first


# DEPENDS_ON


def parse_depends_on(value: object) -> list[Dependency]:
    """The entries of a depends_on label. Labels in archives are attacker-influenced, so
    odd input gives fewer entries, never an error, and the work is bounded."""
    if not isinstance(value, str) or not value:
        return []
    found: dict[str, Dependency] = {}
    for raw in value.split(","):
        if len(found) >= MAX_DEPENDENCIES:
            break
        entry = raw.strip()
        if not entry:
            continue
        parts = entry.split(":", 2)
        service = parts[0]
        if not SERVICE_RE.fullmatch(service) or service in found:
            continue
        condition = parts[1] if len(parts) > 1 and parts[1] in CONDITIONS else ""
        found[service] = Dependency(service, condition)
    return list(found.values())


# DISCOVERY


def discover(api, project: str, instance_id: str) -> list[str]:
    """The sorted IDs of the project's containers on this daemon. Blocking."""
    found = []
    for raw in api.containers(all=True, filters={"label": f"{PROJECT_LABEL}={project}"}):
        labels = raw.get("Labels") or {}
        if labels.get(PROJECT_LABEL) != project:
            continue
        if labels.get(ONEOFF_LABEL, "False") == "True" or is_helper(labels, instance_id):
            continue
        if primary_name(raw).endswith(OLD_SUFFIX):
            continue
        found.append(raw["Id"])
    return sorted(found)


def primary_name(summary: dict[str, Any]) -> str:
    """The container's own name from a list summary. Names also holds the
    '/<linker>/<alias>' names of legacy links, in no promised order, so like the docker CLI
    this takes the first entry without an inner '/'."""
    names = summary.get("Names")
    for name in names if isinstance(names, list) else []:
        if isinstance(name, str) and "/" not in name.lstrip("/"):
            return name.lstrip("/")
    return ""


# ORDER


def labels_of(info: dict[str, Any]) -> dict[str, Any]:
    config = info.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    return labels if isinstance(labels, dict) else {}


def has_healthcheck(info: dict[str, Any]) -> bool:
    config = info.get("Config")
    check = config.get("Healthcheck") if isinstance(config, dict) else None
    test = check.get("Test") if isinstance(check, dict) else None
    return isinstance(test, list) and bool(test) and test[0] != "NONE"


def container_refs(info: dict[str, Any]) -> list[str]:
    """Every container this one names in container: modes, VolumesFrom and Links, at most
    MAX_REFS of them. Docker reports legacy links in HostConfig.Links only on the default
    bridge; on user-defined networks (every Compose project network) `links:` is in each
    endpoint's Links."""
    host = info.get("HostConfig")
    host = host if isinstance(host, dict) else {}
    refs = []
    for key in CONTAINER_MODE_KEYS:
        mode = host.get(key)
        if isinstance(mode, str) and mode.startswith("container:"):
            refs.append(mode.removeprefix("container:"))
    # VolumesFrom: "<ref>[:ro|:rw]"; HostConfig.Links: "/<peer>:/<self>/<alias>";
    # endpoint Links: "<peer>:<alias>".
    lists = [host.get("VolumesFrom"), host.get("Links")]
    settings = info.get("NetworkSettings")
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    for endpoint in networks.values() if isinstance(networks, dict) else []:
        if isinstance(endpoint, dict):
            lists.append(endpoint.get("Links"))
    for entries in lists:
        for entry in entries if isinstance(entries, list) else []:
            if len(refs) >= MAX_REFS:
                return refs
            if isinstance(entry, str):
                refs.append(entry.split(":", 1)[0].lstrip("/"))
    return refs


def sort_key(member: Member, labels: dict[str, Any]) -> tuple[str, int, str, str]:
    number = labels.get(NUMBER_LABEL)
    count = int(number) if isinstance(number, str) and NUMBER_RE.fullmatch(number) else 0
    return (member.service or "", count, member.name, member.id)


def order(infos: Sequence[dict[str, Any]]) -> list[Member]:
    """The members in start order (dependencies first); the reverse is the stop order.
    Deterministic whatever the input order. Raises StackError on a cycle or past
    MAX_EDGES."""
    by_id: dict[str, dict[str, Any]] = {str(info["Id"]): info for info in infos}
    sorted_ids = sorted(by_id)
    by_name = {str(info.get("Name") or "").lstrip("/"): cid for cid, info in by_id.items()}
    by_service: dict[str, list[str]] = {}
    for cid, info in by_id.items():
        service = labels_of(info).get(SERVICE_LABEL)
        if isinstance(service, str) and service:
            by_service.setdefault(service, []).append(cid)

    def ref(value: str) -> str | None:
        if value in by_id:
            return value
        if value in by_name:
            return by_name[value]
        if ID_PREFIX_RE.fullmatch(value):
            # The IDs starting with value are adjacent in sorted order; two tell one from many.
            start = bisect.bisect_left(sorted_ids, value)
            matches = [cid for cid in sorted_ids[start : start + 2] if cid.startswith(value)]
            if len(matches) == 1:
                return matches[0]
        return None

    edges = 0

    def count() -> None:
        nonlocal edges
        edges += 1
        if edges > MAX_EDGES:
            raise StackError("The stack has too many dependencies to order.")

    members: dict[str, Member] = {}
    for cid, info in by_id.items():
        labels = labels_of(info)
        after: set[str] = set()
        healthy: set[str] = set()
        for dependency in parse_depends_on(labels.get(DEPENDS_ON_LABEL)):
            for other in by_service.get(dependency.service, []):
                if other == cid:
                    continue
                count()
                after.add(other)
                if dependency.condition == "service_healthy" and has_healthcheck(by_id[other]):
                    healthy.add(other)
        for value in container_refs(info):
            other = ref(value)
            if other is not None and other != cid:
                count()
                after.add(other)
        service = labels.get(SERVICE_LABEL)
        members[cid] = Member(
            id=cid,
            name=str(info.get("Name") or "").lstrip("/"),
            service=service if isinstance(service, str) and service else None,
            after=tuple(sorted(after)),
            healthy=tuple(sorted(healthy)),
        )

    keys = {cid: sort_key(member, labels_of(by_id[cid])) for cid, member in members.items()}
    waiting = {cid: len(member.after) for cid, member in members.items()}
    dependents: dict[str, list[str]] = {cid: [] for cid in members}
    for cid, member in members.items():
        for other in member.after:
            dependents[other].append(cid)
    ready = [(keys[cid], cid) for cid, count in waiting.items() if count == 0]
    heapq.heapify(ready)
    result = []
    while ready:
        _, cid = heapq.heappop(ready)
        result.append(members[cid])
        for other in dependents[cid]:
            waiting[other] -= 1
            if waiting[other] == 0:
                heapq.heappush(ready, (keys[other], other))
    if len(result) < len(members):
        raise StackError(cycle_message(members, {member.id for member in result}))
    return result


def cycle_message(members: dict[str, Member], done: set[str]) -> str:
    """Names the members on or between cycles. Kahn's leftovers also hold members that only
    depend on a cycle; peel those off from the dependent end first."""
    left = {cid for cid in members if cid not in done}
    dependents = dict.fromkeys(left, 0)
    for cid in left:
        for other in members[cid].after:
            if other in left:
                dependents[other] += 1
    loose = [cid for cid, n in dependents.items() if n == 0]
    while loose:
        cid = loose.pop()
        left.discard(cid)
        for other in members[cid].after:
            if other in left:
                dependents[other] -= 1
                if dependents[other] == 0:
                    loose.append(other)
    names = sorted(members[cid].name for cid in left)
    shown = ", ".join(names[:MAX_CYCLE_NAMES])
    if len(names) > MAX_CYCLE_NAMES:
        shown += f" and {len(names) - MAX_CYCLE_NAMES} more"
    return f"The containers {shown} depend on each other in a cycle."


def unordered(infos: Sequence[dict[str, Any]]) -> bool:
    """True when several containers record no depends_on label at all (Compose v1, or v2
    before it wrote one), so order() falls back to name order where nothing else links
    them."""
    return len(infos) > 1 and not any(DEPENDS_ON_LABEL in labels_of(info) for info in infos)


# HEALTH


def wait_healthy(
    api,
    ids: Sequence[str],
    deadline: float,
    cancel: threading.Event | None,
    log: Callable[[str], None],
) -> bool:
    """Waits, until deadline (time.monotonic), for each container in turn to report healthy.
    True when every one is healthy or has nothing to wait for (not running, no
    healthcheck); False on a cancel, at the deadline, or when one could not be inspected.
    Never raises for Docker errors. Blocking."""
    ok = True
    for cid in ids:
        waiting = False
        while True:
            if cancel is not None and cancel.is_set():
                return False
            try:
                info = api.inspect_container(cid)
            except docker.errors.DockerException, requests.RequestException:
                log(f"Could not check the health of container {cid[:12]}; starting anyway.")
                ok = False
                break
            state = info.get("State") or {}
            health = state.get("Health")
            if not state.get("Running") or not isinstance(health, dict):
                break
            if health.get("Status") == "healthy":
                break
            name = str(info.get("Name") or cid[:12]).lstrip("/")
            now = time.monotonic()
            if now >= deadline:
                log(f"Container {name} is not healthy after waiting; starting the next one anyway.")
                return False
            if not waiting:
                log(f"Waiting for container {name} to be healthy.")
                waiting = True
            pause = min(HEALTH_POLL, deadline - now)
            if cancel is not None:
                cancel.wait(pause)
            else:
                time.sleep(pause)
    return ok
