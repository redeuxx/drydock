"""Updating containers to what their tag names on the registry now.

An update is planned as an overwrite restore of the containers' own configuration with
the newer image (restore.plan.RestorePlan, recreate=True), and carried out by
restore.apply: every image is pulled first by the digest the registry named (so nothing
changes when a pull fails), then each tag moves, each original is stopped with its own stop
timeout, its restart policy turned off and renamed '<name>-drydock-old', and the new
container is created with the original's full configuration (inspect -> create body, as a
restore makes it) but the new image, and started. The journal and its rollback, startup
recovery and the dispatcher's locks are the restore's.

Before the commit, settled() checks the started containers: one with a healthcheck must
become healthy within HEALTH_WAIT; one without must keep running, without restarts, for
SETTLE seconds. Otherwise the whole update rolls back: the new containers are removed, the
originals get their names, restart policies and state back, and the tags name the old
images again. After the commit the originals are removed; their images stay (a later
`docker image prune` removes them).

Not updated, and said so: containers pinned by digest or created from an image ID, images
with no registry digest (built on the host), drydock's own containers and helpers, and
containers whose image is already the newest. Compose files are never edited, and the
Compose labels stay, so a later `docker compose up` on the host sees its own containers.
"""

import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import docker.errors
import docker.utils
import requests

from drydock.engine import stacks
from drydock.engine.capture import distribution_digest
from drydock.hosts import inventory
from drydock.hosts.helper import HELPER_LABEL
from drydock.hosts.inventory import PROJECT_LABEL
from drydock.restore.apply import ApplyError
from drydock.restore.plan import (
    OLD_SUFFIX,
    ContainerStep,
    ImageStep,
    NameMap,
    Original,
    PlanError,
    RestorePlan,
    container_body,
)
from drydock.updates.check import lookup_error, reference

HEALTH_WAIT = stacks.HEALTH_WAIT  # seconds a container with a healthcheck may take, at least
MAX_HEALTH_WAIT = 900  # its own healthcheck timing may ask for more, up to this
SETTLE = 15  # seconds one without must keep running
POLL = 1.0


class UpdateError(Exception):
    """The update cannot be planned. The message is safe to show."""


@dataclass(frozen=True)
class Planned:
    plan: RestorePlan | None  # None: nothing to update
    notes: tuple[str, ...]  # what was left out and why, for the run log
    changes: tuple[tuple[str, str, str], ...]  # (name, old digest or "", new digest)


def image_info(api: Any, ref: str) -> dict[str, Any]:
    try:
        return api.inspect_image(ref)
    except docker.errors.NotFound:
        return {}


def repo_digests(info: dict[str, Any]) -> list[tuple[str, str]]:
    """(repository, digest) of each RepoDigest of an image's inspect."""
    found = []
    for entry in info.get("RepoDigests") or []:
        repository, at, digest = str(entry).partition("@")
        if at:
            found.append((repository, digest))
    return found


# Config keys an image sets and a container inherits unless it gives its own.
IMAGE_KEYS = (
    "Cmd",
    "Entrypoint",
    "WorkingDir",
    "User",
    "Healthcheck",
    "StopSignal",
    "Shell",
    "OnBuild",
    "ArgsEscaped",
)


def without_image_defaults(body: dict[str, Any], image: dict[str, Any]) -> dict[str, Any]:
    """The create body minus what the container only inherited from its old image, so the
    new image's own defaults apply: environment entries, labels, exposed ports and volumes
    the image declared, and command, entrypoint and the like when they are the image's.
    What the container set itself stays. (An explicit setting equal to the old image's
    default goes too, and the new image's default applies, as with docker run.)"""
    config = image.get("Config") or {}
    out = dict(body)
    for key in IMAGE_KEYS:
        if key in out and out[key] == config.get(key):
            del out[key]
    inherited = set(config.get("Env") or [])
    if isinstance(out.get("Env"), list):
        out["Env"] = [e for e in out["Env"] if e not in inherited]
    labels = config.get("Labels") or {}
    if isinstance(out.get("Labels"), dict):
        out["Labels"] = {k: v for k, v in out["Labels"].items() if labels.get(k) != v}
    for key in ("ExposedPorts", "Volumes"):
        if isinstance(out.get(key), dict):
            declared = config.get(key) or {}
            out[key] = {k: v for k, v in out[key].items() if k not in declared}
    return out


def identity(info: dict[str, Any]) -> NameMap:
    """Every name the container's configuration refers to, mapped to itself."""
    name = str(info.get("Name", "")).lstrip("/")
    volumes = {
        str(m["Name"]): str(m["Name"])
        for m in info.get("Mounts") or []
        if m.get("Type") == "volume" and m.get("Name")
    }
    for entry in (info.get("HostConfig") or {}).get("Binds") or []:
        source = str(entry).split(":", 1)[0]
        if source and not source.startswith("/"):
            volumes[source] = source
    networks = {n: n for n in ((info.get("NetworkSettings") or {}).get("Networks") or {})}
    return NameMap(containers={name: name}, ids={}, volumes=volumes, networks=networks)


def stack_order(api: Any, project: str, instance_id: str) -> list[stacks.Member]:
    """Blocking. The Compose project's containers on this daemon, dependencies first.
    Raises UpdateError when it has none, or its dependencies form a cycle."""
    try:
        ids = stacks.discover(api, project, instance_id)
    except docker.errors.DockerException, requests.RequestException:
        raise UpdateError(f"Cannot read stack {project} from the Docker daemon.") from None
    if not ids:
        raise UpdateError(f"Stack {project} has no containers on this host.")
    try:
        return stacks.order([api.inspect_container(i) for i in ids])
    except stacks.StackError as exc:
        raise UpdateError(str(exc)) from None
    except docker.errors.NotFound:
        raise UpdateError(f"A container of stack {project} went away; try again.") from None
    except docker.errors.DockerException, requests.RequestException:
        raise UpdateError(f"Cannot read stack {project} from the Docker daemon.") from None


def newest_digest(api: Any, info: dict[str, Any], ref: str) -> tuple[str | None, str]:
    """Blocking. The digest to pull, or None and why not. Raises UpdateError when the
    registry cannot be asked."""
    old_image = image_info(api, str(info.get("Image") or ""))
    current = {digest for _, digest in repo_digests(old_image)}
    if not current:
        # Built on the host, or (containerd's image store) its tag was pulled anew, which
        # leaves this image nameless: only then does the tag name a pulled image.
        newer = image_info(api, ref)
        if not newer or newer.get("Id") == info.get("Image") or not repo_digests(newer):
            return None, "built on the host (no registry digest), so not updated."
    try:
        latest = distribution_digest(api, ref)
    except (docker.errors.DockerException, requests.RequestException) as exc:
        raise UpdateError(lookup_error(exc)) from None
    except ValueError, KeyError, TypeError:
        raise UpdateError("The registry answer was not understood.") from None
    if latest in current:
        return None, f"already runs the newest {ref}."
    return latest, ""


def namespace_users(api: Any, planned: Mapping[str, str]) -> list[tuple[str, str]]:
    """Blocking. (container, the planned one whose network it joins) for every container
    on the host outside the plan that joins a planned one's network namespace
    (network_mode: container:<id or name>, Compose's service:<name>)."""
    users = []
    names = {
        **planned,
        **{cid[:12]: n for cid, n in planned.items()},
        **{n: n for n in planned.values()},
    }
    for raw in api.containers(all=True):
        if raw.get("Id") in planned:
            continue
        mode = str((raw.get("HostConfig") or {}).get("NetworkMode") or "")
        target = mode.removeprefix("container:") if mode.startswith("container:") else None
        if target in names:
            users.append((stacks.primary_name(raw) or str(raw.get("Id", ""))[:12], names[target]))
    return users


def plan_update(
    api: Any,
    host_id: int,
    container_ids: Iterable[str],
    own: frozenset[str],
    api_version: str,
    healthy_first: Mapping[str, Iterable[str]] | None = None,
    *,
    stack: bool = False,
) -> Planned:
    """Blocking. The plan that updates the containers that have a newer image, in the
    order given (a stack's: dependencies first). healthy_first maps a container ID to the
    IDs of the dependencies that must be healthy before it starts (service_healthy); a
    dependency updated in the same plan is waited for.

    A container that joins the network of, links to or takes volumes from one the plan
    makes again is made again too (with its own image, unless that is newer as well), so it
    names the new one; references by ID are rewritten to the name, which the new container
    keeps. Outside a stack, a container elsewhere on the host that joins a planned one's
    network refuses the update (its stack should be updated instead).

    One container (stack False) that cannot be updated raises UpdateError. In a stack,
    drydock's own containers, helpers and members whose registry cannot be asked are left
    alone with a note; the rest of the stack is still updated."""
    waits = healthy_first or {}
    planned: dict[str, str] = {}  # container ID: name, of those this plan makes again
    images: list[ImageStep] = []
    originals: list[Original] = []
    steps: list[ContainerStep] = []
    keys: set[str] = set()
    projects: set[str] = set()
    notes: list[str] = []
    warnings: list[str] = []
    changes: list[tuple[str, str, str]] = []
    pulls: dict[str, ImageStep] = {}  # one pull per reference

    def skip(name: str, why: str) -> None:
        if not stack:
            raise UpdateError(f"{name}: {why}")
        notes.append(f"{name}: {why} Left alone.")

    for container_id in container_ids:
        try:
            info = api.inspect_container(container_id)
        except docker.errors.NotFound:
            raise UpdateError(f"Container {container_id[:12]} no longer exists.") from None
        name = str(info.get("Name", "")).lstrip("/")
        labels = (info.get("Config") or {}).get("Labels") or {}
        if info["Id"] in own:
            skip(name, "drydock does not update itself or its own project.")
            continue
        if labels.get(HELPER_LABEL):
            skip(name, "drydock's helper containers are left to drydock.")
            continue
        if (info.get("HostConfig") or {}).get("AutoRemove"):
            # Stopping it removes it: there would be nothing to put back.
            skip(name, "it removes itself when stopped (--rm), so it is not updated.")
            continue
        refs = set(stacks.container_refs(info))
        follows = sorted(
            n for cid, n in planned.items() if cid in refs or cid[:12] in refs or n in refs
        )
        ref = reference(str((info.get("Config") or {}).get("Image") or ""))
        latest = None
        if ref is None:
            why = "pinned by digest or image ID, so not updated."
        else:
            try:
                latest, why = newest_digest(api, info, ref)
            except UpdateError as exc:
                skip(name, str(exc))
                why = ""
        if latest is None and not follows:
            if why:
                notes.append(f"{name}: {why}")
            continue
        old_image = image_info(api, str(info.get("Image") or ""))
        if latest is not None and ref is not None:
            repository, _ = docker.utils.parse_repository_tag(ref)
            step = pulls.get(ref)
            if step is None:
                step = pulls[ref] = ImageStep(
                    id=f"update-{len(pulls)}",
                    label=ref,
                    action="pull",
                    member=None,
                    pull=f"{repository}@{latest}",
                    refs=(ref,),
                    os="",
                    architecture="",
                    variant=None,
                    accepted_ids=(),
                    moves=(ref,),
                )
                images.append(step)
            # The tag too: two updates of one image never move it at once.
            keys.add(f"name:{host_id}:image:{ref}")
            own_repo = [d for r, d in repo_digests(old_image) if r == repository]
            current = sorted(d for _, d in repo_digests(old_image))
            changes.append((name, (own_repo or current or [""])[0], latest))
        else:
            notes.append(
                f"{name}: made again with its own image, since it uses {', '.join(follows)}."
            )
        state = info.get("State") or {}
        grace = inventory.stop_timeout(info)
        originals.append(
            Original(
                id=info["Id"],
                name=name,
                old_name=name + OLD_SUFFIX,
                running=bool(state.get("Running")),
                stop_timeout=grace,
            )
        )
        names = identity(info)
        names.ids.update({cid: n for cid, n in planned.items()})
        names.ids.update({cid[:12]: n for cid, n in planned.items()})
        names.containers.update({n: n for n in planned.values()})
        try:
            body = container_body(
                info,
                names=names,
                mode="overwrite",
                api_version=api_version,
                bind_map={},
                warnings=warnings,
            )
        except PlanError as exc:
            raise UpdateError(f"{name}: {exc}") from None
        if latest is not None:
            body = without_image_defaults(body, old_image)
        planned[info["Id"]] = name
        steps.append(
            ContainerStep(
                name=name,
                wait_healthy=tuple(planned[d] for d in waits.get(info["Id"], ()) if d in planned),
                body=body,
                start=bool(state.get("Running")) or state.get("Status") == "restarting",
                # Created from the reference as it was given (the pull has moved its tag),
                # not the image ID: the new container is still checked for updates, and
                # reads like the old one in docker ps.
                image_entry=None,
            )
        )
        keys |= {info["Id"], f"name:{host_id}:container:{name}"}
        if labels.get(PROJECT_LABEL):
            project = str(labels[PROJECT_LABEL])
            projects.add(project)
            keys.add(f"name:{host_id}:project:{project}")
    if not changes:
        return Planned(None, tuple(notes), ())
    # Outside the plan (another stack, or none): it would lose its network. ponytail:
    # only network_mode is in the container list; ipc and pid modes need an inspect each.
    users = namespace_users(api, planned)
    if users:
        user, joined = users[0]
        where = "update it with them" if stack else "update their stack instead"
        raise UpdateError(f"{user} uses the network of {joined}: {where}.")
    plan = RestorePlan(
        mode="overwrite",
        host_id=host_id,
        images=tuple(images),
        networks=(),
        volumes=(),
        # restore.apply stops originals in this order and rolls back in reverse:
        # dependents first, so a stack's are given dependencies first and reversed here.
        originals=tuple(reversed(originals)),
        wipes=(),
        data=(),
        containers=tuple(steps),
        risk=(),
        warnings=tuple(dict.fromkeys(warnings)),
        lock_keys=tuple(sorted(keys)),
        bind_sources=(),
        write_targets=(),
        projects=tuple(sorted(projects)),
        recreate=True,
    )
    return Planned(plan, tuple(notes), tuple(changes))


def plan_stack(
    api: Any, host_id: int, project: str, instance_id: str, own: frozenset[str], api_version: str
) -> Planned:
    """Blocking. plan_update for the Compose project's containers on this daemon, found
    now and put in dependency order."""
    members = stack_order(api, project, instance_id)
    planned = plan_update(
        api,
        host_id,
        [m.id for m in members],
        own,
        api_version,
        {m.id: m.healthy for m in members},
        stack=True,
    )
    order = f"Stack {project}: {', '.join(m.name for m in members)}."
    return Planned(planned.plan, (order, *planned.notes), planned.changes)


def stack_names(api: Any, own: frozenset[str]) -> list[str]:
    """Blocking. The Compose projects on this daemon, drydock's own left out."""
    return sorted(
        {
            label
            for c in api.containers(all=True, filters={"label": PROJECT_LABEL})
            if c["Id"] not in own and (label := (c.get("Labels") or {}).get(PROJECT_LABEL))
        }
    )


def own_health_wait(info: dict[str, Any]) -> float:
    """How long the container's own healthcheck may take to call it healthy: its start
    period, then its retries, each an interval plus a timeout (Docker's defaults where
    unset), at most MAX_HEALTH_WAIT."""
    check = (info.get("Config") or {}).get("Healthcheck") or {}

    def seconds(key: str, default: float) -> float:
        value = check.get(key)
        return value / 1e9 if isinstance(value, int) and value > 0 else default

    retries = check.get("Retries")
    retries = retries if isinstance(retries, int) and retries > 0 else 3
    wait = seconds("StartPeriod", 0) + (retries + 1) * (
        seconds("Interval", 30) + seconds("Timeout", 30)
    )
    return min(wait, MAX_HEALTH_WAIT)


def settled(
    api: Any,
    ids: list[str],
    cancel: threading.Event,
    log: Callable[[str], None],
    *,
    health_wait: float = HEALTH_WAIT,
    settle: float = SETTLE,
) -> None:
    """Blocking. Raises ApplyError unless every started container is sound: healthy within
    health_wait when it has a healthcheck, else running without a restart for settle
    seconds. The verify step of restore.apply, before the commit."""
    for container_id in ids:
        info = api.inspect_container(container_id)
        name = str(info.get("Name") or container_id[:12]).lstrip("/")
        if info.get("RestartCount"):
            raise ApplyError(f"Container {name} restarted after the update.")
        test = ((info.get("Config") or {}).get("Healthcheck") or {}).get("Test") or []
        if test and test[0] != "NONE":
            wait = max(health_wait, own_health_wait(info))
            log(f"Waiting up to {int(wait)} seconds for container {name} to be healthy.")
            deadline = time.monotonic() + wait
            while True:
                state = api.inspect_container(container_id).get("State") or {}
                health = (state.get("Health") or {}).get("Status")
                if not state.get("Running"):
                    raise ApplyError(f"Container {name} stopped after the update.")
                if health == "healthy":
                    break
                if health == "unhealthy":
                    raise ApplyError(f"Container {name} is unhealthy after the update.")
                if time.monotonic() >= deadline:
                    raise ApplyError(f"Container {name} was not healthy in time.")
                if cancel.wait(POLL):
                    return  # the caller's check_cancel stops the update
            if api.inspect_container(container_id).get("RestartCount"):
                raise ApplyError(f"Container {name} restarted after the update.")
            continue
        log(f"Watching container {name} for {int(settle)} seconds.")
        restarts = 0  # a new container: any restart since it started counts
        deadline = time.monotonic() + settle
        while time.monotonic() < deadline:
            if cancel.wait(min(POLL, max(0.0, deadline - time.monotonic()))):
                return
            now = api.inspect_container(container_id)
            state = now.get("State") or {}
            if not state.get("Running") or state.get("Restarting"):
                raise ApplyError(f"Container {name} stopped after the update.")
            if (now.get("RestartCount") or 0) != restarts:
                raise ApplyError(f"Container {name} restarted after the update.")
