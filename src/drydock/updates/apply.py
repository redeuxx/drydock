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
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

import docker.errors
import docker.utils
import requests

from drydock.engine import stacks
from drydock.engine.capture import distribution_digest
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

HEALTH_WAIT = stacks.HEALTH_WAIT  # seconds a container with a healthcheck may take
SETTLE = 15  # seconds one without must keep running
POLL = 1.0
MAX_GRACE = 300


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


def plan_update(
    api: Any,
    host_id: int,
    container_ids: Iterable[str],
    own: frozenset[str],
    api_version: str,
) -> Planned:
    """Blocking. The plan that updates the containers that have a newer image, in the
    order given (a stack's: dependencies first). Raises UpdateError when a container
    cannot be updated at all (gone, drydock's own, a registry that cannot be asked)."""
    images: list[ImageStep] = []
    originals: list[Original] = []
    steps: list[ContainerStep] = []
    keys: set[str] = set()
    projects: set[str] = set()
    notes: list[str] = []
    warnings: list[str] = []
    changes: list[tuple[str, str, str]] = []
    pulls: dict[str, ImageStep] = {}  # one pull per reference
    for container_id in container_ids:
        try:
            info = api.inspect_container(container_id)
        except docker.errors.NotFound:
            raise UpdateError(f"Container {container_id[:12]} no longer exists.") from None
        name = str(info.get("Name", "")).lstrip("/")
        labels = (info.get("Config") or {}).get("Labels") or {}
        if info["Id"] in own:
            raise UpdateError(f"{name}: drydock does not update itself or its own project.")
        if labels.get(HELPER_LABEL):
            raise UpdateError(f"{name}: drydock's helper containers are left to drydock.")
        image = str((info.get("Config") or {}).get("Image") or "")
        ref = reference(image)
        if ref is None:
            notes.append(f"{name}: pinned by digest or image ID, so not updated.")
            continue
        old_image = image_info(api, str(info.get("Image") or ""))
        current = {digest for _, digest in repo_digests(old_image)}
        if not current:
            # Built on the host, or (containerd's image store) its tag was pulled anew,
            # which leaves this image nameless: only then does the tag name a pulled image.
            newer = image_info(api, ref)
            if not newer or newer.get("Id") == info.get("Image") or not repo_digests(newer):
                notes.append(f"{name}: built on the host (no registry digest), so not updated.")
                continue
        try:
            latest = distribution_digest(api, ref)
        except (docker.errors.DockerException, requests.RequestException) as exc:
            raise UpdateError(f"{name}: {lookup_error(exc)}") from None
        except ValueError, KeyError, TypeError:
            raise UpdateError(f"{name}: the registry answer was not understood.") from None
        if latest in current:
            notes.append(f"{name}: already runs the newest {ref}.")
            continue
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
        state = info.get("State") or {}
        grace = (info.get("Config") or {}).get("StopTimeout")
        grace = grace if isinstance(grace, int) and 0 <= grace <= MAX_GRACE else 10
        originals.append(
            Original(
                id=info["Id"],
                name=name,
                old_name=name + OLD_SUFFIX,
                running=bool(state.get("Running")),
                stop_timeout=grace,
            )
        )
        try:
            body = container_body(
                info,
                names=identity(info),
                mode="overwrite",
                api_version=api_version,
                bind_map={},
                warnings=warnings,
            )
        except PlanError as exc:
            raise UpdateError(f"{name}: {exc}") from None
        body = without_image_defaults(body, old_image)
        steps.append(
            ContainerStep(
                name=name,
                body=body,
                start=bool(state.get("Running")) or state.get("Status") == "restarting",
                # Created from the reference as it was given (the pull has moved its tag),
                # not the image ID: the new container is still checked for updates, and
                # reads like the old one in docker ps.
                image_entry=None,
            )
        )
        # The tag too: two updates of one image never move it at once.
        keys |= {info["Id"], f"name:{host_id}:container:{name}", f"name:{host_id}:image:{ref}"}
        if labels.get(PROJECT_LABEL):
            project = str(labels[PROJECT_LABEL])
            projects.add(project)
            keys.add(f"name:{host_id}:project:{project}")
        own_repo = [d for r, d in repo_digests(old_image) if r == repository]
        old = (own_repo or sorted(current) or [""])[0]
        changes.append((name, old, latest))
    if not steps:
        return Planned(None, tuple(notes), ())
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
            log(f"Waiting for container {name} to be healthy.")
            deadline = time.monotonic() + health_wait
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
