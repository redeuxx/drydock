"""Helper containers: short-lived, locked-down containers that mount volumes for transfers.

A helper has no network, a read-only root filesystem, no capabilities and
no-new-privileges. Only three restore helpers add capabilities, each a fixed command: the
wipe helper exactly DAC_OVERRIDE and FOWNER (restore.apply.WIPE_CAPS), so find -delete can
empty directories owned by other uids, sticky ones included; a data helper, started after
its put, exactly CHOWN, FOWNER and FSETID (restore.apply.ROOT_CAPS), to give the top
directory it wrote the archived owner and mode; and the compose directory helper exactly
DAC_OVERRIDE (restore.apply.MKDIR_CAPS), whose fixed script (restore.apply.COMPOSE_SCRIPT)
runs mkdir -m 0700 without -p, so it creates one new directory and fails on any existing
path, and extracts the compose files from its own anonymous volume through its working
directory, the checked new directory. A helper carries the labels
drydock.helper=1 and drydock.instance=<this installation's ID>, so the reaper never
touches another drydock's helpers on a shared daemon. It is removed in a finally block;
anything left behind by a crash is removed by the reaper at startup, and the reaper runs
again every hour (jobs.scheduler). Each helper's name is registered in this process from
before it is created until after it is removed, and the reaper skips registered names, so
it never removes a helper a run is still using.

Blocking (docker-py). Call from async code through hosts.client.run_blocking.
"""

import contextlib
import logging
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import docker
import docker.errors
import docker.types
import docker.utils
import requests
from docker.models.containers import Container

log = logging.getLogger("drydock.hosts.helper")

HELPER_LABEL = "drydock.helper"
INSTANCE_LABEL = "drydock.instance"
PIDS_LIMIT = 64
NAME_PREFIX = "drydock-helper-"

_live: set[str] = set()  # names of this process's helpers, created or about to be
_live_lock = threading.Lock()


def helper_labels(instance_id: str) -> dict[str, str]:
    return {HELPER_LABEL: "1", INSTANCE_LABEL: instance_id}


def is_helper(labels: dict[str, str], instance_id: str) -> bool:
    """True only for this installation's helpers."""
    return all(labels.get(k) == v for k, v in helper_labels(instance_id).items())


def ensure_image(client: docker.DockerClient, image: str) -> None:
    """Pulls the digest-pinned image when the host does not have it yet."""
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        log.info("Pulling helper image %s", image)
        client.images.pull(image)


def helper_options(
    image: str,
    instance_id: str,
    command: list[str] | None = None,
    mounts: list[docker.types.Mount] | None = None,
    cap_add: list[str] | None = None,
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "image": image,
        "command": command,
        "labels": helper_labels(instance_id),
        "mounts": mounts or [],
        "network_mode": "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": PIDS_LIMIT,
        "detach": True,
    }
    if cap_add:
        options["cap_add"] = list(cap_add)
    return options


@contextlib.contextmanager
def helper(
    client: docker.DockerClient,
    image: str,
    instance_id: str,
    command: list[str] | None = None,
    mounts: list[docker.types.Mount] | None = None,
    start: bool = False,
    cap_add: list[str] | None = None,
) -> Iterator[Container]:
    """Creates (and optionally starts) a helper, and always removes it afterwards."""
    ensure_image(client, image)
    # docker-py inspects the container right after creating it. The name lets the finally
    # block remove it even when that inspect fails and create() raises.
    name = f"{NAME_PREFIX}{uuid.uuid4().hex}"
    with _live_lock:
        _live.add(name)
    try:
        container = client.containers.create(
            name=name, **helper_options(image, instance_id, command, mounts, cap_add)
        )
        if start:
            container.start()
        yield container
    finally:
        try:
            remove(client, name)
        finally:
            with _live_lock:
                _live.discard(name)


@contextlib.contextmanager
def open_archive(
    box: Container, path: str, chunk_size: int
) -> Iterator[tuple[Iterator[bytes], dict[str, Any]]]:
    """GET /containers/{id}/archive as (chunks, path stat); the response is always closed.

    docker-py's get_archive leaves the response open when its body is not read to the end,
    and the daemon then keeps streaming and will not remove the helper until it stops (a
    cancelled run would hang). Uses docker-py's private _get, _url, _raise_for_status and
    _stream_raw_result, which docker==7.2.0 provides; tests/test_capture.py pins them.
    """
    api = box.client.api  # type: ignore[union-attr]
    response = api._get(
        api._url("/containers/{0}/archive", box.id),
        params={"path": path},
        stream=True,
        headers={"Accept-Encoding": "identity"},
    )
    try:
        api._raise_for_status(response)
        encoded = response.headers.get("x-docker-container-path-stat")
        stat = docker.utils.decode_json_header(encoded) if encoded else {}
        yield api._stream_raw_result(response, chunk_size, False), stat
    finally:
        response.close()


def remove(client: docker.DockerClient, container: str) -> bool:
    """Force-removes a helper (by ID or name) and its anonymous volumes. Never raises.
    True only when this call removed it."""
    try:
        client.api.remove_container(container, force=True, v=True)
    except docker.errors.NotFound:
        return False
    except (docker.errors.DockerException, requests.RequestException) as exc:
        log.warning("Could not remove helper %s (the reaper retries): %s", container, exc)
        return False
    return True


def reap(client: docker.DockerClient, instance_id: str) -> int:
    """Removes this installation's helpers that no helper() in this process is using.

    The live names are read after the listing: a helper is registered before it is created,
    so one the listing shows is either registered by then or already done with."""
    labels = [f"{key}={value}" for key, value in helper_labels(instance_id).items()]
    found = client.containers.list(all=True, sparse=True, filters={"label": labels})
    with _live_lock:
        live = set(_live)
    removed = 0
    for container in found:
        names = {name.lstrip("/") for name in container.attrs.get("Names") or []}
        if not names:
            log.warning("Helper %s was listed without a name; it is left alone", container.id)
            continue
        if names & live:
            continue
        removed += remove(client, container.id)
    return removed
