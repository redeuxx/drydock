"""Capture: turns containers on a Docker host into one archive.

Scopes and the members they produce:
- config: config/containers/<id>.json, config/images/<id>.json, config/networks/<id>.json
  (non-default networks), config/volumes/<name>.json, and compose/<n>/<file> for
  compose-managed containers.
- data: volumes/<name>.tar and binds/<n>.tar.
- image: images/<id>.tar.
- all: everything above. With images_reference_only_if_pullable, an image is recorded by
  reference and digest only when its registry confirms it still holds that exact digest
  (GET /distribution/<repo>@<digest>/json returns the same digest). RepoDigests alone
  prove nothing: Docker 29's containerd store gives local builds one too. Any error,
  timeout or mismatch saves the image.
The manifest always describes every container, network, volume, bind and image, and
says which members hold what. tmpfs mounts are never captured; they are recorded. Nor
is the data of a bind of /, a pseudo-filesystem or Docker's own storage.

Everything that needs no stopped container (inspect, compose files, registry lookups)
happens first; before_data (the dispatcher runs pre-hooks and stops or pauses the
containers there) runs just before the first data member, and after_data (where they
run again) right after the last one, before the images, so containers stay down only
while their data is read.

Volume and bind data come from get_archive on one created (never started) helper that
mounts them all read-only, so the daemon reads every file whatever its owner and mode,
and the helper keeps CapDrop=ALL. Volumes and directory binds are requested as
"<mount>/.", so members are named "./..." relative to the root. A file bind holds one
member named after its mount point, b<n>.

Images are exported with the raw /images/get endpoint, with ?platform= on API 1.48 and
later (docker-py has no public parameter for it), once per image ID.

Blocking (docker-py). Run on a worker thread.
"""

import contextlib
import hashlib
import importlib.metadata
import io
import json
import re
import tarfile
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import docker
import docker.errors
import requests
from docker.types import Mount

from drydock.archive import manifest as m
from drydock.archive.writer import ArchiveResult, ArchiveWriter, Cancelled
from drydock.crypto import Crypto
from drydock.engine import compose_files
from drydock.hosts import helper
from drydock.hosts.client import DockerHandle, api_tuple
from drydock.hosts.inventory import PROJECT_LABEL, SERVICE_LABEL

COMPOSE_LABEL_PREFIX = "com.docker.compose."

DATA_CHUNK = 1024 * 1024  # get_archive and image chunks; cancellation is checked between them
DEFAULT_NETWORKS = {"bridge", "host", "none", "default"}
SAFE_STEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}")
PLATFORM_API = (1, 48)
GO_MODE_DIR = 1 << 31
# Each registry lookup runs after the containers are stopped; keep a slow registry short.
DISTRIBUTION_TIMEOUT = 10
REPO_DIGEST_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]{0,254}@(sha256:[0-9a-f]{64})")
SCOPE_PARTS = {
    "config": {"config"},
    "data": {"data"},
    "image": {"image"},
    "all": {"config", "data", "image"},
}

Log = Callable[[str], None]


class CaptureError(Exception):
    """The capture cannot proceed. The message is safe to show."""


@dataclass(frozen=True)
class CaptureJob:
    uuid: str
    name: str
    scope: m.Scope
    consistency_mode: str = "stop"
    images_reference_only_if_pullable: bool = False
    encrypted: bool = False
    target_type: str = "container"
    project: str | None = None
    skip_mounts: frozenset[str] = frozenset()  # "bind:<host path>" or "volume:<name>"


@dataclass(frozen=True)
class CaptureEnv:
    handle: DockerHandle
    host_name: str
    helper_image: str
    instance_id: str
    staging_dir: Path
    crypto: Crypto


@dataclass
class Plan:
    """Everything known before the first byte is written."""

    containers: list[dict[str, Any]] = field(default_factory=list)
    images: dict[str, dict[str, Any] | None] = field(default_factory=dict)  # by image ID
    image_refs: dict[str, list[str]] = field(default_factory=dict)
    networks: dict[str, dict[str, Any]] = field(default_factory=dict)  # by network ID
    volumes: dict[str, dict[str, Any]] = field(default_factory=dict)  # by name
    volume_mounts: dict[str, list[m.MountRef]] = field(default_factory=dict)
    binds: dict[str, list[m.MountRef]] = field(default_factory=dict)  # by host path
    refused_binds: dict[str, str] = field(default_factory=dict)  # host path: reason
    skipped_volumes: dict[str, str] = field(default_factory=dict)  # name: reason
    tmpfs: list[m.TmpfsMount] = field(default_factory=list)
    compose: list[compose_files.CapturedFile] = field(default_factory=list)
    compose_skipped: list[compose_files.SkippedFile] = field(default_factory=list)
    secret_values: list[str] = field(default_factory=list)  # from captured env files


def drydock_version() -> str:
    try:
        return importlib.metadata.version("drydock")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def stem(name: str) -> str:
    """A member-safe stem for a Docker-provided name (volume names follow Docker's rules)."""
    if SAFE_STEM.fullmatch(name) and ".." not in name:
        return name
    return hashlib.sha256(name.encode()).hexdigest()


def hex_id(value: str) -> str:
    digest = value.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CaptureError(f"Unexpected image ID {value!r}.")
    return digest


def as_json(document: object) -> bytes:
    return json.dumps(document, indent=2, sort_keys=True).encode()


# PLANNING


def inspect_targets(env: CaptureEnv, refs: list[str], parts: set[str], log: Log) -> Plan:
    api = env.handle.client.api
    plan = Plan()
    seen: set[str] = set()
    for ref in refs:
        try:
            container = api.inspect_container(ref)
        except docker.errors.NotFound:
            raise CaptureError(f"Container {ref} does not exist on this host.") from None
        if helper.is_helper(container["Config"].get("Labels") or {}, env.instance_id):
            raise CaptureError("Drydock helper containers cannot be backed up.")
        if container["Id"] in seen:
            continue
        seen.add(container["Id"])
        plan.containers.append(container)
        add_image(api, plan, container)
        add_networks(api, plan, container, log)
        add_mounts(api, plan, container, log)
    if "config" in parts:
        add_compose_files(env, plan, log)
    return plan


def add_image(api, plan: Plan, container: dict[str, Any]) -> None:
    image_id = container["Image"]
    if image_id not in plan.images:
        try:
            plan.images[image_id] = api.inspect_image(image_id)
        except docker.errors.NotFound:
            plan.images[image_id] = None
        plan.image_refs[image_id] = []
    ref = container["Config"].get("Image") or ""
    if ref and ref != image_id and ref not in plan.image_refs[image_id]:
        plan.image_refs[image_id].append(ref)


def add_networks(api, plan: Plan, container: dict[str, Any], log: Log) -> None:
    endpoints = (container.get("NetworkSettings") or {}).get("Networks") or {}
    for name, endpoint in sorted(endpoints.items()):
        if name in DEFAULT_NETWORKS:
            continue
        # A created, never started container has no NetworkID yet; look it up by name.
        try:
            network = api.inspect_network((endpoint or {}).get("NetworkID") or name)
        except docker.errors.NotFound:
            log(f"Skipped network {name}: it no longer exists on the host.")
            continue
        plan.networks.setdefault(network["Id"], network)


SKIPPED_BY_JOB = "the job skips it"


def skip_mounts(plan: Plan, keys: frozenset[str]) -> None:
    """Marks the mounts the job skips. A system path keeps its own reason; a key that
    names no mount of these containers does nothing."""
    for source in plan.binds:
        if f"bind:{source}" in keys and source not in plan.refused_binds:
            plan.refused_binds[source] = SKIPPED_BY_JOB
    for name in plan.volumes:
        if f"volume:{name}" in keys:
            plan.skipped_volumes[name] = SKIPPED_BY_JOB


def add_mounts(api, plan: Plan, container: dict[str, Any], log: Log) -> None:
    container_id = container["Id"]
    name = container["Name"].lstrip("/")
    for mount in container.get("Mounts") or []:
        kind = mount.get("Type")
        ref = m.MountRef(
            container=container_id,
            destination=mount.get("Destination", ""),
            read_only=not mount.get("RW", True),
        )
        if kind == "volume":
            volume = mount["Name"]
            if volume not in plan.volumes:
                plan.volumes[volume] = api.inspect_volume(volume)
            plan.volume_mounts.setdefault(volume, []).append(ref)
        elif kind == "bind":
            source = mount["Source"]
            plan.binds.setdefault(source, []).append(ref)
            if compose_files.system_path(source):
                plan.refused_binds[source] = "a system path"
        elif kind == "tmpfs":
            plan.tmpfs.append(m.TmpfsMount(container=container_id, destination=ref.destination))
            log(f"Skipped tmpfs mount {ref.destination} of {name}: tmpfs is never backed up.")
        else:
            log(f"Skipped {kind} mount {ref.destination} of {name}: not supported.")
    # --tmpfs mounts appear only in HostConfig.Tmpfs, not in Mounts.
    for destination in sorted((container.get("HostConfig") or {}).get("Tmpfs") or {}):
        if not any(
            t.container == container_id and t.destination == destination for t in plan.tmpfs
        ):
            plan.tmpfs.append(m.TmpfsMount(container=container_id, destination=destination))
            log(f"Skipped tmpfs mount {destination} of {name}: tmpfs is never backed up.")


def compose_labels(container: dict[str, Any], image: dict[str, Any] | None, log: Log) -> dict:
    """The container's Compose labels, without any it inherits from its image.

    Docker merges image labels into the container's, and Compose sets these labels only
    on containers, so a value equal to the image's came from whoever built the image.
    """
    labels = container["Config"].get("Labels") or {}
    inherited = ((image or {}).get("Config") or {}).get("Labels") or {}
    own = {}
    for key, value in labels.items():
        if not key.startswith(COMPOSE_LABEL_PREFIX):
            continue
        if inherited.get(key) == value:
            name = container["Name"].lstrip("/")
            log(f"Ignored the label {key} of {name}: it comes from its image.")
        else:
            own[key] = value
    return own


def add_compose_files(env: CaptureEnv, plan: Plan, log: Log) -> None:
    client = env.handle.client
    budget = [compose_files.MAX_FILES, compose_files.MAX_TOTAL_BYTES]
    per_container: list[tuple[dict[str, str], list[compose_files.ComposeRef]]] = []
    refs: list[compose_files.ComposeRef] = []
    for container in plan.containers:
        labels = compose_labels(container, plan.images.get(container["Image"]), log)
        if PROJECT_LABEL not in labels:
            continue
        own = compose_files.referenced_files(labels)
        per_container.append((labels, own))
        refs += [r for r in own if all(r.host_path != known.host_path for known in refs)]
    if not refs:
        return
    plan.compose, plan.compose_skipped = compose_files.read_files(
        client, env.helper_image, env.instance_id, refs, log, budget
    )
    # A service's env_file entries are named only inside its compose files.
    by_path = {c.ref.host_path: c.data for c in plan.compose}
    env_refs: list[compose_files.ComposeRef] = []
    for labels, own in per_container:
        service = labels.get(SERVICE_LABEL) or ""
        base = (labels.get(compose_files.WORKING_DIR_LABEL) or "").strip()
        for ref in own:
            if ref.role != "config_file" or ref.host_path not in by_path:
                continue
            found, skipped = compose_files.env_file_refs(
                by_path[ref.host_path], service, base or ref.host_path.rsplit("/", 1)[0]
            )
            for item in skipped:
                log(f"Skipped compose file {item.ref.host_path}: {item.reason}.")
            plan.compose_skipped += skipped
            env_refs += [
                r
                for r in found
                if r.host_path not in by_path
                and all(r.host_path != known.host_path for known in env_refs + refs)
            ]
    if env_refs:
        captured, skipped = compose_files.read_files(
            client, env.helper_image, env.instance_id, env_refs, log, budget
        )
        plan.compose += captured
        plan.compose_skipped += skipped
    for captured_file in plan.compose:
        if captured_file.ref.role != "config_file":
            plan.secret_values += compose_files.dotenv_values(captured_file.data)


# MANIFEST


def registry_confirms(api, digests: list[str], cancel: threading.Event) -> tuple[str | None, str]:
    """The first RepoDigest whose registry still serves exactly that digest, or None and why.

    Asks the daemon for GET /distribution/<repo>@<digest>/json (the socket proxy allows
    only this read-only lookup). Uses docker-py's private _get, _url and _result for the
    timeout, like image_stream.
    """
    reason = "it has no registry digest"
    for repo_digest in digests:
        if cancel.is_set():
            break
        match = REPO_DIGEST_RE.fullmatch(repo_digest)
        if match is None:
            reason = "its registry digest is malformed"
            continue
        try:
            response = api._get(
                api._url("/distribution/{0}/json", repo_digest), timeout=DISTRIBUTION_TIMEOUT
            )
            found = api._result(response, json=True)["Descriptor"]["digest"]
        except (docker.errors.DockerException, requests.RequestException) as exc:
            reason = f"the registry lookup failed ({type(exc).__name__})"
            continue
        except ValueError, KeyError, TypeError:
            reason = "the registry answer was not understood"
            continue
        if found == match.group(1):
            return repo_digest, "confirmed"
        reason = "the registry holds a different digest"
    return None, reason


def image_entries(
    api, plan: Plan, parts: set[str], job: CaptureJob, cancel: threading.Event, log: Log
) -> list[tuple[m.ImageEntry, dict[str, Any] | None]]:
    entries = []
    reference_only = job.scope == "all" and job.images_reference_only_if_pullable
    for image_id, inspect in plan.images.items():
        inspect = inspect or {}
        tags = [t for t in inspect.get("RepoTags") or [] if t != "<none>:<none>"]
        refs = [r for r in plan.image_refs[image_id] if r in tags] + [
            t for t in tags if t not in plan.image_refs[image_id]
        ]
        refs = refs or list(plan.image_refs[image_id])
        digests = list(inspect.get("RepoDigests") or [])
        saved = bool(inspect) and "image" in parts
        confirmed = None
        if saved and reference_only:
            label = refs[0] if refs else image_id
            confirmed, reason = registry_confirms(api, digests, cancel)
            if confirmed is not None:
                saved = False
                log(f"Image {label}: the registry confirmed {confirmed}; stored by reference only.")
            else:
                log(f"Image {label} is saved in full: {reason}.")
        hex_digest = hex_id(image_id)
        entry = m.ImageEntry(
            id=image_id,
            refs=refs,
            repo_digests=digests,
            os=str(inspect.get("Os") or "unknown"),
            architecture=str(inspect.get("Architecture") or "unknown"),
            variant=inspect.get("Variant") or None,
            saved=saved,
            confirmed_digest=confirmed,
            config_member=(
                f"config/images/{hex_digest}.json" if "config" in parts and inspect else None
            ),
            data_member=f"images/{hex_digest}.tar" if saved else None,
        )
        entries.append((entry, inspect or None))
    return entries


def build_manifest(
    env: CaptureEnv,
    job: CaptureJob,
    plan: Plan,
    images: list[m.ImageEntry],
    bind_kinds: dict[str, str],
    created_at: datetime,
    bind_owners: dict[str, tuple[int, int, int]] | None = None,
) -> m.Manifest:
    parts = SCOPE_PARTS[job.scope]
    config = "config" in parts
    data = "data" in parts
    containers = []
    for container in plan.containers:
        labels = compose_labels(container, plan.images.get(container["Image"]), lambda _: None)
        containers.append(
            m.ContainerEntry(
                id=container["Id"],
                name=container["Name"].lstrip("/"),
                image=container["Config"].get("Image") or container["Image"],
                image_id=container["Image"],
                compose_project=labels.get(PROJECT_LABEL),
                compose_service=labels.get(SERVICE_LABEL),
                config_member=f"config/containers/{stem(container['Id'])}.json" if config else None,
            )
        )
    networks = [
        m.NetworkEntry(
            id=network_id,
            name=network["Name"],
            driver=network.get("Driver") or "",
            config_member=f"config/networks/{stem(network_id)}.json" if config else None,
        )
        for network_id, network in plan.networks.items()
    ]
    volumes = [
        m.VolumeEntry(
            name=name,
            driver=volume.get("Driver") or "local",
            mounts=plan.volume_mounts[name],
            config_member=f"config/volumes/{stem(name)}.json" if config else None,
            data_member=f"volumes/{stem(name)}.tar"
            if data and name not in plan.skipped_volumes
            else None,
            skipped=plan.skipped_volumes.get(name),
        )
        for name, volume in plan.volumes.items()
    ]
    binds = [
        m.BindEntry(
            n=n,
            source=source,
            kind=bind_kinds.get(source),  # type: ignore[arg-type]
            mounts=refs,
            data_member=f"binds/{n}.tar" if data and source not in plan.refused_binds else None,
            skipped=plan.refused_binds.get(source) if data else None,
            **owner_fields((bind_owners or {}).get(source)),
        )
        for n, (source, refs) in enumerate(plan.binds.items())
    ]
    compose = [
        m.ComposeFile(
            n=n,
            role=captured.ref.role,  # type: ignore[arg-type]
            host_path=captured.ref.host_path,
            member=f"compose/{n}/{compose_basename(captured.ref.host_path)}",
            size=len(captured.data),
        )
        for n, captured in enumerate(plan.compose)
    ]
    skipped = [
        m.SkippedFile(role=s.ref.role, host_path=s.ref.host_path, reason=s.reason)
        for s in plan.compose_skipped
    ]
    members = (
        [c.config_member for c in containers if c.config_member]
        + [i.config_member for i in images if i.config_member]
        + [n.config_member for n in networks if n.config_member]
        + [v.config_member for v in volumes if v.config_member]
        + [c.member for c in compose]
        + [v.data_member for v in volumes if v.data_member]
        + [b.data_member for b in binds if b.data_member]
        + [i.data_member for i in images if i.data_member]
    )
    info = env.handle
    return m.Manifest(
        instance_id=env.instance_id,
        drydock_version=drydock_version(),
        created_at=created_at,
        source=m.Source(
            host_name=env.host_name,
            arch=info.arch,
            os=info.os,
            api_version=info.api_version,
            engine_version=info.engine_version,
        ),
        job=m.JobInfo(
            uuid=job.uuid,
            name=job.name,
            scope=job.scope,
            consistency_mode=job.consistency_mode,  # type: ignore[arg-type]
            images_reference_only_if_pullable=job.images_reference_only_if_pullable,
            target_type=job.target_type,  # type: ignore[arg-type]
            project=job.project,
        ),
        containers=containers,
        networks=networks,
        volumes=volumes,
        binds=binds,
        images=images,
        compose_files=compose,
        skipped_compose_files=skipped,
        skipped_tmpfs=plan.tmpfs,
        encryption=(
            m.Encryption(method="age-scrypt", derivation="hkdf-job-uuid") if job.encrypted else None
        ),
        members=members,
    )


def compose_basename(host_path: str) -> str:
    name = host_path.rsplit("/", 1)[-1]
    if re.fullmatch(r"[A-Za-z0-9._-]{1,255}", name) and name not in (".", ".."):
        return name
    return "file"


# DATA STREAMS


def data_mounts(plan: Plan) -> list[Mount]:
    mounts = [
        Mount(f"/v{n}", name, type="volume", read_only=True)
        for n, name in enumerate(plan.volumes)
        if name not in plan.skipped_volumes
    ]
    mounts += [
        Mount(f"/b{n}", source, type="bind", read_only=True)
        for n, source in enumerate(plan.binds)
        if source not in plan.refused_binds
    ]
    return mounts


def owner_fields(owner: tuple[int, int, int] | None) -> dict[str, int]:
    if owner is None:
        return {}
    uid, gid, mode = owner
    return {"uid": uid, "gid": gid, "mode": mode}


OWNER_HEAD = 64 * 1024  # enough for a PAX header and the directory's own entry


def skipped_bind_owners(env: CaptureEnv, plan: Plan, log: Log) -> dict[str, tuple[int, int, int]]:
    """The owner and mode of each directory bind the job skips, read in a helper of its
    own: a skipped bind that is missing or unreadable must not fail the backup, so it
    only loses its owner (a restore then asks to create it by hand)."""
    owners: dict[str, tuple[int, int, int]] = {}
    client = env.handle.client
    for source, reason in plan.refused_binds.items():
        if reason != SKIPPED_BY_JOB:
            continue
        mount = Mount("/b0", source, type="bind", read_only=True)
        try:
            with helper.helper(client, env.helper_image, env.instance_id, mounts=[mount]) as box:
                owner = bind_owner(box, 0)
        except (CaptureError, docker.errors.DockerException, requests.RequestException) as exc:
            log(f"Could not read the owner of skipped bind mount {source}: {exc}")
            continue
        if owner is not None:
            owners[source] = owner
    return owners


def bind_owner(box, n: int) -> tuple[int, int, int] | None:
    """A bind's owner and mode when it is a directory (None for a file), from the first
    entry of its archive (the directory itself); the stream is closed after OWNER_HEAD
    bytes, so nothing below it is read. The setuid bit is dropped."""
    head = b""
    with helper.open_archive(box, f"/b{n}", DATA_CHUNK) as (chunks, _stat):
        for chunk in chunks:
            head += chunk
            if len(head) >= OWNER_HEAD:
                break
    try:
        with tarfile.open(fileobj=io.BytesIO(head[:OWNER_HEAD]), mode="r|") as tar:
            first = tar.next()
    except tarfile.TarError:
        first = None
    if first is None:
        raise CaptureError(f"Bind mount {n}: the daemon reported nothing.")
    if not first.isdir():
        return None
    return first.uid, first.gid, first.mode & 0o3777


def bind_kind(box, n: int) -> str:
    """dir or file, from the daemon's stat header (the body is never read)."""
    try:
        with helper.open_archive(box, f"/b{n}", DATA_CHUNK) as (_, stat):
            return "dir" if int(stat.get("mode", 0)) & GO_MODE_DIR else "file"
    except docker.errors.NotFound:
        raise CaptureError(f"Bind mount {n} cannot be read on the host.") from None


def archive_stream(box, path: str) -> Iterator[bytes]:
    with helper.open_archive(box, path, DATA_CHUNK) as (chunks, _stat):
        yield from chunks


def image_stream(api, entry: m.ImageEntry, api_version: str) -> Iterator[bytes]:
    """docker save of one image (all its refs), for one platform on API 1.48 and later.

    Uses docker-py's private _get, _url, _raise_for_status and _stream_raw_result, which
    docker==7.2.0 provides; tests/test_capture.py pins that behaviour.
    """
    # Tags keep their names in the export; an untagged image is saved by ID.
    names = [ref for ref in entry.refs if "@" not in ref] or [entry.id]
    params: dict[str, Any] = {"names": names}
    if api_tuple(api_version) >= PLATFORM_API:
        platform = {"os": entry.os, "architecture": entry.architecture}
        if entry.variant:
            platform["variant"] = entry.variant
        params["platform"] = json.dumps(platform, separators=(",", ":"))
    response = api._get(api._url("/images/get"), params=params, stream=True)
    try:
        api._raise_for_status(response)
        yield from api._stream_raw_result(response, DATA_CHUNK, False)
    finally:
        response.close()


# CAPTURE


def capture(
    env: CaptureEnv,
    job: CaptureJob,
    containers: list[str],
    out_path: Path,
    *,
    cancel: threading.Event,
    log: Log,
    created_at: datetime | None = None,
    before_data: Callable[[], None] | None = None,
    after_data: Callable[[], None] | None = None,
    on_abort: Callable[[], None] | None = None,
    secrets: Callable[[list[str]], None] | None = None,
) -> tuple[m.Manifest, ArchiveResult]:
    """Writes the archive for containers to out_path. Raises CaptureError, ArchiveError,
    docker.errors.DockerException or requests.RequestException on failure; nothing is
    left behind in that case (no output file, no staged member, no helper).

    before_data runs once everything else is known, just before the data is read, and
    after_data once the last volume and bind mount are written, before the images (which
    need nothing stopped or paused).
    secrets receives the values of captured env files, so the caller can redact them.

    On failure on_abort runs after the output is gone but before the helper is removed:
    a daemon can take many seconds to release a helper whose archive stream was cut off
    (Docker Desktop finishes reading the volume first), and the caller should not keep
    stopped containers waiting for that."""
    if job.scope not in SCOPE_PARTS:
        raise CaptureError(f"Unknown scope {job.scope!r}.")
    uuid.UUID(job.uuid)
    created_at = created_at or datetime.now(UTC)
    parts = SCOPE_PARTS[job.scope]
    client = env.handle.client
    plan = inspect_targets(env, containers, parts, log)
    if secrets is not None:
        secrets(plan.secret_values)
    if "data" in parts:
        skip_mounts(plan, job.skip_mounts)
        for source, reason in plan.refused_binds.items():
            if reason == SKIPPED_BY_JOB:
                log(f"Skipped the data of bind mount {source}: the job skips it.")
            else:
                log(f"Skipped the data of bind mount {source}: a system path is never backed up.")
        for name in plan.skipped_volumes:
            log(f"Skipped the data of volume {name}: the job skips it.")
    images = image_entries(client.api, plan, parts, job, cancel, log)
    if cancel.is_set():
        raise Cancelled("The run was cancelled.")
    if before_data is not None:
        before_data()
        if cancel.is_set():
            raise Cancelled("The run was cancelled.")
    needs_helper = "data" in parts and bool(
        set(plan.volumes) - set(plan.skipped_volumes) or set(plan.binds) - set(plan.refused_binds)
    )
    bind_owners = skipped_bind_owners(env, plan, log) if "data" in parts else {}
    with contextlib.ExitStack() as stack:
        box = None
        if needs_helper:
            box = stack.enter_context(
                helper.helper(client, env.helper_image, env.instance_id, mounts=data_mounts(plan))
            )
        try:
            bind_kinds = (
                {
                    source: bind_kind(box, n)
                    for n, source in enumerate(plan.binds)
                    if source not in plan.refused_binds
                }
                if box
                else {}
            )
            bind_kinds |= {source: "dir" for source in bind_owners}
            manifest = build_manifest(
                env,
                job,
                plan,
                [entry for entry, _ in images],
                bind_kinds,
                created_at,
                bind_owners,
            )
            passphrase = env.crypto.job_passphrase(uuid.UUID(job.uuid)) if job.encrypted else None
            with ArchiveWriter(
                out_path,
                env.staging_dir,
                env.crypto,
                mtime=int(created_at.timestamp()),
                passphrase=passphrase,
                cancel=cancel,
            ) as writer:
                writer.add_manifest(manifest)
                write_members(writer, env, plan, manifest, images, box, log, after_data)
                result = writer.close()
        except BaseException:
            if on_abort is not None:
                on_abort()
            raise
    log(f"Archive written: {result.size} bytes, {len(result.members) + 1} members.")
    return manifest, result


def write_members(
    writer: ArchiveWriter,
    env: CaptureEnv,
    plan: Plan,
    manifest: m.Manifest,
    images: list[tuple[m.ImageEntry, dict[str, Any] | None]],
    box,
    log: Log,
    after_data: Callable[[], None] | None = None,
) -> None:
    by_id = {c["Id"]: c for c in plan.containers}
    for entry in manifest.containers:
        if entry.config_member:
            writer.add_bytes(entry.config_member, as_json(by_id[entry.id]))
    for entry, inspect in images:
        if entry.config_member:
            writer.add_bytes(entry.config_member, as_json(inspect))
    for entry in manifest.networks:
        if entry.config_member:
            writer.add_bytes(entry.config_member, as_json(plan.networks[entry.id]))
    for entry in manifest.volumes:
        if entry.config_member:
            writer.add_bytes(entry.config_member, as_json(plan.volumes[entry.name]))
    for entry, captured in zip(manifest.compose_files, plan.compose, strict=True):
        writer.add_bytes(entry.member, captured.data)
    for n, entry in enumerate(manifest.volumes):
        if entry.data_member:
            log(f"Saving volume {entry.name}.")
            with contextlib.closing(archive_stream(box, f"/v{n}/.")) as chunks:
                writer.add_stream(entry.data_member, chunks)
    for entry in manifest.binds:
        if entry.data_member:
            log(f"Saving bind mount {entry.source}.")
            path = f"/b{entry.n}/." if entry.kind == "dir" else f"/b{entry.n}"
            with contextlib.closing(archive_stream(box, path)) as chunks:
                writer.add_stream(entry.data_member, chunks)
    if after_data is not None:
        # The data is read: images never change while a container runs, so the containers
        # stopped or paused for the data need not wait for the images.
        after_data()
    api = env.handle.client.api
    for entry, _ in images:
        if entry.data_member:
            log(f"Saving image {entry.refs[0] if entry.refs else entry.id}.")
            with contextlib.closing(image_stream(api, entry, env.handle.api_version)) as chunks:
                writer.add_stream(entry.data_member, chunks)
