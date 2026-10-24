"""Compose files named by a container's labels, read from the Docker host.

Only these files are read: every path in the config_files and environment_file labels,
working_dir/.env, and the service's env_file entries in the captured config files
(Compose sets no label for env_file). Each must be a regular file of at most 1 MiB, at
most MAX_FILES are read per capture and at most MAX_TOTAL_BYTES in all; anything else is
skipped and logged, never fatal. Labels are set by whoever created the container (or
inherited from its image, which capture filters out), so system locations are refused.

Files are read with get_archive from a created (never started) helper that binds the
parent directory read-only. The daemon reads the file, so ownership and modes on the host
do not matter and the helper needs no capabilities.

Blocking (docker-py). Call from async code through hosts.client.run_blocking.
"""

import io
import posixpath
import tarfile
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import docker
import docker.errors
import requests
import yaml
from docker.types import Mount

from drydock.hosts import helper

CONFIG_FILES_LABEL = "com.docker.compose.project.config_files"
ENVIRONMENT_FILE_LABEL = "com.docker.compose.project.environment_file"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 64  # per capture; each distinct directory costs one helper
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PATH = 4096
# Never backed up as bind mount data: pseudo-filesystems and Docker's own storage.
SYSTEM_PREFIXES = ("/proc", "/sys", "/dev", "/var/lib/docker", "/var/lib/containerd")
# Compose files are never read from these either, nor from any .ssh or .gnupg directory.
DENIED_PREFIXES = (*SYSTEM_PREFIXES, "/etc", "/boot")
DENIED_PARTS = (".ssh", ".gnupg")
SafeLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
MOUNT = "/c"
# Go os.FileMode type bits, as the daemon reports them in the archive stat header.
GO_MODE_TYPE = (1 << 31) | (1 << 27) | (1 << 26) | (1 << 25) | (1 << 24) | (1 << 21) | (1 << 19)


@dataclass(frozen=True)
class ComposeRef:
    role: str  # config_file, environment_file, dotenv or env_file
    host_path: str


@dataclass(frozen=True)
class CapturedFile:
    ref: ComposeRef
    data: bytes


@dataclass(frozen=True)
class SkippedFile:
    ref: ComposeRef
    reason: str


def split_paths(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def referenced_files(labels: dict[str, str]) -> list[ComposeRef]:
    """The files a container's compose labels name, without duplicates, in label order."""
    refs = [ComposeRef("config_file", p) for p in split_paths(labels.get(CONFIG_FILES_LABEL))]
    refs += [
        ComposeRef("environment_file", p) for p in split_paths(labels.get(ENVIRONMENT_FILE_LABEL))
    ]
    working_dir = (labels.get(WORKING_DIR_LABEL) or "").strip()
    if working_dir:
        refs.append(ComposeRef("dotenv", posixpath.join(working_dir, ".env")))
    seen: set[str] = set()
    unique = []
    for ref in refs:
        if ref.host_path not in seen:
            seen.add(ref.host_path)
            unique.append(ref)
    return unique


def under(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def system_path(path: str) -> bool:
    """True for / itself and anything under a pseudo-filesystem or Docker's storage."""
    normalized = posixpath.normpath(path)
    return normalized == "/" or under(normalized, SYSTEM_PREFIXES)


def path_problem(path: str) -> str | None:
    """Why a compose file path is refused, or None."""
    if len(path) > MAX_PATH or "\0" in path:
        return "invalid path"
    if not path.startswith("/") or posixpath.normpath(path) != path:
        return "not an absolute, normalized host path"
    parent = posixpath.dirname(path)
    if (
        parent == "/"
        or under(parent, DENIED_PREFIXES)
        or any(part in DENIED_PARTS for part in path.split("/"))
    ):
        return "refused location"
    return None


# ENV_FILE ENTRIES AND ENV VALUES


def env_file_refs(
    config: bytes, service: str, base_dir: str
) -> tuple[list[ComposeRef], list[SkippedFile]]:
    """The env_file entries of one service in one compose file, resolved against base_dir
    (the project directory, which Compose resolves relative paths against)."""
    try:
        document = yaml.load(config, Loader=SafeLoader)  # noqa: S506 (a safe loader)
    except yaml.YAMLError, RecursionError:
        return [], []
    services = document.get("services") if isinstance(document, dict) else None
    entry = services.get(service) if isinstance(services, dict) else None
    value: Any = entry.get("env_file") if isinstance(entry, dict) else None
    items = value if isinstance(value, list) else [value] if value is not None else []
    refs: list[ComposeRef] = []
    skipped: list[SkippedFile] = []
    for item in items[:MAX_FILES]:
        path = item.get("path") if isinstance(item, dict) else item
        if not isinstance(path, str) or not path.strip():
            continue
        if "$" in path:
            skipped.append(SkippedFile(ComposeRef("env_file", path), "uses a variable"))
            continue
        resolved = posixpath.normpath(posixpath.join(base_dir, path.strip()))
        refs.append(ComposeRef("env_file", resolved))
    return refs, skipped


def dotenv_values(data: bytes) -> list[str]:
    """The values in an env file ("KEY=value" lines), quoted and unquoted, for redaction."""
    values = []
    for raw in data.decode(errors="replace").splitlines():
        line = raw.strip().removeprefix("export ").strip()
        if line.startswith("#") or "=" not in line:
            continue
        value = line.split("=", 1)[1].strip()
        values.append(value)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            values.append(value[1:-1])
    return values


# READING


def read_files(
    client: docker.DockerClient,
    image: str,
    instance_id: str,
    refs: list[ComposeRef],
    log: Callable[[str], None],
    budget: list[int],
) -> tuple[list[CapturedFile], list[SkippedFile]]:
    """Reads refs. budget holds the files and bytes still allowed and is updated."""
    captured: list[CapturedFile] = []
    skipped: list[SkippedFile] = []

    def skip(ref: ComposeRef, reason: str) -> None:
        log(f"Skipped compose file {ref.host_path}: {reason}.")
        skipped.append(SkippedFile(ref, reason))

    by_parent: dict[str, list[ComposeRef]] = {}
    for ref in refs:
        problem = path_problem(ref.host_path)
        if problem is None and budget[0] <= 0:
            problem = f"more than {MAX_FILES} compose files"
        if problem:
            skip(ref, problem)
        else:
            budget[0] -= 1
            by_parent.setdefault(posixpath.dirname(ref.host_path), []).append(ref)
    results: dict[str, CapturedFile | SkippedFile] = {}
    for parent, group in by_parent.items():
        mounts = [Mount(MOUNT, parent, type="bind", read_only=True)]
        try:
            with helper.helper(client, image, instance_id, mounts=mounts) as box:
                for ref in group:
                    results[ref.host_path] = read_one(box, ref)
        except docker.errors.DockerException, requests.RequestException:
            # Typically the directory no longer exists on the host.
            for ref in group:
                results.setdefault(ref.host_path, SkippedFile(ref, "directory not readable"))
    for ref in refs:
        result = results.get(ref.host_path)
        if isinstance(result, CapturedFile):
            if len(result.data) > budget[1]:
                skip(ref, f"compose files over {MAX_TOTAL_BYTES // 2**20} MiB in total")
                continue
            budget[1] -= len(result.data)
            captured.append(result)
        elif isinstance(result, SkippedFile):
            skip(ref, result.reason)
    return captured, skipped


def read_one(box, ref: ComposeRef) -> CapturedFile | SkippedFile:
    name = posixpath.basename(ref.host_path)
    try:
        with helper.open_archive(box, f"{MOUNT}/{name}", 64 * 1024) as (stream, stat):
            return parse_one(ref, stream, stat)
    except docker.errors.NotFound:
        return SkippedFile(ref, "not found")
    except docker.errors.DockerException, requests.RequestException:
        return SkippedFile(ref, "not readable")


def parse_one(ref: ComposeRef, stream, stat: dict) -> CapturedFile | SkippedFile:
    mode = int(stat.get("mode", 0))
    if mode & GO_MODE_TYPE:
        return SkippedFile(ref, "not a regular file")
    if int(stat.get("size", 0)) > MAX_FILE_BYTES:
        return SkippedFile(ref, "larger than 1 MiB")
    # One member of at most 1 MiB plus tar headers and padding.
    buffer = bytearray()
    for chunk in stream:
        buffer += chunk
        if len(buffer) > MAX_FILE_BYTES + 64 * 1024:
            return SkippedFile(ref, "larger than 1 MiB")
    with tarfile.open(fileobj=io.BytesIO(bytes(buffer)), mode="r:") as tar:
        members = tar.getmembers()
        if len(members) != 1 or not members[0].isreg():
            return SkippedFile(ref, "not a regular file")
        if members[0].size > MAX_FILE_BYTES:
            return SkippedFile(ref, "larger than 1 MiB")
        source = tar.extractfile(members[0])
        if source is None:
            return SkippedFile(ref, "not a regular file")
        return CapturedFile(ref, source.read())
