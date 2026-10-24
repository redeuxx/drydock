"""Volume round-trip probe: the Phase 1 spike behind capture and restore. Used only by tests.

export_volume streams a volume out of a helper with get_archive into a staging file, and
import_volume streams that file into another volume with put_archive. Both are timed.
The Docker daemon reads and writes the files itself, so ownership, modes, symlinks and
empty directories survive, and the helper needs no capabilities and is never started.

Asking for "/v/." makes the daemon name the members relative to the volume root ("./x"),
so the archive extracts straight into any volume mounted at /v. put_archive must target
the volume itself: the daemon refuses to extract onto a helper's read-only root.

Blocking (docker-py). Call from async code through hosts.client.run_blocking.
"""

import hashlib
import io
import os
import tarfile
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import docker
from docker.types import Mount

from drydock.hosts import helper

MOUNT = "/v"
CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Transfer:
    size: int
    seconds: float

    @property
    def mib_per_s(self) -> float:
        return self.size / (1024 * 1024) / max(self.seconds, 1e-9)


@dataclass(frozen=True)
class Entry:
    """What a round trip must preserve for one archive member."""

    type: bytes  # tarfile.REGTYPE, DIRTYPE, SYMTYPE, ...
    uid: int
    gid: int
    mode: int
    size: int
    linkname: str
    sha256: str | None


# STAGING


def staging_file(staging_dir: Path) -> Path:
    """A fresh, server-named path in the staging directory (created 0700)."""
    staging_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return staging_dir / f"probe-{uuid.uuid4().hex}.tar"


def write_new(path: Path, chunks: Iterable[bytes]) -> int:
    """Writes to a file that must not exist yet (no symlink games), mode 0600."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    size = 0
    with os.fdopen(os.open(path, flags, 0o600), "wb") as out:
        for chunk in chunks:
            out.write(chunk)
            size += len(chunk)
    return size


def read_chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as source:
        while chunk := source.read(CHUNK):
            yield chunk


# TRANSFERS


def volume_mount(volume: str, read_only: bool) -> list[Mount]:
    return [Mount(MOUNT, volume, type="volume", read_only=read_only)]


def export_volume(
    client: docker.DockerClient, image: str, instance_id: str, volume: str, dest: Path
) -> Transfer:
    """get_archive of the whole volume into dest."""
    mounts = volume_mount(volume, read_only=True)
    with helper.helper(client, image, instance_id, mounts=mounts) as box:
        start = time.monotonic()
        stream, _stat = box.get_archive(f"{MOUNT}/.", chunk_size=CHUNK)
        size = write_new(dest, stream)
        return Transfer(size, time.monotonic() - start)


def import_volume(
    client: docker.DockerClient, image: str, instance_id: str, source: Path, volume: str
) -> Transfer:
    """put_archive of source into the (existing, normally empty) volume."""
    size = source.stat().st_size
    mounts = volume_mount(volume, read_only=False)
    with helper.helper(client, image, instance_id, mounts=mounts) as box:
        start = time.monotonic()
        # A generator is sent with chunked encoding in 1 MiB writes, not 16 KiB ones.
        if not box.put_archive(MOUNT, read_chunks(source)):
            raise RuntimeError(f"put_archive into volume {volume} failed")
        return Transfer(size, time.monotonic() - start)


# VERIFICATION


class ChunkReader(io.RawIOBase):
    """A read-only file over an iterator of byte chunks, for tarfile's stream mode."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = iter(chunks)
        self._pending = memoryview(b"")

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        while not self._pending:
            chunk = next(self._chunks, None)
            if chunk is None:
                return 0
            self._pending = memoryview(chunk)
        count = min(len(buffer), len(self._pending))
        buffer[:count] = self._pending[:count]
        self._pending = self._pending[count:]
        return count


def describe(fileobj: io.IOBase) -> dict[str, Entry]:
    """Every member of a tar stream by its path relative to the volume root."""
    entries: dict[str, Entry] = {}
    with tarfile.open(fileobj=fileobj, mode="r|") as tar:
        for member in tar:
            digest = None
            data = tar.extractfile(member) if member.isfile() else None
            if data is not None:
                hasher = hashlib.sha256()
                while chunk := data.read(CHUNK):
                    hasher.update(chunk)
                digest = hasher.hexdigest()
            name = member.name.removeprefix("./").rstrip("/")
            entries["" if name == "." else name] = Entry(
                type=member.type,
                uid=member.uid,
                gid=member.gid,
                mode=member.mode,
                size=member.size,
                linkname=member.linkname,
                sha256=digest,
            )
    return entries


def describe_file(path: Path) -> dict[str, Entry]:
    with path.open("rb") as source:
        return describe(source)


def describe_volume(
    client: docker.DockerClient, image: str, instance_id: str, volume: str
) -> dict[str, Entry]:
    """Reads a volume back through get_archive without staging it."""
    mounts = volume_mount(volume, read_only=True)
    with helper.helper(client, image, instance_id, mounts=mounts) as box:
        stream, _stat = box.get_archive(f"{MOUNT}/.", chunk_size=CHUNK)
        return describe(io.BufferedReader(ChunkReader(stream), CHUNK))
