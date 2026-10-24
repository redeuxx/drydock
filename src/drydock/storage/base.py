"""The storage backend interface and archive naming.

Backends are blocking; call them from async code through hosts.client.run_blocking.
Archive names are built here from the job UUID, a slug of the job name and the time,
never from raw user input, and every backend refuses any name not of that exact form.
"""

import re
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Protocol

NAME_RE = re.compile(
    r"drydock-[a-z0-9-]{1,40}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"-\d{8}T\d{6}Z\.tar\.zst(\.age)?"
)
# The same names, split. The UUID is anchored right before the stamp, so a slug that looks
# like a UUID cannot be taken for it.
NAME_PARTS_RE = re.compile(
    r"drydock-(?P<slug>[a-z0-9-]{1,40})"
    r"-(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"-(?P<stamp>\d{8}T\d{6}Z)\.tar\.zst(?P<age>\.age)?"
)
SLUG_MAX = 40
ARCHIVE_SUFFIX = ".tar.zst"
ENCRYPTED_SUFFIX = ".tar.zst.age"

Progress = Callable[[int], None]  # total bytes transferred so far


class StorageError(Exception):
    """A storage operation failed. The message is safe to show."""


@dataclass(frozen=True)
class ArchiveName:
    slug: str
    job_uuid: uuid.UUID
    created_at: datetime  # UTC
    encrypted: bool


@dataclass(frozen=True)
class StoredObject:
    name: str
    size: int
    modified: datetime


class StorageBackend(Protocol):
    def put(
        self, local: Path, name: str, progress: Progress | None, cancel: threading.Event
    ) -> StoredObject:
        """Uploads a local file under name. Nothing is visible under name until it is complete."""
        ...

    def get(
        self, name: str, local: Path, progress: Progress | None, cancel: threading.Event
    ) -> int:
        """Downloads name into a new local file and returns its size."""
        ...

    def read_head(self, name: str, max_bytes: int) -> bytes: ...

    def open(self, name: str) -> BinaryIO:
        """Opens name for reading. Restore binds every read of an archive to this handle."""
        ...

    def list(self, prefix: str = "") -> list[StoredObject]: ...

    def delete(self, name: str) -> None: ...

    def test(self) -> None:
        """Raises StorageError unless the backend is reachable and writable."""
        ...


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:SLUG_MAX].strip("-")
    return slug or "job"


def archive_name(job_uuid: str, job_name: str, created_at: datetime, encrypted: bool) -> str:
    """drydock-<slug>-<job uuid>-<UTC time>.tar.zst[.age]

    The job UUID lets drydock re-derive the passphrase of an encrypted archive from the
    secret key alone, after losing the database.
    """
    job_id = str(uuid.UUID(job_uuid))
    stamp = created_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    suffix = ENCRYPTED_SUFFIX if encrypted else ARCHIVE_SUFFIX
    return check_name(f"drydock-{slugify(job_name)}-{job_id}-{stamp}{suffix}")


def check_name(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise StorageError("Invalid archive name.")
    return name


def parse_name(name: str) -> ArchiveName:
    """The parts of an archive name. Raises StorageError for anything else."""
    match = NAME_PARTS_RE.fullmatch(name)
    if match is None:
        raise StorageError("Invalid archive name.")
    try:
        created_at = datetime.strptime(match["stamp"], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise StorageError("Invalid archive name.") from None
    return ArchiveName(
        slug=match["slug"],
        job_uuid=uuid.UUID(match["uuid"]),
        created_at=created_at,
        encrypted=match["age"] is not None,
    )
