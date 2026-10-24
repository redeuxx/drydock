"""Local directory storage.

The root must resolve inside one of DRYDOCK_LOCAL_STORAGE_ROOTS and must not overlap
drydock's own data, run, staging or application directories (in either direction).

Every operation re-validates the root and opens it once, with O_NOFOLLOW, checking that
the directory it opened is the one it validated. Files are then opened, linked and
removed relative to that directory descriptor, so a path component swapped for a symlink
cannot redirect them. Names are checked by storage.base.check_name.

Archives are written under a temporary name (.partial-<32 hex>) and published with a
hard link, which never replaces an existing archive, so a reader never sees a partial
archive. On a filesystem without hard links publishing falls back to a rename after an
existence check.
"""

import contextlib
import errno
import os
import re
import stat
import sys
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

import drydock
from drydock.archive.writer import create_new
from drydock.config import Settings
from drydock.storage.base import Progress, StorageError, StoredObject, check_name

CHUNK = 8 * 1024 * 1024
PARTIAL_PREFIX = ".partial-"
PARTIAL_RE = re.compile(r"\.partial-[0-9a-f]{32}")
NO_HARD_LINKS = {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS, errno.EMLINK}


def forbidden_dirs(settings: Settings) -> list[Path]:
    app_dirs = [Path(drydock.__file__).parent, Path(sys.prefix)]
    return [
        settings.data_dir,
        settings.run_dir,
        settings.staging_dir,
        Path("/data"),
        Path("/run"),
        Path("/app"),
        *app_dirs,
    ]


def overlaps(a: Path, b: Path) -> bool:
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def validate_root(root: str | Path, settings: Settings) -> Path:
    """Returns the resolved root, or raises StorageError with a message safe to show."""
    candidate = Path(root)
    if not candidate.is_absolute() or "\0" in str(candidate):
        raise StorageError("The storage path must be an absolute path.")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError, RuntimeError:
        raise StorageError("The storage path does not exist.") from None
    if not resolved.is_dir():
        raise StorageError("The storage path is not a directory.")
    allowed = [r.resolve() for r in settings.local_storage_roots]
    if not any(resolved.is_relative_to(r) for r in allowed):
        raise StorageError(
            "The storage path is outside DRYDOCK_LOCAL_STORAGE_ROOTS. Mount the directory "
            "into the container and list it there first."
        )
    for path in forbidden_dirs(settings):
        if overlaps(resolved, path.resolve()):
            raise StorageError(
                "The storage path overlaps drydock's own data, run or application directories."
            )
    return resolved


class LocalStorage:
    def __init__(self, root: str | Path, settings: Settings) -> None:
        self._configured = root
        self._settings = settings
        self.root = validate_root(root, settings)

    @contextlib.contextmanager
    def _dir(self) -> Iterator[int]:
        """The root, re-validated (the directory or the allowlist may have changed) and open."""
        root = validate_root(self._configured, self._settings)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(root, flags)
        except OSError as exc:
            raise StorageError(f"The storage path cannot be opened: {exc.strerror}.") from None
        try:
            if Path(f"/proc/self/fd/{fd}").readlink() != root:
                raise StorageError("The storage path changed while it was being opened.")
            yield fd
        finally:
            os.close(fd)

    # STORAGEBACKEND

    def put(
        self, local: Path, name: str, progress: Progress | None, cancel: threading.Event
    ) -> StoredObject:
        check_name(name)
        with self._dir() as fd:
            if exists(fd, name):
                raise StorageError(f"{name} already exists in storage.")
            partial = new_partial_name()
            try:
                with open_regular(local) as reader, create_new(partial, dir_fd=fd) as writer:
                    size = copy(reader, writer, progress, cancel, "the storage directory")
                publish(fd, partial, name)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(partial, dir_fd=fd)
            return StoredObject(name, size, mtime(os.stat(name, dir_fd=fd, follow_symlinks=False)))

    def get(
        self, name: str, local: Path, progress: Progress | None, cancel: threading.Event
    ) -> int:
        check_name(name)
        try:
            with self._dir() as fd, open_regular(name, fd) as reader, create_new(local) as writer:
                return copy(reader, writer, progress, cancel, "the staging directory")
        except BaseException:
            local.unlink(missing_ok=True)
            raise

    def read_head(self, name: str, max_bytes: int) -> bytes:
        check_name(name)
        with self._dir() as fd, open_regular(name, fd) as handle:
            return handle.read(max_bytes)

    def open(self, name: str) -> BinaryIO:
        """Opens an archive for reading in place: O_NOFOLLOW, relative to the re-validated
        root, regular files only. The handle stays valid after the root is closed, so a
        caller can bind every read of the archive to this one open file."""
        check_name(name)
        with self._dir() as fd:
            return open_regular(name, fd)

    def list(self, prefix: str = "") -> list[StoredObject]:
        found = []
        with self._dir() as fd, os.scandir(fd) as entries:
            for entry in entries:
                if not entry.name.startswith(prefix) or not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    check_name(entry.name)
                except StorageError:
                    continue  # partial uploads and anything not made by drydock
                info = entry.stat(follow_symlinks=False)
                found.append(StoredObject(entry.name, info.st_size, mtime(info)))
        return sorted(found, key=lambda o: o.name)

    def delete(self, name: str) -> None:
        check_name(name)
        with self._dir() as fd:
            if not exists(fd, name, regular=True):
                raise StorageError(f"{name} does not exist in storage.")
            os.unlink(name, dir_fd=fd)

    def test(self) -> None:
        with self._dir() as fd:
            probe = new_partial_name()
            try:
                with create_new(probe, dir_fd=fd) as handle:
                    handle.write(b"drydock")
            except OSError as exc:
                raise StorageError(f"The storage path is not writable: {exc.strerror}.") from None
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(probe, dir_fd=fd)

    # ARCHIVES WRITTEN IN PLACE

    def new_partial(self) -> Path:
        """A fresh temporary path in the root for an archive written in place (not created).
        publish() gives it its final name; remove_partials() clears any left by a crash."""
        return validate_root(self._configured, self._settings) / new_partial_name()

    def publish(self, partial: Path, name: str) -> StoredObject:
        """Gives a complete file from new_partial() its archive name. Never replaces one."""
        check_name(name)
        if partial.parent != self.root or not PARTIAL_RE.fullmatch(partial.name):
            raise StorageError("Invalid temporary name.")
        with self._dir() as fd:
            if not exists(fd, partial.name, regular=True):
                raise StorageError("The archive to publish is missing.")
            publish(fd, partial.name, name)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            return StoredObject(name, info.st_size, mtime(info))

    def remove_partials(self) -> int:
        """Deletes temporary files left by an interrupted run. Startup recovery calls this."""
        removed = 0
        with self._dir() as fd, os.scandir(fd) as entries:
            for entry in entries:
                if PARTIAL_RE.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(entry.name, dir_fd=fd)
                        removed += 1
        return removed


# FILES


def new_partial_name() -> str:
    return f"{PARTIAL_PREFIX}{uuid.uuid4().hex}"


def mtime(info: os.stat_result) -> datetime:
    return datetime.fromtimestamp(info.st_mtime, UTC)


def exists(fd: int, name: str, *, regular: bool = False) -> bool:
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(info.st_mode) or not regular


def publish(fd: int, partial: str, name: str) -> None:
    """Links partial to name (failing if name exists), removes partial and syncs the root."""
    try:
        os.link(partial, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    except FileExistsError:
        raise StorageError(f"{name} already exists in storage.") from None
    except OSError as exc:
        if exc.errno not in NO_HARD_LINKS:
            raise
        if exists(fd, name):
            raise StorageError(f"{name} already exists in storage.") from None
        os.rename(partial, name, src_dir_fd=fd, dst_dir_fd=fd)
    else:
        os.unlink(partial, dir_fd=fd)
    os.fsync(fd)


def open_regular(path: Path | str, dir_fd: int | None = None) -> BinaryIO:
    """Opens a regular file for reading. O_NONBLOCK keeps a FIFO planted under the name
    from blocking the open; it is cleared once the file is known to be regular."""
    name = Path(path).name
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        raise StorageError(f"{name} does not exist in storage.") from None
    except OSError as exc:
        raise StorageError(f"{name} cannot be opened: {exc.strerror}.") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise StorageError(f"{name} is not a regular file.")
    os.set_blocking(fd, True)
    return os.fdopen(fd, "rb")


def copy(
    reader: BinaryIO,
    writer: BinaryIO,
    progress: Progress | None,
    cancel: threading.Event,
    label: str,
) -> int:
    """Copies in 8 MiB chunks, checking for cancellation between chunks, then syncs."""
    total = 0
    try:
        while chunk := reader.read(CHUNK):
            if cancel.is_set():
                raise StorageError("The transfer was cancelled.")
            writer.write(chunk)
            total += len(chunk)
            if progress is not None:
                progress(total)
        writer.flush()
        os.fsync(writer.fileno())
    except OSError as exc:
        if exc.errno in (errno.ENOSPC, errno.EDQUOT):
            raise StorageError(f"The disk holding {label} is full.") from None
        raise
    return total
