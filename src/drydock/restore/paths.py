"""Restores from a file on the drydock server: POST /restore/from-path (routes.restore).

The allowlist comes only from DRYDOCK_RESTORE_PATHS (Settings.restore_paths, frozen at
startup); no route can change it. A path is resolved with realpath and must lie inside an
allowlisted directory, then opened with O_NOFOLLOW (O_NONBLOCK, so a FIFO cannot block the
open), and the path the kernel reports for the open descriptor (/proc/self/fd) must still
be that resolved path: a directory swapped for a symlink between the check and the open is
caught there. Only regular files named as drydock names its archives are accepted.

Both restore passes open the file this way (ServerFile), and pass 2 also compares its
fstat identity with pass 1's (restore.verify.open_verified).
"""

import os
import stat
from pathlib import Path
from typing import BinaryIO

from drydock.storage.base import StorageError, check_name

MAX_PATH = 4096


class PathError(StorageError):
    """The path is refused. The message is safe to show."""


def open_checked(path: str, allowed: tuple[Path, ...]) -> tuple[BinaryIO, Path]:
    """The open file at path and its resolved path. Raises PathError."""
    if not allowed:
        raise PathError("Restores from a server path are off. Set DRYDOCK_RESTORE_PATHS.")
    if not path.startswith("/") or len(path) > MAX_PATH or "\0" in path:
        raise PathError("Enter the absolute path of the archive file.")
    real = Path(os.path.realpath(path))
    roots = [Path(os.path.realpath(root)) for root in allowed]
    if not any(real.is_relative_to(root) and real != root for root in roots):
        raise PathError("The path is not inside a directory DRYDOCK_RESTORE_PATHS allows.")
    try:
        check_name(real.name)
    except StorageError:
        raise PathError("Only archives drydock wrote, under the name it gave them.") from None
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(real, flags)
    except FileNotFoundError:
        raise PathError(f"{real} does not exist.") from None
    except OSError as exc:
        raise PathError(f"{real} cannot be opened: {exc.strerror}.") from None
    try:
        if Path(f"/proc/self/fd/{fd}").readlink() != real:
            raise PathError(f"{real} changed while it was opened.")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PathError(f"{real} is not a regular file.")
        os.set_blocking(fd, True)
        return os.fdopen(fd, "rb"), real
    except BaseException:
        os.close(fd)
        raise


class ServerFile:
    """A server path as a restore reads it: the storage that restore.verify opens."""

    def __init__(self, path: str, allowed: tuple[Path, ...]) -> None:
        self.path = path
        self.allowed = allowed

    def open(self, name: str) -> BinaryIO:
        handle, real = open_checked(self.path, self.allowed)
        if real.name != name:
            handle.close()
            raise PathError(f"{real} is no longer the archive {name}.")
        return handle
