"""Archives uploaded in the browser for a restore: PUT /restore/uploads (routes.restore).

One streamed request per upload, its body the archive itself. Before a byte of the body is
read: the type must be application/octet-stream (415), the archive name one drydock
writes (422), Content-Length present (411) and at most MAX_UPLOAD (413), and the staging
disk must hold the declared size on top of RESERVE and of every upload and download
already in flight (507; storage.rclone.Reserved counts both). The body then goes to a new
server-named file in <staging>/uploads, written CHUNK by CHUNK on a worker thread and
counted against the declared size. Going past it (413), ending short or disconnecting
(400), stalling for IDLE_TIMEOUT (408) or filling the disk (507) removes the file and the
row. BodySizeLimitMiddleware lets only this route's octet-stream bodies through.

Complete uploads expire LIFETIME after they completed (expire, from the hourly maintenance).
Startup removes what a stop cut short (recover). A failed upload leaves nothing behind.
POST /restore/from-upload/{id} restores one, which uses it up (UploadMove).
"""

import contextlib
import logging
import os
import re
import stat
import time
import uuid
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path
from typing import BinaryIO

import anyio
from fastapi import Request
from sqlalchemy import Row, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import ClientDisconnect

from drydock import audit
from drydock.archive.writer import (
    CHUNK,
    STAGING,
    InsufficientSpace,
    create_new,
    disk_full_is_insufficient_space,
)
from drydock.config import Settings
from drydock.models import Upload, utcnow
from drydock.storage.base import StorageError
from drydock.storage.base import check_name as check_archive_name
from drydock.storage.rclone import Reserved

log = logging.getLogger("drydock.uploads")

MAX_UPLOAD = 50 * 10**9  # 50 GB
LIFETIME = timedelta(hours=24)
IDLE_TIMEOUT = 300  # seconds without a byte from the client
CONTENT_TYPE = "application/octet-stream"
GONE = "The upload is gone: it expired, failed or was restored. Upload the archive again."
# An upload expires LIFETIME after it completed and is gone an hour later. A restore takes
# it before then and moves the file within seconds: a file without a row this old is
# left over, never one a restore is about to move.
ORPHAN_AGE = 2 * LIFETIME
FILE_RE = re.compile(r"upload-[0-9a-f]{32}")


class UploadError(Exception):
    """The upload is refused or failed. The message is safe to show."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code


def uploads_dir(settings: Settings) -> Path:
    return settings.staging_dir / "uploads"


# CHECKS BEFORE THE BODY


def checked_request(request: Request, name: str) -> tuple[str, int]:
    """The archive name and the declared size. Reads only the headers and the query."""
    media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type != CONTENT_TYPE:
        raise UploadError(415, f"Send the archive as {CONTENT_TYPE}.")
    try:
        check_archive_name(name)
    except StorageError:
        raise UploadError(
            422,
            "Only archives drydock wrote can be uploaded, under the name drydock gave them "
            "(drydock-<job>-<id>-<time>.tar.zst, or .tar.zst.age when encrypted).",
        ) from None
    header = request.headers.get("content-length")
    if header is None:
        raise UploadError(411, "The upload has no Content-Length.")
    if not (header.isascii() and header.isdigit()) or len(header) > 15:
        raise UploadError(400, "The upload's Content-Length is not valid.")
    declared = int(header)
    if declared == 0:
        raise UploadError(400, "The file is empty.")
    if declared > MAX_UPLOAD:
        raise UploadError(413, f"An upload can be at most {MAX_UPLOAD // 10**9} GB.")
    return name, declared


# RECEIVING


async def receive(
    request: Request, sessions: sessionmaker[Session], user_id: int, name: str, declared: int
) -> int:
    """Streams the body into a new upload and returns its ID. Raises UploadError, after
    removing the row and the file."""
    settings: Settings = request.app.state.settings
    folder = uploads_dir(settings)
    path = folder / f"upload-{uuid.uuid4().hex}"
    try:
        with contextlib.ExitStack() as stack:
            await anyio.to_thread.run_sync(prepare, folder)
            # statvfs may block on a slow disk, so not on the event loop. Leaving only counts.
            await anyio.to_thread.run_sync(stack.enter_context, Reserved.space(folder, declared))
            upload_id = await anyio.to_thread.run_sync(
                insert, sessions, user_id, name, declared, path
            )
            try:
                await write_body(request, path, declared)
                await anyio.to_thread.run_sync(finish, sessions, upload_id, declared)
            except BaseException:
                with anyio.CancelScope(shield=True):
                    await anyio.to_thread.run_sync(discard, sessions, upload_id, path)
                raise
    except InsufficientSpace as exc:
        raise UploadError(507, str(exc)) from None
    except ClientDisconnect:
        raise UploadError(400, "The upload was interrupted.") from None
    except TimeoutError:
        raise UploadError(408, "The upload stalled and was dropped.") from None
    except OSError as exc:  # after TimeoutError, which is one
        log.warning("Upload to %s failed: %s", path, exc)
        raise UploadError(500, f"The upload could not be written: {exc.strerror or exc}.") from None
    return upload_id


async def write_body(request: Request, path: Path, declared: int) -> None:
    received = 0
    buffer = bytearray()
    handle = await anyio.to_thread.run_sync(create_new, path)
    try:
        async with contextlib.aclosing(request.stream()) as chunks:
            while True:
                with anyio.fail_after(IDLE_TIMEOUT):
                    chunk = await anext(chunks, None)
                if chunk is None:
                    break
                received += len(chunk)
                if received > declared:
                    raise UploadError(413, "The upload is larger than its Content-Length.")
                buffer += chunk
                if len(buffer) >= CHUNK:
                    await write(handle, buffer)
                    buffer = bytearray()
        if received < declared:
            raise UploadError(400, "The upload ended before its Content-Length.")
        await write(handle, buffer)
        await anyio.to_thread.run_sync(os.fsync, handle.fileno())  # complete means on disk
    finally:
        with anyio.CancelScope(shield=True):
            await anyio.to_thread.run_sync(handle.close)


async def write(handle: BinaryIO, data: bytearray) -> None:
    with disk_full_is_insufficient_space(STAGING):
        await anyio.to_thread.run_sync(handle.write, data)


# RESTORING ONE


def available(upload: Upload | None, name: str | None = None) -> bool:
    """Whether a restore may take the upload: complete and not past expires_at (what
    expire deletes), and named name when given."""
    return (
        upload is not None
        and upload.status == "complete"
        and upload.expires_at > utcnow()
        and (name is None or upload.name == name)
    )


class UploadMove:
    """An upload as restore.verify.Downloaded fetches it: moved into the run's restore
    directory (both are on the staging disk). Starting the restore deleted its row, so the
    file is the restore's now. Not a hard link: the upload's own name going away later
    would change the file's ctime, which pass 2 checks."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def get(self, name: str, local: Path, progress: object, cancel: object) -> int:
        try:
            self.path.rename(local)
        except FileNotFoundError:
            raise StorageError(GONE) from None
        except OSError as exc:
            raise StorageError(f"The upload cannot be read: {exc.strerror}.") from None
        return local.stat().st_size


# DATABASE AND FILES (BLOCKING)


def prepare(folder: Path) -> None:
    folder.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder.mkdir(mode=0o700, exist_ok=True)


def insert(
    sessions: sessionmaker[Session], user_id: int, name: str, declared: int, path: Path
) -> int:
    now = utcnow()
    with sessions() as db, db.begin():
        upload = Upload(
            user_id=user_id,
            name=name,
            declared_size=declared,
            path=str(path),
            created_at=now,
            expires_at=now + LIFETIME,
        )
        db.add(upload)
        db.flush()
        return upload.id


def finish(sessions: sessionmaker[Session], upload_id: int, received: int) -> None:
    with sessions() as db, db.begin():
        upload = db.get(Upload, upload_id)
        if upload is not None:
            upload.received = received
            upload.status = "complete"
            upload.expires_at = utcnow() + LIFETIME  # from now: a slow upload keeps its day


def discard(sessions: sessionmaker[Session], upload_id: int, path: Path) -> None:
    """Removes the file, then the row: a row left by a crash in between still names it."""
    path.unlink(missing_ok=True)
    with sessions() as db, db.begin():
        upload = db.get(Upload, upload_id)
        if upload is not None:
            db.delete(upload)


def expire(sessions: sessionmaker[Session], settings: Settings) -> None:
    """Deletes complete uploads past expires_at, files first. Audited. Also deletes upload
    files no row names, older than ORPHAN_AGE: what a restore that took an upload and
    failed before moving it left, if the dispatcher could not delete it."""
    sweep(sessions, uploads_dir(settings))
    with sessions() as db:
        rows = db.execute(
            select(Upload.id, Upload.path).where(
                Upload.status == "complete", Upload.expires_at <= utcnow()
            )
        ).all()
    deleted = remove(sessions, rows)
    if deleted:
        with sessions() as db, db.begin():
            audit.record(
                db, actor=None, action="restore.upload_expire", details={"uploads": deleted}
            )
        log.info("Deleted %d expired upload(s)", len(deleted))


def sweep(sessions: sessionmaker[Session], folder: Path, age: timedelta = ORPHAN_AGE) -> None:
    if not folder.is_dir():
        return
    with sessions() as db:
        named = set(db.scalars(select(Upload.path)))
    cutoff = time.time() - age.total_seconds()
    for entry in folder.iterdir():
        if not FILE_RE.fullmatch(entry.name) or str(entry) in named:
            continue
        try:
            info = entry.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                entry.unlink()
                log.warning("Deleted %s, an upload file no upload names", entry.name)
        except OSError as exc:
            log.warning("Could not delete %s: %s", entry.name, exc.strerror)


def recover(sessions: sessionmaker[Session], settings: Settings) -> None:
    """At startup: uploads still receiving were cut short by the stop, and files no row
    names were taken by restores the stop interrupted (Dispatcher.recover ends them first).
    Removes both."""
    with sessions() as db:
        rows = db.execute(select(Upload.id, Upload.path).where(Upload.status == "receiving")).all()
    if removed := remove(sessions, rows):
        log.warning("Removed %d upload(s) that drydock stopped in the middle of", len(removed))
    sweep(sessions, uploads_dir(settings), timedelta(0))


def remove(sessions: sessionmaker[Session], rows: Sequence[Row[tuple[int, str]]]) -> list[int]:
    """Discards each upload; one whose file cannot be deleted is logged and kept."""
    removed = []
    for upload_id, path in rows:
        try:
            discard(sessions, upload_id, Path(path))
        except OSError as exc:
            log.warning("Could not delete upload %d: %s", upload_id, exc.strerror)
            continue
        removed.append(upload_id)
    return removed
