"""The backup catalog: every archive drydock stored. Every role may view it and filter it
by job, storage or a search of archive and job names.

Admins download an archive, with the password from the last 10 minutes: it is the whole
backup (an unencrypted one in the clear), so each download is audited. It streams from
storage as stored, unverified; its SHA-256 is in the catalog, and the restore page of this
or another drydock verifies it on upload.
"""

import re
from collections.abc import Iterator
from itertools import chain
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import Backup, Job, StorageTarget
from drydock.routes.auth import client_ip
from drydock.routes.restore import target_root
from drydock.routes.storage import remote_backend
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.storage.base import StorageError, check_name
from drydock.storage.local import LocalStorage
from drydock.storage.rclone import KINDS as REMOTE_KINDS
from drydock.templating import render

router = APIRouter(prefix="/backups")

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]

PAGE_SIZE = 100
MAX_QUERY = 100


def list_page(
    request: Request,
    auth: Auth,
    db: Session,
    before: int | None = None,
    job: int | None = None,
    storage: int | None = None,
    q: str = "",
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    query = q.strip()[:MAX_QUERY]
    found = select(Backup).order_by(Backup.id.desc()).limit(PAGE_SIZE)
    if before is not None:
        found = found.where(Backup.id < before)
    if job is not None:
        found = found.where(Backup.job_id == job)
    if storage is not None:
        found = found.where(Backup.storage_target_id == storage)
    if query:
        named = select(Job.id).where(Job.name.contains(query, autoescape=True))
        found = found.where(
            or_(Backup.name.contains(query, autoescape=True), Backup.job_id.in_(named))
        )
    backups = list(db.scalars(found))
    jobs = dict(db.execute(select(Job.id, Job.name).order_by(Job.name)).all())
    targets = dict(db.execute(select(StorageTarget.id, StorageTarget.name)).all())
    filters = {
        k: v for k, v in (("job", job), ("storage", storage), ("q", query)) if v not in (None, "")
    }
    return render(
        request,
        "backups/list.html",
        status_code,
        auth=auth,
        backups=backups,
        jobs=jobs,
        targets=targets,
        job=job,
        storage=storage,
        q=query,
        filtered=bool(filters),
        older_url=f"/backups?{urlencode(filters | {'before': backups[-1].id})}"
        if len(backups) == PAGE_SIZE
        else None,
        error=error,
    )


@router.get("")
def list_backups(
    request: Request,
    auth: Viewer,
    before: int | None = Query(default=None, ge=1),
    job: str = "",
    storage: str = "",
    q: str = "",
    db: Session = Depends(get_db),
) -> Response:
    """job and storage are text: their "All" options send them empty."""
    return list_page(request, auth, db, before, id_of(job), id_of(storage), q)


def id_of(value: str) -> int | None:
    return int(value) if re.fullmatch(r"[1-9][0-9]{0,8}", value) else None


@router.post("/{backup_id}/download")
def download(request: Request, backup_id: int, auth: Admin, db: Session = Depends(get_db)):
    """The archive as stored, streamed from its storage."""
    require_recent_auth(auth)
    backup = db.get(Backup, backup_id)
    if backup is None:
        raise HTTPException(status_code=404)
    name, size = backup.name, backup.size
    target = db.get(StorageTarget, backup.storage_target_id)
    username = auth.user.username
    chunks: Iterator[bytes] = iter(())
    first = b""
    error = None
    try:
        check_name(name)  # also what makes it safe in Content-Disposition
        if target is None:
            raise StorageError("Its storage was deleted.")
        if target.kind == "local":
            root = target_root(request, target)
            if root is None:
                raise StorageError("The storage settings cannot be read.")
            chunks = LocalStorage(root, request.app.state.settings).stream(name)
        elif target.kind in REMOTE_KINDS:
            chunks = remote_backend(request, target).stream(name)
        else:
            raise StorageError("This kind of storage cannot be read here.")
        db.rollback()  # no read transaction held while on the network
        # The first chunk opens the archive, so a missing one is an error page, not a
        # broken download.
        first = next(chunks, b"")
    except StorageError as exc:
        error = str(exc)
    audit.record(
        db,
        actor=username,
        action="backup.download",
        target=f"backup:{backup_id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"name": name} | ({} if error is None else {"error": error}),
    )
    db.commit()
    if error is not None:
        return list_page(
            request, auth, db, error=f"Cannot download {name}: {error}", status_code=502
        )
    return StreamingResponse(
        chain([first], chunks),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Content-Length": str(size),
            "Cache-Control": "no-store",
        },
    )
