"""The backup catalog: every archive drydock stored. Every role may view it."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock.db import get_db
from drydock.models import Backup, Job, StorageTarget
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import render

router = APIRouter(prefix="/backups")

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]

PAGE_SIZE = 100


@router.get("")
def list_backups(
    request: Request,
    auth: Viewer,
    before: int | None = Query(default=None, ge=1),
    db: Session = Depends(get_db),
) -> Response:
    query = select(Backup).order_by(Backup.id.desc()).limit(PAGE_SIZE)
    if before is not None:
        query = query.where(Backup.id < before)
    backups = list(db.scalars(query))
    jobs = dict(db.execute(select(Job.id, Job.name)).all())
    targets = dict(db.execute(select(StorageTarget.id, StorageTarget.name)).all())
    next_before = backups[-1].id if len(backups) == PAGE_SIZE else None
    return render(
        request,
        "backups/list.html",
        auth=auth,
        backups=backups,
        jobs=jobs,
        targets=targets,
        next_before=next_before,
    )
