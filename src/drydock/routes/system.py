"""Home page, audit log and health check."""

import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock.db import get_db
from drydock.models import AuditEvent
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import render

router = APIRouter()

AUDIT_PAGE_SIZE = 100


@router.get("/")
def home(request: Request, auth: Auth = Depends(require_role(Role.viewer))) -> Response:
    return render(request, "home.html", auth=auth)


@router.get("/audit")
def audit_log(
    request: Request,
    before: int | None = Query(default=None, ge=1),
    auth: Auth = Depends(require_role(Role.admin)),
    db: Session = Depends(get_db),
) -> Response:
    query = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(AUDIT_PAGE_SIZE)
    if before is not None:
        query = query.where(AuditEvent.id < before)
    events = db.scalars(query).all()
    rows = [(e, json.loads(e.details)) for e in events]
    next_before = events[-1].id if len(events) == AUDIT_PAGE_SIZE else None
    return render(request, "audit.html", auth=auth, rows=rows, next_before=next_before)


@router.get("/healthz")
def healthz() -> Response:
    return JSONResponse({"status": "ok"})
