"""The settings page: settings of the whole installation, on its single row. Admins only;
every change is audited."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import UPDATE_CHECK_HOURS, Installation
from drydock.routes.auth import FormStr, client_ip
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter()

Admin = Annotated[Auth, Depends(require_role(Role.admin))]


def settings_page(
    request: Request, auth: Auth, hours: int, errors: list[str], status_code: int = 200
) -> Response:
    return render(
        request,
        "settings.html",
        status_code,
        auth=auth,
        hours=hours,
        choices=UPDATE_CHECK_HOURS,
        errors=errors,
    )


@router.get("/settings")
def settings(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    hours = db.scalars(select(Installation)).one().update_check_hours
    return settings_page(request, auth, hours, [])


@router.post("/settings")
def settings_submit(
    request: Request,
    auth: Admin,
    update_check_hours: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    """The update checker reads the interval at its next loop (at most 5 minutes)."""
    row = db.scalars(select(Installation)).one()
    hours = int(update_check_hours) if update_check_hours.isdigit() else -1
    if hours not in UPDATE_CHECK_HOURS:
        db.rollback()
        return settings_page(
            request, auth, row.update_check_hours, ["Choose one of the intervals."], 422
        )
    before = row.update_check_hours
    row.update_check_hours = hours
    audit.record(
        db,
        actor=auth.user.username,
        action="settings.update",
        target="settings",
        ip=client_ip(request),
        details={"update_check_hours": hours, "was": before},
    )
    db.commit()
    return see_other(request, "/settings")
