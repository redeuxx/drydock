"""The signed-in user's own account."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import UserSession
from drydock.routes.auth import TOO_MANY, FormStr, client_ip
from drydock.security import passwords, sessions
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter()


@router.get("/account")
def account(
    request: Request,
    auth: Auth = Depends(require_role(Role.viewer)),
    db: Session = Depends(get_db),
) -> Response:
    own_sessions = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == auth.user.id)
        .order_by(UserSession.last_seen_at.desc())
    ).all()
    return render(request, "account/index.html", auth=auth, sessions=own_sessions)


@router.post("/account/preferences")
def preferences_submit(
    request: Request,
    hosts_collapsed: FormStr = "",
    auth: Auth = Depends(require_role(Role.viewer)),
    db: Session = Depends(get_db),
) -> Response:
    auth.user.hosts_collapsed = hosts_collapsed == "1"
    audit.record(
        db,
        actor=auth.user.username,
        action="account.preferences",
        target=f"user:{auth.user.id}",
        ip=client_ip(request),
        details={"hosts_collapsed": auth.user.hosts_collapsed},
    )
    db.commit()
    return see_other(request, "/account")


@router.get("/account/password")
def password_form(request: Request, auth: Auth = Depends(require_role(Role.viewer))) -> Response:
    return render(request, "account/password.html", auth=auth, errors=[])


@router.post("/account/password")
def password_submit(
    request: Request,
    current_password: FormStr = "",
    new_password: FormStr = "",
    new_password_confirm: FormStr = "",
    auth: Auth = Depends(require_role(Role.viewer)),
    db: Session = Depends(get_db),
) -> Response:
    user = auth.user
    limiter = request.app.state.login_limiter
    ip = client_ip(request) or ""
    if limiter.blocked(user.username, ip):
        return render(request, "account/password.html", 429, auth=auth, errors=[TOO_MANY])
    if not passwords.verify_password(user.password_hash, current_password):
        limiter.failure(user.username, ip)
        audit.record(db, actor=user.username, action="account.password", outcome="failure", ip=ip)
        db.commit()
        errors = ["Current password is incorrect."]
        return render(request, "account/password.html", 422, auth=auth, errors=errors)
    limiter.reset(user.username, ip)
    errors = [e for e in (passwords.validate_new(new_password),) if e]
    if new_password != new_password_confirm:
        errors.append("New passwords do not match.")
    if errors:
        return render(request, "account/password.html", 422, auth=auth, errors=errors)
    user.password_hash = passwords.hash_password(new_password)
    # Every session for this user ends, including this one; a fresh one replaces it.
    sessions.revoke_user(db, user.id)
    token = sessions.create(db, user, client_ip(request))
    audit.record(
        db, actor=user.username, action="account.password", target=f"user:{user.id}", ip=ip
    )
    db.commit()
    response = see_other(request, "/account")
    sessions.set_cookie(response, request.app.state.settings, token)
    return response
