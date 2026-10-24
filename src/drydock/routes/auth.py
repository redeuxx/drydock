"""Setup wizard, login, logout and re-authentication."""

import re
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.models import User, utcnow
from drydock.security import csrf, passwords, sessions
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import render, see_other

router = APIRouter()

USERNAME_RE = re.compile(r"[\x21-\x7e]{1,64}")  # printable ASCII, no spaces
LOGIN_FAILED = "Invalid username or password."
TOO_MANY = "Too many failed attempts. Wait 15 minutes and try again."

FormStr = Annotated[str, Form()]


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def validate_username(username: str) -> str | None:
    if not USERNAME_RE.fullmatch(username):
        return "Username must be 1 to 64 printable characters with no spaces."
    return None


def safe_next(value: str | None) -> str:
    """Only same-site absolute paths, so a redirect can never leave drydock."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or any(ord(c) < 0x21 for c in value):
        return "/"
    return value


def login_response(request: Request, db: Session, user: User, target: str) -> Response:
    """Rotates the session: the presented cookie's session is revoked, a new one is issued."""
    settings = request.app.state.settings
    sessions.revoke_token(db, request.cookies.get(sessions.cookie_name(settings)))
    sessions.purge_expired(db, utcnow())
    token = sessions.create(db, user, client_ip(request))
    response = see_other(request, target)
    sessions.set_cookie(response, settings, token)
    csrf.clear_presession(response, settings)
    return response


def presession_page(request: Request, name: str, status_code: int = 200, **context) -> Response:
    form_token, new_cookie = csrf.presession_token(request)
    response = render(request, name, status_code, form_token=form_token, **context)
    csrf.set_presession_cookie(response, request.app.state.settings, new_cookie)
    return response


def users_exist(db: Session) -> bool:
    return db.scalar(select(func.count()).select_from(User)) > 0


# SETUP


def setup_open(request: Request, db: Session = Depends(get_db)) -> None:
    """404 once any user exists. Checked before CSRF so the answer never varies."""
    state = request.app.state
    if not state.setup_complete:
        state.setup_complete = users_exist(db)
        db.rollback()
    if state.setup_complete:
        raise HTTPException(status_code=404)


@router.get("/setup", dependencies=[Depends(setup_open)])
def setup_form(request: Request) -> Response:
    return presession_page(request, "setup.html", errors=[], username="")


@router.post("/setup", dependencies=[Depends(setup_open), Depends(csrf.verify_presession)])
def setup_submit(
    request: Request,
    username: FormStr = "",
    password: FormStr = "",
    password_confirm: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    errors = [e for e in (validate_username(username), passwords.validate_new(password)) if e]
    if password != password_confirm:
        errors.append("Passwords do not match.")
    if errors:
        return presession_page(request, "setup.html", 422, errors=errors, username=username)
    password_hash = passwords.hash_password(password)  # before the write lock is taken
    # The first statement opens a BEGIN IMMEDIATE transaction, so concurrent
    # submissions serialize here and only the first one sees an empty table.
    if users_exist(db):
        db.rollback()
        raise HTTPException(status_code=404)
    user = User(username=username, password_hash=password_hash, role=Role.superadmin)
    db.add(user)
    db.flush()
    ip = client_ip(request)
    audit.record(
        db,
        actor=username,
        action="setup.complete",
        target=f"user:{user.id}",
        ip=ip,
        details={"source_ip": ip},
    )
    response = login_response(request, db, user, "/")
    db.commit()
    request.app.state.setup_complete = True
    return response


# LOGIN


@router.get("/login")
def login_form(request: Request) -> Response:
    return presession_page(request, "login.html", error=None)


@router.post("/login", dependencies=[Depends(csrf.verify_presession)])
def login_submit(
    request: Request,
    username: FormStr = "",
    password: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    limiter = request.app.state.login_limiter
    ip = client_ip(request) or ""
    username = username[:128]
    if limiter.blocked(username, ip):
        return presession_page(request, "login.html", 429, error=TOO_MANY)
    user = db.scalar(select(User).where(User.username == username)) if username else None
    stored_hash = user.password_hash if user else None
    known_name = user.username if user else None
    user_id = user.id if user and not user.disabled else None
    # Every transaction holds SQLite's write lock (BEGIN IMMEDIATE), so release it before
    # Argon2 runs. Otherwise logins, and every authenticated request, queue behind it.
    db.rollback()
    ok = passwords.verify_password(stored_hash, password)
    new_hash = None
    if ok and stored_hash is not None and passwords.needs_rehash(stored_hash):
        new_hash = passwords.hash_password(password)
    user = db.get(User, user_id) if ok and user_id is not None else None
    # The password or the account may have changed while the lock was released.
    if user is None or user.disabled or user.password_hash != stored_hash:
        limiter.failure(username, ip)
        # Never the submitted text: people type passwords into the username field.
        audit.record(
            db,
            actor=known_name,
            action="auth.login",
            outcome="failure",
            ip=ip,
            details={"known_user": stored_hash is not None},
        )
        db.commit()
        return presession_page(request, "login.html", 422, error=LOGIN_FAILED)
    limiter.reset(username, ip)
    if new_hash:
        user.password_hash = new_hash
    audit.record(db, actor=user.username, action="auth.login", target=f"user:{user.id}", ip=ip)
    response = login_response(request, db, user, "/")
    db.commit()
    return response


# LOGOUT


@router.post("/logout")
def logout(
    request: Request,
    auth: Auth = Depends(require_role(Role.viewer)),
    db: Session = Depends(get_db),
) -> Response:
    settings = request.app.state.settings
    sessions.revoke_token(db, request.cookies.get(sessions.cookie_name(settings)))
    audit.record(db, actor=auth.user.username, action="auth.logout", ip=client_ip(request))
    db.commit()
    response = see_other(request, "/login")
    sessions.clear_cookie(response, settings)
    return response


# RE-AUTHENTICATION


@router.get("/reauth")
def reauth_form(
    request: Request,
    next_path: Annotated[str, Query(alias="next")] = "/",
    auth: Auth = Depends(require_role(Role.viewer)),
) -> Response:
    return render(request, "reauth.html", auth=auth, next=safe_next(next_path), error=None)


@router.post("/reauth")
def reauth_submit(
    request: Request,
    password: FormStr = "",
    next_path: Annotated[str, Form(alias="next")] = "/",
    auth: Auth = Depends(require_role(Role.viewer)),
    db: Session = Depends(get_db),
) -> Response:
    limiter = request.app.state.login_limiter
    ip = client_ip(request) or ""
    target = safe_next(next_path)
    if limiter.blocked(auth.user.username, ip):
        return render(request, "reauth.html", 429, auth=auth, next=target, error=TOO_MANY)
    if not passwords.verify_password(auth.user.password_hash, password):
        limiter.failure(auth.user.username, ip)
        audit.record(db, actor=auth.user.username, action="auth.reauth", outcome="failure", ip=ip)
        db.commit()
        return render(request, "reauth.html", 422, auth=auth, next=target, error=LOGIN_FAILED)
    limiter.reset(auth.user.username, ip)
    auth.session.reauth_at = utcnow()
    audit.record(db, actor=auth.user.username, action="auth.reauth", ip=ip)
    db.commit()
    return see_other(request, target)
