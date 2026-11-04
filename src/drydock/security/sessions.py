"""Server-side sessions behind an opaque cookie token. Only the token's sha256 is stored."""

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Depends, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from drydock.config import Settings
from drydock.db import get_db
from drydock.models import User, UserSession, utcnow

IDLE_TIMEOUT = timedelta(hours=1)
POLL_HEADER = "x-drydock-poll"  # set by frontend/app.ts on every background poll
ABSOLUTE_TIMEOUT = timedelta(hours=12)
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")


class LoginRequired(Exception):
    """No valid session. Handled by redirecting to /login (or 401 for htmx)."""


@dataclass
class Auth:
    user: User
    session: UserSession

    @property
    def csrf_token(self) -> str:
        return self.session.csrf_token


def cookie_name(settings: Settings) -> str:
    return "__Host-drydock_session" if settings.cookie_secure else "drydock_session"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db: Session, user: User, ip: str | None) -> str:
    """Adds a fresh session for user and returns the raw token for the cookie."""
    now = utcnow()
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_sha256=token_hash(token),
            user_id=user.id,
            csrf_token=secrets.token_urlsafe(32),
            ip=ip,
            created_at=now,
            last_seen_at=now,
            expires_at=now + ABSOLUTE_TIMEOUT,
            reauth_at=now,  # the password was just entered
        )
    )
    return token


def revoke_user(db: Session, user_id: int) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))


def revoke_token(db: Session, token: str | None) -> None:
    if token and TOKEN_RE.fullmatch(token):
        db.execute(delete(UserSession).where(UserSession.token_sha256 == token_hash(token)))


def purge_expired(db: Session, now: datetime) -> None:
    db.execute(
        delete(UserSession).where(
            (UserSession.expires_at <= now) | (UserSession.last_seen_at <= now - IDLE_TIMEOUT)
        )
    )


def set_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        cookie_name(settings),
        token,
        max_age=int(ABSOLUTE_TIMEOUT.total_seconds()),
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )


def clear_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        cookie_name(settings),
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )


def load_auth(request: Request, db: Session = Depends(get_db)) -> Auth:
    """Resolves the session cookie. The only write is the last_seen_at bump."""
    token = request.cookies.get(cookie_name(request.app.state.settings))
    if not token or not TOKEN_RE.fullmatch(token):
        raise LoginRequired
    now = utcnow()
    row = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_sha256 == token_hash(token))
    ).one_or_none()
    if row is None:
        db.rollback()
        raise LoginRequired
    session, user = row
    if user.disabled or session.expires_at <= now or session.last_seen_at <= now - IDLE_TIMEOUT:
        db.rollback()  # stale rows are purged at the next login, keeping GETs write-free
        raise LoginRequired
    # A page polling in the background (live status, a run's log) is not the user being
    # active: it must not keep an idle session alive. Sending the header can only shorten
    # one's own session.
    if request.headers.get(POLL_HEADER) != "1":
        session.last_seen_at = now
    db.commit()
    auth = Auth(user=user, session=session)
    request.state.auth = auth  # lets error pages keep the logged-in header
    return auth
