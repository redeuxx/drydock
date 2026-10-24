"""Roles and the dependencies that enforce them.

require_role() is the only way routes get a user: it validates the session and,
for any method that is not GET/HEAD/OPTIONS, the CSRF token and Origin.
"""

from datetime import timedelta
from enum import IntEnum

from fastapi import Depends, HTTPException, Request

from drydock.models import utcnow
from drydock.security import csrf
from drydock.security.sessions import Auth, load_auth

REAUTH_WINDOW = timedelta(minutes=10)


class Role(IntEnum):
    viewer = 10
    operator = 20
    admin = 30
    superadmin = 40


class RecentAuthRequired(Exception):
    """The password must be re-entered. Handled by rendering the re-auth form."""

    def __init__(self, auth: Auth) -> None:
        super().__init__("recent authentication required")
        self.auth = auth


async def authenticated(request: Request, auth: Auth = Depends(load_auth)) -> Auth:
    if request.method not in csrf.SAFE_METHODS:
        await csrf.verify_session_token(request, auth.csrf_token)
    return auth


def require_role(minimum: Role):
    async def dependency(auth: Auth = Depends(authenticated)) -> Auth:
        if auth.user.role < minimum:
            raise HTTPException(status_code=403, detail="Your role does not allow this.")
        return auth

    dependency.required_role = minimum  # read by the route inventory tests
    return dependency


def has_recent_auth(auth: Auth) -> bool:
    reauth_at = auth.session.reauth_at
    return reauth_at is not None and utcnow() - reauth_at <= REAUTH_WINDOW


def require_recent_auth(auth: Auth) -> None:
    if not has_recent_auth(auth):
        raise RecentAuthRequired(auth)
