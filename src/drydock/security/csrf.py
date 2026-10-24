"""CSRF defenses.

After login: a per-session synchronizer token in the X-CSRF-Token header or the
csrf_token form field. Before login (/setup, /login): a double-submit cookie
whose form token is an HMAC of the cookie value. Both also check Origin and
Sec-Fetch-Site.
"""

import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response

from drydock.config import Settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
HEADER = "x-csrf-token"
FIELD = "csrf_token"
FORM_TYPES = ("application/x-www-form-urlencoded", "multipart/form-data")
ALLOWED_FETCH_SITES = frozenset({"same-origin", "none"})


def forbidden() -> HTTPException:
    return HTTPException(
        status_code=403, detail="The request failed a CSRF check. Reload and retry."
    )


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ORIGIN CHECKS


def _origin_tuple(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return parts.scheme, parts.hostname.lower(), port or (443 if parts.scheme == "https" else 80)


def check_origin(request: Request) -> None:
    """Rejects requests a browser marks as coming from another site."""
    origin = request.headers.get("origin")
    if origin is not None:
        given = _origin_tuple(origin)
        allowed = {
            _origin_tuple(request.app.state.settings.base_url),
            _origin_tuple(f"{request.url.scheme}://{request.headers.get('host', '')}"),
        }
        if given is None or given not in allowed:
            raise forbidden()
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site not in ALLOWED_FETCH_SITES:
        raise forbidden()


async def submitted_token(request: Request) -> str:
    token = request.headers.get(HEADER)
    if token is None and request.headers.get("content-type", "").startswith(FORM_TYPES):
        value = (await request.form()).get(FIELD)
        token = value if isinstance(value, str) else None
    return token or ""


# AFTER LOGIN


async def verify_session_token(request: Request, expected: str) -> None:
    check_origin(request)
    if not tokens_equal(await submitted_token(request), expected):
        raise forbidden()


# BEFORE LOGIN


def presession_cookie_name(settings: Settings) -> str:
    return "__Host-drydock_precsrf" if settings.cookie_secure else "drydock_precsrf"


def presession_token(request: Request) -> tuple[str, str | None]:
    """Returns (form token, new cookie value or None when the existing cookie is reused)."""
    value = request.cookies.get(presession_cookie_name(request.app.state.settings), "")
    new_value = None
    if len(value) != 43:
        value = new_value = secrets.token_urlsafe(32)
    return request.app.state.crypto.presession_tag(value), new_value


def set_presession_cookie(response: Response, settings: Settings, value: str | None) -> None:
    if value is not None:
        response.set_cookie(
            presession_cookie_name(settings),
            value,
            path="/",
            secure=settings.cookie_secure,
            httponly=True,
            samesite="strict",
        )


async def verify_presession(request: Request) -> None:
    check_origin(request)
    cookie = request.cookies.get(presession_cookie_name(request.app.state.settings), "")
    submitted = await submitted_token(request)
    expected = request.app.state.crypto.presession_tag(cookie)
    if not cookie or not tokens_equal(submitted, expected):
        raise forbidden()


def clear_presession(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        presession_cookie_name(settings),
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
