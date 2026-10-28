"""Google Drive OAuth: connecting a drive storage target with the user's own Google client.

The authorization-code flow with PKCE (S256), access_type=offline and prompt=consent, so
Google always returns a refresh token. Drydock builds rclone's token JSON from it, and the
target's encrypted config keeps it (config["token"]); rclone refreshes the access token
itself and never writes it back, so only the refresh token has to stay valid.

Pending flows live in memory (Flows), keyed by the sha256 of the state:
- each holds the PKCE verifier, the user, the target and the redirect URI, for 10 minutes;
- take() removes a flow whatever happens next, so a state works once;
- a flow only completes for the user who started it, on the target it was started for;
- a restart drops them all, and the user starts again.

Two redirect modes, because Google allows plain http redirects to localhost only:
- "redirect": a web application client redirects to <DRYDOCK_BASE_URL>/storage/oauth/
  callback. That works over the SSH tunnel at localhost, or on an https host name.
- "paste": a desktop client redirects to http://127.0.0.1:<port>/, where nothing listens.
  The user pastes the address the browser shows back into drydock, which accepts it only
  for that exact host and port.

Google answering a refresh with invalid_grant (revoked access, a client in testing mode
after 7 days) marks the target "reconnect required" (mark_reconnect) and sends a
notification once.
"""

import base64
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from sqlalchemy.orm import Session, sessionmaker

from drydock import audit
from drydock.crypto import Crypto, CryptoError
from drydock.models import StorageTarget

log = logging.getLogger("drydock.gdrive")

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 (a URL; tests fake it)
SCOPES = {
    "drive.file": "https://www.googleapis.com/auth/drive.file",
    "drive": "https://www.googleapis.com/auth/drive",
}
CALLBACK_PATH = "/storage/oauth/callback"
MODES = ("redirect", "paste")
FLOW_TTL = 600.0  # seconds
MAX_FLOWS = 64  # pending at once; the oldest goes first
TOKEN_TIMEOUT = 15.0
MAX_RESPONSE = 64 * 1024
MAX_PASTE = 4096
# Tokens go into rclone's connection string: no quotes, brackets or control characters.
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]{1,4096}")
CODE_RE = re.compile(r"[A-Za-z0-9._~+/=-]{1,2048}")
STATE_RE = re.compile(r"[A-Za-z0-9_-]{43}")

USED = "This connection attempt expired or was already used. Connect again."
NOT_YOURS = "This connection attempt was started by another user, or for another storage."


class OAuthError(Exception):
    """The message is safe to show."""


@dataclass(frozen=True)
class Flow:
    verifier: str
    user_id: int
    storage_id: int
    redirect_uri: str
    expires: float  # time.monotonic()
    client_id: str = ""  # the client and scope the consent page asked for: a flow
    scope: str = ""  # completes only while the target still has them


class Flows:
    """Pending flows (see the module docstring). Thread-safe."""

    def __init__(self) -> None:
        self._flows: dict[bytes, Flow] = {}
        self._lock = threading.Lock()

    def start(
        self, user_id: int, storage_id: int, redirect_uri: str, client_id: str, scope: str
    ) -> tuple[str, str]:
        """A new flow: its state and PKCE challenge."""
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = b64(hashlib.sha256(verifier.encode()).digest())
        now = time.monotonic()
        flow = Flow(verifier, user_id, storage_id, redirect_uri, now + FLOW_TTL, client_id, scope)
        with self._lock:
            self._flows = {k: f for k, f in self._flows.items() if f.expires > now}
            while len(self._flows) >= MAX_FLOWS:
                del self._flows[next(iter(self._flows))]
            self._flows[key(state)] = flow
        return state, challenge

    def take(self, state: str, user_id: int, storage_id: int | None = None) -> Flow:
        """Removes and returns the flow of state, if it is live and this user's (and, given
        storage_id, that target's). Raises OAuthError; the flow is gone either way."""
        with self._lock:
            flow = self._flows.pop(key(state), None) if STATE_RE.fullmatch(state) else None
        if flow is None or flow.expires <= time.monotonic():
            raise OAuthError(USED)
        if flow.user_id != user_id or storage_id not in (None, flow.storage_id):
            raise OAuthError(NOT_YOURS)
        return flow


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def key(state: str) -> bytes:
    return hashlib.sha256(state.encode()).digest()


def redirect_uri(mode: str, base_url: str) -> str:
    if mode == "redirect":
        return base_url.rstrip("/") + CALLBACK_PATH
    return f"http://127.0.0.1:{secrets.randbelow(16384) + 49152}/"


def authorize_url(client_id: str, scope: str, redirect: str, state: str, challenge: str) -> str:
    query = {
        "client_id": client_id,
        "redirect_uri": redirect,
        "response_type": "code",
        "scope": SCOPES[scope],
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_URL}?{urlencode(query)}"


def pasted(url: str) -> tuple[str, str, str]:
    """(state, code, the redirect URI it arrived at) from the address the user pasted.
    Raises OAuthError."""
    url = url.strip()
    if not url or len(url) > MAX_PASTE:
        raise OAuthError("Paste the whole address from the browser's address bar.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise OAuthError("That is not the address Google redirected to.") from None
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or not port:
        raise OAuthError("That is not the address Google redirected to.")
    if parts.path not in ("", "/") or parts.username or parts.password or parts.fragment:
        raise OAuthError("That is not the address Google redirected to.")
    try:
        query = parse_qs(parts.query, max_num_fields=16)
    except ValueError:  # too many fields
        raise OAuthError("That is not the address Google redirected to.") from None
    if "error" in query:
        raise OAuthError(denied(query["error"][0]))
    state, code = query.get("state", [""]), query.get("code", [""])
    if len(state) != 1 or len(code) != 1:
        raise OAuthError("The address holds no answer from Google. Paste all of it.")
    return state[0], code[0], f"http://127.0.0.1:{port}/"


def denied(error: str) -> str:
    if error == "access_denied":
        return "Access was not granted on Google's page."
    return "Google did not grant access."


def exchange(code: str, flow: Flow, client_id: str, client_secret: str) -> str:
    """Trades the code (and the PKCE verifier) for tokens; returns rclone's token JSON.
    Raises OAuthError."""
    if not CODE_RE.fullmatch(code):
        raise OAuthError("Google's answer holds no valid code. Connect again.")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": flow.redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": flow.verifier,
    }
    try:
        with httpx.Client(timeout=TOKEN_TIMEOUT, trust_env=False) as client:
            response = client.post(TOKEN_URL, data=form)  # no redirects followed
    except httpx.HTTPError as exc:
        log.warning("Google token request failed: %s", type(exc).__name__)
        raise OAuthError("Google could not be reached. Try again.") from None
    body = parse_body(response.content)
    if response.status_code != 200:
        error = str(body.get("error", ""))
        log.warning("Google refused the code: %s %s", response.status_code, error[:64])
        if error == "invalid_client":
            raise OAuthError("Google refused the client ID or secret.")
        if error == "redirect_uri_mismatch":
            raise OAuthError("The OAuth client does not allow this redirect URI.")
        raise OAuthError("Google refused the code: it expired or was used. Connect again.")
    access, refresh = body.get("access_token"), body.get("refresh_token")
    expires_in = body.get("expires_in")
    if not isinstance(refresh, str) or not TOKEN_RE.fullmatch(refresh):
        raise OAuthError("Google returned no refresh token. Connect again.")
    if not isinstance(access, str) or not TOKEN_RE.fullmatch(access):
        raise OAuthError("Google returned no valid access token. Connect again.")
    if type(expires_in) is not int or not 0 < expires_in < 86400:
        expires_in = 0  # rclone refreshes at once
    expiry = datetime.now(UTC) + timedelta(seconds=expires_in)
    return json.dumps(
        {
            "access_token": access,
            "token_type": "Bearer",
            "refresh_token": refresh,
            "expiry": expiry.isoformat(timespec="seconds").replace("+00:00", "Z"),
        },
        separators=(",", ":"),
    )


def parse_body(content: bytes) -> dict[str, Any]:
    try:
        body = json.loads(content[:MAX_RESPONSE])
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


# RECONNECT REQUIRED


def mark_reconnect(
    sessions: sessionmaker[Session], crypto: Crypto, notify: Any, storage_id: int, token: str
) -> None:
    """Marks a drive target "reconnect required" after Google answered invalid_grant to
    token, and tells the notification targets of its jobs, once. A token connecting again
    replaced meanwhile marks nothing. Never raises."""
    try:
        with sessions() as db, db.begin():
            target = db.get(StorageTarget, storage_id)
            if target is None or target.kind != "drive":
                return
            config = json.loads(crypto.decrypt(target.config_enc))
            if not isinstance(config, dict) or config.get("reconnect"):
                return
            if config.get("token") != token:
                log.info("Storage %d: a replaced token was refused; nothing to mark", storage_id)
                return
            config["reconnect"] = True
            target.config_enc = crypto.encrypt(json.dumps(config))
            audit.record(
                db,
                actor="drydock",
                action="storage.oauth_revoked",
                target=f"storage:{storage_id}",
                outcome="failure",
                details={"name": target.name},
            )
        log.warning("Storage %d: Google refused drydock's access; reconnect required", storage_id)
        if notify is not None:
            notify(storage_id)
    except CryptoError, ValueError:
        log.warning("Storage %d: cannot mark it reconnect required", storage_id)
    except Exception:
        log.exception("Storage %d: cannot mark it reconnect required", storage_id)
