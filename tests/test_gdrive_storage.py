"""Google Drive storage (Phase 6f): connecting with the user's own OAuth client against a
fake Google token endpoint (PKCE, both redirect modes, single-use user-bound states), what
reaches rclone, and "reconnect required" after invalid_grant.

Transfers to a real drive need a real Google account: that check is manual (PLAN.md)."""

import base64
import hashlib
import html
import json
import re
import secrets
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from drydock import notify
from drydock.storage import gdrive_oauth
from drydock.storage.base import StorageError
from drydock.storage.rclone import (
    FIXED,
    NOT_CONNECTED,
    RECONNECT,
    RcloneBackend,
    ReconnectRequired,
    settings_for,
)
from drydock.storage.rclone_rc import RcloneError
from tests.conftest import Browser, add_user
from tests.test_jobs import add_job, add_storage, start_run
from tests.test_notify import new_target
from tests.test_sftp_storage import fake_host, finished

__all__ = ["fake_host"]  # a fixture used here

pytestmark = pytest.mark.anyio

CLIENT_ID = "1234-abc.apps.googleusercontent.com"
CLIENT_SECRET = "client-secret-5e2c"


# A FAKE GOOGLE


class FakeGoogle:
    """Google's consent page and token endpoint, as far as drydock sees them."""

    def __init__(self) -> None:
        self.codes: dict[str, dict[str, str]] = {}
        self.token_requests: list[dict[str, str]] = []
        self.answer: tuple[int, bytes] | None = None  # replaces a valid code's answer

    def consent(self, auth_url: str, *, challenge: str | None = None) -> dict[str, str]:
        """Grants access on the consent page: the query Google redirects back with."""
        parts = urlsplit(auth_url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == gdrive_oauth.AUTH_URL
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        assert query["response_type"] == "code" and query["client_id"] == CLIENT_ID
        assert query["access_type"] == "offline" and query["prompt"] == "consent"
        assert query["code_challenge_method"] == "S256"
        assert query["scope"] == gdrive_oauth.SCOPES["drive.file"]
        code = "4/" + secrets.token_urlsafe(24)
        self.codes[code] = {
            "challenge": challenge or query["code_challenge"],
            "redirect_uri": query["redirect_uri"],
        }
        return {"state": query["state"], "code": code, "redirect_uri": query["redirect_uri"]}

    def token(self, form: dict[str, str]) -> tuple[int, dict]:
        self.token_requests.append(form)
        grant = self.codes.pop(form.get("code", ""), None)
        if form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET:
            return 401, {"error": "invalid_client"}
        if grant is None or form.get("grant_type") != "authorization_code":
            return 400, {"error": "invalid_grant"}
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return 400, {"error": "redirect_uri_mismatch"}
        digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
        if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != grant["challenge"]:
            return 400, {"error": "invalid_grant", "error_description": "Bad code verifier"}
        if self.answer is not None:
            return self.answer
        return 200, {
            "access_token": "ya29." + secrets.token_urlsafe(32),
            "refresh_token": "1//" + secrets.token_urlsafe(32),
            "expires_in": 3599,
            "token_type": "Bearer",
            "scope": gdrive_oauth.SCOPES["drive.file"],
        }


@pytest.fixture
def google(monkeypatch) -> Iterator[FakeGoogle]:
    fake = FakeGoogle()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
            status, body = fake.token(form) if self.path == "/token" else (404, {})
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(gdrive_oauth, "TOKEN_URL", f"http://127.0.0.1:{server.server_port}/token")
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


# HELPERS


async def add_drive(browser: Browser, name: str = "gdrive", **fields: str) -> int:
    form = {
        "name": name,
        "kind": "drive",
        "enabled": "1",
        "opt_client_id": CLIENT_ID,
        "opt_client_secret": CLIENT_SECRET,
        "folder": "backups",
    } | fields
    response = await browser.post("/storage", form)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def config(browser: Browser, storage_id: int) -> dict:
    (blob,) = browser.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,))[0]
    return json.loads(browser.app.state.crypto.decrypt(blob))


async def start(browser: Browser, storage_id: int, mode: str = "redirect") -> str:
    """Starts a flow; returns Google's consent URL."""
    headers = {"HX-Request": "true"} if mode == "redirect" else {}
    response = await browser.post(
        f"/storage/{storage_id}/oauth/start", {"mode": mode}, headers=headers
    )
    if mode == "redirect":
        assert response.status_code == 204, response.text
        return response.headers["HX-Redirect"]
    assert response.status_code == 200, response.text
    match = re.search(r'href="(https://accounts\.google\.com/[^"]+)"', response.text)
    assert match, "no consent link"
    return html.unescape(match[1])


async def callback(browser: Browser, answer: dict[str, str]):
    query = urlencode({k: v for k, v in answer.items() if k != "redirect_uri"})
    return await browser.get(f"/storage/oauth/callback?{query}")


def audits(browser: Browser, action: str) -> list[tuple[str, str]]:
    return browser.sql(
        "SELECT outcome, details FROM audit_events WHERE action = ? ORDER BY id", (action,)
    )


# REDIRECT MODE


async def test_redirect_mode_connects_once(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    assert "not connected" in (await admin.get(f"/storage/{storage_id}")).text
    url = await start(admin, storage_id)
    answer = google.consent(url)
    assert answer["redirect_uri"] == "https://drydock.test/storage/oauth/callback"
    response = await callback(admin, answer)
    assert response.status_code == 303, response.text
    assert response.headers["location"] == f"/storage/{storage_id}"
    token = json.loads(config(admin, storage_id)["token"])
    assert token["refresh_token"].startswith("1//") and token["token_type"] == "Bearer"
    assert token["access_token"].startswith("ya29.") and token["expiry"].endswith("Z")
    page = (await admin.get(f"/storage/{storage_id}")).text
    assert ">connected<" in page and token["refresh_token"] not in page
    assert token["access_token"] not in (await admin.get("/storage")).text
    assert [o for o, _ in audits(admin, "storage.oauth_start")] == ["success"]
    assert [o for o, _ in audits(admin, "storage.oauth_connect")] == ["success"]
    assert CLIENT_SECRET not in str(admin.sql("SELECT details FROM audit_events"))
    # The state works once.
    before = config(admin, storage_id)
    replay = await callback(admin, answer)
    assert replay.status_code == 400 and gdrive_oauth.USED in replay.text
    assert config(admin, storage_id) == before


async def test_the_verifier_must_match_the_challenge(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id), challenge="not-the-challenge")
    response = await callback(admin, answer)
    assert response.status_code == 400 and "Google refused the code" in response.text
    assert "token" not in config(admin, storage_id)
    assert [o for o, _ in audits(admin, "storage.oauth_connect")] == ["failure"]
    assert google.token_requests[0]["code_verifier"]  # sent, and refused


async def test_a_state_is_bound_to_its_user(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id))
    await add_user(admin, "other", "superadmin")
    await admin.login("other")
    response = await callback(admin, answer)
    assert response.status_code == 400 and "started by another user" in response.text
    await admin.login("admin")
    response = await callback(admin, answer)  # gone: a state is single-use whatever happens
    assert response.status_code == 400 and gdrive_oauth.USED in response.text
    assert google.token_requests == [] and "token" not in config(admin, storage_id)


async def test_a_state_expires(admin: Browser, google: FakeGoogle, monkeypatch) -> None:
    storage_id = await add_drive(admin)
    monkeypatch.setattr(gdrive_oauth, "FLOW_TTL", 0.0)
    answer = google.consent(await start(admin, storage_id))
    response = await callback(admin, answer)
    assert response.status_code == 400 and gdrive_oauth.USED in response.text
    assert google.token_requests == []


@pytest.mark.parametrize("state", ["", "x" * 43, "bad state!"])
async def test_unknown_states_are_refused(admin: Browser, google: FakeGoogle, state: str) -> None:
    await add_drive(admin)
    response = await admin.get(f"/storage/oauth/callback?{urlencode({'state': state})}&code=4/x")
    assert response.status_code == 400 and google.token_requests == []


async def test_a_refusal_on_googles_page(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id))
    response = await callback(admin, {"state": answer["state"], "error": "access_denied"})
    assert response.status_code == 400 and "Access was not granted" in response.text
    assert google.token_requests == [] and "token" not in config(admin, storage_id)


# PASTE MODE


async def test_paste_mode_connects(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id, "paste"))
    redirect = answer["redirect_uri"]
    assert re.fullmatch(r"http://127\.0\.0\.1:\d{5}/", redirect)
    pasted = f"{redirect}?state={answer['state']}&code={answer['code']}&scope=x"
    response = await admin.post(f"/storage/{storage_id}/oauth/paste", {"url": pasted})
    assert response.status_code == 303, response.text
    assert json.loads(config(admin, storage_id)["token"])["refresh_token"]


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda url: url.replace("127.0.0.1", "localhost"),
        lambda url: url.replace("127.0.0.1", "127.0.0.2"),
        lambda url: re.sub(r":(\d+)/", lambda m: f":{int(m[1]) + 1}/", url),
        lambda url: url.replace("http://", "https://"),
        lambda url: url.replace("/?", "/x?"),
    ],
)
async def test_a_pasted_address_must_be_the_loopback_one(
    admin: Browser, google: FakeGoogle, rewrite
) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id, "paste"))
    url = rewrite(f"{answer['redirect_uri']}?state={answer['state']}&code={answer['code']}")
    response = await admin.post(f"/storage/{storage_id}/oauth/paste", {"url": url})
    assert response.status_code == 422 and "not the address Google redirected to" in response.text
    assert google.token_requests == [] and "token" not in config(admin, storage_id)


async def test_a_flow_completes_only_for_its_storage(admin: Browser, google: FakeGoogle) -> None:
    first, second = await add_drive(admin, "one"), await add_drive(admin, "two")
    answer = google.consent(await start(admin, first, "paste"))
    url = f"{answer['redirect_uri']}?state={answer['state']}&code={answer['code']}"
    response = await admin.post(f"/storage/{second}/oauth/paste", {"url": url})
    assert response.status_code == 422 and "for another storage" in response.text
    assert "token" not in config(admin, first) and "token" not in config(admin, second)


# ROUTES AND ROLES


async def test_starting_is_a_post(admin: Browser) -> None:
    storage_id = await add_drive(admin)
    assert (await admin.get(f"/storage/{storage_id}/oauth/start")).status_code == 405


async def test_only_superadmins_with_recent_auth_connect(
    admin: Browser, google: FakeGoogle
) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id))
    await add_user(admin, "plain", "admin")
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    response = await admin.post(f"/storage/{storage_id}/oauth/start", {"mode": "redirect"})
    assert response.status_code == 403
    await admin.login("plain")
    for path, data in (
        (f"/storage/{storage_id}/oauth/start", {"mode": "redirect"}),
        (f"/storage/{storage_id}/oauth/paste", {"url": "http://127.0.0.1:50000/?state=x&code=y"}),
    ):
        assert (await admin.post(path, data)).status_code == 403
    assert (await callback(admin, answer)).status_code == 403
    assert "Google connection" in (await admin.get(f"/storage/{storage_id}")).text
    assert (await admin.get("/storage/oauth/guide")).status_code == 200


async def test_the_guide_names_the_redirect_uri(admin: Browser) -> None:
    page = (await admin.get("/storage/oauth/guide")).text
    assert "https://drydock.test/storage/oauth/callback" in page and "Publish the app" in page


async def test_a_new_client_drops_the_token(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    await callback(admin, google.consent(await start(admin, storage_id)))
    form = {
        "name": "gdrive",
        "kind": "drive",
        "enabled": "1",
        "opt_client_id": CLIENT_ID,
        "opt_root_folder_id": "folder-1",
        "folder": "backups",
    }
    response = await admin.post(f"/storage/{storage_id}", form)  # the secret is kept
    assert response.status_code == 303, response.text
    assert "token" in config(admin, storage_id)
    other = "5678-def.apps.googleusercontent.com"
    form |= {"opt_client_id": other, "opt_client_secret": "new-secret"}
    response = await admin.post(f"/storage/{storage_id}", form)
    assert response.status_code == 303, response.text
    assert "token" not in config(admin, storage_id)
    assert "not connected" in (await admin.get(f"/storage/{storage_id}")).text


# WHAT REACHES RCLONE


def test_settings_for_drive() -> None:
    stored = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "scope": "drive.file"}
    base = {"folder": "backups", "options": stored}
    with pytest.raises(StorageError, match=NOT_CONNECTED):
        settings_for("drive", base, lambda secret: secret)
    token = json.dumps({"access_token": "a", "refresh_token": "r", "token_type": "Bearer"})
    with pytest.raises(StorageError, match="refused drydock's access"):
        settings_for("drive", base | {"token": token, "reconnect": True}, lambda s: s)
    values = settings_for("drive", base | {"token": token}, lambda secret: secret)
    assert values["token"] == token and values["client_secret"] == CLIENT_SECRET
    for name, value in FIXED["drive"].items():
        assert values[name] == value
    assert values["token_url"] == "" and values["service_account_file"] == ""
    for planted in ({"token_url": "https://evil.example/token"}, {"service_account_file": "/x"}):
        bad = {"folder": "", "options": stored | planted, "token": token}
        with pytest.raises(StorageError):
            settings_for("drive", bad, lambda secret: secret)
    storage = RcloneBackend(None, "drive", base | {"token": token}, Path("/nonexistent"))  # type: ignore[arg-type]
    assert {token, "a", "r", CLIENT_SECRET} <= set(storage._secrets())


def test_invalid_grant_needs_a_reconnect() -> None:
    told: list[str] = []
    token = json.dumps({"access_token": "ya29.access-x", "refresh_token": "1//refresh-x"})
    storage = RcloneBackend(
        None,  # type: ignore[arg-type]
        "drive",
        {"folder": "", "options": {"client_id": CLIENT_ID}, "token": token},
        Path("/nonexistent"),
        told.append,
    )
    text = 'couldn\'t fetch token: oauth2: "invalid_grant" "Token has been expired or revoked."'
    error = storage._error(RcloneError(500, text))
    assert isinstance(error, ReconnectRequired) and str(error) == RECONNECT and told == [token]
    other = storage._error(RcloneError(500, "some other failure"))
    assert not isinstance(other, ReconnectRequired) and told == [token]


async def test_a_revoked_grant_marks_the_storage_and_notifies_once(
    admin: Browser, google: FakeGoogle, monkeypatch
) -> None:
    storage_id = await add_drive(admin)
    await callback(admin, google.consent(await start(admin, storage_id)))
    target_id = await new_target(admin, webhook_url="https://hooks.example/drydock")
    await add_job(
        admin,
        storage_id=str(storage_id),
        notifications="1",
        notify_failure=str(target_id),
    )
    sent: list[tuple[str, str]] = []
    done = threading.Event()

    def send(name, url, title, body, *, failure):
        sent.append((name, title))
        done.set()
        return notify.Outcome(name, True, "ok")

    monkeypatch.setattr(notify, "send", send)

    def revoked(self) -> None:
        raise self._error(RcloneError(500, 'oauth2: "invalid_grant" "Token has been revoked."'))

    monkeypatch.setattr(RcloneBackend, "test", revoked)
    page = (await admin.post(f"/storage/{storage_id}/test")).text
    assert "Connect it again on its storage page" in page
    assert config(admin, storage_id)["reconnect"] is True
    assert done.wait(10)
    assert sent == [("ops", "drydock: storage gdrive needs reconnecting")]
    assert [o for o, _ in audits(admin, "storage.oauth_revoked")] == ["failure"]
    await admin.post(f"/storage/{storage_id}/test")  # already marked: no second message
    assert len(audits(admin, "storage.oauth_revoked")) == 1
    assert "reconnect required" in (await admin.get("/storage")).text
    # Connecting again clears it.
    await callback(admin, google.consent(await start(admin, storage_id)))
    assert "reconnect" not in config(admin, storage_id)
    assert len(sent) == 1


# AUDIT FOLLOW-UPS


def good_answer(**changes) -> tuple[int, bytes]:
    body = {
        "access_token": "ya29.access",
        "refresh_token": "1//refresh",
        "expires_in": 3599,
        "token_type": "Bearer",
    } | changes
    return 200, json.dumps({k: v for k, v in body.items() if v is not None}).encode()


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (good_answer(refresh_token=None), "no refresh token"),
        (good_answer(refresh_token='1//r"x'), "no refresh token"),
        (good_answer(refresh_token="1//r\nx"), "no refresh token"),
        (good_answer(access_token="a]b"), "no valid access token"),
        (good_answer(access_token=None), "no valid access token"),
        ((200, b"not json"), "no refresh token"),
        ((401, b'{"error": "invalid_client"}'), "refused the client ID or secret"),
        ((400, b'{"error": "redirect_uri_mismatch"}'), "does not allow this redirect URI"),
        ((500, b"<html>"), "Google refused the code"),
    ],
)
async def test_googles_answer_is_checked(
    admin: Browser, google: FakeGoogle, answer: tuple[int, bytes], message: str
) -> None:
    storage_id = await add_drive(admin)
    google.answer = answer
    response = await callback(admin, google.consent(await start(admin, storage_id)))
    assert response.status_code == 400 and message in response.text
    assert "token" not in config(admin, storage_id)
    assert [o for o, _ in audits(admin, "storage.oauth_connect")] == ["failure"]


@pytest.mark.parametrize("expires_in", [True, -1, 10**9, "3599"])
async def test_an_odd_lifetime_means_refresh_at_once(
    admin: Browser, google: FakeGoogle, expires_in
) -> None:
    storage_id = await add_drive(admin)
    google.answer = good_answer(expires_in=expires_in)
    response = await callback(admin, google.consent(await start(admin, storage_id)))
    assert response.status_code == 303
    expiry = json.loads(config(admin, storage_id)["token"])["expiry"]
    assert expiry <= datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def test_flows_last_ten_minutes(monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(gdrive_oauth.time, "monotonic", lambda: clock[0])
    flows = gdrive_oauth.Flows()
    state, _ = flows.start(1, 2, "https://x/cb", CLIENT_ID, "drive.file")
    clock[0] += 599
    assert flows.take(state, 1, 2).storage_id == 2
    state, _ = flows.start(1, 2, "https://x/cb", CLIENT_ID, "drive.file")
    clock[0] += 600
    with pytest.raises(gdrive_oauth.OAuthError, match="expired"):
        flows.take(state, 1, 2)


async def test_a_flow_ends_if_the_scope_changes(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id))
    form = {
        "name": "gdrive",
        "kind": "drive",
        "enabled": "1",
        "opt_client_id": CLIENT_ID,
        "opt_client_secret": CLIENT_SECRET,
        "opt_scope": "drive",
        "folder": "backups",
    }
    assert (await admin.post(f"/storage/{storage_id}", form)).status_code == 303
    response = await callback(admin, answer)
    assert response.status_code == 400 and "client or access changed" in response.text
    assert google.token_requests == [] and "token" not in config(admin, storage_id)


async def test_too_many_fields_in_a_pasted_address(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    answer = google.consent(await start(admin, storage_id, "paste"))
    extra = "&".join(f"x{i}=1" for i in range(20))
    url = f"{answer['redirect_uri']}?state={answer['state']}&code={answer['code']}&{extra}"
    response = await admin.post(f"/storage/{storage_id}/oauth/paste", {"url": url})
    assert response.status_code == 422 and "not the address Google redirected to" in response.text


async def test_a_replaced_token_marks_nothing(admin: Browser, google: FakeGoogle) -> None:
    storage_id = await add_drive(admin)
    await callback(admin, google.consent(await start(admin, storage_id)))
    state = admin.app.state
    state.mark_reconnect(storage_id, json.dumps({"access_token": "old", "refresh_token": "old"}))
    assert "reconnect" not in config(admin, storage_id)
    assert audits(admin, "storage.oauth_revoked") == []
    state.mark_reconnect(storage_id, config(admin, storage_id)["token"])
    assert config(admin, storage_id)["reconnect"] is True


async def test_only_drive_targets_are_marked_or_connected(admin: Browser) -> None:
    local_id = await add_storage(admin)
    admin.app.state.mark_reconnect(local_id, "")
    assert audits(admin, "storage.oauth_revoked") == []
    for path in ("oauth/start", "oauth/paste"):
        data = {"mode": "redirect", "url": "http://127.0.0.1:50000/?state=x&code=y"}
        assert (await admin.post(f"/storage/{local_id}/{path}", data)).status_code == 404
    told: list[str] = []
    sftp = {"folder": "", "options": {"host": "h"}}
    storage = RcloneBackend(None, "sftp", sftp, Path("/nonexistent"), told.append)  # type: ignore[arg-type]
    error = storage._error(RcloneError(500, "invalid_grant"))
    assert not isinstance(error, ReconnectRequired) and told == []


async def test_listing_a_refused_drive_writes_nothing(
    admin: Browser, google: FakeGoogle, monkeypatch
) -> None:
    storage_id = await add_drive(admin)
    await callback(admin, google.consent(await start(admin, storage_id)))

    def refused(self, prefix=""):
        raise self._error(RcloneError(500, 'oauth2: "invalid_grant"'))

    monkeypatch.setattr(RcloneBackend, "list", refused)
    before = config(admin, storage_id)
    page = (await admin.get(f"/restore/storage/{storage_id}")).text
    assert "Connect it again on its storage page" in page
    assert config(admin, storage_id) == before
    assert audits(admin, "storage.oauth_revoked") == []


async def test_a_backup_refused_by_google_marks_the_storage(
    admin: Browser, google: FakeGoogle, fake_host: dict, monkeypatch
) -> None:
    storage_id = await add_drive(admin)
    await callback(admin, google.consent(await start(admin, storage_id)))
    target_id = await new_target(admin, webhook_url="https://hooks.example/drydock")
    job_id = await add_job(
        admin,
        storage_id=str(storage_id),
        encrypted="",
        notifications="1",
        notify_failure=str(target_id),
    )
    sent: list[str] = []
    done = threading.Event()

    def send(name, url, title, body, *, failure):
        sent.append(title)
        if "reconnecting" in title:
            done.set()
        return notify.Outcome(name, True, "ok")

    monkeypatch.setattr(notify, "send", send)

    def refused(self, local, name, progress, cancel):
        raise self._error(RcloneError(500, 'oauth2: "invalid_grant" "Token has been revoked."'))

    monkeypatch.setattr(RcloneBackend, "put", refused)
    run_id = await start_run(admin, job_id)
    assert await finished(admin, run_id) == "failed"
    (error,) = admin.sql("SELECT error FROM runs WHERE id = ?", (run_id,))[0]
    assert error == RECONNECT
    assert config(admin, storage_id)["reconnect"] is True
    assert len(audits(admin, "storage.oauth_revoked")) == 1
    assert done.wait(10) and "drydock: storage gdrive needs reconnecting" in sent
