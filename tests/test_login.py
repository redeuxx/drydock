import logging
import sqlite3
from contextlib import closing
from datetime import timedelta

import pytest
from argon2 import PasswordHasher

from drydock.models import utcnow
from drydock.security import passwords
from drydock.security.sessions import cookie_name
from tests.conftest import (
    PASSWORD,
    Browser,
    add_user,
    make_settings,
    running,
    sqlite_ts,
    without_nonces,
)

pytestmark = pytest.mark.anyio


class SpyHasher(PasswordHasher):
    def __init__(self) -> None:
        super().__init__()
        self.verify_calls = 0

    def verify(self, hash_: str | bytes, password: str | bytes) -> bool:
        self.verify_calls += 1
        return super().verify(hash_, password)


async def test_wrong_username_and_wrong_password_look_identical(
    admin: Browser, monkeypatch
) -> None:
    spy = SpyHasher()
    monkeypatch.setattr(passwords, "_hasher", spy)
    admin.client.cookies.clear()
    unknown = await admin.login("nobody", PASSWORD)
    assert spy.verify_calls == 1
    wrong = await admin.login("admin", "wrong password!!")
    assert spy.verify_calls == 2
    assert unknown.status_code == wrong.status_code == 422
    assert without_nonces(unknown.text) == without_nonces(wrong.text)
    assert "nobody" not in unknown.text
    rows = admin.sql("SELECT actor, outcome FROM audit_events WHERE action='auth.login'")
    assert rows == [(None, "failure"), ("admin", "failure")]


async def test_failed_login_never_stores_the_submitted_username(admin: Browser) -> None:
    admin.client.cookies.clear()
    await admin.login(PASSWORD)  # a password typed into the username field
    await admin.login("ADMIN", "wrong password!!")
    dump = "\n".join(admin.db().iterdump())
    assert PASSWORD not in dump
    rows = admin.sql("SELECT actor FROM audit_events WHERE action='auth.login'")
    assert rows == [(None,), ("admin",)]  # the canonical name, not what was typed


class LockCheckingHasher(PasswordHasher):
    """Fails if the request still holds SQLite's write lock while Argon2 runs."""

    def __init__(self, browser: Browser) -> None:
        super().__init__()
        self.browser = browser
        self.calls: list[str] = []

    def assert_unlocked(self, name: str) -> None:
        self.calls.append(name)
        db_path = self.browser.settings.data_dir / "drydock.db"
        with closing(sqlite3.connect(db_path, timeout=0)) as conn:
            conn.execute("BEGIN IMMEDIATE")  # "database is locked" if the request holds it
            conn.rollback()

    def verify(self, hash_: str | bytes, password: str | bytes) -> bool:
        self.assert_unlocked("verify")
        return super().verify(hash_, password)

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        self.assert_unlocked("hash")
        return super().hash(password, salt=salt)


async def test_login_hashes_outside_the_write_lock(admin: Browser, monkeypatch) -> None:
    old_hash = admin.sql("SELECT password_hash FROM users")[0][0]
    passwords._dummy_hash()  # cached now, so it does not show up as a hash call
    hasher = LockCheckingHasher(admin)
    monkeypatch.setattr(passwords, "_hasher", hasher)
    monkeypatch.setattr(passwords, "needs_rehash", lambda _hash: True)
    admin.client.cookies.clear()
    assert (await admin.login("nobody")).status_code == 422
    assert (await admin.login("admin", "wrong password!!")).status_code == 422
    assert (await admin.login("admin")).status_code == 303
    assert hasher.calls == ["verify", "verify", "verify", "hash"]
    assert admin.sql("SELECT password_hash FROM users")[0][0] != old_hash  # rehashed


async def test_password_changed_during_verify_fails_the_login(admin: Browser, monkeypatch) -> None:
    class RacingHasher(PasswordHasher):
        def verify(self, hash_: str | bytes, password: str | bytes) -> bool:
            result = super().verify(hash_, password)
            admin.sql("UPDATE users SET password_hash = 'changed meanwhile'")
            return result

    monkeypatch.setattr(passwords, "_hasher", RacingHasher())
    admin.client.cookies.clear()
    sessions_before = admin.sql("SELECT COUNT(*) FROM sessions")
    assert (await admin.login("admin")).status_code == 422
    assert admin.sql("SELECT COUNT(*) FROM sessions") == sessions_before


async def test_disabled_user_gets_the_same_failure(admin: Browser) -> None:
    user_id = await add_user(admin, "bob", "viewer")
    await admin.post(f"/users/{user_id}/disabled", {"disabled": "1"})
    bad = await admin.login("nobody")
    disabled = await admin.login("bob")
    assert disabled.status_code == bad.status_code == 422
    assert without_nonces(disabled.text) == without_nonces(bad.text)


async def test_eleventh_failure_is_rate_limited(admin: Browser) -> None:
    admin.client.cookies.clear()
    for _ in range(10):
        assert (await admin.login("admin", "wrong password!!")).status_code == 422
    assert (await admin.login("admin", "wrong password!!")).status_code == 429
    assert (await admin.login("admin", PASSWORD)).status_code == 429
    assert (await admin.login("ADMIN", PASSWORD)).status_code == 429  # case-insensitive key


async def test_forwarded_for_ignored_from_untrusted_peer(tmp_path) -> None:
    settings = make_settings(tmp_path / "data")  # FORWARDED_ALLOW_IPS defaults to 127.0.0.1
    async with running(settings, client_ip="10.0.0.2") as browser:
        await browser.setup()
        browser.client.cookies.clear()
        for i in range(10):
            browser.client.headers["X-Forwarded-For"] = f"198.51.100.{i}"
            await browser.login("admin", "wrong password!!")
        browser.client.headers["X-Forwarded-For"] = "198.51.100.200"
        assert (await browser.login("admin", "wrong password!!")).status_code == 429
        ips = browser.sql("SELECT DISTINCT ip FROM audit_events WHERE action='auth.login'")
        assert ips == [("10.0.0.2",)]


async def test_forwarded_for_honored_from_trusted_proxy(tmp_path) -> None:
    settings = make_settings(tmp_path / "data", FORWARDED_ALLOW_IPS="10.0.0.1")
    async with running(settings, client_ip="10.0.0.1") as browser:
        await browser.setup()
        browser.client.cookies.clear()
        for i in range(11):
            browser.client.headers["X-Forwarded-For"] = f"198.51.100.{i}"
            assert (await browser.login("admin", "wrong password!!")).status_code == 422
        ips = browser.sql("SELECT ip FROM audit_events WHERE action='auth.login'")
        assert ips[0] == ("198.51.100.0",)
        browser.client.headers["X-Forwarded-For"] = "198.51.100.77"
        for _ in range(10):
            await browser.login("admin", "wrong password!!")
        assert (await browser.login("admin", PASSWORD)).status_code == 429


async def test_login_rotates_session_and_stores_only_hashes(admin: Browser) -> None:
    name = cookie_name(admin.settings)
    first = admin.client.cookies[name]
    response = await admin.login("admin")
    assert response.status_code == 303
    second = admin.client.cookies[name]
    assert second != first
    admin.client.cookies.clear()
    response = await admin.get("/", headers={"Cookie": f"{name}={first}"})
    assert response.status_code == 303  # the old session was revoked on login
    dump = "\n".join(admin.db().iterdump())
    assert first not in dump
    assert second not in dump


async def test_idle_and_absolute_timeouts(admin: Browser) -> None:
    assert (await admin.get("/")).status_code == 200
    old = sqlite_ts(utcnow() - timedelta(hours=1, minutes=1))
    admin.sql("UPDATE sessions SET last_seen_at = ?", (old,))
    response = await admin.get("/")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    await admin.login("admin")
    assert (await admin.get("/")).status_code == 200
    admin.sql("UPDATE sessions SET expires_at = ?", (sqlite_ts(utcnow() - timedelta(seconds=1)),))
    assert (await admin.get("/")).status_code == 303


async def test_htmx_request_without_session_gets_401(fresh: Browser) -> None:
    await fresh.setup()
    fresh.client.cookies.clear()
    response = await fresh.get("/account", headers={"HX-Request": "true"})
    assert response.status_code == 401


async def test_logout_ends_the_session(admin: Browser) -> None:
    response = await admin.post("/logout")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert admin.sql("SELECT COUNT(*) FROM sessions") == [(0,)]
    assert (await admin.get("/")).status_code == 303
    assert admin.sql("SELECT action FROM audit_events ORDER BY id DESC LIMIT 1") == [
        ("auth.logout",)
    ]


async def test_password_change_revokes_other_sessions(admin: Browser) -> None:
    name = cookie_name(admin.settings)
    old_cookie = admin.client.cookies[name]
    response = await admin.post(
        "/account/password",
        {"current_password": "wrong", "new_password": "x" * 12, "new_password_confirm": "x" * 12},
    )
    assert response.status_code == 422
    new_password = "a brand new passphrase"
    response = await admin.post(
        "/account/password",
        {
            "current_password": PASSWORD,
            "new_password": new_password,
            "new_password_confirm": new_password,
        },
    )
    assert response.status_code == 303
    assert admin.client.cookies[name] != old_cookie
    assert (await admin.get("/account")).status_code == 200
    assert admin.sql("SELECT COUNT(*) FROM sessions") == [(1,)]
    admin.client.cookies.clear()
    assert (await admin.login("admin", PASSWORD)).status_code == 422
    assert (await admin.login("admin", new_password)).status_code == 303


@pytest.mark.parametrize(
    ("env", "warns"),
    [
        ({}, True),
        ({"FORWARDED_ALLOW_IPS": "172.18.0.1"}, False),
        ({"DRYDOCK_BASE_URL": "http://localhost:8000"}, False),
        ({"DRYDOCK_BASE_URL": "https://localhost:8443"}, False),
    ],
)
async def test_reverse_proxy_without_trusted_proxy_warns(
    tmp_path, caplog, env: dict, warns: bool
) -> None:
    caplog.set_level(logging.WARNING, logger="drydock")
    async with running(make_settings(tmp_path / "data", **env)):  # base URL https://drydock.test
        pass
    assert ("FORWARDED_ALLOW_IPS is still" in caplog.text) is warns
