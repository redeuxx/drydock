import json
from datetime import timedelta

import pytest

from drydock.models import utcnow
from tests.conftest import PASSWORD, Browser, add_user, sqlite_ts

pytestmark = pytest.mark.anyio


def expire_reauth(browser: Browser) -> None:
    browser.sql("UPDATE sessions SET reauth_at = ?", (sqlite_ts(utcnow() - timedelta(minutes=11)),))


def last_audit(browser: Browser, action: str) -> tuple:
    return browser.sql(
        "SELECT actor, target, outcome, details FROM audit_events WHERE action = ? "
        "ORDER BY id DESC LIMIT 1",
        (action,),
    )[0]


async def test_role_change_requires_recent_auth(admin: Browser) -> None:
    bob = await add_user(admin, "bob", "viewer")
    expire_reauth(admin)
    response = await admin.post(
        f"/users/{bob}/role",
        {"role": "admin"},
        headers={"Referer": f"https://drydock.test/users/{bob}"},
    )
    assert response.status_code == 403
    assert 'action="/reauth"' in response.text
    assert f'name="next" value="/users/{bob}"' in response.text
    assert admin.sql("SELECT role FROM users WHERE id = ?", (bob,)) == [(10,)]

    response = await admin.post("/reauth", {"password": "wrong password!!", "next": "/users"})
    assert response.status_code == 422
    response = await admin.post("/reauth", {"password": PASSWORD, "next": "//evil.example/x"})
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    response = await admin.post(f"/users/{bob}/role", {"role": "admin"})
    assert response.status_code == 303
    assert admin.sql("SELECT role FROM users WHERE id = ?", (bob,)) == [(30,)]
    actor, target, outcome, details = last_audit(admin, "user.role")
    assert (actor, target, outcome) == ("admin", f"user:{bob}", "success")
    assert json.loads(details) == {"from": "viewer", "to": "admin"}


async def test_user_creation_requires_recent_auth(admin: Browser) -> None:
    expire_reauth(admin)
    response = await admin.post(
        "/users", {"username": "eve", "password": PASSWORD, "role": "superadmin"}
    )
    assert response.status_code == 403
    assert admin.sql("SELECT COUNT(*) FROM users") == [(1,)]


async def test_last_superadmin_is_protected(admin: Browser) -> None:
    for path, data in (
        ("/users/1/role", {"role": "admin"}),
        ("/users/1/disabled", {"disabled": "1"}),
        ("/users/1/delete", {}),
    ):
        response = await admin.post(path, data)
        assert response.status_code == 409, path
        assert "last active superadmin" in response.text
    assert admin.sql("SELECT role, disabled FROM users WHERE id = 1") == [(40, 0)]
    assert last_audit(admin, "user.role")[2] == "denied"

    # A disabled superadmin does not count as a second one.
    other = await add_user(admin, "root2", "superadmin")
    await admin.post(f"/users/{other}/disabled", {"disabled": "1"})
    assert (await admin.post("/users/1/role", {"role": "viewer"})).status_code == 409

    await admin.post(f"/users/{other}/disabled", {"disabled": "0"})
    response = await admin.post("/users/1/role", {"role": "viewer"})
    assert response.status_code == 303
    # Demoting yourself revokes your sessions.
    assert (await admin.get("/")).status_code == 303


async def test_role_change_disable_and_reset_revoke_sessions(admin: Browser) -> None:
    bob = await add_user(admin, "bob", "operator")
    now = sqlite_ts(utcnow())
    for path, data in (
        (f"/users/{bob}/role", {"role": "viewer"}),
        (f"/users/{bob}/disabled", {"disabled": "1"}),
        (f"/users/{bob}/password", {"password": "another long password"}),
        (f"/users/{bob}/sessions/revoke", {}),
    ):
        admin.sql("UPDATE users SET disabled = 0 WHERE id = ?", (bob,))
        admin.sql(
            "INSERT INTO sessions (token_sha256, user_id, csrf_token, created_at, last_seen_at,"
            " expires_at) VALUES (?, ?, 'x', ?, ?, ?)",
            (f"{len(path):064d}", bob, now, now, sqlite_ts(utcnow() + timedelta(hours=1))),
        )
        response = await admin.post(path, data)
        assert response.status_code == 303, path
        assert admin.sql("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (bob,)) == [(0,)]
    actions = {r[0] for r in admin.sql("SELECT action FROM audit_events")}
    assert {
        "user.create",
        "user.role",
        "user.disable",
        "user.password_reset",
        "user.sessions_revoke",
    } <= actions


async def test_delete_user(admin: Browser) -> None:
    bob = await add_user(admin, "bob", "viewer")
    response = await admin.post(f"/users/{bob}/delete")
    assert response.status_code == 303
    assert admin.sql("SELECT COUNT(*) FROM users WHERE id = ?", (bob,)) == [(0,)]
    assert last_audit(admin, "user.delete")[1] == f"user:{bob}"


async def test_usernames_are_case_insensitive_unique(admin: Browser) -> None:
    response = await admin.post(
        "/users", {"username": "ADMIN", "password": PASSWORD, "role": "viewer"}
    )
    assert response.status_code == 422
    assert "taken" in response.text
    await add_user(admin, "Carol", "viewer")
    admin.client.cookies.clear()
    assert (await admin.login("carol")).status_code == 303


async def test_invalid_input_is_rejected(admin: Browser) -> None:
    assert (
        await admin.post("/users", {"username": "x", "password": PASSWORD, "role": "root"})
    ).status_code == 422
    assert (await admin.post("/users/1/disabled", {"disabled": "maybe"})).status_code == 422
    assert (await admin.get("/users/999")).status_code == 404
    assert (await admin.get("/users/abc")).status_code == 422
    response = await admin.post("/users/1/role", {"role": "superadmin"})
    assert response.status_code == 303


async def test_usernames_render_escaped(admin: Browser) -> None:
    evil = "<script>alert(1)</script>"
    user_id = await add_user(admin, evil, "viewer")
    for path in ("/users", f"/users/{user_id}", "/audit"):
        body = (await admin.get(path)).text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body, path
        assert evil not in body, path
    await admin.login(evil)
    body = (await admin.get("/account")).text
    assert evil not in body
    assert "&lt;script&gt;" in body
