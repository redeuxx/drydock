import json
import logging
import threading

import anyio
import pytest

from drydock.config import Settings
from drydock.security import passwords
from tests.conftest import CLIENT_IP, PASSWORD, Browser, form_token, running

pytestmark = pytest.mark.anyio

WARNING_TEXT = "NO SUPERADMIN EXISTS"


async def test_everything_redirects_to_setup_before_first_user(fresh: Browser) -> None:
    for path in ("/", "/login", "/account", "/users", "/audit", "/users/1", "/nope"):
        response = await fresh.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"] == "/setup"
    response = await fresh.post("/login", {"username": "x", "password": "y"}, csrf=False)
    assert response.headers["location"] == "/setup"
    assert (await fresh.get("/healthz")).status_code == 200
    assert (await fresh.get("/setup")).status_code == 200
    assert (await fresh.get("/static/missing.js")).status_code == 404


async def test_startup_warns_while_no_superadmin(settings: Settings, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="drydock")
    async with running(settings) as browser:
        assert WARNING_TEXT in caplog.text
        await browser.setup()
    caplog.clear()
    async with running(settings):
        assert WARNING_TEXT not in caplog.text


async def test_concurrent_setup_creates_exactly_one_superadmin(fresh: Browser, monkeypatch) -> None:
    # Hold every request at the hash, just before the check-then-insert, and release them
    # together so they all reach it at once. Without BEGIN IMMEDIATE this creates several.
    password_hash = passwords.hash_password(PASSWORD)
    barrier = threading.Barrier(20, timeout=10)

    def hash_together(_password: str) -> str:
        barrier.wait()
        return password_hash

    monkeypatch.setattr(passwords, "hash_password", hash_together)
    token = form_token((await fresh.get("/setup")).text)
    statuses: list[int] = []

    async def attempt(i: int) -> None:
        data = {
            "csrf_token": token,
            "username": f"admin{i}",
            "password": PASSWORD,
            "password_confirm": PASSWORD,
        }
        response = await fresh.client.post("/setup", data=data, headers=fresh.origin_headers)
        statuses.append(response.status_code)

    async with anyio.create_task_group() as group:
        for i in range(20):
            group.start_soon(attempt, i)

    assert sorted(statuses) == [303] + [404] * 19
    assert fresh.sql("SELECT role FROM users") == [(40,)]
    assert (await fresh.get("/setup")).status_code == 404
    response = await fresh.client.post(
        "/setup",
        data={
            "csrf_token": token,
            "username": "late",
            "password": PASSWORD,
            "password_confirm": PASSWORD,
        },
        headers=fresh.origin_headers,
    )
    assert response.status_code == 404
    assert fresh.sql("SELECT COUNT(*) FROM users") == [(1,)]


async def test_setup_audit_row_records_source_ip(admin: Browser) -> None:
    rows = admin.sql("SELECT actor, ip, details FROM audit_events WHERE action='setup.complete'")
    assert len(rows) == 1
    actor, ip, details = rows[0]
    assert actor == "admin"
    assert ip == CLIENT_IP
    assert json.loads(details)["source_ip"] == CLIENT_IP


async def test_setup_logs_in_and_validates_input(fresh: Browser) -> None:
    token = form_token((await fresh.get("/setup")).text)
    bad = [
        {"username": "has space", "password": PASSWORD, "password_confirm": PASSWORD},
        {"username": "admin", "password": "short", "password_confirm": "short"},
        {"username": "admin", "password": PASSWORD, "password_confirm": PASSWORD + "x"},
        {"username": "x" * 65, "password": PASSWORD, "password_confirm": PASSWORD},
    ]
    for data in bad:
        response = await fresh.client.post(
            "/setup", data={"csrf_token": token, **data}, headers=fresh.origin_headers
        )
        assert response.status_code == 422
    assert fresh.sql("SELECT COUNT(*) FROM users") == [(0,)]
    response = await fresh.setup()
    assert response.status_code == 303
    assert (await fresh.get("/")).status_code == 200
