import json
import sqlite3

import pytest

from drydock.audit import REDACTED, redact
from tests.conftest import Browser

pytestmark = pytest.mark.anyio


async def test_audit_events_are_append_only(admin: Browser) -> None:
    assert admin.sql("SELECT COUNT(*) FROM audit_events")[0][0] >= 1
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        admin.sql("UPDATE audit_events SET outcome = 'tampered'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        admin.sql("DELETE FROM audit_events")


async def test_logins_and_user_changes_are_audited(admin: Browser) -> None:
    await admin.login("admin")
    await admin.login("admin", "wrong password!!")
    await admin.login("admin")
    rows = admin.sql("SELECT action, outcome FROM audit_events ORDER BY id")
    assert rows == [
        ("setup.complete", "success"),
        ("auth.login", "success"),
        ("auth.login", "failure"),
        ("auth.login", "success"),
    ]


async def test_audit_page_shows_events(admin: Browser) -> None:
    body = (await admin.get("/audit")).text
    assert "setup.complete" in body
    assert (await admin.get("/audit?before=0")).status_code == 422


def test_redaction() -> None:
    details = {
        "username": "bob",
        "password": "hunter2",
        "nested": {"api_token": "abc", "list": [{"secretValue": "x", "ok": 1}]},
        "SSH_KEY": "-----BEGIN",
    }
    out = redact(details)
    assert out["username"] == "bob"
    assert out["password"] == REDACTED
    assert out["nested"]["api_token"] == REDACTED
    assert out["nested"]["list"][0] == {"secretValue": REDACTED, "ok": 1}
    assert out["SSH_KEY"] == REDACTED
    assert "hunter2" not in json.dumps(out)
