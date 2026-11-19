"""The settings page and the update checker's interval."""

import base64

import pytest

from drydock.updates.check import CHECK_EVERY
from tests.conftest import Browser, add_user

pytestmark = pytest.mark.anyio


async def test_admins_set_how_often_updates_are_checked(admin: Browser) -> None:
    checker = admin.app.state.updates
    page = (await admin.get("/settings")).text
    assert '<option value="6" selected>Every 6 hours</option>' in page
    checker._load_hosts()
    assert checker._every == CHECK_EVERY

    done = await admin.post("/settings", {"update_check_hours": "0"})
    assert done.status_code == 303 and done.headers["location"] == "/settings"
    assert admin.sql("SELECT update_check_hours FROM installation") == [(0,)]
    assert admin.sql("SELECT details FROM audit_events WHERE action = 'settings.update'") == [
        ('{"update_check_hours": 0, "was": 6}',)
    ]
    checker._load_hosts()
    assert checker._every == 0, "read at the next loop: never by itself"

    for wrong in ("5", "-1", "x", ""):
        refused = await admin.post("/settings", {"update_check_hours": wrong})
        assert refused.status_code == 422 and "Choose one of the intervals." in refused.text
    assert admin.sql("SELECT update_check_hours FROM installation") == [(0,)]

    await add_user(admin, "runner", "operator")
    await admin.login("runner")
    assert (await admin.get("/settings")).status_code == 403
    assert (await admin.post("/settings", {"update_check_hours": "1"})).status_code == 403
    assert 'href="/settings"' not in (await admin.get("/")).text


async def test_a_superadmin_reveals_the_secret_key_with_a_recent_password(
    admin: Browser,
) -> None:
    key = base64.urlsafe_b64encode(admin.settings.secret_keys[0]).decode()
    page = (await admin.get("/settings")).text
    assert 'action="/settings/secret-key"' in page and key not in page

    admin.sql("UPDATE sessions SET reauth_at = NULL")
    stale = await admin.post("/settings/secret-key")
    assert stale.status_code == 403 and "Re-enter your password" in stale.text
    assert key not in stale.text

    await admin.login("admin")
    shown = await admin.post("/settings/secret-key")
    assert shown.status_code == 200 and key in shown.text
    assert admin.sql(
        "SELECT actor, details FROM audit_events WHERE action = 'settings.secret_key_reveal'"
    ) == [("admin", '{"count": 1}')]

    await add_user(admin, "boss", "admin")
    await admin.login("boss")
    assert "secret-key" not in (await admin.get("/settings")).text
    assert (await admin.post("/settings/secret-key")).status_code == 403
