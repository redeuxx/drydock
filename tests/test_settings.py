"""The settings page and the update checker's interval."""

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
