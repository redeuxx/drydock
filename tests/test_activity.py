"""The activity page: stored container events, filtered, paged and cleared."""

import html
import re
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from drydock.hosts import events
from drydock.hosts.events import Event
from drydock.models import Job, Run, StorageTarget
from tests.conftest import PASSWORD, Browser, add_user
from tests.test_events import quiet_host

pytestmark = pytest.mark.anyio

CID = "a" * 64


def put(browser: Browser, *rows: Event) -> None:
    events.store(browser.app.state.sessionmaker, list(rows))


def names(page: str) -> list[str]:
    found = re.findall(r'<td class="truncate font-semibold" title="([^"]*)"', page)
    return [html.unescape(name) for name in found]


def poller(page: str) -> bool:
    return bool(re.search(r'<div id="activity" data-poller="Activity"[^>]*hx-nonce="', page))


async def test_every_role_sees_the_activity_escaped(admin: Browser) -> None:
    host_id = await quiet_host(admin)
    now = time.time_ns()
    put(
        admin,
        Event(host_id, now - 2, "die", CID, "<script>alert(1)</script>", "nginx", exit_code=137),
        Event(host_id, now - 1, "start", CID, "web", "nginx"),
        Event(host_id, now, "health_status", CID, "web", "nginx", health="unhealthy"),
    )
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    page = (await admin.get("/activity")).text
    assert 'href="/activity"' in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<script>alert" not in page
    assert names(page) == ["web", "web", "<script>alert(1)</script>"], "newest first"
    assert '<span class="font-semibold text-error">137</span>' in page
    assert "Health: unhealthy" in page and "1 to 3 of 3" in page
    assert poller(page) and "Clear&hellip;" not in page, "the clear button is for admins"
    assert re.search(r'id="activity-filter"[^>]*hx-nonce="', page)


async def test_filters_by_container_action_host_and_time(admin: Browser) -> None:
    web = await quiet_host(admin, name="web-host")
    other = await quiet_host(admin, name="other-host")
    now = time.time_ns()
    put(
        admin,
        Event(web, now, "start", CID, "web", "nginx"),
        Event(web, now - 1, "stop", "b" * 64, "db_1", "postgres"),
        Event(other, now - 2, "start", "c" * 64, "cache", "redis"),
        Event(web, now - 2 * 86400 * events.NS, "start", CID, "web", "nginx"),
    )

    async def shown(query: str) -> list[str]:
        return names((await admin.get(f"/activity?{query}")).text)

    assert await shown("") == ["web", "db_1", "cache"], "the last 24 hours by default"
    assert await shown("range=all") == ["web", "db_1", "cache", "web"]
    assert await shown("range=nonsense") == ["web", "db_1", "cache"]
    assert await shown("container=WE") == ["web"], "a substring, any case"
    assert await shown("container=bbbb") == ["db_1"], "the start of an ID"
    assert await shown("container=_") == ["db_1"], "LIKE's wildcards are plain text"
    assert await shown("container=%") == []
    assert await shown("action=stop") == ["db_1"]
    assert await shown("action=<b>") == ["web", "db_1", "cache"], "an unknown action: ignored"
    assert await shown(f"host={other}") == ["cache"]
    # What the filter form sends for "All hosts" and "All actions".
    assert await shown("container=&action=&host=&range=24h") == ["web", "db_1", "cache"]
    assert await shown("host=x") == ["web", "db_1", "cache"]
    region = await admin.get(
        f"/activity?host={web}", headers={"HX-Request": "true", "HX-Target": "div#activity"}
    )
    assert 'id="activity"' in region.text and "<header" not in region.text
    assert 'id="activity-filter"' not in region.text


async def test_pages_hold_still_while_events_arrive(admin: Browser) -> None:
    host_id = await quiet_host(admin)
    base = time.time_ns() - 10**9
    put(admin, *(Event(host_id, base + i, "start", CID, f"c{i:03}", "x") for i in range(120)))
    first = (await admin.get("/activity")).text
    assert names(first)[0] == "c119" and "1 to 50 of 120" in first and poller(first)
    older = re.search(r'href="(/activity\?[^"]*before=[^"]*)">Older', first)
    assert older is not None
    url = older.group(1).replace("&amp;", "&")
    second = (await admin.get(url)).text
    assert names(second)[0] == "c069" and "51 to 100 of 120" in second
    assert not poller(second) and ">Newest</a>" in second

    # Newer events arrive: the second page shows the same rows, further down the list.
    put(admin, *(Event(host_id, base + 1000 + i, "start", CID, f"n{i}", "x") for i in range(5)))
    again = (await admin.get(url)).text
    assert names(again) == names(second) and "56 to 105 of 125" in again
    for junk in ("junk", "9999999999999999999-1", "1-9999999999999999999"):
        assert (await admin.get(f"/activity?before={junk}")).status_code == 200, junk


def add_runs(browser: Browser, host_id: int, *runs: tuple[str, int]) -> None:
    """A job "nightly" on the host, and a run of each (kind, queued at ns) given."""
    with browser.app.state.sessionmaker() as db, db.begin():
        storage = StorageTarget(name="disk", kind="local", config_enc="x")
        db.add(storage)
        db.flush()
        job = Job(
            uuid=str(uuid.uuid4()),
            name="nightly",
            host_id=host_id,
            storage_target_id=storage.id,
            target_type="container",
            target="web",
            scope="all",
            enabled=True,
        )
        db.add(job)
        db.flush()
        for kind, ns in runs:
            queued = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=ns // 1000)
            db.add(Run(job_id=job.id if kind == "backup" else None, kind=kind, created_at=queued))


async def test_backup_runs_show_among_the_events(admin: Browser) -> None:
    web = await quiet_host(admin, name="web-host")
    other = await quiet_host(admin, name="other-host")
    now = time.time_ns() // 1000 * 1000
    add_runs(admin, web, ("backup", now - 2 * 10**9), ("restore", now - 10**9))
    put(
        admin,
        Event(web, now, "start", CID, "web", "nginx"),
        Event(other, now - 3 * 10**9, "stop", "b" * 64, "db", "postgres"),
    )

    async def shown(query: str) -> list[str]:
        return names((await admin.get(f"/activity?{query}")).text)

    page = (await admin.get("/activity")).text
    assert names(page) == ["web", "nightly", "db"], "restores are not listed"
    assert re.search(r'href="/runs/[0-9]+">', page) and "Backup run" in page
    assert "1 to 3 of 3" in page
    assert await shown("action=backup") == ["nightly"]
    assert await shown("action=start") == ["web"]
    assert await shown(f"host={web}") == ["web", "nightly"]
    assert await shown(f"host={other}") == ["db"]
    assert await shown("container=NIGHT") == ["nightly"], "the job's name"


async def test_pages_split_on_a_run_that_shares_an_instant_with_an_event(admin: Browser) -> None:
    host_id = await quiet_host(admin)
    base = (time.time_ns() - 10**9) // 1000 * 1000
    put(admin, *(Event(host_id, base + i * 1000, "start", CID, f"c{i:03}", "x") for i in range(60)))
    add_runs(admin, host_id, ("backup", base + 11 * 1000))  # with c011: the event comes first
    first = (await admin.get("/activity")).text
    shown = names(first)
    assert shown[0] == "c059" and shown[-2:] == ["c011", "nightly"] and len(shown) == 50
    older = re.search(r'href="(/activity\?[^"]*before=[^"]*)">Older', first)
    assert older is not None and "-r" in older.group(1), "the cursor is the run"
    second = (await admin.get(older.group(1).replace("&amp;", "&"))).text
    assert names(second) == [f"c{i:03}" for i in range(10, -1, -1)]
    assert "51 to 61 of 61" in second


async def test_clearing_is_for_admins_with_recent_auth_and_audited(admin: Browser) -> None:
    web = await quiet_host(admin, name="web-host")
    other = await quiet_host(admin, name="other-host")
    now = time.time_ns()
    put(admin, Event(web, now, "start", CID, "web", "x"), Event(other, now, "start", CID, "o", "x"))

    assert (await admin.post("/activity/clear", {"host": str(web)}, csrf=False)).status_code == 403
    await add_user(admin, "runner", "operator")
    await admin.login("runner")
    assert (await admin.post("/activity/clear", {"host": str(web)})).status_code == 403
    await admin.login("admin")
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    asked = await admin.post("/activity/clear", {"host": str(web)})
    assert asked.status_code in (303, 403) and admin.sql("SELECT count(*) FROM docker_events") == [
        (2,)
    ], "no recent password: nothing cleared"
    assert (await admin.post("/activity/clear", {"host": "999999"})).status_code in (403, 404)

    await admin.post("/reauth", {"password": PASSWORD, "next": "/activity"})
    cleared = await admin.post("/activity/clear", {"host": str(web)})
    assert cleared.status_code == 303
    assert admin.sql("SELECT host_id FROM docker_events") == [(other,)]
    assert admin.sql(
        "SELECT target, outcome, details FROM audit_events WHERE action = 'activity.clear'"
    ) == [(f"host:{web}", "success", '{"deleted": 1, "host": "web-host"}')]
    assert (await admin.post("/activity/clear", {})).status_code == 422, "no default"
    assert admin.sql("SELECT count(*) FROM docker_events") == [(1,)]
    await admin.post("/activity/clear", {"host": "0"})
    assert admin.sql("SELECT count(*) FROM docker_events") == [(0,)]
