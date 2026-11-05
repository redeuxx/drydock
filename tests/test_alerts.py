"""Alerts on container and host changes: the rules (Watch), how the event collector feeds
them, how they are told, the bell, and the host's settings."""

import asyncio
import json
from typing import Any

import pytest

from drydock.hosts import alerts
from drydock.hosts.alerts import KILL_GRACE, RESTART_COUNT, RESTART_WINDOW, UNREACHABLE_AFTER, Watch
from drydock.hosts.events import Event, EventCollector
from drydock.models import Host, NotificationTarget
from tests.conftest import Browser, add_user
from tests.test_events import quiet_host

pytestmark = pytest.mark.anyio

CID = "a" * 64
NS = 1_000_000_000


def ev(action: str, at: float, **fields: Any) -> Event:
    return Event(1, int(at * NS), action, fields.pop("cid", CID), "web", "nginx", **fields)


def kinds(found: list[alerts.Alert]) -> list[str]:
    return [a.kind for a in found]


def test_health_alerts_once_per_change() -> None:
    watch = Watch(lambda cid, name: False)
    assert kinds(watch.event(ev("health_status", 1, health="healthy"))) == []
    assert kinds(watch.event(ev("health_status", 2, health="unhealthy"))) == ["unhealthy"]
    assert kinds(watch.event(ev("health_status", 3, health="unhealthy"))) == [], "once"
    back = watch.event(ev("health_status", 4, health="healthy"))
    assert kinds(back) == ["healthy"] and back[0].failure is False
    assert back[0].text == "web is healthy again."


def test_a_die_alerts_unless_asked_for_and_at_most_every_window() -> None:
    watch = Watch(lambda cid, name: False)
    died = watch.event(ev("die", 10, exit_code=1))
    assert kinds(died) == ["died"] and died[0].text == "web exited with code 1."
    assert kinds(watch.event(ev("die", 20, exit_code=1))) == [], "not again so soon"
    assert kinds(watch.event(ev("die", 21, exit_code=0))) == [], "a clean exit"
    later = 10 + RESTART_WINDOW + 1
    watch.event(ev("kill", later))
    assert kinds(watch.event(ev("die", later + 45, exit_code=143))) == [], "a slow docker stop"
    assert kinds(watch.event(ev("die", later + KILL_GRACE + 1, exit_code=137))) == ["died"]


def test_a_reconnect_repeating_events_and_a_recreated_container() -> None:
    watch = Watch(lambda cid, name: False)
    assert kinds(watch.event(ev("health_status", 1, health="unhealthy"))) == ["unhealthy"]
    assert kinds(watch.event(ev("die", 2, exit_code=1))) == ["died"]
    assert watch.event(ev("die", 2, exit_code=1)) == [], "the same event again"
    # compose up -d: the old one goes, a new ID under the name becomes healthy.
    watch.event(ev("destroy", 3))
    back = watch.event(ev("health_status", 4, health="healthy", cid="c" * 64))
    assert kinds(back) == ["healthy"]


def test_a_restart_loop_alerts_and_settles() -> None:
    watch = Watch(lambda cid, name: False)
    found = []
    for n in range(RESTART_COUNT):
        found += watch.event(ev("start", 100 + n))
        found += watch.event(ev("die", 100.5 + n, exit_code=1))
    assert kinds(found) == ["died", "restarting"], "one died, then the loop"
    assert kinds(watch.event(ev("start", 100 + RESTART_COUNT))) == [], "once"
    assert watch.quiet(int((100 + RESTART_COUNT + RESTART_WINDOW / 2) * NS)) == []
    settled = watch.quiet(int((101 + RESTART_COUNT + RESTART_WINDOW) * NS))
    assert kinds(settled) == ["settled"] and settled[0].subject == "web"
    slow = Watch(lambda cid, name: False)
    spread = [slow.event(ev("start", n * RESTART_WINDOW)) for n in range(RESTART_COUNT + 2)]
    assert not any(spread), "starts spread out are no loop"


def test_containers_a_run_holds_are_left_out() -> None:
    watch = Watch(lambda cid, name: cid == CID)
    assert watch.event(ev("die", 1, exit_code=1)) == []
    assert watch.event(ev("health_status", 2, health="unhealthy")) == []
    other = "b" * 64
    assert kinds(watch.event(ev("die", 3, exit_code=1, cid=other))) == ["died"]


async def test_a_run_holds_a_container_by_its_id_or_its_name(admin: Browser) -> None:
    dispatcher = admin.app.state.dispatcher
    assert not dispatcher.holds(CID, "web")
    assert await dispatcher.try_hold([CID], "run 1")
    assert dispatcher.holds(CID, "other")
    dispatcher.release_held([CID])
    assert await dispatcher.try_hold(["name:d1234:container:web"], "update 2")
    assert dispatcher.holds("f" * 64, "web") and not dispatcher.holds("f" * 64, "web2")
    dispatcher.release_held(["name:d1234:container:web"])


def test_a_host_alerts_after_minutes_unreachable_and_again_when_back() -> None:
    watch = Watch(lambda cid, name: False)
    assert watch.stream(1, False, "rigel", now=0) == []
    assert watch.stream(1, False, "rigel", now=UNREACHABLE_AFTER - 1) == []
    down = watch.stream(1, False, "rigel", now=UNREACHABLE_AFTER)
    assert (
        kinds(down) == ["unreachable"]
        and "rigel has been unreachable for 5 minutes" in down[0].text
    )
    assert watch.stream(1, False, "rigel", now=UNREACHABLE_AFTER + 60) == [], "once"
    assert kinds(watch.stream(1, True, "rigel", now=UNREACHABLE_AFTER + 61)) == ["reachable"]
    assert watch.stream(1, True, "rigel") == [], "a short drop says nothing"
    watch.stream(1, False, "rigel", now=1000)
    assert watch.stream(1, True, "rigel", now=1010) == []


# THE COLLECTOR, DELIVERY AND THE BELL


async def test_alerts_are_judged_once_per_event_for_hosts_that_have_them(admin: Browser) -> None:
    on = await quiet_host(admin, name="on", alerts_enabled=True)
    off = await quiet_host(admin, name="off")
    told: list[tuple[str, int]] = []
    collector = EventCollector(admin.app.state.sessionmaker, admin.app.state.hosts)
    collector.use(lambda cid, name: False, lambda alert, host: told.append((alert.kind, host.id)))
    await collector.supervise()
    for host_id in (on, off):
        collector._take(Event(host_id, NS, "die", CID, "web", "x", exit_code=2))
    await asyncio.gather(*collector._sending)
    assert told == [("died", on)]
    assert len(collector._pending) == 2, "both stored"
    with admin.app.state.sessionmaker() as db, db.begin():
        db.get(Host, on).alerts_enabled = False
    await collector.supervise()
    collector._take(Event(on, 2 * NS, "die", CID, "web", "x", exit_code=2))
    await asyncio.gather(*collector._sending)
    assert told == [("died", on)], "turned off"
    await collector.close()


async def test_an_alert_rings_the_bell_and_tells_the_target(admin: Browser) -> None:
    host_id = await quiet_host(admin, name="rigel", alerts_enabled=True)
    with admin.app.state.sessionmaker() as db, db.begin():
        target = NotificationTarget(
            name="ops", kind="ntfy", url_enc=admin.app.state.crypto.encrypt("ntfy://x/y")
        )
        db.add(target)
        db.flush()
        db.get(Host, host_id).alert_target_id = target.id
        target_id = target.id
    told: list[tuple] = []

    class Notifier:
        def alert(self, *args: Any) -> None:
            told.append(args)

    with admin.app.state.sessionmaker() as db:
        host = db.get(Host, host_id)
        db.expunge(host)
    alerts.deliver(
        admin.app.state.sessionmaker,
        Notifier(),
        alerts.Alert(host_id, "unhealthy", "<b>web</b>", "<b>web</b> is unhealthy.", True),
        host,
    )
    alerts.deliver(
        admin.app.state.sessionmaker,
        Notifier(),
        alerts.Alert(host_id, "reachable", "", "rigel is reachable again.", False),
        host,
    )
    assert told[0] == (
        target_id,
        "drydock: rigel: <b>web</b> is unhealthy.",
        "rigel: <b>web</b> is unhealthy.",
        True,
    )
    assert told[1][3] is False
    rows = admin.sql(
        "SELECT action, target, outcome, details FROM audit_events WHERE action LIKE 'alert.%'"
    )
    assert [r[:3] for r in rows] == [
        ("alert.unhealthy", f"host:{host_id}", "failure"),
        ("alert.reachable", f"host:{host_id}", "success"),
    ]
    assert json.loads(rows[0][3])["container"] == "<b>web</b>"
    bell = (await admin.get("/feed")).text
    assert "rigel: &lt;b&gt;web&lt;/b&gt; is unhealthy." in bell and "<b>web</b>" not in bell
    assert f'href="/containers?host={host_id}&amp;q=%3Cb%3Eweb%3C/b%3E"' in bell
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    assert "is unhealthy" not in (await admin.get("/feed")).text, "admins only"


async def test_alert_settings_are_for_admins_checked_and_audited(admin: Browser) -> None:
    host_id = await quiet_host(admin, name="rigel")
    with admin.app.state.sessionmaker() as db, db.begin():
        target = NotificationTarget(
            name="ops", kind="ntfy", url_enc=admin.app.state.crypto.encrypt("ntfy://x/y")
        )
        db.add(target)
        db.flush()
        target_id = target.id
    page = (await admin.get(f"/hosts/{host_id}")).text
    assert 'action="/hosts/' in page and "Save alerts" in page and ">ops</option>" in page
    form = {"enabled": "1", "alert_target_id": str(target_id)}
    url = f"/hosts/{host_id}/alerts"
    assert (await admin.post(url, form, csrf=False)).status_code == 403
    assert (await admin.post(url, form | {"alert_target_id": "999"})).status_code == 422
    assert (await admin.post(url, form)).status_code == 303
    assert admin.sql(
        "SELECT alerts_enabled, alert_target_id FROM hosts WHERE id = ?", (host_id,)
    ) == [(1, target_id)]
    assert admin.sql("SELECT details FROM audit_events WHERE action = 'host.alerts'") == [
        (json.dumps({"enabled": True, "target": "ops"}),)
    ]
    await add_user(admin, "runner", "operator")
    await admin.login("runner")
    assert (await admin.post(url, {})).status_code == 403


async def test_deleting_a_target_clears_it_from_hosts(admin: Browser) -> None:
    host_id = await quiet_host(admin, name="rigel")
    with admin.app.state.sessionmaker() as db, db.begin():
        target = NotificationTarget(
            name="ops", kind="ntfy", url_enc=admin.app.state.crypto.encrypt("ntfy://x/y")
        )
        db.add(target)
        db.flush()
        db.get(Host, host_id).alert_target_id = target.id
        target_id = target.id
    assert (await admin.post(f"/notifications/{target_id}/delete", {})).status_code == 303
    assert admin.sql("SELECT alert_target_id FROM hosts WHERE id = ?", (host_id,)) == [(None,)]
