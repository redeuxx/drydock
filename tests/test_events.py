"""Docker events without a daemon: what is kept of an event, storing, pruning and counting,
and the dashboard's counts (the daemon side: test_status_docker.py)."""

import asyncio
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select

from drydock.hosts import events, status
from drydock.hosts.events import Event, EventCollector, event_of
from drydock.hosts.helper import helper_labels
from drydock.models import DockerEvent, Host
from tests.conftest import Browser
from tests.test_status import add_host, cached, put, reading, summary

pytestmark = pytest.mark.anyio

INSTANCE = "drydocktestinstance"
CID = "a" * 64
T = 1_793_815_200_123_456_789


def message(action: str, **attributes: Any) -> dict[str, Any]:
    return {
        "Type": "container",
        "Action": action,
        "Actor": {
            "ID": CID,
            "Attributes": {"name": "web", "image": "nginx:1.27"} | attributes,
        },
        "time": T // events.NS,
        "timeNano": T,
    }


# WHAT IS KEPT


def test_an_event_keeps_only_its_few_fields() -> None:
    found = event_of(
        message("start", password="hunter2", **{"com.docker.compose.project": "app"}), 7, INSTANCE
    )
    assert found == Event(7, T, "start", CID, "web", "nginx:1.27")


def test_exec_commands_and_labels_are_never_kept() -> None:
    found = event_of(message("exec_start: sh -c 'echo hunter2'", secret="hunter2"), 1, INSTANCE)
    assert found is not None and found.action == "exec_start"
    assert "hunter2" not in repr(found)


def test_exit_codes_and_health_results() -> None:
    died = event_of(message("die", exitCode="137"), 1, INSTANCE)
    assert died is not None and died.exit_code == 137
    assert event_of(message("die", exitCode="x"), 1, INSTANCE).exit_code is None
    assert event_of(message("start", exitCode="1"), 1, INSTANCE).exit_code is None
    healthy = event_of(message("health_status: healthy"), 1, INSTANCE)
    assert healthy is not None and (healthy.action, healthy.health) == ("health_status", "healthy")
    odd = event_of(message("health_status: <script>"), 1, INSTANCE)
    assert odd is not None and odd.health is None


def test_what_is_left_out() -> None:
    assert event_of(message("start") | {"Type": "network"}, 1, INSTANCE) is None
    assert event_of(message("start", **helper_labels(INSTANCE)), 1, INSTANCE) is None
    other = event_of(message("start", **helper_labels("someoneelse")), 1, INSTANCE)
    assert other is not None, "another drydock's helpers are just containers"
    assert event_of(message("<b>start</b>"), 1, INSTANCE) is None
    assert event_of(message("start") | {"Actor": {"ID": "../x"}}, 1, INSTANCE) is None
    assert event_of("not a dict", 1, INSTANCE) is None
    no_nanos = message("start")
    del no_nanos["timeNano"]
    assert event_of(no_nanos, 1, INSTANCE).time_ns == (T // events.NS) * events.NS
    del no_nanos["time"]
    assert event_of(no_nanos, 1, INSTANCE) is None


def test_since_is_seconds_and_nanoseconds() -> None:
    assert events.since_of(T) == "1793815200.123456789"


# STORING, PRUNING, COUNTING


async def quiet_host(browser: Browser, **fields: Any) -> int:
    """A host, with the app's own collector stopped: it would store the real daemon's
    events for it."""
    await browser.app.state.events.close()
    return add_host(browser, **fields)


def stored(browser: Browser) -> list[tuple]:
    return browser.sql("SELECT host_id, time_ns, action, name FROM docker_events ORDER BY id")


async def test_an_event_sent_twice_is_stored_once(admin: Browser) -> None:
    host_id = await quiet_host(admin)
    sessions = admin.app.state.sessionmaker
    one = Event(host_id, T, "start", CID, "web", "nginx")
    events.store(sessions, [one, one])
    events.store(sessions, [one, Event(host_id, T, "die", CID, "web", "nginx", exit_code=0)])
    assert stored(admin) == [(host_id, T, "start", "web"), (host_id, T, "die", "web")]
    assert events.newest(sessions, host_id) == T
    assert events.newest(sessions, host_id + 1) is None


async def test_retention_keeps_30_days_and_the_newest_rows(admin: Browser, monkeypatch) -> None:
    host_id = await quiet_host(admin)
    sessions = admin.app.state.sessionmaker
    now = T + 40 * 86400 * events.NS
    old = Event(host_id, T, "start", CID, "old", "x")
    recent = [Event(host_id, now - i, "start", CID, f"r{i}", "x") for i in range(5)]
    events.store(sessions, [old, *recent])
    monkeypatch.setattr(events, "KEEP_ROWS", 3)
    assert events.prune(sessions, now) == 3
    assert [row[3] for row in stored(admin)] == ["r0", "r1", "r2"]


async def test_deleting_a_host_deletes_its_events(admin: Browser) -> None:
    host_id = await quiet_host(admin)
    events.store(admin.app.state.sessionmaker, [Event(host_id, T, "start", CID, "web", "x")])
    with admin.app.state.sessionmaker() as db, db.begin():
        db.delete(db.get(Host, host_id))
    assert stored(admin) == []


async def test_a_burst_is_stored_in_one_transaction(admin: Browser, monkeypatch) -> None:
    host_id = await quiet_host(admin)
    collector = EventCollector(admin.app.state.sessionmaker, admin.app.state.hosts)
    calls: list[int] = []
    real = events.store
    monkeypatch.setattr(
        events, "store", lambda s, batch: (calls.append(len(batch)), real(s, batch))
    )
    collector._pending.extend(Event(host_id, T + i, "create", CID, "ci", "x") for i in range(500))
    await collector.flush()
    assert calls == [500] and len(stored(admin)) == 500
    await collector.flush()
    assert calls == [500], "nothing pending: no transaction"


async def test_the_cards_count_events_today_and_in_all(admin: Browser, monkeypatch) -> None:
    collector = await cached(admin, monkeypatch)
    host_id = await quiet_host(admin)
    taken, _ = status.summarize(host_id, reading([summary(CID, "web")], {}), {}, datetime.now(UTC))
    put(collector, taken)
    today = time.time_ns()
    events.store(
        admin.app.state.sessionmaker,
        [Event(host_id, today - i, "start", CID, "web", "x") for i in range(3)]
        + [Event(host_id, T, "start", CID, "web", "x")],
    )
    admin.app.state.events._counts = events.Counts()  # pages read them moments ago
    cards = (await admin.get("/status/hosts", headers={"HX-Request": "true"})).text
    assert '<span class="font-semibold">3</span> <span class="opacity-70">today,</span>' in cards
    assert '<span class="font-semibold">4</span> <span class="opacity-70">stored</span>' in cards
    # Read again within a few seconds: the same counts, without a query.
    with admin.app.state.sessionmaker() as db:
        assert admin.app.state.events.counts(db, datetime.now(UTC)) is not None


# THE COLLECTOR, WITH A FAKE DAEMON


class FakeStream:
    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self.messages = messages
        self.closed = False

    def __iter__(self):
        yield from self.messages

    def close(self) -> None:
        self.closed = True


async def test_the_collector_follows_hosts_from_their_newest_stored_event(
    admin: Browser, monkeypatch
) -> None:
    host_id = await quiet_host(admin, docker_url="tcp://fake:2375")
    sessions = admin.app.state.sessionmaker
    events.store(sessions, [Event(host_id, T, "start", CID, "web", "x")])
    asked: list[str] = []
    streams: list[FakeStream] = []

    class Api:
        def events(self, since: str, filters: dict, decode: bool) -> FakeStream:
            assert filters == {"type": ["container"]} and decode
            asked.append(since)
            streams.append(FakeStream([message("stop") | {"timeNano": T + 5}, message("start")]))
            return streams[-1]

    class Handle:
        class client:
            api = Api()

        def __enter__(self):
            return self

        def __exit__(self, *exc: object) -> None:
            pass

    monkeypatch.setattr(events.client, "open_client", lambda url, timeout: Handle())
    monkeypatch.setattr(events, "BACKOFF", (0.05,))
    collector = EventCollector(sessions, admin.app.state.hosts)
    collector._loop = asyncio.get_running_loop()
    await collector.supervise()
    deadline = time.monotonic() + 10
    while len(asked) < 2 and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await collector.close()
    assert asked[0] == events.since_of(T), "from the newest stored"
    assert asked[1] == events.since_of(T + 5), "a stream that ended reopens from its newest"
    assert all(s.closed for s in streams)
    rows = admin.sql("SELECT action, time_ns FROM docker_events ORDER BY time_ns, action")
    assert rows == [("start", T), ("stop", T + 5)], "the repeats were stored once"

    # A disabled host is no longer followed.
    with sessions() as db, db.begin():
        db.get(Host, host_id).enabled = False
    await collector.supervise()
    assert collector._follows == {}
    with sessions() as db:
        assert db.scalar(select(func.count()).select_from(DockerEvent)) == 2


async def test_a_deleted_hosts_events_never_cost_the_others_theirs(admin: Browser) -> None:
    host_id = await quiet_host(admin)
    sessions = admin.app.state.sessionmaker
    events.store(
        sessions,
        [Event(host_id, T, "start", CID, "web", "x"), Event(999, T, "start", CID, "gone", "x")],
    )
    assert stored(admin) == [(host_id, T, "start", "web")]


async def test_a_refused_batch_is_kept_for_the_next_flush(admin: Browser, monkeypatch) -> None:
    host_id = await quiet_host(admin)
    collector = EventCollector(admin.app.state.sessionmaker, admin.app.state.hosts)
    real = events.store

    def busy(sessions, batch):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(events, "store", busy)
    collector._pending.append(Event(host_id, T, "start", CID, "web", "x"))
    with pytest.raises(RuntimeError):
        await collector.flush()
    collector._pending.append(Event(host_id, T + 1, "die", CID, "web", "x"))
    monkeypatch.setattr(events, "store", real)
    await collector.flush()
    assert [row[2] for row in stored(admin)] == ["start", "die"]


async def test_a_host_with_nothing_stored_streams_from_the_daemons_now(
    admin: Browser, monkeypatch
) -> None:
    await quiet_host(admin, docker_url="tcp://fake:2375")
    asked: list[Any] = []

    class Api:
        def events(self, since: Any, filters: dict, decode: bool) -> FakeStream:
            asked.append(since)
            return FakeStream([])

    class Handle:
        class client:
            api = Api()

        def __enter__(self):
            return self

        def __exit__(self, *exc: object) -> None:
            pass

    monkeypatch.setattr(events.client, "open_client", lambda url, timeout: Handle())
    collector = EventCollector(admin.app.state.sessionmaker, admin.app.state.hosts)
    collector._loop = asyncio.get_running_loop()
    await collector.supervise()
    deadline = time.monotonic() + 10
    while not asked and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await collector.close()
    assert asked[0] is None, "no since: nothing before the daemon's present"
