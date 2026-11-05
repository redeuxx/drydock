"""Docker events without a daemon: what is kept of an event, storing, pruning and counting,
and the dashboard's counts (the daemon side: test_status_docker.py)."""

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any

import docker.errors
import pytest
import requests
import urllib3.exceptions
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


def test_execs_are_not_kept_and_labels_never() -> None:
    """Healthcheck probes are execs: three events each, every few seconds."""
    for action in ("exec_create: sh -c 'echo hunter2'", "exec_start: x", "exec_die"):
        assert event_of(message(action, secret="hunter2"), 1, INSTANCE) is None
    found = event_of(message("start", secret="hunter2"), 1, INSTANCE)
    assert found is not None and "hunter2" not in repr(found)


def test_values_outside_sqlites_range_are_dropped() -> None:
    assert event_of(message("start") | {"timeNano": 2**63}, 1, INSTANCE) is None
    assert event_of(message("start") | {"timeNano": -5, "time": -1}, 1, INSTANCE) is None
    huge = event_of(message("die", exitCode=str(2**40)), 1, INSTANCE)
    assert huge is not None and huge.exit_code is None


def test_a_quiet_stream_times_out_and_is_opened_again() -> None:
    assert events.idle(urllib3.exceptions.ReadTimeoutError(None, "/events", "timed out"))
    assert events.idle(TimeoutError())
    wrapped = requests.exceptions.ConnectionError(
        urllib3.exceptions.ReadTimeoutError(None, "/events", "timed out")
    )
    assert events.idle(wrapped)
    assert not events.idle(requests.exceptions.ConnectionError("refused"))


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


class FakeResponse:
    def __init__(self, messages: list[dict[str, Any]], status: int = 200) -> None:
        self.messages = messages
        self.status = status
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeApi:
    """The raw /events request _read makes; batches(n) gives the nth stream's messages."""

    def __init__(self, batches, status: int = 200) -> None:
        self.batches = batches
        self.status = status
        self.asked: list[dict[str, Any]] = []
        self.responses: list[FakeResponse] = []

    def _url(self, path: str) -> str:
        return path

    def _get(self, url: str, params: dict, stream: bool, timeout: float) -> FakeResponse:
        assert url == "/events" and stream and timeout == events.STREAM_IDLE
        assert json.loads(params["filters"]) == {"type": ["container"]}
        self.asked.append(params)
        self.responses.append(FakeResponse(self.batches(len(self.asked)), self.status))
        return self.responses[-1]

    def _raise_for_status(self, response: FakeResponse) -> None:
        if response.status != 200:
            refused = requests.Response()
            refused.status_code, refused.reason = 403, "Forbidden"
            raise docker.errors.APIError("refused", response=refused)

    def _stream_helper(self, response: FakeResponse, decode: bool):
        assert decode
        return iter(response.messages)


class Stream:
    """docker.types.CancellableStream without a real socket."""

    def __init__(self, stream, response: FakeResponse) -> None:
        self._stream, self._response = stream, response

    def __iter__(self):
        return self._stream

    def close(self) -> None:
        self._response.close()


def fake_daemon(monkeypatch, api: FakeApi) -> None:
    class Handle:
        class client:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc: object) -> None:
            pass

    Handle.client.api = api
    monkeypatch.setattr(events.client, "open_client", lambda url, timeout: Handle())
    monkeypatch.setattr(events.docker.types, "CancellableStream", Stream)


async def test_the_collector_follows_hosts_from_their_newest_stored_event(
    admin: Browser, monkeypatch
) -> None:
    host_id = await quiet_host(admin, docker_url="tcp://fake:2375")
    sessions = admin.app.state.sessionmaker
    events.store(sessions, [Event(host_id, T, "start", CID, "web", "x")])
    api = FakeApi(lambda n: [message("stop") | {"timeNano": T + 5}, message("start")])
    fake_daemon(monkeypatch, api)
    monkeypatch.setattr(events, "BACKOFF", (0.05,))
    collector = EventCollector(sessions, admin.app.state.hosts)
    collector._loop = asyncio.get_running_loop()
    await collector.supervise()
    deadline = time.monotonic() + 10
    while len(api.asked) < 2 and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await collector.close()
    assert api.asked[0]["since"] == events.since_of(T), "from the newest stored"
    assert api.asked[1]["since"] == events.since_of(T + 5), (
        "an ended stream reopens from its newest"
    )
    assert all(r.closed for r in api.responses)
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
    api = FakeApi(lambda n: [])
    fake_daemon(monkeypatch, api)
    collector = EventCollector(admin.app.state.sessionmaker, admin.app.state.hosts)
    collector._loop = asyncio.get_running_loop()
    await collector.supervise()
    deadline = time.monotonic() + 10
    while not api.asked and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await collector.close()
    assert "since" not in api.asked[0], "no since: nothing before the daemon's present"


async def test_a_refused_stream_is_no_working_stream(admin: Browser, monkeypatch) -> None:
    host_id = await quiet_host(admin, docker_url="tcp://fake:2375", alerts_enabled=True)
    api = FakeApi(lambda n: [message("start")], status=403)
    fake_daemon(monkeypatch, api)
    monkeypatch.setattr(events, "BACKOFF", (0.05,))
    collector = EventCollector(admin.app.state.sessionmaker, admin.app.state.hosts)
    collector._loop = asyncio.get_running_loop()
    seen: list[bool] = []
    monkeypatch.setattr(collector, "_stream", lambda hid, ok: seen.append(ok))
    await collector.supervise()
    deadline = time.monotonic() + 10
    while len(api.asked) < 2 and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
    await collector.close()
    assert seen and not any(seen), "never reported working"
    assert collector._follows == {} and host_id
