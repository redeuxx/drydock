"""The container status collector without a daemon (parsing, read(), the poll loop), and
the dashboard cards and containers page it feeds."""

import asyncio
import re
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import docker.errors
import pytest
import requests
from sqlalchemy import select, update

from drydock.hosts import client, status
from drydock.hosts.helper import helper_labels
from drydock.hosts.manager import HostUnavailable
from drydock.hosts.status import Reading, Sample, StatusCollector
from drydock.models import Host, Job, JobTarget, StorageTarget, UpdatePolicy, UserSession
from drydock.routes import containers
from drydock.routes import images as images_routes
from drydock.updates.check import HostChecks, Verdict
from tests.conftest import Browser, add_user

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)
INSTANCE = "drydocktestinstance"
INFO = {
    "Name": "rigel",
    "OperatingSystem": "Ubuntu 24.04 LTS",
    "Architecture": "x86_64",
    "ServerVersion": "29.9.2",
    "NCPU": 8,
    "MemTotal": 8 * 2**30,
    "Images": 41,
}


def summary(
    cid: str,
    name: str,
    state: str = "running",
    status_text: str = "Up 2 hours",
    labels: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "Id": cid,
        "Names": [f"/{name}"],
        "Image": "busybox:1.37.0",
        "State": state,
        "Status": status_text,
        "Labels": labels or {},
        **extra,
    }


def stats(
    cpu: int, system: int, usage: int = 100 * 2**20, detail: dict[str, Any] | None = None
) -> dict[str, Any]:
    """One-shot stats as Docker 29 sends them: no precpu_stats."""
    return {
        "cpu_stats": {
            "cpu_usage": {"total_usage": cpu},
            "system_cpu_usage": system,
            "online_cpus": 8,
        },
        "precpu_stats": {"cpu_usage": {"total_usage": 0}},
        "memory_stats": {
            "usage": usage,
            "stats": {"inactive_file": 20 * 2**20} if detail is None else detail,
            "limit": 8 * 2**30,
        },
        "networks": {"eth0": {"rx_bytes": 1500, "tx_bytes": 120}, "eth1": {"rx_bytes": 500}},
        "blkio_stats": {
            "io_service_bytes_recursive": [
                {"major": 8, "minor": 0, "op": "read", "value": 4096},
                {"major": 8, "minor": 0, "op": "write", "value": 1024},
                {"major": 8, "minor": 16, "op": "read", "value": 4096},
            ]
        },
    }


def reading(containers: list[dict], stats_by_id: dict[str, dict], **kwargs: Any) -> Reading:
    return Reading(
        info=kwargs.get("info", INFO),
        containers=containers,
        stats=stats_by_id,
        restarts=kwargs.get("restarts", {}),
        volumes=kwargs.get("volumes", 3),
        networks=kwargs.get("networks", 4),
    )


def by_name(snapshot: status.HostSnapshot) -> dict[str, status.ContainerStatus]:
    return {c.name: c for c in snapshot.containers}


# SUMMARIZE


def test_summary_counts_states_health_and_stacks() -> None:
    project = {"com.docker.compose.project": "web", "com.docker.compose.service": "app"}
    containers = [
        summary("a" * 64, "web-app-1", labels=project, Health={"Status": "healthy"}),
        summary("b" * 64, "web-db-1", "exited", "Exited (0) 3 days ago", labels=project),
        summary("c" * 64, "solo", "paused", "Up 1 hour (Paused)"),
        summary(
            "d" * 64,
            "api",
            status_text="Up 5 minutes (unhealthy)",
            labels={"com.docker.compose.project": "api"},
        ),
    ]
    snapshot, _ = status.summarize(7, reading(containers, {}), {}, NOW)
    assert snapshot.host_id == 7 and snapshot.taken_at == NOW and snapshot.error is None
    assert (snapshot.name, snapshot.engine, snapshot.ncpu, snapshot.images) == (
        "rigel",
        "29.9.2",
        8,
        41,
    )
    assert (snapshot.volumes, snapshot.networks) == (3, 4)
    assert snapshot.states == {"running": 2, "exited": 1, "paused": 1}
    assert snapshot.health == {"healthy": 1, "unhealthy": 1}
    assert snapshot.stacks == (1, 1, 0)  # api runs, web is partial
    rows = by_name(snapshot)
    assert rows["web-app-1"].project == "web" and rows["web-app-1"].service == "app"
    assert rows["solo"].project is None and rows["solo"].health is None
    assert [c.name for c in snapshot.containers] == sorted(rows)


def test_health_from_the_status_text_on_older_apis() -> None:
    for text, expected in [
        ("Up 2 hours (healthy)", "healthy"),
        ("Up 2 hours (unhealthy)", "unhealthy"),
        ("Up 3 seconds (health: starting)", "starting"),
        ("Up 2 hours", None),
        ("Exited (1) 2 hours ago", None),
    ]:
        assert status.health_of(summary("a", "x", status_text=text)) == expected
    # The Health field wins, and an unknown value in it falls back to the text.
    assert status.health_of(summary("a", "x", "running", "Up (healthy)", Health={})) == "healthy"
    weird = summary("a", "x", status_text="Up 1 hour", Health={"Status": "none"})
    assert status.health_of(weird) is None


def test_cpu_needs_two_samples() -> None:
    cid = "a" * 64
    containers = [summary(cid, "busy")]
    first, samples = status.summarize(1, reading(containers, {cid: stats(1_000, 10_000)}), {}, NOW)
    assert by_name(first)["busy"].cpu_percent is None
    assert first.cpu_percent is None, "unknown, not 0, until a second sample"
    assert samples == {cid: Sample(1_000, 10_000)}

    second, samples = status.summarize(
        1, reading(containers, {cid: stats(3_000, 20_000)}), samples, NOW
    )
    # 2 000 of 10 000 ns of all-core time: 20 % of the host, 160 % of one core on 8 cores.
    assert second.cpu_percent == pytest.approx(20.0)
    assert by_name(second)["busy"].cpu_percent == pytest.approx(160.0)
    assert samples == {cid: Sample(3_000, 20_000)}


def test_cpu_counter_reset_is_unknown_never_negative() -> None:
    cid = "a" * 64
    before = {cid: Sample(50_000, 10_000)}
    snapshot, samples = status.summarize(
        1, reading([summary(cid, "restarted")], {cid: stats(1_000, 20_000)}), before, NOW
    )
    assert by_name(snapshot)["restarted"].cpu_percent is None
    assert snapshot.cpu_percent is None
    assert samples == {cid: Sample(1_000, 20_000)}, "the new counter is the next baseline"


def test_host_cpu_sums_what_is_known_and_is_zero_with_nothing_running() -> None:
    a, b = "a" * 64, "b" * 64
    containers = [summary(a, "old"), summary(b, "new")]
    snapshot, _ = status.summarize(
        1,
        reading(containers, {a: stats(2_000, 20_000), b: stats(500, 20_000)}),
        {a: Sample(1_000, 10_000)},
        NOW,
    )
    assert snapshot.cpu_percent == pytest.approx(10.0)  # b is new: only a is counted
    idle, _ = status.summarize(1, reading([summary(a, "x", "exited")], {}), {}, NOW)
    assert idle.cpu_percent == 0.0
    # A daemon whose stats carry no CPU counters: unknown, never a made-up 0.
    blind = stats(0, 0)
    del blind["cpu_stats"]["system_cpu_usage"]
    unknown, _ = status.summarize(1, reading([summary(a, "x")], {a: blind}), {}, NOW)
    assert unknown.cpu_percent is None


def test_memory_leaves_out_the_inactive_page_cache() -> None:
    mib = 2**20
    assert status.memory_used(stats(0, 0, 100 * mib)) == 80 * mib  # cgroup v2
    # cgroup v1 has both; docker stats subtracts the recursive total.
    v1_detail = {"total_inactive_file": 30 * mib, "inactive_file": 10 * mib, "cache": 50 * mib}
    assert status.memory_used(stats(0, 0, 100 * mib, v1_detail)) == 70 * mib
    assert status.memory_used(stats(0, 0, 100 * mib, {})) == 100 * mib
    assert status.memory_used(stats(0, 0, mib, {"inactive_file": 2 * mib})) == mib
    assert status.memory_used({"memory_stats": {}}) is None
    cid = "a" * 64
    snapshot, _ = status.summarize(1, reading([summary(cid, "x")], {cid: stats(0, 1)}), {}, NOW)
    assert snapshot.mem_bytes == 80 * mib
    assert snapshot.mem_percent == pytest.approx(100 * 80 / (8 * 1024))
    assert by_name(snapshot)["x"].mem_limit == 8 * 2**30


def test_network_and_block_io() -> None:
    assert status.network_bytes(stats(0, 0)) == (2000, 120)
    assert status.network_bytes({}) == (None, None)  # network_mode none: no interfaces
    assert status.block_bytes(stats(0, 0)) == (8192, 1024)
    v1 = {
        "blkio_stats": {
            "io_service_bytes_recursive": [
                {"op": "Read", "value": 10},
                {"op": "Write", "value": 5},
                {"op": "Total", "value": 15},
            ]
        }
    }
    assert status.block_bytes(v1) == (10, 5)
    assert status.block_bytes({"blkio_stats": {"io_service_bytes_recursive": None}}) == (
        None,
        None,
    )
    empty = {"blkio_stats": {"io_service_bytes_recursive": []}}  # some cgroup v2 hosts
    assert status.block_bytes(empty) == (None, None)


def test_ips_and_ports() -> None:
    container = summary(
        "a",
        "web",
        NetworkSettings={
            "Networks": {
                "web_default": {"IPAddress": "172.30.21.4"},
                "bridge": {"IPAddress": "172.17.0.2"},
                "none": {"IPAddress": ""},
            }
        },
        Ports=[
            {"IP": "0.0.0.0", "PrivatePort": 8080, "PublicPort": 21002, "Type": "tcp"},  # noqa: S104
            {"IP": "::", "PrivatePort": 8080, "PublicPort": 21002, "Type": "tcp"},
            {"PrivatePort": 9000, "Type": "tcp"},  # exposed, not published
            {"IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 53, "Type": "udp"},  # noqa: S104
            {"IP": "127.0.0.1", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"},
            {"IP": "::1", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"},
        ],
    )
    assert status.ips_of(container) == (("bridge", "172.17.0.2"), ("web_default", "172.30.21.4"))
    assert status.ports_of(container) == (
        status.Port(53, 53, "udp"),
        status.Port(5432, 5432, "tcp", loopback=True),
        status.Port(21002, 8080, "tcp"),
    )


def test_bad_values_from_the_daemon_are_ignored() -> None:
    cid = "a" * 64
    junk = {
        "cpu_stats": {"cpu_usage": {"total_usage": "1"}, "system_cpu_usage": True},
        "memory_stats": {"usage": None, "limit": "big"},
        "networks": {"eth0": "x"},
        "blkio_stats": {"io_service_bytes_recursive": ["x", {"op": "read", "value": "1"}]},
    }
    info = {"NCPU": "8", "MemTotal": None, "Images": False}
    snapshot, samples = status.summarize(
        1, reading([summary(cid, "x")], {cid: junk}, info=info), {}, NOW
    )
    row = by_name(snapshot)["x"]
    assert (row.cpu_percent, row.mem_bytes, row.mem_limit, row.net_rx) == (None, None, None, None)
    assert (row.block_read, row.block_write) == (None, None)
    assert (snapshot.ncpu, snapshot.mem_total, snapshot.images, snapshot.mem_percent) == (
        None,
        None,
        0,
        None,
    )
    assert samples == {}


def test_error_text_never_shows_the_daemon_body() -> None:
    response = requests.Response()
    response.status_code = 500
    exc = docker.errors.APIError("secret body", response, explanation="token=hunter2")
    assert status.error_text(exc) == "The Docker daemon answered HTTP 500."
    old = client.UnsupportedDaemon("Docker Engine 20.10 is too old.")
    assert status.error_text(old) == "Docker Engine 20.10 is too old."
    # Raw connection errors name socket paths and URLs: every role would see them.
    for raw in [
        client.DockerUnavailable("Cannot reach the Docker daemon: /run/drydock/hosts/3.sock"),
        requests.ConnectionError("http+docker://localhost/v1.56/info"),
        OSError("No such file: /run/drydock/hosts/3.sock"),
    ]:
        assert status.error_text(raw) == "Cannot reach the Docker daemon."


# READ


@dataclass
class FakeApi:
    containers_list: list[dict[str, Any]]
    stats_by_id: dict[str, Any] = field(default_factory=dict)
    restart_counts: dict[str, Any] = field(default_factory=dict)
    started: dict[str, Any] = field(default_factory=dict)
    inspected: list[str] = field(default_factory=list)

    def info(self) -> dict[str, Any]:
        return INFO

    def containers(self, all: bool) -> list[dict[str, Any]]:
        assert all
        return self.containers_list

    def stats(self, cid: str, stream: bool, one_shot: bool) -> dict[str, Any]:
        assert stream is False and one_shot is True
        found = self.stats_by_id.get(cid, stats(1, 1))
        if isinstance(found, Exception):
            raise found
        return found

    def inspect_container(self, cid: str) -> dict[str, Any]:
        self.inspected.append(cid)
        found = self.restart_counts.get(cid, 0)
        if isinstance(found, Exception):
            raise found
        return {
            "RestartCount": found,
            "State": {"StartedAt": self.started.get(cid, "2026-11-03T10:00:00.123456789Z")},
        }

    def volumes(self) -> dict[str, Any]:
        return {"Volumes": None}

    def networks(self) -> list[dict[str, Any]]:
        return [{}, {}]


def test_read_skips_helpers_and_stats_of_stopped_or_vanished_containers() -> None:
    gone = docker.errors.NotFound("gone")
    api = FakeApi(
        [
            summary("run", "run"),
            summary("paused", "paused", "paused"),
            summary("exited", "exited", "exited"),
            summary("vanished", "vanished"),
            summary("slow", "slow"),
            summary("helper", "drydock-helper-1", labels=helper_labels(INSTANCE)),
            summary("other", "other-helper", labels=helper_labels("anotherdrydock")),
        ],
        stats_by_id={"vanished": gone, "slow": requests.exceptions.ReadTimeout("slow")},
        restart_counts={"run": 3, "vanished": gone, "paused": True},
        started={"exited": "0001-01-01T00:00:00Z", "slow": "not a time", "paused": None},
    )
    result = status.read(api, INSTANCE, {}, 100.0)
    assert [c["Id"] for c in result.containers] == [
        "run",
        "paused",
        "exited",
        "vanished",
        "slow",
        "other",
    ]
    assert set(result.stats) == {"run", "paused", "other"}
    assert result.restarts == {"run": 3, "paused": 0, "exited": 0, "slow": 0, "other": 0}
    started = datetime(2026, 11, 3, 10, 0, tzinfo=UTC)
    assert result.started == {
        "run": started,
        "paused": None,
        "exited": None,  # never started
        "slow": None,
        "other": started,
    }
    snapshot, _ = status.summarize(1, result, {}, NOW)
    assert by_name(snapshot)["run"].started_at == started
    assert by_name(snapshot)["other-helper"].labels == tuple(
        sorted(helper_labels("anotherdrydock").items())
    )

    # A dead connection is no single container's problem: the whole reading fails.
    api.stats_by_id["run"] = requests.ConnectionError("tunnel gone")
    with pytest.raises(requests.ConnectionError):
        status.read(api, INSTANCE, {}, 100.0)
    assert (result.volumes, result.networks) == (0, 2)


def test_read_inspects_on_new_state_change_or_age_only() -> None:
    api = FakeApi([summary("a", "a"), summary("b", "b")], restart_counts={"a": 1, "b": 0})
    inspected: dict[str, status.Inspected] = {}
    status.read(api, INSTANCE, inspected, 100.0)
    assert sorted(api.inspected) == ["a", "b"]

    api.inspected.clear()
    status.read(api, INSTANCE, inspected, 100.0 + status.INSPECT_EVERY - 1)
    assert api.inspected == []

    api.containers_list[1]["State"] = "exited"
    api.restart_counts["a"] = 2
    result = status.read(api, INSTANCE, inspected, 100.0 + status.INSPECT_EVERY - 1)
    assert api.inspected == ["b"]
    assert result.restarts["a"] == 1, "not inspected again yet"

    api.inspected.clear()
    result = status.read(api, INSTANCE, inspected, 100.0 + status.INSPECT_EVERY)
    assert api.inspected == ["a"]
    assert result.restarts["a"] == 2

    api.containers_list.pop()
    status.read(api, INSTANCE, inspected, 200.0)
    assert set(inspected) == {"a"}, "a removed container is forgotten"


# THE COLLECTOR


@dataclass
class FakeHandle:
    api: FakeApi
    closed: bool = False

    @property
    def client(self) -> FakeHandle:
        return self

    def close(self) -> None:
        self.closed = True


class FakeManager:
    instance_id = INSTANCE

    def __init__(self) -> None:
        self.down: dict[int, str] = {}

    def docker_url(self, host: Host) -> str:
        if host.id in self.down:
            raise HostUnavailable(self.down[host.id])
        return host.docker_url or f"unix:///run/drydock/hosts/{host.id}.sock"


def make_host(host_id: int, url: str = "tcp://socket-proxy:2375") -> Host:
    return Host(id=host_id, name=f"h{host_id}", kind="local", docker_url=url, enabled=True)


@pytest.fixture
async def collector(monkeypatch) -> tuple[StatusCollector, FakeManager, list[Any], list[Host]]:
    """A collector over fake hosts. opens records each open_client(); it hands out the
    queued items in turn: a FakeApi to connect to, or an exception to raise."""
    manager = FakeManager()
    hosts: list[Host] = []
    opens: list[Any] = []
    queue: list[Any] = []

    def open_client(url: str, timeout: float) -> FakeHandle:
        assert timeout == status.TIMEOUT
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        handle = FakeHandle(item)
        opens.append(handle)
        return handle

    monkeypatch.setattr(status.client, "open_client", open_client)
    collector = StatusCollector(None, manager)  # type: ignore[arg-type]
    monkeypatch.setattr(collector, "_load_hosts", lambda: list(hosts))
    monkeypatch.setattr(collector, "_load_acks", lambda: None)  # no database to read
    collector.queue = queue  # type: ignore[attr-defined]
    collector.opens = opens  # type: ignore[attr-defined]
    return collector, manager, queue, hosts


async def poll(collector: StatusCollector) -> None:
    await asyncio.gather(*await collector.poll())


async def test_collector_is_idle_until_a_page_looks(collector, monkeypatch) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    loads = []
    monkeypatch.setattr(status_collector, "_load_hosts", lambda: loads.append(1) or list(hosts))
    assert await status_collector.poll() == []
    assert loads == [], "not even the database is read"

    queue.append(FakeApi([summary("a", "web")]))
    status_collector.touch()
    await poll(status_collector)
    snapshot = status_collector.snapshot(1)
    assert snapshot is not None and [c.name for c in snapshot.containers] == ["web"]

    status_collector._viewed_at = -1e9  # looked at long ago
    assert await status_collector.poll() == []


async def test_a_host_no_page_shows_lets_go_of_its_connection_and_samples(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    api = FakeApi([summary("a", "web")], stats_by_id={"a": stats(1_000, 10_000)})
    queue.append(api)
    status_collector.touch()
    await poll(status_collector)
    await poll(status_collector)
    taken_at = status_collector.snapshot(1).taken_at

    status_collector._viewed_at = -1e9  # nobody looked for a long time
    assert await status_collector.poll() == []
    assert status_collector.opens[0].closed
    assert status_collector.snapshot(1).taken_at == taken_at, "the last reading stays"

    # Hours later: the first poll compares with nothing, not with the old sample.
    api.stats_by_id["a"] = stats(900_000, 90_000_000)
    queue.append(api)
    status_collector.touch()
    await poll(status_collector)
    assert len(status_collector.opens) == 2
    assert status_collector.snapshot(1).cpu_percent is None


async def test_one_client_per_host_is_kept_between_polls(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    api = FakeApi([summary("a", "web")], stats_by_id={"a": stats(1_000, 10_000)})
    queue.append(api)
    status_collector.touch()
    await poll(status_collector)
    api.stats_by_id["a"] = stats(2_000, 20_000)
    await poll(status_collector)
    assert len(status_collector.opens) == 1
    assert status_collector.snapshot(1).cpu_percent == pytest.approx(10.0)


async def test_a_dropped_connection_is_retried_once_anew(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    stale = FakeApi([summary("a", "old")])
    queue.append(stale)
    status_collector.touch()
    await poll(status_collector)

    stale.info = lambda: (_ for _ in ()).throw(requests.ConnectionError("tunnel restarted"))
    queue.append(FakeApi([summary("b", "new")]))
    await poll(status_collector)
    first, second = status_collector.opens
    assert first.closed and not second.closed
    snapshot = status_collector.snapshot(1)
    assert snapshot.error is None and [c.name for c in snapshot.containers] == ["new"]


async def test_failures_keep_the_last_data_and_say_since_when(collector) -> None:
    status_collector, manager, queue, hosts = collector
    hosts.append(make_host(1))
    queue.append(FakeApi([summary("a", "web")]))
    status_collector.touch()
    await poll(status_collector)
    taken_at = status_collector.snapshot(1).taken_at

    manager.down[1] = "Connect call failed (10.0.0.5, 22)"
    await poll(status_collector)
    first = status_collector.snapshot(1)
    assert first.error == status.NOT_CONNECTED, "the address is for admins only"
    assert first.taken_at == taken_at and [c.name for c in first.containers] == ["web"]
    assert first.stale_since is not None

    del manager.down[1]
    status_collector.opens[0].api.info = lambda: (_ for _ in ()).throw(OSError("reset"))
    queue.append(client.DockerUnavailable("Cannot reach the Docker daemon: refused"))
    await poll(status_collector)
    second = status_collector.snapshot(1)
    assert second.error == "Cannot reach the Docker daemon."
    assert second.stale_since == first.stale_since, "stale since the first failure"
    assert status_collector.opens[0].closed

    queue.append(FakeApi([summary("a", "web")]))
    await poll(status_collector)
    recovered = status_collector.snapshot(1)
    assert recovered.error is None and recovered.stale_since is None


async def test_a_host_never_reached_has_only_an_error(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    queue.append(client.UnsupportedDaemon("Docker Engine 20.10 is too old."))
    status_collector.touch()
    await poll(status_collector)
    snapshot = status_collector.snapshot(1)
    assert snapshot.taken_at is None and snapshot.containers == ()
    assert snapshot.error == "Docker Engine 20.10 is too old."
    assert len(queue) == 0, "a fresh connection that fails is not retried"


async def test_unexpected_errors_are_logged_not_shown(collector, caplog) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    api = FakeApi([summary("a", "web")])
    api.info = lambda: (_ for _ in ()).throw(ValueError("internal detail"))
    queue.append(api)
    status_collector.touch()
    await poll(status_collector)
    assert "internal detail" not in status_collector.snapshot(1).error
    assert "internal detail" in caplog.text


async def test_changed_or_removed_hosts_are_forgotten(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    queue.append(FakeApi([summary("a", "old-daemon")]))
    status_collector.touch()
    await poll(status_collector)

    hosts[0] = make_host(1, "tcp://elsewhere:2375")
    queue.append(FakeApi([summary("b", "new-daemon")]))
    await poll(status_collector)
    assert status_collector.opens[0].closed
    assert [c.name for c in status_collector.snapshot(1).containers] == ["new-daemon"]

    hosts.clear()  # deleted or disabled
    await poll(status_collector)
    assert status_collector.snapshot(1) is None
    assert status_collector.opens[1].closed


async def test_a_slow_host_is_not_polled_twice_at_once(collector) -> None:
    status_collector, _, _, hosts = collector
    hosts.append(make_host(1))
    release = asyncio.Event()

    async def slow(host, cache) -> None:
        await release.wait()

    status_collector._read_into = slow  # type: ignore[method-assign]
    status_collector.touch()
    first = await status_collector.poll()
    assert len(first) == 1
    assert await status_collector.poll() == []
    release.set()
    await asyncio.gather(*first)
    assert len(await status_collector.poll()) == 1
    await status_collector.close()


# THE DASHBOARD'S ENVIRONMENT CARDS


def add_host(browser: Browser, **fields: Any) -> int:
    values = {
        "name": "rigel",
        "kind": "local",
        "docker_url": "tcp://socket-proxy:2375",
        "enabled": True,
    }
    host = Host(**(values | fields))
    with browser.app.state.sessionmaker() as db, db.begin():
        db.add(host)
        db.flush()
        return host.id


async def cached(browser: Browser, monkeypatch) -> StatusCollector:
    """The app's collector, stopped so that only what a test puts in its cache shows, with
    every way to reach Docker made to fail."""

    def no_docker(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a page called Docker")

    monkeypatch.setattr(client, "open_client", no_docker)
    collector: StatusCollector = browser.app.state.status
    await collector.close()
    return collector


def put(collector: StatusCollector, snapshot: status.HostSnapshot) -> None:
    collector._caches[snapshot.host_id] = status.HostCache(key=(), snapshot=snapshot)


async def test_cards_show_the_cache_and_never_call_docker(admin: Browser, monkeypatch) -> None:
    collector = await cached(admin, monkeypatch)
    host_id = add_host(admin)
    containers = [
        summary("a" * 64, "<script>alert(1)</script>", Health={"Status": "unhealthy"}),
        summary("b" * 64, "db", "exited", "Exited (0) 2 hours ago"),
    ]
    taken, _ = status.summarize(host_id, reading(containers, {}), {}, datetime.now(UTC))
    put(collector, taken)
    for path, headers in [
        ("/", {}),
        ("/status/hosts", {}),
        ("/status/hosts", {"HX-Request": "true"}),
    ]:
        response = await admin.get(path, headers=headers)
        assert response.status_code == 200, path
        text = response.text
        assert 'id="host-status"' in text and 'data-poller="Live status"' in text
        assert "1 unhealthy: &lt;script&gt;alert(1)&lt;/script&gt;" in text
        assert "<script>alert(1)" not in text
        assert "Docker 29.9.2" in text and "Read just now" in text
        assert "(0 bytes / 8.0 GiB)" in text, "memory used of the total"
        assert ("<header" in text) is not bool(headers), "a poll gets the cards alone"
    assert collector._viewed_at > 0, "the page marked the hosts as shown"


async def test_viewers_see_the_cards_without_addresses_or_settings(
    admin: Browser, monkeypatch
) -> None:
    collector = await cached(admin, monkeypatch)
    host_id = add_host(admin)
    taken, _ = status.summarize(host_id, reading([], {}), {}, datetime.now(UTC))
    put(collector, taken)
    page = (await admin.get("/")).text
    assert "tcp://socket-proxy:2375" in page and f'href="/hosts/{host_id}"' in page
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    for path in ("/", "/status/hosts"):
        response = await admin.get(path)
        assert response.status_code == 200
        assert "rigel" in response.text
        assert (
            "socket-proxy" not in response.text and f'href="/hosts/{host_id}"' not in response.text
        )


async def test_cards_for_hosts_unread_failing_stale_or_disabled(
    admin: Browser, monkeypatch
) -> None:
    collector = await cached(admin, monkeypatch)
    unread = add_host(admin, name="unread")
    failing = add_host(admin, name="failing")
    stale = add_host(admin, name="stale")
    add_host(admin, name="off", enabled=False)
    put(collector, status.HostSnapshot(host_id=failing, taken_at=None, error="Cannot reach it."))
    old, _ = status.summarize(stale, reading([], {}), {}, datetime.now(UTC))
    put(collector, replace(old, error="The SSH connection is not up.", stale_since=old.taken_at))
    text = (await admin.get("/status/hosts")).text
    assert "Reading the containers" in text
    assert "Cannot read the containers: Cannot reach it." in text
    assert "Stale since just now: The SSH connection is not up." in text
    assert "Disabled: drydock does not connect to it." in text
    assert unread  # its card is the one still reading


async def test_no_hosts_no_poller(admin: Browser, monkeypatch) -> None:
    await cached(admin, monkeypatch)
    text = (await admin.get("/")).text
    assert "No host is set up yet." in text and "data-poller" not in text


async def test_polls_never_keep_a_session_alive(admin: Browser) -> None:
    def last_seen() -> datetime:
        with admin.app.state.sessionmaker() as db:
            return db.scalars(select(UserSession.last_seen_at)).one()

    def set_last_seen(value: datetime) -> None:
        with admin.app.state.sessionmaker() as db, db.begin():
            db.execute(update(UserSession).values(last_seen_at=value))

    earlier = datetime.now(UTC) - timedelta(minutes=30)
    set_last_seen(earlier)
    polled = await admin.get("/status/hosts", headers={"HX-Request": "true", "X-Drydock-Poll": "1"})
    assert polled.status_code == 200
    assert last_seen() == earlier
    await admin.get("/status/hosts")
    assert last_seen() > earlier

    set_last_seen(datetime.now(UTC) - timedelta(hours=2))  # idle past the timeout
    expired = await admin.get(
        "/status/hosts", headers={"HX-Request": "true", "X-Drydock-Poll": "1"}
    )
    assert expired.status_code == 401


async def test_a_page_wakes_the_collector_for_a_cold_host(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    queue.append(FakeApi([summary("a", "web")]))
    status_collector.start()
    try:
        await asyncio.sleep(0.1)  # the first tick found nothing to read
        assert status_collector.snapshot(1) is None
        await client.run_blocking(status_collector.touch)  # as a sync route calls it
        for _ in range(50):  # long before the next tick, INTERVAL seconds away
            if status_collector.snapshot(1) is not None:
                break
            await asyncio.sleep(0.05)
        assert status_collector.snapshot(1) is not None
    finally:
        await status_collector.close()


# THE CONTAINERS PAGE


def add_jobs(browser: Browser, host_id: int) -> dict[str, int]:
    """A job of the container web, and a disabled one of the stack app with a second
    target, cache."""
    with browser.app.state.sessionmaker() as db, db.begin():
        storage = StorageTarget(name="disk", kind="local", config_enc="x")
        db.add(storage)
        db.flush()
        ids = {}
        for name, kind, what in [("web-nightly", "container", "web"), ("app-all", "stack", "app")]:
            job = Job(
                uuid=str(uuid.uuid4()),
                name=name,
                host_id=host_id,
                storage_target_id=storage.id,
                target_type=kind,
                target=what,
                scope="all",
                enabled=kind == "container",
            )
            db.add(job)
            db.flush()
            ids[name] = job.id
        db.add(
            JobTarget(
                job_id=ids["app-all"],
                position=1,
                target_type="container",
                target="cache",
                uuid=str(uuid.uuid4()),
            )
        )
        return ids


async def a_host_with_containers(admin: Browser, monkeypatch) -> tuple[StatusCollector, int]:
    """The local host with web (a port, an address, a secret label), db and cache (stack
    app; db unhealthy, cache exited) and one with markup for a name. web and db have CPU."""
    collector = await cached(admin, monkeypatch)
    host_id = add_host(admin)
    app = {status.PROJECT_LABEL: "app"}
    containers = [
        summary(
            "a" * 64,
            "web",
            labels={"traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$secret"},
            Ports=[
                {"PublicPort": 8080, "PrivatePort": 80, "Type": "tcp"},
                {"PublicPort": 9090, "PrivatePort": 90, "Type": "tcp", "IP": "127.0.0.1"},
                {"PublicPort": 9090, "PrivatePort": 90, "Type": "tcp", "IP": "::1"},
            ],
            NetworkSettings={"Networks": {"bridge": {"IPAddress": "172.17.0.9"}}},
        ),
        summary("b" * 64, "db", labels=app, Health={"Status": "unhealthy"}),
        summary("c" * 64, "cache", "exited", "Exited (0) 2 hours ago", labels=app),
        summary(
            "d" * 64,
            "<img src=x onerror=alert(1)>",
            NetworkSettings={"Networks": {"bridge": {"IPAddress": "172.17.0.10"}}},
        ),
    ]
    idle = {"a" * 64: stats(0, 0), "b" * 64: stats(0, 0)}
    _, samples = status.summarize(host_id, reading(containers, idle), {}, datetime.now(UTC))
    busy = {"a" * 64: stats(10**9, 8 * 10**9), "b" * 64: stats(4 * 10**9, 8 * 10**9)}
    taken, _ = status.summarize(host_id, reading(containers, busy), samples, datetime.now(UTC))
    put(collector, taken)
    return collector, host_id


MARKUP = "&lt;img src=x onerror=alert(1)&gt;"


def names_in_order(text: str) -> list[str]:
    return re.findall(r'aria-haspopup="dialog" title="([^"]*)"', text)


async def shown(browser: Browser, query: str) -> list[str]:
    return names_in_order((await browser.get(f"/containers?{query}")).text)


async def test_containers_page_shows_the_cache_and_never_calls_docker(
    admin: Browser, monkeypatch
) -> None:
    collector, host_id = await a_host_with_containers(admin, monkeypatch)
    jobs = add_jobs(admin, host_id)
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert 'id="containers"' in page and 'data-poller="Container status"' in page
    assert 'id="containers-filter"' in page and "<header" in page
    for form in ("host-picker", "containers-filter"):  # else hx-csp strips its hx-* attributes
        assert re.search(rf'id="{form}"[^>]*hx-nonce="', page), form
    assert MARKUP in page and "<img src=x" not in page
    assert "Docker 29.9.2" in page and "8 cores" in page and "Live, read just now" in page
    assert "tcp://socket-proxy:2375" in page, "admins see the address"
    assert 'href="http://drydock.test:8080"' in page, "the local host's ports, at drydock's address"
    assert "9090&rarr;90/tcp" in page and ":9090" not in page, "no link to a loopback-only port"
    assert f'href="/jobs/{jobs["web-nightly"]}">web-nightly</a>' in page
    assert page.count(f'href="/jobs/{jobs["app-all"]}">app-all</a> (disabled)') == 4, "db, cache"
    assert "4 containers" in page
    assert collector._viewed_at > 0, "the page keeps the collector reading"

    # The table's own requests (poll, toolbar) get the table alone; the host picker the page.
    table = await admin.get(
        f"/containers?host={host_id}",
        headers={"HX-Request": "true", "HX-Target": "div#containers"},
    )
    assert 'id="containers"' in table.text and "<header" not in table.text
    assert 'id="containers-filter"' not in table.text
    picked = await admin.get(
        f"/containers?host={host_id}", headers={"HX-Request": "true", "HX-Target": "main#main"}
    )
    assert 'id="containers-filter"' in picked.text


async def test_containers_sort_by_an_allowed_column_only(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    by_name_page = await shown(admin, f"host={host_id}")
    assert by_name_page == [MARKUP, "cache", "db", "web"]
    cpu = (await admin.get(f"/containers?host={host_id}&sort=cpu&order=desc")).text
    assert names_in_order(cpu) == ["db", "web", MARKUP, "cache"], "busiest first, unknown last"
    assert 'aria-sort="descending"' in cpu
    assert await shown(admin, f"host={host_id}&sort=cpu") == ["web", "db", MARKUP, "cache"]
    assert (await shown(admin, f"host={host_id}&sort=ip"))[:2] == ["web", MARKUP]
    odd = await admin.get(
        f"/containers?host={host_id}&sort=__class__&order=sideways&status=nope&whatever=1"
    )
    assert odd.status_code == 200
    assert names_in_order(odd.text) == by_name_page, "unknown values fall back to the defaults"
    assert "4 containers" in odd.text


async def test_containers_filter_by_state_stack_and_search(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    every = await shown(admin, f"host={host_id}")
    assert await shown(admin, f"host={host_id}&status=unhealthy") == ["db"]
    assert await shown(admin, f"host={host_id}&status=exited") == ["cache"]
    assert await shown(admin, f"host={host_id}&stack=app") == ["cache", "db"]
    assert await shown(admin, f"host={host_id}&stack=app&status=running") == ["db"]
    assert await shown(admin, f"host={host_id}&q=WEB") == ["web"]
    assert await shown(admin, f"host={host_id}&q=busybox") == every, "the image"
    assert await shown(admin, f"host={host_id}&q=basicauth") == ["web"], "label keys"
    assert await shown(admin, f"host={host_id}&q=apr1") == ["web"], "label values, for admins"
    text = (await admin.get(f"/containers?host={host_id}&q=nothing-like-it")).text
    assert "No container matches." in text and "0 of 4 containers" in text


async def test_viewers_see_containers_without_addresses_or_label_values(
    admin: Browser, monkeypatch
) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    ssh = add_host(
        admin,
        name="vega",
        kind="ssh",
        docker_url=None,
        address="vega.example",
        port=22,
        username="drydock",
    )
    api = summary("e" * 64, "api", Ports=[{"PublicPort": 9000, "PrivatePort": 9000}])
    put(
        admin.app.state.status,
        status.summarize(ssh, reading([api], {}), {}, datetime.now(UTC))[0],
    )
    assert 'href="http://vega.example:9000"' in (await admin.get(f"/containers?host={ssh}")).text

    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    local = await admin.get(f"/containers?host={host_id}")
    assert local.status_code == 200 and "web" in local.text
    assert "socket-proxy" not in local.text
    assert 'href="http://drydock.test:8080"' in local.text, "drydock's own address is no secret"
    assert await shown(admin, f"host={host_id}&q=basicauth") == ["web"]
    assert await shown(admin, f"host={host_id}&q=apr1") == []
    remote = (await admin.get(f"/containers?host={ssh}")).text
    assert "api" in remote and "vega.example" not in remote


async def test_containers_page_for_no_unread_failing_stale_or_disabled_hosts(
    admin: Browser, monkeypatch
) -> None:
    collector = await cached(admin, monkeypatch)
    text = (await admin.get("/containers")).text
    assert "No host is set up yet." in text and "data-poller" not in text
    off = add_host(admin, name="aaa-off", enabled=False)
    unread = add_host(admin, name="unread")
    failing = add_host(admin, name="failing")
    stale = add_host(admin, name="stale")
    put(collector, status.HostSnapshot(host_id=failing, taken_at=None, error="Cannot reach it."))
    old, _ = status.summarize(stale, reading([], {}), {}, datetime.now(UTC))
    put(collector, replace(old, error="The SSH connection is not up.", stale_since=old.taken_at))

    for path in ("/containers", "/containers?host=999999"):
        first = (await admin.get(path)).text
        assert f'<option value="{failing}" selected>' in first, "the first enabled host by name"
        assert "Cannot read the containers: Cannot reach it." in first
    assert "Reading the containers" in (await admin.get(f"/containers?host={unread}")).text
    stale_page = (await admin.get(f"/containers?host={stale}")).text
    assert "Stale since just now: The SSH connection is not up." in stale_page
    assert "No containers on this host." in stale_page
    disabled = (await admin.get(f"/containers?host={off}")).text
    assert "Disabled: drydock does not connect to this host." in disabled
    assert "data-poller" not in disabled


async def test_dashboard_counters_link_to_the_filtered_containers(
    admin: Browser, monkeypatch
) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    cards = (await admin.get("/status/hosts")).text
    assert f'href="/containers?host={host_id}&amp;status=unhealthy"' in cards
    assert f'href="/containers?host={host_id}&amp;status=running"' in cards
    assert f'href="/containers?host={host_id}"' in cards


# THE CONTAINERS PAGE'S ACTIONS AND INSPECT (the Docker side: test_status_docker.py)


async def test_actions_and_inspect_need_their_roles_and_csrf(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    action = {"host": str(host_id), "action": f"stop:{'a' * 64}"}
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert 'id="container-actions"' in page and 'name="id" value="' + "a" * 64 in page
    assert f'hx-get="/containers/{host_id}/{"a" * 64}/inspect"' in page
    assert 'commandfor="confirm-stop"' in page, "stopping the selected ones asks first"
    assert (await admin.post("/containers/actions", action, csrf=False)).status_code == 403

    await add_user(admin, "runner", "operator")
    await add_user(admin, "watcher", "viewer")
    await admin.login("runner")
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert 'id="container-actions"' in page and "/inspect" not in page
    assert (await admin.get(f"/containers/{host_id}/{'a' * 64}/inspect")).status_code == 403

    await admin.login("watcher")
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert 'id="container-actions"' not in page and "data-select" not in page
    assert (await admin.post("/containers/actions", action)).status_code == 403


async def test_actions_refuse_bad_input_before_calling_docker(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    off = add_host(admin, name="off", enabled=False)
    for data, code in [
        ({"host": str(host_id), "action": "kill"}, 422),
        ({"host": str(host_id), "action": "stop:../../etc"}, 422),
        ({"host": str(host_id), "action": "stop", "id": ["not-an-id"]}, 422),
        ({"host": "999999", "action": "stop", "id": ["a" * 64]}, 404),
    ]:
        assert (await admin.post("/containers/actions", data)).status_code == code, data
    htmx = {"HX-Request": "true"}
    nothing = await admin.post(
        "/containers/actions", {"host": str(host_id), "action": "stop"}, headers=htmx
    )
    assert nothing.status_code == 200 and "Select containers first." in nothing.text
    assert nothing.headers["HX-Replace-Url"] == f"/containers?host={host_id}&sort=name&order=asc"
    many = {"host": str(host_id), "action": "stop", "id": [f"{i:064x}" for i in range(101)]}
    too_many = await admin.post("/containers/actions", many, headers=htmx)
    assert "Select at most 100 containers." in too_many.text
    assert not admin.sql("SELECT 1 FROM audit_events WHERE action LIKE 'container.%'")

    # A valid request on a disabled host: refused, and audited per container.
    disabled = await admin.post(
        "/containers/actions", {"host": str(off), "action": "start", "id": ["a" * 64]}, headers=htmx
    )
    assert "The host is disabled." in disabled.text
    assert admin.sql(
        "SELECT target, outcome FROM audit_events WHERE action = 'container.start'"
    ) == [("container:" + "a" * 12, "failure")]
    inspected = await admin.get(f"/containers/{off}/{'a' * 64}/inspect")
    assert "The host is disabled." in inspected.text

    # Without script the answer is a redirect, so a reload never acts again.
    plain = await admin.post(
        "/containers/actions", {"host": str(off), "action": "start", "id": ["a" * 64]}
    )
    assert plain.status_code == 303 and plain.headers["location"].startswith("/containers?host=")


async def test_remove_needs_an_admin_with_a_recent_password(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    remove = {"host": str(host_id), "action": f"remove:{'a' * 64}"}
    assert 'value="remove:' + "a" * 64 in (await admin.get(f"/containers?host={host_id}")).text
    await add_user(admin, "runner", "operator")
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    stale = await admin.post("/containers/actions", remove)
    assert stale.status_code == 403 and "Re-enter your password" in stale.text

    await admin.login("runner")
    assert 'value="remove:' not in (await admin.get(f"/containers?host={host_id}")).text
    assert (await admin.post("/containers/actions", remove)).status_code == 403
    stack = {"host": str(host_id), "stack": "app", "action": "remove"}
    assert (await admin.post("/stacks/actions", stack)).status_code == 403
    assert not admin.sql("SELECT 1 FROM audit_events WHERE action LIKE '%.remove'")


async def test_stacks_page_groups_the_cache_and_acts_on_every_member(
    admin: Browser, monkeypatch
) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    page = (await admin.get(f"/stacks?host={host_id}")).text
    assert ">app</a>" in page and "1 of 2" in page  # db runs, cache exited
    assert 'value="remove"' in page

    calls = []

    def fake(request, auth, host, verb, chosen):
        calls.append((verb, sorted(chosen)))
        return [containers.Outcome(verb, "db"), containers.Outcome(verb, "cache", "Nope.")]

    monkeypatch.setattr(containers, "run_actions", fake)
    htmx = {"HX-Request": "true"}
    data = {"host": str(host_id), "stack": "app", "action": "stop"}
    done = await admin.post("/stacks/actions", data, headers=htmx)
    assert calls == [("stop", ["b" * 64, "c" * 64])]
    assert "db: stopped" in done.text and "cache: Nope." in done.text
    assert done.headers["HX-Replace-Url"] == f"/stacks?host={host_id}"
    assert admin.sql("SELECT target, outcome FROM audit_events WHERE action = 'stack.stop'") == [
        ("stack:app", "failure")
    ]
    assert (await admin.post("/stacks/actions", data | {"stack": "nope"})).status_code == 404
    assert (await admin.post("/stacks/actions", data | {"action": "kill"})).status_code == 422

    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    page = (await admin.get(f"/stacks?host={host_id}")).text
    assert ">app</a>" in page and "/stacks/actions" not in page
    assert (await admin.post("/stacks/actions", data)).status_code == 403


async def test_stacks_page_shows_each_stacks_update_policies(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    page = (await admin.get(f"/stacks?host={host_id}")).text
    assert f'href="/updates/new?host={host_id}&amp;type=stack&amp;target=app"' in page
    assert f'href="/updates/new?host={host_id}&amp;type=stack&amp;target=%2A"' in page
    with admin.app.state.sessionmaker() as db, db.begin():
        policy = UpdatePolicy(
            name="app weekly", host_id=host_id, target_type="stack", target="app", cron="0 4 * * 0"
        )
        db.add(policy)
        db.flush()
        policy_id = policy.id
        db.add(
            UpdatePolicy(
                name="all", host_id=host_id, target_type="stack", target="*", cron="0 5 * * 0"
            )
        )
    page = (await admin.get(f"/stacks?host={host_id}")).text
    assert f'href="/updates/{policy_id}">app weekly</a>' in page and "/updates/new" not in page
    assert ">all</a>" in page, "every stack's policy is listed for each stack"
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    page = (await admin.get(f"/stacks?host={host_id}")).text
    assert "app weekly" in page and "/updates/" not in page


def test_an_exited_container_keeps_the_health_its_last_inspect_found() -> None:
    """Daemons before API 1.52 leave Health out of the list: inspect has it, also after
    an exit. A running container's health comes from the list alone."""
    containers = [
        summary("a" * 64, "gone", "exited", "Exited (1) 1 minute ago"),
        summary("b" * 64, "up", "running", "Up 2 hours"),
    ]
    found = replace(reading(containers, {}), health={"a" * 64: "unhealthy", "b" * 64: "unhealthy"})
    taken, _ = status.summarize(1, found, {}, datetime.now(UTC))
    assert by_name(taken)["gone"].health == "unhealthy"
    assert by_name(taken)["up"].health is None
    assert status.health_in({"State": {"Health": {"Status": "unhealthy"}}}) == "unhealthy"
    assert status.health_in({"State": {"Health": {"Status": "<b>"}}}) is None


async def test_an_acknowledged_exit_is_unhealthy_no_more_until_it_starts_again(
    admin: Browser, monkeypatch
) -> None:
    collector = await cached(admin, monkeypatch)
    host_id = add_host(admin)
    started = datetime(2026, 11, 1, tzinfo=UTC)
    containers = [
        summary(
            "e" * 64, "worker", "exited", "Exited (1) 1 hour ago", Health={"Status": "unhealthy"}
        ),
        summary("a" * 64, "web", Health={"Status": "unhealthy"}),
    ]

    def show(start: datetime) -> None:
        found = replace(reading(containers, {}), started={"e" * 64: start})
        put(collector, status.summarize(host_id, found, {}, datetime.now(UTC))[0])

    show(started)
    page = (await admin.get(f"/containers?host={host_id}&status=unhealthy")).text
    assert names_in_order(page) == ["web", "worker"]
    assert 'value="acknowledge:' + "e" * 64 in page
    assert 'value="acknowledge:' + "a" * 64 not in page, "running containers: not yet"

    htmx = {"HX-Request": "true"}
    data = {"host": str(host_id), "action": "acknowledge", "id": ["e" * 64, "a" * 64]}
    done = await admin.post("/containers/actions", data, headers=htmx)
    assert "worker: acknowledged" in done.text
    assert "web: It is not an exited, unhealthy one." in done.text
    assert names_in_order(
        (await admin.get(f"/containers?host={host_id}&status=unhealthy")).text
    ) == ["web"]
    assert admin.sql("SELECT container_id, acked_by FROM health_acks") == [("e" * 64, "admin")]
    assert admin.sql(
        "SELECT target, outcome FROM audit_events WHERE action = 'container.acknowledge'"
    ) == [("container:worker", "success"), ("container:web", "failure")]

    collector._acks = None  # as after a restart: start reads them from the database again
    collector._load_acks()
    assert collector.snapshot(host_id).health == {"unhealthy": 1}

    # It started again (and exited unhealthy again) after the acknowledgement.
    show(datetime.now(UTC) + timedelta(minutes=1))
    assert collector.snapshot(host_id).health == {"unhealthy": 2}

    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    assert (await admin.post("/containers/actions", data)).status_code == 403


def test_inspect_hides_environment_values_and_secret_labels() -> None:
    info = {
        "Id": "a" * 64,
        "Config": {
            "Env": ["DB_PASSWORD=hunter2", "PATH=/usr/bin", "ODD"],
            "Labels": {"traefik.http.middlewares.a.basicauth.users": "x:$apr1$y", "tier": "web"},
        },
    }
    info["HostConfig"] = {"LogConfig": {"Type": "splunk", "Config": {"splunk-token": "t0k"}}}
    shown = containers.redacted(info)
    assert shown["HostConfig"]["LogConfig"] == {"Type": "splunk", "Config": {"splunk-token": "***"}}
    assert shown["Config"]["Env"] == ["DB_PASSWORD=***", "PATH=***", "ODD"]
    assert shown["Config"]["Labels"] == {
        "traefik.http.middlewares.a.basicauth.users": "***",
        "tier": "web",
    }
    assert info["Config"]["Env"][0] == "DB_PASSWORD=hunter2", "the original is left alone"
    assert containers.redacted({"Config": None}) == {"Config": None}


def test_actions_refuse_drydock_itself_and_its_helpers() -> None:
    mine = {"Id": "a" * 64, "Config": {"Labels": {}}}
    assert "itself" in containers.refusal(mine, frozenset({"a" * 64}))
    helper_info = {"Id": "b" * 64, "Config": {"Labels": helper_labels("another")}}
    assert "helper" in containers.refusal(helper_info, frozenset())
    assert containers.refusal({"Id": "c" * 64, "Config": {"Labels": None}}, frozenset()) is None
    keys = containers.lock_keys(
        {"Id": "c" * 64, "Name": "/web", "Config": {"Labels": {status.PROJECT_LABEL: "app"}}},
        "dscope",
    )
    assert keys == sorted(["c" * 64, "name:dscope:container:web", "name:dscope:project:app"])


async def test_try_hold_takes_all_keys_or_none(admin: Browser) -> None:
    dispatcher = admin.app.state.dispatcher
    assert await dispatcher.try_hold(["k1", "k2"], "run 1")
    assert not await dispatcher.try_hold(["k2", "k3"], "an action")
    assert not dispatcher._locks["k3"].locked(), "nothing taken when one is held"
    dispatcher.release_held(["k1", "k2"])
    assert await dispatcher.try_hold(["k2", "k3"], "an action")
    dispatcher.release_held(["k2", "k3"])


async def test_try_hold_never_jumps_a_waiting_run(admin: Browser) -> None:
    dispatcher = admin.app.state.dispatcher
    lock = dispatcher._locks["k"]
    await lock.acquire()
    waiter = asyncio.create_task(lock.acquire())  # a run waiting for the key
    await asyncio.sleep(0)
    lock.release()  # wakes the run, which has not run yet
    assert not await dispatcher.try_hold(["k"], "an action"), "it would wait behind the run"
    assert await waiter
    lock.release()
    assert await dispatcher.try_hold(["k"], "an action")
    dispatcher.release_held(["k"])


async def test_refresh_waits_for_a_reading_however_it_starts(collector) -> None:
    status_collector, _, queue, hosts = collector
    hosts.append(make_host(1))
    queue.append(FakeApi([summary("a", "web")]))
    await status_collector.refresh(1)
    assert status_collector.snapshot(1) is None, "only the process running the collector"
    status_collector.start()
    try:
        # touch() wakes the collector's own loop, which may start the reading first.
        await status_collector.refresh(1)
        assert by_name(status_collector.snapshot(1))["web"].state == "running"
    finally:
        await status_collector.close()


async def test_stacks_and_images_pages_check_for_updates(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    newer = {"b" * 64: Verdict("update", "newer", "postgres:17", "sha256:" + "2" * 64)}

    async def check_now(host) -> HostChecks:
        found = HostChecks(datetime.now(UTC), newer)
        admin.app.state.updates._results[host.id] = found
        return found

    monkeypatch.setattr(admin.app.state.updates, "check_now", check_now)
    monkeypatch.setattr(
        images_routes,
        "read_images",
        lambda request, host, behind: (
            [images_routes.Image("sha256:" + "f" * 64, ["pg:17"], 1, datetime.now(UTC), [])],
            None,
        ),
    )
    assert "Not checked yet" in (await admin.get(f"/stacks?host={host_id}")).text
    htmx = {"HX-Request": "true"}
    done = await admin.post("/stacks/check-updates", {"host": str(host_id)}, headers=htmx)
    assert "1 container with a newer image." in done.text
    assert "1 stack with a newer image" in done.text
    assert done.headers["HX-Replace-Url"] == f"/stacks?host={host_id}"
    done = await admin.post("/images/check-updates", {"host": str(host_id)}, headers=htmx)
    assert done.status_code == 200 and "Check for updates" in done.text
    assert (await admin.post("/stacks/check-updates", {"host": "999"})).status_code == 404

    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    assert "Check for updates" not in (await admin.get(f"/stacks?host={host_id}")).text
    assert (await admin.post("/images/check-updates", {"host": str(host_id)})).status_code == 403


def test_an_image_used_by_a_container_with_a_newer_image_is_marked(monkeypatch) -> None:
    class Api:
        def containers(self, all: bool) -> list[dict]:
            return [{"Id": "c1", "Names": ["/web"], "ImageID": "sha256:old"}]

        def images(self) -> list[dict]:
            return [
                {"Id": "sha256:old", "RepoTags": ["web:1"], "Size": 1, "Created": 0},
                {"Id": "sha256:other", "RepoTags": ["x:1"], "Size": 1, "Created": 0},
            ]

    class Handle:
        client = type("C", (), {"api": Api()})

        def close(self) -> None:
            pass

    monkeypatch.setattr(images_routes, "open_host", lambda request, host, timeout: Handle())
    found, error = images_routes.read_images(None, None, {"c1"})  # type: ignore[arg-type]
    assert error is None and {i.tags[0]: i.newer for i in found} == {"web:1": True, "x:1": False}
