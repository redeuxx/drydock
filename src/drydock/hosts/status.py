"""Live status of each host's containers (state, health, CPU, memory, I/O), read by one
background collector so that pages never call Docker themselves.

The collector polls a host only while someone has looked at a status page in the last
WARM seconds (touch()), so an idle drydock makes no extra Docker calls. It goes through
the connections drydock already has (HostManager.docker_url: the socket proxy, or the
local end of a host's SSH tunnel) and keeps one client per host between polls. Snapshots
live in memory only: there is one uvicorn worker, and nothing in them outlives a restart.

CPU comes from one-shot stats, which the daemon answers at once but without
precpu_stats. The collector keeps each container's previous sample and takes the
difference between its own polls, so CPU shows from a container's second poll on.

Docker calls run on the collector's own threads (THREADS at most), so a slow host never
holds the worker threads that the app's sync routes run on.
"""

import asyncio
import contextlib
import functools
import ipaddress
import logging
import math
import re
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

import anyio
import anyio.to_thread
import docker.errors
import requests
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from drydock.hosts import client
from drydock.hosts.helper import is_helper
from drydock.hosts.inventory import PROJECT_LABEL, SERVICE_LABEL
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.models import Host, utcnow

log = logging.getLogger("drydock.hosts.status")

INTERVAL = 10  # seconds between polls of a host
WARM = 60  # a host is polled while a status page showed it this recently
TIMEOUT = 8  # per Docker request
THREADS = 4
REFRESH_WAIT = 15  # seconds a page waits for a host's reading after an action
# Restart counts need an inspect, which the container list lacks. A container is inspected
# when it first shows up or changes state, and again after this many seconds.
INSPECT_EVERY = 60
# Sparklines: the latest readings kept in memory, about 10 minutes of a host and 5 of a
# container at INTERVAL. ponytail: lost on restart and while no page shows the host;
# keeping history means a table and retention.
HOST_HISTORY = 60
CONTAINER_HISTORY = 30
STATS_STATES = frozenset({"running", "paused"})
HEALTH = frozenset({"healthy", "unhealthy", "starting"})
NOT_CONNECTED = "Drydock is not connected to this host."
HEALTH_TEXT_RE = re.compile(r"\((healthy|unhealthy|health: starting)\)")
# What one container's stats or inspect may fail with while the rest of the host still
# answers. A connection error is not among them: then the whole reading fails.
CONTAINER_ERRORS = (docker.errors.APIError, requests.exceptions.ReadTimeout)
READ_ERRORS = (
    client.DockerUnavailable,
    docker.errors.DockerException,
    requests.RequestException,
    OSError,
)


def is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# SNAPSHOTS


@dataclass(frozen=True)
class Port:
    public: int
    private: int
    protocol: str
    loopback: bool = False  # published on 127.0.0.1 or ::1 only: no use from another machine


@dataclass(frozen=True)
class ContainerStatus:
    id: str
    name: str
    image: str
    state: str
    status: str  # Docker's own text: "Up 2 hours (healthy)", "Exited (0) 3 days ago"
    health: str | None  # healthy, unhealthy, starting; None without a healthcheck
    project: str | None
    service: str | None
    restarts: int | None
    started_at: datetime | None  # the latest start, from the same inspect as restarts
    cpu_percent: float | None  # of one core, like docker stats; None until a second sample
    mem_bytes: int | None
    mem_limit: int | None
    net_rx: int | None
    net_tx: int | None
    block_read: int | None
    block_write: int | None
    ips: tuple[tuple[str, str], ...]  # (network, address)
    ports: tuple[Port, ...]
    labels: tuple[tuple[str, str], ...] = ()

    @property
    def status_text(self) -> str:
        """Docker's status without the health, which is shown on its own."""
        return HEALTH_TEXT_RE.sub("", self.status).strip()


@dataclass(frozen=True)
class HostSnapshot:
    """One host's containers as last read. taken_at is None while the host has never been
    read; error and stale_since are set while the latest polls fail (the data is older)."""

    host_id: int
    taken_at: datetime | None
    error: str | None = None
    stale_since: datetime | None = None
    name: str = ""
    os: str = ""
    arch: str = ""
    engine: str = ""
    ncpu: int | None = None
    mem_total: int | None = None
    images: int = 0
    volumes: int = 0
    networks: int = 0
    cpu_percent: float | None = None  # of the whole host
    mem_bytes: int = 0
    containers: tuple[ContainerStatus, ...] = ()

    @property
    def states(self) -> Counter[str]:
        return Counter(c.state for c in self.containers)

    @property
    def health(self) -> Counter[str]:
        return Counter(c.health for c in self.containers if c.health)

    @property
    def stacks(self) -> tuple[int, int, int]:
        """Compose projects (running, partial, stopped): all, some or none of whose
        containers run."""
        running: dict[str, list[bool]] = {}
        for c in self.containers:
            if c.project:
                running.setdefault(c.project, []).append(c.state == "running")
        found = Counter(
            "running" if all(v) else "stopped" if not any(v) else "partial"
            for v in running.values()
        )
        return found["running"], found["partial"], found["stopped"]

    @property
    def mem_percent(self) -> float | None:
        if not self.mem_total:
            return None
        return min(100.0, 100 * self.mem_bytes / self.mem_total)


# READING A HOST


@dataclass(frozen=True)
class Sample:
    cpu: int  # the container's total CPU time, ns
    system: int  # the host's total CPU time (all cores), ns


@dataclass(frozen=True)
class Inspected:
    at: float  # monotonic
    state: str
    restarts: int
    started_at: datetime | None


@dataclass(frozen=True)
class Reading:
    info: dict[str, Any]
    containers: list[dict[str, Any]]
    stats: dict[str, dict[str, Any]]
    restarts: dict[str, int]
    volumes: int
    networks: int
    started: dict[str, datetime | None] = field(default_factory=dict)


def started_of(inspect: dict[str, Any]) -> datetime | None:
    """State.StartedAt (RFC 3339 with nanoseconds), or None: never started ("0001-..."),
    missing or not a time."""
    value = (inspect.get("State") or {}).get("StartedAt")
    if not isinstance(value, str) or value.startswith("0001-"):
        return None
    try:
        return datetime.fromisoformat(value[:19]).replace(tzinfo=UTC)
    except ValueError:
        return None


def read(api, instance_id: str, inspected: dict[str, Inspected], now: float) -> Reading:
    """Blocking. Everything a snapshot needs from one daemon. inspected (what the last
    inspect of each container found) is kept between polls and updated here; containers
    that are gone are dropped from it."""
    info = api.info()
    containers = [
        c for c in api.containers(all=True) if not is_helper(c.get("Labels") or {}, instance_id)
    ]
    stats: dict[str, dict[str, Any]] = {}
    restarts: dict[str, int] = {}
    started: dict[str, datetime | None] = {}
    # ponytail: one request per container, one after another. Fine for tens of containers
    # per host; send them concurrently (bounded by the collector's threads) if a host's
    # poll ever takes close to INTERVAL.
    for c in containers:
        cid = c["Id"]
        if c.get("State") in STATS_STATES:
            # Removed or stopped since the list, or too slow to answer: no stats this time.
            with contextlib.suppress(*CONTAINER_ERRORS):
                stats[cid] = api.stats(cid, stream=False, one_shot=True)
        seen = inspected.get(cid)
        state = str(c.get("State"))
        # ponytail: a container that crashed and came back between two polls is "running"
        # both times, so its start time (the containers page's uptime sort) can be up to
        # INSPECT_EVERY old. Inspect on every poll if that ever matters.
        if seen is None or seen.state != state or now - seen.at >= INSPECT_EVERY:
            try:
                details = api.inspect_container(cid)
            except CONTAINER_ERRORS:
                continue
            count = details.get("RestartCount")
            seen = inspected[cid] = Inspected(
                now, state, count if is_int(count) else 0, started_of(details)
            )
        restarts[cid] = seen.restarts
        started[cid] = seen.started_at
    for gone in inspected.keys() - {c["Id"] for c in containers}:
        del inspected[gone]
    return Reading(
        info=info,
        containers=containers,
        stats=stats,
        restarts=restarts,
        volumes=len(api.volumes().get("Volumes") or []),
        networks=len(api.networks()),
        started=started,
    )


# FROM A READING TO A SNAPSHOT


def cpu_sample(stats: dict[str, Any]) -> Sample | None:
    cpu = stats.get("cpu_stats") or {}
    total = (cpu.get("cpu_usage") or {}).get("total_usage")
    system = cpu.get("system_cpu_usage")
    return Sample(total, system) if is_int(total) and is_int(system) else None


def cpu_share(now: Sample, before: Sample | None) -> float | None:
    """The share (0 to 1) of all the host's CPU time a container used between two samples.
    None without an earlier sample, or when its counter went back (it restarted)."""
    if before is None:
        return None
    used, elapsed = now.cpu - before.cpu, now.system - before.system
    if used < 0 or elapsed <= 0:
        return None
    return min(1.0, used / elapsed)


def memory_used(stats: dict[str, Any]) -> int | None:
    """Usage without the inactive page cache, as docker stats shows it: cgroup v1 reports
    total_inactive_file (and a non-recursive inactive_file), v2 only inactive_file."""
    memory = stats.get("memory_stats") or {}
    usage = memory.get("usage")
    if not is_int(usage):
        return None
    detail = memory.get("stats") or {}
    for key in ("total_inactive_file", "inactive_file"):
        cache = detail.get(key)
        if is_int(cache) and 0 <= cache <= usage:
            return usage - cache
    return usage


def network_bytes(stats: dict[str, Any]) -> tuple[int | None, int | None]:
    interfaces = [i for i in (stats.get("networks") or {}).values() if isinstance(i, dict)]
    if not interfaces:
        return None, None
    rx = sum(i["rx_bytes"] for i in interfaces if is_int(i.get("rx_bytes")))
    tx = sum(i["tx_bytes"] for i in interfaces if is_int(i.get("tx_bytes")))
    return rx, tx


def block_bytes(stats: dict[str, Any]) -> tuple[int | None, int | None]:
    entries = (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive")
    if not isinstance(entries, list):
        return None, None
    totals = Counter()
    for entry in entries:
        if isinstance(entry, dict) and is_int(entry.get("value")):
            totals[str(entry.get("op", "")).lower()] += entry["value"]  # v1 Read, v2 read
    if not ({"read", "write"} & totals.keys()):
        return None, None  # an empty list: unknown, not no I/O
    return totals["read"], totals["write"]


def health_of(container: dict[str, Any]) -> str | None:
    """From the list's Health field (API 1.52 on), else from the Status text."""
    status = (container.get("Health") or {}).get("Status")
    if status in HEALTH:
        return status
    match = HEALTH_TEXT_RE.search(str(container.get("Status", "")))
    if match is None:
        return None
    return "starting" if match.group(1) == "health: starting" else match.group(1)


def ips_of(container: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    networks = (container.get("NetworkSettings") or {}).get("Networks") or {}
    return tuple(
        sorted(
            (name, settings["IPAddress"])
            for name, settings in networks.items()
            if isinstance(settings, dict) and settings.get("IPAddress")
        )
    )


def is_loopback(address: object) -> bool:
    try:
        return ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False  # no address (all interfaces) or not one


def ports_of(container: dict[str, Any]) -> tuple[Port, ...]:
    """Published ports, once each (Docker lists one per address family)."""
    loopback: dict[tuple[int, int, str], bool] = {}
    for p in container.get("Ports") or []:
        if isinstance(p, dict) and is_int(p.get("PublicPort")) and is_int(p.get("PrivatePort")):
            key = (p["PublicPort"], p["PrivatePort"], str(p.get("Type", "tcp")))
            loopback[key] = loopback.get(key, True) and is_loopback(p.get("IP"))
    return tuple(Port(*key, loopback=local) for key, local in sorted(loopback.items()))


def summarize(
    host_id: int, reading: Reading, samples: dict[str, Sample], taken_at: datetime
) -> tuple[HostSnapshot, dict[str, Sample]]:
    """The snapshot of a reading, and the CPU samples to compare the next reading with."""
    info = reading.info
    ncpu = info.get("NCPU") if is_int(info.get("NCPU")) else None
    rows = []
    shares = []
    next_samples: dict[str, Sample] = {}
    for c in reading.containers:
        cid = c["Id"]
        stats = reading.stats.get(cid)
        labels = c.get("Labels") or {}
        names = c.get("Names") or []
        cpu_percent = mem = limit = None
        rx = tx = block_read = block_write = None
        if stats is not None:
            if (sample := cpu_sample(stats)) is not None:
                next_samples[cid] = sample
                share = cpu_share(sample, samples.get(cid))
                if share is not None:
                    shares.append(share)
                    cores = (stats.get("cpu_stats") or {}).get("online_cpus")
                    cores = cores if is_int(cores) and cores > 0 else ncpu or 1
                    cpu_percent = 100 * share * cores
            mem = memory_used(stats)
            limit = (stats.get("memory_stats") or {}).get("limit")
            limit = limit if is_int(limit) else None
            rx, tx = network_bytes(stats)
            block_read, block_write = block_bytes(stats)
        rows.append(
            ContainerStatus(
                id=cid,
                name=names[0].lstrip("/") if names else cid[:12],
                image=str(c.get("Image", "")),
                state=str(c.get("State", "")),
                status=str(c.get("Status", "")),
                health=health_of(c),
                project=labels.get(PROJECT_LABEL),
                service=labels.get(SERVICE_LABEL),
                restarts=reading.restarts.get(cid),
                started_at=reading.started.get(cid),
                cpu_percent=cpu_percent,
                mem_bytes=mem,
                mem_limit=limit,
                net_rx=rx,
                net_tx=tx,
                block_read=block_read,
                block_write=block_write,
                ips=ips_of(c),
                ports=ports_of(c),
                labels=tuple(sorted((str(k), str(v)) for k, v in labels.items())),
            )
        )
    # ponytail: host CPU sums the containers with two samples, so for one poll it leaves
    # out a container that is new or just restarted. Showing it as unknown instead would
    # blank it on every poll of a host whose CI creates containers all the time. It is
    # unknown only while no container has two samples, and 0 with nothing running.
    if shares or not reading.stats:
        cpu_percent: float | None = min(100.0, 100 * math.fsum(shares))
    else:
        cpu_percent = None
    snapshot = HostSnapshot(
        host_id=host_id,
        taken_at=taken_at,
        name=str(info.get("Name", "")),
        os=str(info.get("OperatingSystem", "")),
        arch=str(info.get("Architecture", "")),
        engine=str(info.get("ServerVersion", "")),
        ncpu=ncpu,
        mem_total=info["MemTotal"] if is_int(info.get("MemTotal")) else None,
        images=info["Images"] if is_int(info.get("Images")) else 0,
        volumes=reading.volumes,
        networks=reading.networks,
        cpu_percent=cpu_percent,
        mem_bytes=sum(r.mem_bytes or 0 for r in rows),
        containers=tuple(sorted(rows, key=lambda r: r.name)),
    )
    return snapshot, next_samples


def error_text(exc: BaseException) -> str:
    """Safe to show to every role: drydock's own version messages, or only the HTTP status
    the daemon gave. Other errors name socket paths and URLs, so they go to the log only."""
    if isinstance(exc, client.UnsupportedDaemon):
        return str(exc)
    if isinstance(exc, docker.errors.APIError):
        return f"The Docker daemon answered HTTP {exc.status_code or 'an error'}."
    return "Cannot reach the Docker daemon."


# THE COLLECTOR


@dataclass(frozen=True)
class History:
    """Sparkline values: the host's CPU and memory (percent), and per container ID its CPU
    (percent) and memory (bytes). None where a reading had no value."""

    cpu: list[float | None] = field(default_factory=list)
    memory: list[float | None] = field(default_factory=list)
    containers: dict[str, tuple[list[float | None], list[int | None]]] = field(default_factory=dict)


def connection_key(host: Host) -> tuple[Any, ...]:
    """What makes a host the same daemon: a change drops what was collected for it."""
    return (
        host.kind,
        host.docker_url,
        host.address,
        host.port,
        host.username,
        host.remote_socket_path,
        host.known_host_line,
    )


@dataclass
class HostCache:
    """What the collector keeps for one host. Only one poll of a host runs at a time."""

    key: tuple[Any, ...]
    url: str | None = None
    handle: client.DockerHandle | None = None
    samples: dict[str, Sample] = field(default_factory=dict)
    inspected: dict[str, Inspected] = field(default_factory=dict)
    # (CPU %, memory %) of the host, and (CPU %, memory bytes) of each container, per
    # reading; None where a reading had no value.
    history: deque[tuple[float | None, float | None]] = field(
        default_factory=lambda: deque(maxlen=HOST_HISTORY)
    )
    container_history: dict[str, deque[tuple[float | None, int | None]]] = field(
        default_factory=dict
    )
    # The loop writes the history; sync routes read it on worker threads.
    lock: threading.Lock = field(default_factory=threading.Lock)
    snapshot: HostSnapshot | None = None
    task: asyncio.Task[None] | None = None
    dropped: bool = False

    def close_handle(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def cool(self) -> None:
        """No page shows the host any more: let go of its connection, and of CPU samples
        that the next poll, maybe hours later, must not take a difference against. The
        snapshot stays, with its taken_at telling how old it is."""
        self.close_handle()
        self.samples.clear()
        # Readings resume who knows when: a line must not join them across the gap.
        with self.lock:
            self.history.clear()
            self.container_history.clear()

    def remember(self, snapshot: HostSnapshot) -> None:
        """Adds a reading to the sparklines; containers that are gone are dropped.

        ponytail: points are spaced evenly, so the extra readings after an action
        (refresh) look INTERVAL apart. Keep reading times if that ever misleads."""
        with self.lock:
            self.history.append((snapshot.cpu_percent, snapshot.mem_percent))
            current = {c.id for c in snapshot.containers}
            for gone in self.container_history.keys() - current:
                del self.container_history[gone]
            for c in snapshot.containers:
                line = self.container_history.get(c.id)
                if line is None:
                    line = self.container_history[c.id] = deque(maxlen=CONTAINER_HISTORY)
                line.append((c.cpu_percent, c.mem_bytes))

    def missed(self) -> None:
        """A reading failed: a gap, so the lines break instead of joining across it."""
        with self.lock:
            if self.history:
                self.history.append((None, None))
            for line in self.container_history.values():
                line.append((None, None))


class StatusCollector:
    def __init__(self, sessions: sessionmaker[Session], hosts: HostManager) -> None:
        self._sessions = sessions
        self._hosts = hosts
        self._limiter = anyio.CapacityLimiter(THREADS)
        self._viewed_at = -math.inf  # when a page last showed the hosts' status (monotonic)
        self._caches: dict[int, HostCache] = {}
        self._task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake = asyncio.Event()  # a page showed the hosts after none had lately

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Only in the process holding the data directory lock (it owns the tunnels)."""
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run(), name="status-collector")

    async def close(self) -> None:
        tasks = [c.task for c in self._caches.values() if c.task is not None]
        if self._task is not None:
            tasks.append(self._task)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for host_id in list(self._caches):
            self._drop(host_id)

    def touch(self) -> None:
        """A page shows the hosts' status, so keep reading them; after a quiet spell, read
        them at once, not at the next tick. Sync routes call this on worker threads: it
        only assigns a float, and wakes the collector through its loop."""
        now = time.monotonic()
        cold = now - self._viewed_at >= WARM
        self._viewed_at = now
        if cold and self._loop is not None:
            with contextlib.suppress(RuntimeError):  # the loop has closed: shutting down
                self._loop.call_soon_threadsafe(self._wake.set)

    async def refresh(self, host_id: int, wait: float = REFRESH_WAIT) -> None:
        """After drydock changed the host (a container started or stopped): read that host
        again now, and wait up to wait seconds in all for the reading, so the page shows
        the change. A reading already under way may predate the change: it is waited out
        first, and if it outlasts wait, the page shows what it has. Only in the process
        that runs the collector (the one that owns the tunnels)."""
        if not self.running:
            return
        self.touch()
        deadline = asyncio.get_running_loop().time() + wait
        cache = self._caches.get(host_id)
        if cache is not None and cache.task is not None and not cache.task.done():
            await asyncio.wait({cache.task}, timeout=wait)
            if not cache.task.done():
                return
        host = next(
            (h for h in await client.run_blocking(self._load_hosts) if h.id == host_id), None
        )
        if host is None:
            return
        # None when the collector's own loop (woken by touch) started one meanwhile: it
        # started after the change too, so wait for that one.
        task = self._start(host) or self._caches[host_id].task
        if task is not None:
            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            await asyncio.wait({task}, timeout=remaining)

    def snapshot(self, host_id: int) -> HostSnapshot | None:
        cache = self._caches.get(host_id)
        return cache.snapshot if cache is not None else None

    def history(self, host_id: int, containers: bool = True) -> History:
        """The host's sparklines, oldest reading first (and its containers' unless
        containers is False); empty for a host not read lately. Thread-safe."""
        cache = self._caches.get(host_id)
        if cache is None:
            return History()
        with cache.lock:
            return History(
                cpu=[cpu for cpu, _ in cache.history],
                memory=[mem for _, mem in cache.history],
                containers={
                    cid: ([cpu for cpu, _ in line], [mem for _, mem in line])
                    for cid, line in cache.container_history.items()
                }
                if containers
                else {},
            )

    async def _run(self) -> None:
        while True:
            try:
                await self.poll()
            except Exception:
                log.exception("The status collector failed")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), INTERVAL)
            self._wake.clear()

    async def poll(self) -> list[asyncio.Task[None]]:
        """Starts a poll of every enabled host, unless one is still running, and returns
        the polls started. Makes no call at all while no page showed the hosts lately."""
        if time.monotonic() - self._viewed_at >= WARM:
            for cache in self._caches.values():
                if cache.task is None or cache.task.done():
                    cache.cool()
            return []
        hosts = await client.run_blocking(self._load_hosts)
        for host_id in self._caches.keys() - {h.id for h in hosts}:
            self._drop(host_id)  # deleted or disabled
        return [task for host in hosts if (task := self._start(host)) is not None]

    def _start(self, host: Host) -> asyncio.Task[None] | None:
        """Starts a poll of the host, unless one is under way."""
        cache = self._caches.get(host.id)
        if cache is not None and cache.key != connection_key(host):
            self._drop(host.id)
            cache = None
        if cache is None:
            cache = self._caches[host.id] = HostCache(connection_key(host))
        if cache.task is not None and not cache.task.done():
            return None
        cache.task = asyncio.create_task(self._poll_host(host, cache))
        return cache.task

    def _drop(self, host_id: int) -> None:
        cache = self._caches.pop(host_id, None)
        if cache is None:
            return
        cache.dropped = True
        if cache.task is None or cache.task.done():
            cache.close_handle()  # else the poll closes it when it ends

    async def _blocking[T](self, fn: Callable[..., T], /, *args: Any) -> T:
        # Abandoned on cancel, so shutdown never waits out a slow host's timeouts. The
        # thread then fails fast: close() closes its client and the tunnels close next.
        return await anyio.to_thread.run_sync(
            functools.partial(fn, *args), limiter=self._limiter, abandon_on_cancel=True
        )

    async def _poll_host(self, host: Host, cache: HostCache) -> None:
        try:
            await self._read_into(host, cache)
        except Exception:
            log.exception("Host %s: reading its status failed", host.id)
            self._failed(cache, host.id, "Reading the status failed; see the server log.")
        finally:
            if cache.dropped:
                cache.close_handle()

    async def _read_into(self, host: Host, cache: HostCache) -> None:
        try:
            url = self._hosts.docker_url(host)
        except HostUnavailable:
            # Its reason can name the host's address, which only admins see; the card's
            # connection badge and the host page tell them the rest.
            self._failed(cache, host.id, NOT_CONNECTED)
            return
        if url != cache.url:
            cache.close_handle()
            cache.url = url
        while True:
            fresh = cache.handle is None
            try:
                if cache.handle is None:
                    cache.handle = await self._blocking(client.open_client, url, TIMEOUT)
                reading = await self._blocking(
                    read,
                    cache.handle.client.api,
                    self._hosts.instance_id,
                    cache.inspected,
                    time.monotonic(),
                )
            except READ_ERRORS as exc:
                cache.close_handle()
                if fresh:
                    if cache.snapshot is None or cache.snapshot.error is None:
                        log.warning("Host %s: reading its status failed: %s", host.id, exc)
                    self._failed(cache, host.id, error_text(exc))
                    return
                continue  # the kept connection may have gone with a tunnel: once more, anew
            break
        if not cache.dropped:
            cache.snapshot, cache.samples = summarize(host.id, reading, cache.samples, utcnow())
            cache.remember(cache.snapshot)

    def _failed(self, cache: HostCache, host_id: int, message: str) -> None:
        cache.missed()
        previous = cache.snapshot or HostSnapshot(host_id=host_id, taken_at=None)
        cache.snapshot = replace(
            previous, error=message, stale_since=previous.stale_since or utcnow()
        )

    def _load_hosts(self) -> list[Host]:
        with self._sessions() as db:
            return list(db.scalars(select(Host).where(Host.enabled).order_by(Host.id)))
