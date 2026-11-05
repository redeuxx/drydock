"""Docker container events from every host, stored for the activity page and counted on
the dashboard's cards.

Unlike the status collector, this one is always on: an event nobody stored is gone. Each
enabled host gets one long-lived `GET /events` stream (container events only) over the
connection drydock already has (HostManager.docker_url: the socket proxy, or the local end
of the host's SSH tunnel), read on a thread of its own. A stream that ends or fails is
opened again after a growing pause, from the newest event stored for that host, so a short
drop loses nothing; the table's unique key drops what the daemon sends twice. A change to
a host's connection, or its removal, ends its stream.

Only a few fields are kept: the time, the action, the container's ID, name and image, a
die's exit code and a health check's result. Everything else an event carries is dropped,
since labels and exec commands can hold secrets: an exec_start's command, which Docker
puts in the action itself, is cut off. This installation's helper containers are left out.

Events go to the database in batches (every FLUSH_EVERY seconds, or at FLUSH_AT), so a
burst of hundreds of containers (CI runners) costs a few transactions. The table keeps
KEEP_DAYS days and at most KEEP_ROWS rows, pruned hourly.
"""

import asyncio
import contextlib
import functools
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import anyio
import anyio.to_thread
from sqlalchemy import case, delete, func, insert, select
from sqlalchemy.orm import Session, sessionmaker

from drydock.hosts import client
from drydock.hosts.helper import is_helper
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.hosts.status import HEALTH, connection_key
from drydock.models import DockerEvent, Host

log = logging.getLogger("drydock.hosts.events")

SUPERVISE_EVERY = 10.0  # seconds between checks of which hosts to follow
FLUSH_EVERY = 1.0
FLUSH_AT = 200
PRUNE_EVERY = 3600.0
KEEP_DAYS = 30
KEEP_ROWS = 200_000
COUNTS_TTL = 5.0  # seconds the cards' counts are reused
BACKOFF = (1, 2, 5, 10, 30, 60)  # seconds before reopening a failed stream, growing
MAX_HOSTS = 64  # stream threads, one per followed host
MAX_PENDING = 50_000  # events kept while the database refuses them
TIMEOUT = 15  # opening the stream; reading it waits as long as the host is quiet
ACTION_RE = re.compile(r"[a-z_]{1,32}")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}")
NS = 1_000_000_000


@dataclass(frozen=True)
class Event:
    host_id: int
    time_ns: int
    action: str
    container_id: str
    name: str
    image: str
    exit_code: int | None = None
    health: str | None = None


def event_of(raw: Any, host_id: int, instance_id: str) -> Event | None:
    """The fields kept from one of Docker's event messages, or None for anything that is
    not a container event worth keeping."""
    if not isinstance(raw, dict) or raw.get("Type") != "container":
        return None
    actor = raw.get("Actor") if isinstance(raw.get("Actor"), dict) else {}
    attributes = actor.get("Attributes") if isinstance(actor.get("Attributes"), dict) else {}
    if is_helper(attributes, instance_id):
        return None
    # "exec_start: sh -c <command>", "health_status: healthy": the part after the colon
    # is the command (never kept) or the health result.
    action, _, rest = str(raw.get("Action") or "").partition(":")
    action = action.strip()
    container_id = str(actor.get("ID") or "")
    if not ACTION_RE.fullmatch(action) or not CONTAINER_ID_RE.fullmatch(container_id):
        return None
    stamp = raw.get("timeNano")
    if not isinstance(stamp, int) or isinstance(stamp, bool):
        seconds = raw.get("time")
        if not isinstance(seconds, int) or isinstance(seconds, bool):
            return None
        stamp = seconds * NS
    health = rest.strip() if action == "health_status" else None
    exit_code = None
    if action == "die":
        with contextlib.suppress(TypeError, ValueError):
            exit_code = int(str(attributes.get("exitCode")))
    return Event(
        host_id=host_id,
        time_ns=stamp,
        action=action,
        container_id=container_id,
        name=str(attributes.get("name") or "")[:255],
        image=str(attributes.get("image") or "")[:255],
        exit_code=exit_code,
        health=health if health in HEALTH else None,
    )


def since_of(time_ns: int) -> str:
    """Docker's `since`: seconds and nanoseconds."""
    seconds, nanos = divmod(time_ns, NS)
    return f"{seconds}.{nanos:09d}"


# THE DATABASE


def store(sessions: sessionmaker[Session], events: list[Event]) -> None:
    """Blocking. What the daemon sent twice (a reconnect overlaps) is ignored, and so are
    the events of a host deleted meanwhile, which would fail the whole batch."""
    with sessions() as db, db.begin():
        ids = {e.host_id for e in events}
        hosts = set(db.scalars(select(Host.id).where(Host.id.in_(ids))))
        rows = [vars(e) for e in events if e.host_id in hosts]
        if rows:
            db.execute(insert(DockerEvent).prefix_with("OR IGNORE"), rows)


def newest(sessions: sessionmaker[Session], host_id: int) -> int | None:
    with sessions() as db:
        return db.scalar(
            select(func.max(DockerEvent.time_ns)).where(DockerEvent.host_id == host_id)
        )


def prune(sessions: sessionmaker[Session], now_ns: int) -> int:
    """Blocking. Drops events older than KEEP_DAYS, then the oldest past KEEP_ROWS."""
    with sessions() as db, db.begin():
        old = db.execute(
            delete(DockerEvent).where(DockerEvent.time_ns < now_ns - KEEP_DAYS * 86400 * NS)
        ).rowcount
        excess = (
            select(DockerEvent.id)
            .order_by(DockerEvent.time_ns.desc(), DockerEvent.id.desc())
            .offset(KEEP_ROWS)
            .scalar_subquery()
        )
        extra = db.execute(delete(DockerEvent).where(DockerEvent.id.in_(excess))).rowcount
    return old + extra


def count(db: Session, today_ns: int) -> dict[int, tuple[int, int]]:
    """Each host's events since today_ns and in all."""
    rows = db.execute(
        select(
            DockerEvent.host_id,
            func.sum(case((DockerEvent.time_ns >= today_ns, 1), else_=0)),
            func.count(),
        ).group_by(DockerEvent.host_id)
    )
    return {host_id: (int(today or 0), int(total)) for host_id, today, total in rows}


# THE COLLECTOR


@dataclass
class Follow:
    """One host's stream. The thread reading it sets stream; cancelling the task sets closed
    and closes the stream, which ends the thread's read (or, if the thread is still
    connecting, makes it stop as soon as it has the stream). fresh: the host's connection
    changed, so its stream starts from now, not from the old daemon's newest event."""

    key: tuple[Any, ...]
    fresh: bool = False
    task: asyncio.Task[None] | None = None
    stream: Any = None
    closed: bool = False
    newest: int = 0
    failures: int = 0


@dataclass
class Counts:
    at: float = -1e9
    day_start: int = 0
    by_host: dict[int, tuple[int, int]] = field(default_factory=dict)


class EventCollector:
    def __init__(self, sessions: sessionmaker[Session], hosts: HostManager) -> None:
        self._sessions = sessions
        self._hosts = hosts
        self._limiter = anyio.CapacityLimiter(MAX_HOSTS)
        self._follows: dict[int, Follow] = {}
        self._pending: list[Event] = []
        self._task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._counts = Counts()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Only in the process holding the data directory lock (it owns the tunnels)."""
        self._loop = asyncio.get_running_loop()
        self._task = asyncio.create_task(self._run(), name="event-collector")

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        for host_id in list(self._follows):
            await self._unfollow(host_id)
        with contextlib.suppress(Exception):  # logged by flush; shutting down regardless
            await self.flush()

    def counts(self, db: Session, today: datetime) -> dict[int, tuple[int, int]]:
        """Blocking (a sync route's thread, through its session: a second one would wait
        for its write lock). Each host's events since today (the start of the day in
        drydock's zone) and in all, read at most every COUNTS_TTL seconds."""
        now = time.monotonic()
        day_start = int(today.timestamp()) * NS
        if now - self._counts.at >= COUNTS_TTL or day_start != self._counts.day_start:
            self._counts = Counts(now, day_start, count(db, day_start))
        return self._counts.by_host

    def forget_counts(self) -> None:
        """The next counts() reads the table again (it was cleared)."""
        self._counts = Counts()

    async def flush(self) -> None:
        """Stores what the streams brought. A batch the database refused (busy) is kept for
        the next flush, up to MAX_PENDING events; the oldest beyond that are dropped."""
        batch, self._pending = self._pending, []
        if not batch:
            return
        try:
            await client.run_blocking(store, self._sessions, batch)
        except Exception:
            self._pending[:0] = batch
            if len(self._pending) > MAX_PENDING:
                log.warning("Dropped %d Docker event(s)", len(self._pending) - MAX_PENDING)
                del self._pending[:-MAX_PENDING]
            raise

    async def _run(self) -> None:
        supervised = flushed = pruned = -1e9  # prune at start too: restarts may be frequent
        while True:
            now = time.monotonic()
            try:
                if now - supervised >= SUPERVISE_EVERY:
                    supervised = now
                    await self.supervise()
                if len(self._pending) >= FLUSH_AT or now - flushed >= FLUSH_EVERY:
                    flushed = now
                    await self.flush()
                if now - pruned >= PRUNE_EVERY:
                    pruned = now
                    removed = await client.run_blocking(prune, self._sessions, time.time_ns())
                    if removed:
                        log.info("Pruned %d stored Docker event(s)", removed)
            except Exception:
                log.exception("The event collector failed")
            await asyncio.sleep(0.25)

    async def supervise(self) -> None:
        """Follows every enabled host, and no other. A changed connection starts anew, from
        now; a follow that ended (it never should) starts again."""
        hosts = await client.run_blocking(self._load_hosts)
        wanted = {h.id: h for h in hosts}
        moved: set[int] = set()
        for host_id, follow in list(self._follows.items()):
            host = wanted.get(host_id)
            changed = host is not None and follow.key != connection_key(host)
            if host is None or changed or (follow.task is not None and follow.task.done()):
                await self._unfollow(host_id)
                if changed:
                    moved.add(host_id)
        for host in hosts:
            if host.id not in self._follows:
                follow = Follow(connection_key(host), fresh=host.id in moved)
                self._follows[host.id] = follow
                follow.task = asyncio.create_task(self._follow(host, follow))

    async def _unfollow(self, host_id: int) -> None:
        follow = self._follows.pop(host_id, None)
        if follow is None or follow.task is None:
            return
        if follow.task.done() and not follow.task.cancelled() and follow.task.exception():
            log.error(
                "Host %s: following its events ended", host_id, exc_info=follow.task.exception()
            )
        follow.task.cancel()
        await asyncio.gather(follow.task, return_exceptions=True)

    async def _follow(self, host: Host, follow: Follow) -> None:
        """Keeps one stream open, from the newest event stored for the host (none stored, or
        a changed connection: from the daemon's now)."""
        if not follow.fresh:
            follow.newest = await client.run_blocking(newest, self._sessions, host.id) or 0
        while True:
            try:
                url = self._hosts.docker_url(host)
                await anyio.to_thread.run_sync(
                    functools.partial(self._read, url, host.id, follow),
                    limiter=self._limiter,
                    abandon_on_cancel=True,
                )
                follow.failures = 0  # it ended on its own (a proxy's idle timeout)
            except asyncio.CancelledError:
                follow.closed = True
                if follow.stream is not None:
                    follow.stream.close()  # ends the thread's read
                raise
            except HostUnavailable:
                await asyncio.sleep(SUPERVISE_EVERY)  # the tunnel is not up (yet)
                continue
            except Exception as exc:
                if follow.failures == 0:
                    log.warning("Host %s: the Docker event stream failed: %s", host.id, exc)
                follow.failures += 1
            await asyncio.sleep(BACKOFF[min(follow.failures, len(BACKOFF) - 1)])

    def _read(self, url: str, host_id: int, follow: Follow) -> None:
        """Blocking, on the host's own thread, until the stream ends or is closed."""
        loop = self._loop
        if loop is None:
            return  # not started
        instance = self._hosts.instance_id
        with client.open_client(url, TIMEOUT) as handle:
            since = since_of(follow.newest) if follow.newest else None
            stream = handle.client.api.events(
                since=since, filters={"type": ["container"]}, decode=True
            )
            follow.stream = stream
            try:
                if follow.closed:
                    return  # cancelled while connecting
                for raw in stream:
                    if follow.closed:
                        break
                    found = event_of(raw, host_id, instance)
                    if found is None:
                        continue
                    follow.newest = max(follow.newest, found.time_ns)
                    try:
                        loop.call_soon_threadsafe(self._pending.append, found)
                    except RuntimeError:
                        break  # the loop has closed: shutting down
            finally:
                follow.stream = None
                stream.close()

    def _load_hosts(self) -> list[Host]:
        with self._sessions() as db:
            return list(db.scalars(select(Host).where(Host.enabled).order_by(Host.id)))
