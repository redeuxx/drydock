"""Alerts on container and host state changes, from the Docker events drydock already
follows (hosts/events.py) and the state of each host's event stream.

For each host with alerts on (hosts.alerts_enabled), drydock tells the host's alert target
(a notification target) and the bell (an audit event per alert, which admins see) when:

- a container becomes unhealthy, and again when it is healthy;
- a container dies with a nonzero exit code that nobody asked for: a die within KILL_GRACE
  of a kill (docker stop, docker kill, compose down) is not one, and one container's are
  told at most every RESTART_WINDOW (a loop's are the loop's alert);
- a container restart-loops: RESTART_COUNT starts within RESTART_WINDOW, and again when
  it has been quiet for that long;
- the host's event stream has failed for UNREACHABLE_AFTER, and again when it is back.
  An SSH host that vanishes silently fails its stream through the tunnel's keepalives; the
  local host's proxy is on drydock's own machine.

One alert per transition, never one per event. Containers that a backup, restore or update
run holds are left out: stopping and starting them is the run's job. The state lives in
memory, so a restart of drydock forgets what it last told.
"""

import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sqlalchemy.orm import Session, sessionmaker

from drydock import audit

if TYPE_CHECKING:
    from drydock.hosts.events import Event
    from drydock.models import Host
    from drydock.notify import Notifier

log = logging.getLogger("drydock.hosts.alerts")

KILL_GRACE = 310.0  # seconds: a die this soon after a kill was asked for (a stop timeout
# can be up to 300 s)
RESTART_COUNT = 5
RESTART_WINDOW = 600.0  # seconds; also the least time between two "died" of one container
UNREACHABLE_AFTER = 300.0  # seconds of a failing event stream
RECENT = 16  # events remembered per container, so a reconnect's repeats are judged once
NS = 1_000_000_000


@dataclass(frozen=True)
class Alert:
    host_id: int
    kind: str  # unhealthy, healthy, died, restarting, settled, unreachable, reachable
    subject: str  # the container's name, or "" for the host
    text: str
    failure: bool  # False: a recovery

    @property
    def action(self) -> str:
        return f"alert.{self.kind}"


@dataclass
class ContainerState:
    unhealthy: bool = False
    killed_at: float = -1e18  # event time, seconds
    died_told_at: float = -1e18
    starts: deque[float] = field(default_factory=lambda: deque(maxlen=RESTART_COUNT))
    looping: bool = False
    recent: deque[tuple[int, str, str]] = field(default_factory=lambda: deque(maxlen=RECENT))

    @property
    def failing(self) -> bool:
        return self.unhealthy or self.looping


class Watch:
    """The alert state of every host, fed the events in the order the daemon sent them
    (event times, not the clock, so a burst stored late judges the same) and the event
    streams' failures. Pure: what it returns is sent by the caller.

    A container's state is kept by its name, so one made again (compose up, an update)
    under a new ID carries on: its recovery is told. busy(ID, name) tells whether a run
    holds the container."""

    def __init__(self, busy: Callable[[str, str], bool]) -> None:
        self._busy = busy
        self._containers: dict[tuple[int, str], ContainerState] = {}
        self._down_since: dict[int, float] = {}  # host: monotonic time its stream failed
        self._told_down: set[int] = set()

    def event(self, event: Event) -> list[Alert]:
        name = event.name or event.container_id[:12]
        key = (event.host_id, name)
        state = self._containers.setdefault(key, ContainerState())
        seen = (event.time_ns, event.container_id, event.action)
        if seen in state.recent:
            return []  # sent again after a reconnect (Docker's since includes its time)
        state.recent.append(seen)
        at = event.time_ns / NS
        if event.action == "destroy":
            if not state.failing:
                self._containers.pop(key, None)  # else one made again under the name recovers
            return []
        if event.action == "kill":
            state.killed_at = at
            return []
        if self._busy(event.container_id, name):
            return []
        alerts: list[Alert] = []
        if event.action == "health_status" and event.health in ("unhealthy", "healthy"):
            unhealthy = event.health == "unhealthy"
            if unhealthy != state.unhealthy:
                state.unhealthy = unhealthy
                alerts.append(
                    Alert(event.host_id, "unhealthy", name, f"{name} is unhealthy.", True)
                    if unhealthy
                    else Alert(event.host_id, "healthy", name, f"{name} is healthy again.", False)
                )
        elif (
            event.action == "die"
            and event.exit_code
            and at - state.killed_at > KILL_GRACE
            and not state.looping  # the loop's own alert says it
            and at - state.died_told_at > RESTART_WINDOW
        ):
            state.died_told_at = at
            alerts.append(
                Alert(
                    event.host_id,
                    "died",
                    name,
                    f"{name} exited with code {event.exit_code}.",
                    True,
                )
            )
        elif event.action == "start":
            state.starts.append(at)
            full = len(state.starts) == RESTART_COUNT
            if full and at - state.starts[0] <= RESTART_WINDOW and not state.looping:
                state.looping = True
                alerts.append(
                    Alert(
                        event.host_id,
                        "restarting",
                        name,
                        f"{name} started {RESTART_COUNT} times in "
                        f"{int(RESTART_WINDOW // 60)} minutes.",
                        True,
                    )
                )
        return alerts

    def quiet(self, now_ns: int) -> list[Alert]:
        """Restart loops that have been quiet for RESTART_WINDOW: settled."""
        alerts = []
        for (host_id, name), state in self._containers.items():
            quiet = state.starts and now_ns / NS - state.starts[-1] > RESTART_WINDOW
            if state.looping and quiet:
                state.looping = False
                alerts.append(Alert(host_id, "settled", name, f"{name} stopped restarting.", False))
        return alerts

    def stream(
        self, host_id: int, ok: bool, host_name: str, now: float | None = None
    ) -> list[Alert]:
        """A host's event stream works (ok) or failed, at monotonic now."""
        now = time.monotonic() if now is None else now
        if ok:
            self._down_since.pop(host_id, None)
            if host_id in self._told_down:
                self._told_down.discard(host_id)
                return [Alert(host_id, "reachable", "", f"{host_name} is reachable again.", False)]
            return []
        since = self._down_since.setdefault(host_id, now)
        if now - since >= UNREACHABLE_AFTER and host_id not in self._told_down:
            self._told_down.add(host_id)
            minutes = int(UNREACHABLE_AFTER // 60)
            return [
                Alert(
                    host_id,
                    "unreachable",
                    "",
                    f"{host_name} has been unreachable for {minutes} minutes.",
                    True,
                )
            ]
        return []

    def forget(self, host_id: int) -> None:
        for key in [k for k in self._containers if k[0] == host_id]:
            del self._containers[key]
        self._down_since.pop(host_id, None)
        self._told_down.discard(host_id)


def deliver(sessions: sessionmaker[Session], notifier: Notifier, alert: Alert, host: Host) -> None:
    """Blocking. Records the alert as an audit event (the bell shows it to admins) and tells
    the host's alert target, if it has one."""
    text = alert.text if not alert.subject else f"{host.name}: {alert.text}"
    with sessions() as db, db.begin():
        audit.record(
            db,
            actor=None,
            action=alert.action,
            target=f"host:{alert.host_id}",
            outcome="failure" if alert.failure else "success",
            details={"host": host.name, "container": alert.subject, "text": text},
        )
    if host.alert_target_id is not None:
        notifier.alert(host.alert_target_id, f"drydock: {text}", text, alert.failure)
