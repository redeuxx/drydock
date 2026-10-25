"""Connections to every registered host, owned by the app lifespan.

Local hosts are reached at their docker_url (normally the socket proxy). SSH hosts get a
Tunnel each, and are reachable only while it is connected: without a verified host key
there is no socket, so no Docker call can be made.

Only the process holding the data directory lock calls start(). In any other process the
manager never opens a tunnel, so two processes cannot fight over the same sockets.
"""

import asyncio
import contextlib
import logging
import time
from collections import defaultdict
from collections.abc import Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh
import docker.errors
import requests
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from drydock import audit
from drydock.config import Settings
from drydock.crypto import Crypto, CryptoError
from drydock.hosts import client, helper, ssh
from drydock.models import Host, Installation, utcnow

log = logging.getLogger("drydock.hosts")

REAP_WAIT = 60  # how long a run waits for the startup reap of its host
# How long a run waits for a tunnel still on its first attempt (it has just started: at
# startup, or as the host was saved). A failed attempt ends the wait at once.
FIRST_ATTEMPT_WAIT = ssh.CONNECT_TIMEOUT + 5


class HostUnavailable(Exception):
    """The host cannot be used right now. The message is safe to show."""


@dataclass(frozen=True)
class HostStatus:
    state: str  # local, connecting, connected, disconnected, hostkey_mismatch, error, disabled
    error: str | None = None


def load_instance_id(sessions: sessionmaker[Session]) -> str:
    """This installation's ID (made by migration 0002), which labels its helpers."""
    with sessions() as db:
        return db.scalars(select(Installation.instance_id)).one()


class HostManager:
    def __init__(
        self,
        settings: Settings,
        sessions: sessionmaker[Session],
        crypto: Crypto,
        instance_id: str,
    ) -> None:
        self.socket_dir = settings.run_dir / "hosts"
        self.instance_id = instance_id
        self._sessions = sessions
        self._crypto = crypto
        self._started = False
        self._tunnels: dict[int, ssh.Tunnel] = {}
        self._errors: dict[int, str] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._reap_pending: set[int] = set()  # SSH hosts to reap on their first connection
        # Set once the startup reap of a host has finished (or will not happen).
        self._reaped: dict[int, asyncio.Event] = {}
        # One reload at a time per host, so concurrent requests cannot leave a second
        # tunnel running that nothing tracks.
        self._locks: defaultdict[int, asyncio.Lock] = defaultdict(asyncio.Lock)

    def socket_path(self, host_id: int) -> Path:
        return self.socket_dir / f"{int(host_id)}.sock"

    # LIFECYCLE

    async def start(self) -> None:
        """Opens every enabled host and removes orphaned helpers on first contact."""
        ssh.prepare_socket_dir(self.socket_dir)
        self._started = True
        for host in await client.run_blocking(self._load_hosts):
            async with self._locks[host.id]:
                await self._activate(host, reap=True)

    async def reload(self, host_id: int) -> None:
        """Applies a changed host row: drops the old tunnel and opens a new one if needed."""
        if not self._started:
            return
        async with self._locks[host_id]:
            await self._deactivate(host_id)
            host = await client.run_blocking(self._load_host, host_id)
            if host is not None and self._started:
                await self._activate(host, reap=False)

    async def close(self) -> None:
        self._started = False
        for host_id in list(self._tunnels):
            async with self._locks[host_id]:
                await self._deactivate(host_id)
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _activate(self, host: Host, *, reap: bool) -> None:
        await self._deactivate(host.id)  # never two tunnels for one host
        if not host.enabled:
            return
        if host.kind == "local":
            if reap and host.docker_url:
                self._reaped[host.id] = asyncio.Event()
                self._spawn(self._after_connect(host.id, host.docker_url, reap=True))
            return
        try:
            target = await client.run_blocking(self._target, host)
        except (CryptoError, ssh.SSHKeyError) as exc:
            message = (
                "The stored SSH key cannot be decrypted with the configured secret keys."
                if isinstance(exc, CryptoError)
                else str(exc)
            )
            self._errors[host.id] = message
            log.error("Host %s: %s", host.id, message)
            return
        if reap:
            self._reap_pending.add(host.id)
            self._reaped[host.id] = asyncio.Event()
        tunnel = ssh.Tunnel(
            target,
            self.socket_path(host.id),
            on_connect=self._tunnel_connected,
            on_mismatch=self._tunnel_mismatch,
        )
        self._tunnels[host.id] = tunnel
        tunnel.start()

    async def _deactivate(self, host_id: int) -> None:
        self._errors.pop(host_id, None)
        self._reap_pending.discard(host_id)
        self._reap_done(host_id)
        tunnel = self._tunnels.pop(host_id, None)
        if tunnel is not None:
            await tunnel.close()

    def _target(self, host: Host) -> ssh.SSHTarget:
        if not (host.address and host.username and host.port):
            raise ssh.SSHKeyError("The SSH address, port or user is missing.")
        if not host.known_host_line:
            raise ssh.SSHKeyError("The host key has not been trusted yet.")
        return ssh.SSHTarget(
            host_id=host.id,
            address=host.address,
            port=host.port,
            username=host.username,
            remote_socket_path=host.remote_socket_path or ssh.DEFAULT_REMOTE_SOCKET,
            known_host_line=host.known_host_line,
            private_key=ssh.host_private_key(host, self._crypto),
        )

    # ACCESS

    def status(self, host: Host) -> HostStatus:
        if not host.enabled:
            return HostStatus("disabled")
        if host.kind == "local":
            return HostStatus("local")
        if host.id in self._errors:
            return HostStatus("error", self._errors[host.id])
        tunnel = self._tunnels.get(host.id)
        if tunnel is None:
            return HostStatus("disconnected", "Not started.")
        return HostStatus(tunnel.state, tunnel.error)

    async def ready(self, host_id: int) -> None:
        """Waits (at most REAP_WAIT seconds) until the startup reap of the host's orphaned
        helpers has finished, so it cannot remove a helper a run has just created."""
        event = self._reaped.get(host_id)
        if event is not None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(event.wait(), REAP_WAIT)

    async def first_attempt(self, host: Host) -> None:
        """Waits while the host's SSH tunnel is still on its first connection attempt, so a
        run started right after drydock or the tunnel started (scheduled runs caught up at
        startup, a job run as its host is saved) does not fail on a tunnel about to connect."""
        deadline = time.monotonic() + FIRST_ATTEMPT_WAIT
        while (tunnel := self._tunnels.get(host.id)) is not None and tunnel.state == "connecting":
            if time.monotonic() > deadline:
                return
            await asyncio.sleep(0.2)

    def _reap_done(self, host_id: int) -> None:
        event = self._reaped.pop(host_id, None)
        if event is not None:
            event.set()

    def docker_url(self, host: Host) -> str:
        if not host.enabled:
            raise HostUnavailable("This host is disabled.")
        if host.kind == "local":
            if not host.docker_url:
                raise HostUnavailable("No Docker URL is set for this host.")
            return host.docker_url
        status = self.status(host)
        if status.state != "connected":
            raise HostUnavailable(status.error or "The SSH connection is not up.")
        return f"unix://{self.socket_path(host.id)}"

    async def reap_all(self) -> None:
        """The scheduled reaper: removes orphaned helpers on every host it can reach now.
        Helpers in use are skipped (helper.reap); a host that is down is left for later."""
        for host in await client.run_blocking(self._load_hosts):
            try:
                url = self.docker_url(host)
            except HostUnavailable:
                continue
            try:
                handle = await client.connect(url)
            except client.DockerUnavailable as exc:
                log.warning("Host %s: %s", host.id, exc)
                continue
            try:
                removed = await client.run_blocking(helper.reap, handle.client, self.instance_id)
                if removed:
                    log.warning(
                        "Host %s: removed %d orphaned helper container(s)", host.id, removed
                    )
            except (docker.errors.DockerException, requests.RequestException) as exc:
                log.warning("Host %s: %s", host.id, exc)
            except Exception:
                log.exception("Host %s: the reaper failed", host.id)  # the next host still runs
            finally:
                await client.run_blocking(handle.close)

    # BACKGROUND WORK

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _tunnel_connected(self, tunnel: ssh.Tunnel) -> None:
        url = f"unix://{tunnel.socket_path}"
        host_id = tunnel.target.host_id
        reap = host_id in self._reap_pending
        self._reap_pending.discard(host_id)
        self._spawn(self._after_connect(host_id, url, reap=reap))

    def _tunnel_mismatch(self, tunnel: ssh.Tunnel) -> None:
        self._spawn(self._record_mismatch(tunnel.target))

    async def _after_connect(self, host_id: int, url: str, *, reap: bool) -> None:
        """Records the negotiated API version and, at startup, reaps orphaned helpers."""
        try:
            try:
                handle = await client.connect(url)
            except client.DockerUnavailable as exc:
                log.warning("Host %s: %s", host_id, exc)
                return
            try:
                if reap:
                    removed = await client.run_blocking(
                        helper.reap, handle.client, self.instance_id
                    )
                    if removed:
                        log.warning(
                            "Host %s: removed %d orphaned helper container(s)", host_id, removed
                        )
                    self._reap_done(host_id)
                await client.run_blocking(self._mark_seen, host_id, handle.api_version)
            except (docker.errors.DockerException, requests.RequestException) as exc:
                log.warning("Host %s: %s", host_id, exc)
            finally:
                await client.run_blocking(handle.close)
        finally:
            if reap:
                self._reap_done(host_id)

    async def _record_mismatch(self, target: ssh.SSHTarget) -> None:
        presented = None
        with contextlib.suppress(OSError, TimeoutError, asyncssh.Error, ssh.SSHKeyError):
            _, presented = await ssh.scan_host_key(target.address, target.port)
        await client.run_blocking(self._audit_mismatch, target.host_id, presented)

    # DATABASE

    def _load_hosts(self) -> list[Host]:
        with self._sessions() as db:
            return list(db.scalars(select(Host).order_by(Host.id)))

    def _load_host(self, host_id: int) -> Host | None:
        with self._sessions() as db:
            return db.get(Host, host_id)

    def _mark_seen(self, host_id: int, api_version: str) -> None:
        with self._sessions() as db, db.begin():
            host = db.get(Host, host_id)
            if host is not None:
                host.api_version = api_version
                host.last_seen = utcnow()

    def _audit_mismatch(self, host_id: int, presented: str | None) -> None:
        with self._sessions() as db, db.begin():
            host = db.get(Host, host_id)
            audit.record(
                db,
                actor=None,
                action="host.hostkey_mismatch",
                target=f"host:{host_id}",
                outcome="failure",
                details={
                    "host": host.name if host else None,
                    "trusted_fingerprint": host.host_key_fingerprint if host else None,
                    "presented_fingerprint": presented,
                },
            )
