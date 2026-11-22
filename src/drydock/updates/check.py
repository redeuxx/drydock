"""Which containers run an image whose registry now serves something newer under the same
tag.

A container created from a tag reference (nginx:1.27, ghcr.io/x/y:latest) is checked by
asking the registry, through the daemon (engine.capture.distribution_digest), which digest
that tag names now, and comparing it with the digests its image was pulled as
(RepoDigests). Nothing is pulled. Skipped: containers pinned by digest or created from an
image ID, and images built locally (no registry digest). A private registry answers
"unauthorized" through the daemon's API, which drydock reports as an error.

Hosts are checked every update_check_hours (the settings page; the first time FIRST_CHECK
after start; never when 0), and on demand from the containers, stacks and images pages, at
most once per MIN_GAP per host. Registries limit lookups (Docker Hub counts them), so one
lookup answers every container of the same image and reference, and is reused until the
next check is due. Results live in memory, like the status.
"""

import asyncio
import contextlib
import functools
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Literal

import anyio
import anyio.to_thread
import docker.errors
import docker.utils
import requests
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from drydock.engine.capture import distribution_digest
from drydock.hosts import client
from drydock.hosts.helper import is_helper
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.models import Host, Installation, utcnow
from drydock.updates.versions import Platform, describe, image_version, registry_version

log = logging.getLogger("drydock.updates")

CHECK_EVERY = 6 * 3600  # until the settings are read, and the lookups' reuse when off
FIRST_CHECK = 120  # seconds after start: not in the way of startup recovery
MIN_GAP = 60  # seconds between checks of a host asked for from the page
LOOP_EVERY = 300
TIMEOUT = 30
THREADS = 2
MAX_VERSIONS = 2000  # versions of new digests kept
IMAGE_ID_RE = re.compile(r"(sha256:)?[0-9a-f]{12,64}")
LOOKUP_ERRORS = (docker.errors.DockerException, requests.RequestException)
READ_ERRORS = (client.DockerUnavailable, HostUnavailable, *LOOKUP_ERRORS, OSError)

State = Literal["current", "update", "skipped", "error"]


@dataclass(frozen=True)
class Verdict:
    state: State
    reason: str  # safe to show to every role
    ref: str = ""  # the tag reference checked, normalized
    latest: str = ""  # the digest the registry serves for it now
    digest: str = ""  # the digest the container's image was pulled as
    version: str = ""  # its image's version (updates/versions.py), "" when unknown
    new_version: str = ""  # the version of latest, for an update, "" when unknown

    @property
    def moves(self) -> str:
        """'old -> new' for an update."""
        return describe(self.version, self.digest, self.new_version, self.latest)


def reference(image: str) -> str | None:
    """The tag reference a container was created from, as repository:tag, or None when it
    names a digest or an image ID."""
    if not image or "@" in image or IMAGE_ID_RE.fullmatch(image):
        return None
    repository, tag = docker.utils.parse_repository_tag(image)
    return f"{repository}:{tag or 'latest'}"


def followed_tag(image: str) -> str | None:
    """The tag an image reference follows ("latest" when it names none), or None when it
    is pinned by digest or image ID."""
    ref = reference(image)
    return ref.rpartition(":")[2] if ref else None


def lookup_error(exc: BaseException) -> str:
    """Safe to show: never the registry's or daemon's own text."""
    if isinstance(exc, docker.errors.APIError):
        if exc.status_code in (401, 403):
            return "The registry refused the lookup (a private image?)."
        if exc.status_code == 404:
            return "The registry has no such tag."
        return f"The registry lookup failed (HTTP {exc.status_code or 'error'})."
    return "The registry lookup failed."


def verdict(image: str, repo_digests: list[str], registry: Callable[[str], str]) -> Verdict:
    ref = reference(image)
    if ref is None:
        return Verdict("skipped", "Pinned by digest or image ID: not checked.")
    digests = {d.partition("@")[2] for d in repo_digests if isinstance(d, str) and "@" in d}
    if not digests:
        return Verdict("skipped", "Built locally (no registry digest): not checked.", ref)
    try:
        latest = registry(ref)
    except LOOKUP_ERRORS as exc:
        return Verdict("error", lookup_error(exc), ref)
    except ValueError, KeyError, TypeError:
        return Verdict("error", "The registry answer was not understood.", ref)
    if latest in digests:
        return Verdict("current", "Up to date.", ref, latest)
    return Verdict("update", f"The registry has a newer {ref}.", ref, latest)


def local_image(api: Any, ref: str) -> str | None:
    """The ID of the image ref names on the host, if any."""
    try:
        return str(api.inspect_image(ref).get("Id") or "") or None
    except docker.errors.NotFound:
        return None


def with_versions(
    api: Any,
    found: Verdict,
    image: dict[str, Any],
    newer_version: Callable[[str, str, Platform], str] | None,
) -> Verdict:
    """Blocking. The verdict with its image's version and digest, and for an update the
    version it brings: from the newer image when it is on the host already (latest is
    its ID), else from newer_version."""
    if not found.ref:
        return found
    repository = found.ref.rpartition(":")[0]
    own = [d.partition("@")[2] for d in image.get("RepoDigests") or [] if isinstance(d, str)]
    mine = [d for d in image.get("RepoDigests") or [] if str(d).startswith(repository + "@")]
    digest = (mine[0].partition("@")[2] if mine else "") or (own[0] if own else "")
    new_version = ""
    if found.state == "update" and found.latest.startswith("sha256:"):
        if found.reason.startswith("A newer"):  # on the host: latest is its image ID
            with contextlib.suppress(docker.errors.NotFound):
                newer = api.inspect_image(found.latest).get("Config")
                new_version = image_version(newer, repository)
        elif newer_version is not None:
            platform = (
                str(image.get("Os") or ""),
                str(image.get("Architecture") or ""),
                str(image.get("Variant") or ""),
            )
            new_version = newer_version(found.ref, found.latest, platform)
    return replace(
        found,
        digest=digest,
        version=image_version(image.get("Config"), repository),
        new_version=new_version,
    )


@dataclass
class Cached:
    at: float
    verdict: Verdict


def check(
    api: Any,
    instance_id: str,
    cache: dict[tuple[str, str], Cached],
    now: float,
    max_age: float = CHECK_EVERY,
    newer_version: Callable[[str, str, Platform], str] | None = None,
) -> dict[str, Verdict]:
    """Blocking. Container ID to verdict for every container but this installation's
    helpers. cache maps (image ID, reference) to a verdict reused for max_age seconds;
    errors are not kept, and entries no container uses any more are dropped.
    newer_version(ref, digest, platform) gives the version an update brings."""
    verdicts: dict[str, Verdict] = {}
    digests: dict[str, list[str]] = {}
    images: dict[str, dict[str, Any]] = {}
    used: set[tuple[str, str]] = set()
    asked: dict[str, str | BaseException] = {}  # one lookup per reference and pass

    def registry(ref: str) -> str:
        if ref not in asked:
            try:
                asked[ref] = distribution_digest(api, ref)
            except Exception as exc:  # verdict() tells which kind; kept for the next ask
                asked[ref] = exc
        found = asked[ref]
        if isinstance(found, BaseException):
            raise found
        return found

    for listed in api.containers(all=True):
        if is_helper(listed.get("Labels") or {}, instance_id) or "Id" not in listed:
            continue
        try:
            info = api.inspect_container(listed["Id"])
            image_id = str(info.get("Image") or "")
            image = str((info.get("Config") or {}).get("Image") or "")
            key = (image_id, image)
            used.add(key)
            hit = cache.get(key)
            if hit is not None and now - hit.at < max_age:
                verdicts[listed["Id"]] = hit.verdict
                continue
            if image_id not in digests:
                try:
                    images[image_id] = api.inspect_image(image_id)
                except docker.errors.NotFound:
                    images[image_id] = {}
                digests[image_id] = list(images[image_id].get("RepoDigests") or [])
            found = verdict(image, digests[image_id], registry)
            if found.state == "skipped" and found.ref:
                # No registry digest: built locally, or (containerd's image store) its tag
                # was pulled anew, which leaves this image nameless. Then the tag names
                # another image.
                newer = local_image(api, found.ref)
                if newer is not None and newer != image_id:
                    found = Verdict(
                        "update", f"A newer {found.ref} is already on the host.", found.ref, newer
                    )
            found = with_versions(api, found, images[image_id], newer_version)
        except docker.errors.NotFound:
            continue  # removed since the list
        except docker.errors.APIError as exc:
            found = Verdict("error", f"Docker could not inspect it (HTTP {exc.status_code}).")
        if found.state != "error":
            cache[key] = Cached(now, found)
        verdicts[listed["Id"]] = found
    for gone in cache.keys() - used:
        del cache[gone]
    return verdicts


# THE CHECKER


@dataclass(frozen=True)
class HostChecks:
    checked_at: datetime
    verdicts: dict[str, Verdict] = field(default_factory=dict)
    error: str | None = None  # the host could not be read; verdicts are the last ones

    def count(self, state: State, ids: Iterable[str] | None = None) -> int:
        """Containers with that verdict; with ids, only those (the ones still there)."""
        shown = self.verdicts if ids is None else {i: self.verdicts.get(i) for i in ids}
        return sum(1 for v in shown.values() if v is not None and v.state == state)


class UpdateChecker:
    def __init__(self, sessions: sessionmaker[Session], hosts: HostManager) -> None:
        self._sessions = sessions
        self._hosts = hosts
        self._limiter = anyio.CapacityLimiter(THREADS)
        self._results: dict[int, HostChecks] = {}
        self._caches: dict[int, dict[tuple[str, str], Cached]] = {}
        self._asked: dict[int, float] = {}  # host: when a page last asked for a check
        self._busy: dict[int, asyncio.Task[HostChecks]] = {}
        self._task: asyncio.Task[None] | None = None
        self._every = CHECK_EVERY  # seconds between checks; 0: never by itself
        # (repository, digest, platform): its version. A digest's never changes.
        self._versions: dict[tuple[str, str, Platform], str] = {}

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Only in the process holding the data directory lock (it owns the tunnels)."""
        self._task = asyncio.create_task(self._run(), name="update-checker")

    async def close(self) -> None:
        tasks = [*self._busy.values(), *([self._task] if self._task else [])]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def result(self, host_id: int) -> HostChecks | None:
        return self._results.get(host_id)

    def results(self) -> dict[int, HostChecks]:
        return dict(self._results)

    def wait_before_asking(self, host_id: int) -> int:
        """Seconds until a page may ask for a check of the host again; 0: now."""
        since = time.monotonic() - self._asked.get(host_id, -1e9)
        return max(0, int(MIN_GAP - since + 0.999))

    async def check_now(self, host: Host) -> HostChecks:
        """A check asked for from the page (wait_before_asking said 0): every registry is
        asked again, not answered from the hours-old lookups."""
        self._asked[host.id] = time.monotonic()
        running = self._busy.get(host.id)
        if running is None or running.done():
            self._caches.pop(host.id, None)
        return await self.check_host(host)

    async def check_host(self, host: Host) -> HostChecks:
        """Checks the host, or waits for the check of it already under way."""
        running = self._busy.get(host.id)
        if running is None or running.done():
            running = self._busy[host.id] = asyncio.create_task(self._check(host))
        return await asyncio.shield(running)

    async def _check(self, host: Host) -> HostChecks:
        cache = self._caches.setdefault(host.id, {})
        previous = self._results.get(host.id)
        try:
            url = self._hosts.docker_url(host)
            verdicts = await anyio.to_thread.run_sync(
                functools.partial(self._read, url, cache),
                limiter=self._limiter,
                abandon_on_cancel=True,
            )
            result = HostChecks(utcnow(), verdicts)
        except Exception as exc:
            # The last verdicts stay, with when they were made; the loop tries again soon.
            if isinstance(exc, HostUnavailable):
                error = "Drydock is not connected to this host."
            elif isinstance(exc, READ_ERRORS):
                log.warning("Host %s: checking for updates failed: %s", host.id, exc)
                error = "Cannot reach the Docker daemon."
            else:
                log.exception("Host %s: checking for updates failed", host.id)
                error = "Checking failed; see the server log."
            result = HostChecks(
                previous.checked_at if previous else utcnow(),
                previous.verdicts if previous else {},
                error,
            )
        self._results[host.id] = result
        return result

    def _read(self, url: str, cache: dict[tuple[str, str], Cached]) -> dict[str, Verdict]:
        with client.open_client(url, TIMEOUT) as handle:
            return check(
                handle.client.api,
                self._hosts.instance_id,
                cache,
                time.monotonic(),
                self._every or CHECK_EVERY,
                self._newer_version,
            )

    def _newer_version(self, ref: str, digest: str, platform: Platform) -> str:
        """Blocking. registry_version, asked once per digest and platform; a failed ask
        is asked again at the next check."""
        key = (ref.rpartition(":")[0], digest, platform)
        if key not in self._versions:
            found = registry_version(ref, digest, platform)
            if found is None:
                return ""
            if len(self._versions) >= MAX_VERSIONS:
                self._versions.clear()  # ponytail: drop all; an LRU if this ever churns
            self._versions[key] = found
        return self._versions[key]

    async def _run(self) -> None:
        await asyncio.sleep(FIRST_CHECK)
        while True:
            try:
                hosts = await client.run_blocking(self._load_hosts)
                for gone in self._results.keys() - {h.id for h in hosts}:
                    self._results.pop(gone, None)
                    self._caches.pop(gone, None)
                for host in hosts if self._every else []:  # 0: only when asked
                    done = self._results.get(host.id)
                    age = (utcnow() - done.checked_at).total_seconds() if done else None
                    if age is None or age >= self._every or done.error is not None:
                        with contextlib.suppress(Exception):
                            await self.check_host(host)
            except Exception:
                log.exception("The update checker failed")
            await asyncio.sleep(LOOP_EVERY)

    def _load_hosts(self) -> list[Host]:
        """The enabled hosts; reads the interval too, so a change applies within a loop."""
        with self._sessions() as db:
            hours = db.scalar(select(Installation.update_check_hours))
            self._every = (hours if hours is not None else 6) * 3600
            return list(db.scalars(select(Host).where(Host.enabled).order_by(Host.id)))
