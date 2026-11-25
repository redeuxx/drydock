"""Which containers run an image whose registry now serves something newer under the same
tag.

A container created from a tag reference (nginx:1.27, ghcr.io/x/y:latest) is checked by
asking the registry, through the daemon (engine.capture.distribution_digest), which digest
that tag names now, and comparing it with the digests its image was pulled as
(RepoDigests). Nothing is pulled. Skipped: containers pinned by digest or created from an
image ID, and images built locally (no registry digest). A private registry answers
"unauthorized" through the daemon's API, which drydock reports as an error.

Hosts are checked every update_check_hours (the settings page; the first time FIRST_CHECK
after start; never when 0), after each run of an update policy on them (policy_ran), and
on demand from the containers, stacks and images pages, at most once per MIN_GAP per host.
Registries limit lookups (Docker Hub counts them), so one lookup answers every container of
the same image and reference, and is reused for half the interval (slots are at least that
far apart, so every slot asks anew). They also limit
how fast an address asks (ghcr.io answers 429), so the checks not asked for from a page
wait LOOKUP_GAP between lookups, and each host has its own place in the interval
(next_slot) rather than every host being checked at once. Results live in
memory, like the status.
"""

import asyncio
import contextlib
import functools
import logging
import math
import re
import threading
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
from drydock.models import Host, Installation, UpdatePolicy, utcnow
from drydock.updates.versions import (
    Platform,
    describe,
    image_version,
    own_digest,
    registry_version,
)

log = logging.getLogger("drydock.updates")

CHECK_EVERY = 6 * 3600  # until the settings are read, and the lookups' reuse when off
FIRST_CHECK = 120  # seconds after start: not in the way of startup recovery
MIN_GAP = 60  # seconds between checks of a host asked for from the page
LOOP_EVERY = 300
LOOKUP_GAP = 2.0  # seconds between registry lookups, but in checks a page waits for
TIMEOUT = 30
THREADS = 2
MAX_VERSIONS = 2000  # versions of new digests kept
VERSION_BUDGET = 60  # seconds one host's check may spend reading new versions
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
    created_from: str,
    image: dict[str, Any],
    newer_version: Callable[[str, str, Platform], str] | None,
) -> Verdict:
    """Blocking. The verdict with its image's version and digest (a pinned container's
    too), and for an update the version it brings: from the newer image when it is on
    the host already (latest is its ID), else from newer_version. Reading a version
    never changes the verdict."""
    if found.ref:
        repository = found.ref.rpartition(":")[0]
    elif IMAGE_ID_RE.fullmatch(created_from):
        repository = ""  # made from an image ID: no repository names it
    else:
        repository = docker.utils.parse_repository_tag(created_from.partition("@")[0])[0]
    new_version = ""
    if found.state == "update" and found.latest.startswith("sha256:"):
        if found.reason.startswith("A newer"):  # on the host: latest is its image ID
            with contextlib.suppress(*LOOKUP_ERRORS):
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
        digest=own_digest(image.get("RepoDigests"), repository),
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
    pause: Callable[[], object] | None = None,
) -> dict[str, Verdict]:
    """Blocking. Container ID to verdict for every container but this installation's
    helpers. cache maps (image ID, reference) to a verdict reused for max_age seconds;
    errors are not kept, and entries no container uses any more are dropped.
    newer_version(ref, digest, platform) gives the version an update brings; pause() is
    called between two registry lookups."""
    verdicts: dict[str, Verdict] = {}
    digests: dict[str, list[str]] = {}
    images: dict[str, dict[str, Any]] = {}
    budget = [time.monotonic() + VERSION_BUDGET]  # moved on by the pauses

    def version_of(ref: str, digest: str, platform: Platform) -> str:
        """newer_version, until this pass has spent VERSION_BUDGET on them."""
        if newer_version is None or time.monotonic() > budget[0]:
            return ""
        return newer_version(ref, digest, platform)

    used: set[tuple[str, str]] = set()
    asked: dict[str, str | BaseException] = {}  # one lookup per reference and pass

    def registry(ref: str) -> str:
        if ref not in asked:
            if pause is not None and asked:
                began = time.monotonic()
                pause()
                budget[0] += time.monotonic() - began
            try:
                # No retry: the next pass asks again (errors are not kept), and a page
                # waits for this one.
                asked[ref] = distribution_digest(api, ref, retry=False)
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
            found = with_versions(api, found, image, images[image_id], version_of)
        except docker.errors.NotFound:
            continue  # removed since the list
        except docker.errors.APIError as exc:
            found = Verdict("error", f"Docker could not inspect it (HTTP {exc.status_code}).")
        if found.state != "error":
            cache[key] = Cached(now, found)
        verdicts[listed["Id"]] = found
    for gone in cache.keys() - used:
        cache.pop(gone, None)  # a page's check and a paced one may share the cache
    return verdicts


def next_slot(last: float, epoch: float, every: float, index: int, count: int) -> float:
    """When the host index of count is due after a check at last: its slots are epoch,
    plus its share of the interval (index / count of it), plus whole intervals, and it
    takes the first at least half an interval after last. So the hosts are checked
    every interval but apart. A check between slots (asked from a page, or after a policy
    run) moves none of them, but skips the next if it comes within half an interval."""
    phase = epoch + every * index / count
    return phase + every * math.ceil((last + every / 2 - phase) / every)


# THE CHECKER


class Stopped(Exception):
    """The checker closed during a paced check."""


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
        self._limiter = anyio.CapacityLimiter(THREADS)  # checks a page waits for
        self._paced = anyio.CapacityLimiter(THREADS)  # the rest: never in a page's way
        self._stop = threading.Event()  # set by close: a paced check ends at its next pause
        self._results: dict[int, HostChecks] = {}
        self._caches: dict[int, dict[tuple[str, str], Cached]] = {}
        self._asked: dict[int, float] = {}  # host: when a page last asked for a check
        # (host, paced): its check under way. A page's never joins a paced one.
        self._busy: dict[tuple[int, bool], asyncio.Task[HostChecks]] = {}
        self._task: asyncio.Task[None] | None = None
        self._after: set[asyncio.Task[None]] = set()  # checks after policy runs
        self._every = CHECK_EVERY  # seconds between checks; 0: never by itself
        self._epoch = 0.0  # monotonic: the first loop, where the hosts' slots count from
        self._checked: dict[int, float] = {}  # host: monotonic, its last check that worked
        self._began: dict[int, float] = {}  # host: monotonic, when its result's check began
        # (repository, digest, platform): its version. A digest's never changes.
        self._versions: dict[tuple[str, str, Platform], str] = {}

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Only in the process holding the data directory lock (it owns the tunnels)."""
        self._task = asyncio.create_task(self._run(), name="update-checker")

    async def close(self) -> None:
        self._stop.set()
        tasks = [*self._busy.values(), *self._after, *([self._task] if self._task else [])]
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
        asked again, not answered from the hours-old lookups. It runs at once, on threads
        of its own, beside a paced check of the host under way rather than waiting for it."""
        self._asked[host.id] = time.monotonic()
        running = self._busy.get((host.id, False))
        if running is None or running.done():
            self._caches.pop(host.id, None)
        return await self.check_host(host, paced=False)

    def policy_ran(self, policy_id: int) -> None:
        """An update policy's run ended (Dispatcher on_policy_end, on the event loop): its
        host is checked again, so the pages show what the run left and, with no interval
        set, what else is new. Lookups younger than half the interval (3 hours with none
        set) are reused."""
        if self.running:
            task = asyncio.create_task(self._after_policy(policy_id), name="update-check")
            self._after.add(task)
            task.add_done_callback(self._after.discard)

    async def _after_policy(self, policy_id: int) -> None:
        try:
            hosts = await client.run_blocking(self._load_hosts)
            host_id = await client.run_blocking(self._policy_host, policy_id)
            for host in hosts:
                if host.id == host_id:
                    for paced in (True, False):
                        running = self._busy.get((host.id, paced))
                        if running is not None and not running.done():
                            # It read the host before the run ended: wait it out, then
                            # check again.
                            await asyncio.shield(running)
                    await self.check_host(host)
        except Exception:
            log.exception("Checking for updates after policy %d's run failed", policy_id)

    def _policy_host(self, policy_id: int) -> int | None:
        with self._sessions() as db:
            return db.scalar(select(UpdatePolicy.host_id).where(UpdatePolicy.id == policy_id))

    async def check_host(self, host: Host, *, paced: bool = True) -> HostChecks:
        """Checks the host, or waits for the check of it already under way. paced: with
        LOOKUP_GAP between lookups; not when a page waits for it."""
        key = (host.id, paced)
        running = self._busy.get(key)
        if running is None or running.done():
            running = self._busy[key] = asyncio.create_task(self._check(host, paced))
        return await asyncio.shield(running)

    async def _check(self, host: Host, paced: bool = True) -> HostChecks:
        cache = self._caches.setdefault(host.id, {})
        previous = self._results.get(host.id)
        began = time.monotonic()
        try:
            url = self._hosts.docker_url(host)
            verdicts = await anyio.to_thread.run_sync(
                functools.partial(self._read, url, cache, self._pause if paced else None),
                limiter=self._paced if paced else self._limiter,
                abandon_on_cancel=True,
            )
            result = HostChecks(utcnow(), verdicts)
            self._checked[host.id] = time.monotonic()
            if failed := result.count("error"):
                # The page says so too; here for when a policy run later finds nothing.
                log.warning("Host %s: %d containers could not be checked", host.id, failed)
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
        if self._began.get(host.id, -math.inf) <= began:
            # Not over the result of a check begun after this one (a page's, beside this
            # paced one), whichever ended first.
            self._results[host.id] = result
            self._began[host.id] = began
        return result

    def _pause(self) -> None:
        """Blocking: LOOKUP_GAP between two lookups of a paced check. After close, its
        abandoned thread ends here rather than asking the rest at once."""
        if self._stop.wait(LOOKUP_GAP):
            raise Stopped

    def _read(
        self,
        url: str,
        cache: dict[tuple[str, str], Cached],
        pause: Callable[[], object] | None = None,
    ) -> dict[str, Verdict]:
        with client.open_client(url, TIMEOUT) as handle:
            return check(
                handle.client.api,
                self._hosts.instance_id,
                cache,
                time.monotonic(),
                (self._every or CHECK_EVERY) / 2,  # next_slot: slots are further apart
                self._newer_version,
                pause,
            )

    def _newer_version(self, ref: str, digest: str, platform: Platform) -> str:
        """Blocking. registry_version, asked once per digest and platform; a failed ask
        is asked again at the next check."""
        key = (ref.rpartition(":")[0], digest, platform)
        found = self._versions.get(key)
        if found is None:
            found = registry_version(ref, digest, platform)
            if found is None:
                return ""
            if len(self._versions) >= MAX_VERSIONS:
                self._versions.clear()  # ponytail: drop all; an LRU if this ever churns
            self._versions[key] = found
        return found

    async def _run(self) -> None:
        await asyncio.sleep(FIRST_CHECK)
        self._epoch = time.monotonic()
        while True:
            try:
                hosts = await client.run_blocking(self._load_hosts)
                for gone in self._results.keys() - {h.id for h in hosts}:
                    self._results.pop(gone, None)
                    self._caches.pop(gone, None)
                    self._checked.pop(gone, None)
                    self._began.pop(gone, None)
                every = self._every  # 0: after policy runs, or asked
                for index, host in enumerate(hosts if every else []):
                    done = self._results.get(host.id)
                    last = self._checked.get(host.id)
                    if (
                        last is None  # since the start: every host once, for the pages
                        or done is None
                        or done.error is not None
                        or time.monotonic()
                        >= next_slot(last, self._epoch, every, index, len(hosts))
                    ):
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
