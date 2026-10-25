"""The dispatcher: the single entry point that runs jobs and restores.

Phase 2 runs backups and Phase 3 restores; the scheduler (Phase 5) goes through here too.

Locking: one asyncio.Lock per key, taken in sorted order, so two runs that share a key
never overlap and never deadlock. The keys are container IDs (64 hex characters, unique
across daemons) and name keys 'name:<scope>:<container|volume|network>:<name>'. The scope
is derived from the daemon's ID (/info), so two host entries for the same daemon share
their name keys too (lock_scope); a restore's journal records the scope it locked under,
for startup recovery. A backup locks the ID and the name of each container it backs up;
once it holds them it resolves the job's containers by name again, and waits again if one
was replaced meanwhile (an overwrite restore gives the container a new ID under the same
name). One that finds no container of a name another run holds waits for that run first,
since an overwrite restore renames the original long before it creates the new
container. A run waiting for a lock stays "queued". Startup recovery
holds the locks of the containers it is about to start again or roll back, so a run on
one of them waits for that. A job has at most one queued or running run at a time.

The blocking work runs on a ThreadPoolExecutor (two workers by default). Cancellation sets
a threading.Event that the capture and the archive writer check between chunks of at
most 8 MiB.

Consistency modes: stop mode stops the job's running containers while their data is read,
pause mode pauses them (their processes keep their uptime), and live mode changes nothing
(the data is read while they run, so the backup is crash-consistent at best). The list of
containers drydock is about to stop or pause is written to the run row
(stopped_containers_json, paused_containers_json) before the first call. Containers are
stopped or paused as late as possible (after the inspect, compose file and registry work,
see engine.capture), and each is counted before its call, since a call that fails or
times out may still have done it. Every one is started or unpaused again in a finally
block; if drydock dies in between, startup recovery reads the lists and unpauses, then
starts them. What a run or recovery could not unpause or start again stays in the lists
and is tried again with a new client (see _undo): while the host is unreachable, for as
long as drydock runs, with the containers' locks held, so a run cancelled or failed
mid-stream still puts them right once an SSH tunnel is back. What Docker refused while it
answered is marked abandoned in the list, named in the run's error and left to the user.
Stop and pause go in reverse dependency order (dependents first), start and
unpause forward, and a start waits (bounded, cancellable) for the dependencies Compose
says must be healthy. Containers that are already stopped or paused are left as they are.
A running container of drydock's own deployment (its container or Compose project) is
refused in every mode: stopping or pausing the socket proxy would leave drydock unable to
undo it, and a live archive would hold drydock's own secrets. Stop mode also refuses
containers that remove themselves when stopped (--rm), containers in the network, IPC or
PID namespace of one that is not running (Docker would refuse to start them again), and
containers whose namespaces a running container shares that the run does not stop with
them (it would be left in a dead namespace). When drydock shuts down while a
worker is stuck in a Docker call, the containers on the run row are unpaused and started,
and the run is left open: the stuck call may still complete afterwards, so startup
recovery marks the run interrupted and does both again.

Stacks: a stack job backs up the containers of one Compose project, found at run time by
their com.docker.compose.project label (engine.stacks.discover) and ordered by their
dependencies (engine.stacks.order). Membership is resolved again once the locks are held,
and the run waits again if it changed. A stack run also holds the key
'name:<scope>:project:<project>', which every restore that touches the project takes too.

Hooks: pre-hooks run right before the first stop or pause (live mode: the data read),
post-hooks after every container was started and unpaused again, also when a pre-hook or
the capture failed. They are checked against the job again once the locks are held, before
anything changes (see jobs.hooks). Startup recovery does not run post-hooks; for a run that
was running it names the job's post-hooks in the run log as not run.

The archive is written straight into the storage directory under a temporary name and
published once complete, so the staging directory only ever holds one member.

Retention (jobs.retention) runs right after the archive is stored and catalogued, unless a
post-hook failed. It deletes only the job's own archives, never the one just stored nor
one an open restore names, and drops their catalog rows (audited). An archive it cannot
delete does not stop the others, and a cancel stops it before the next one; either way the
run fails (or ends cancelled) with the backup stored.

Run logs live at <data dir>/logs/<run_id>.log and are redacted (see jobs.runlog). Error
messages stored on the run row are redacted the same way, because the UI shows them.

Restores: submit_restore creates a run (kind "restore", no job) in "verifying" and
verifies the archive on the executor (restore.verify pass 1). That task holds no lock
and opens no Docker client. A verified run waits in "awaiting_confirmation" with its
metadata staged encrypted in $DRYDOCK_STAGING_DIR/restore-<run id>/; at most MAX_AWAITING
restores verify or wait at once, and an hourly task (and every submit) cancels those not
confirmed within CONFIRM_TTL and removes their staged data. execute_restore moves the run
to "queued" with a compare-and-set, so it runs once. The task then plans the restore
again against the target's current state, before and after taking the plan's lock keys:
the summary the user confirmed must still match, every flagged field must be
acknowledged, and the keys held must cover the fresh plan. restore.apply writes its
journal (runs.restore_originals_json) before every mutation; when apply fails, the
journal is rolled back under the same locks. After a crash, recover() marks the run
interrupted and start() rolls the journal back under its locks once the host is
reachable and reaped. Those locks stay held until the rollback has run, however long the
host stays unreachable, and a rollback that could not reach Docker halfway through is
tried again the same way: once they are released, other runs may change the host, and
the journal would no longer describe it. If drydock stops first, the next start rolls it
back. If the host entry is deleted, or a rollback raises or cannot undo something for
another reason, the journal is marked abandoned and its leftovers are put right by hand.
Originals a restore stops are never put in stopped_containers_json.
"""

import asyncio
import contextlib
import functools
import hashlib
import itertools
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
import zoneinfo
from collections import defaultdict
from collections.abc import Callable, Coroutine, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import docker.errors
import requests
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from drydock import audit
from drydock.archive.verify import VerifyError
from drydock.archive.writer import ArchiveError, Cancelled
from drydock.config import Settings
from drydock.crypto import Crypto, CryptoError
from drydock.engine import capture, stacks
from drydock.hosts import client as docker_client
from drydock.hosts.client import DockerHandle, run_blocking
from drydock.hosts.inventory import (
    DEFAULT_STOP_TIMEOUT,
    PROJECT_LABEL,
    SERVICE_LABEL,
    own_container,
    stop_timeout,
)
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.jobs import hooks, retention
from drydock.jobs.runlog import RunLog, env_values, log_dir, log_path
from drydock.models import Backup, Host, Job, Run, StorageTarget, utcnow
from drydock.models import Hook as HookRow
from drydock.restore import apply as restore_apply
from drydock.restore import plan as restore_plan
from drydock.restore import verify as restore_verify
from drydock.security import hostpaths
from drydock.storage import options
from drydock.storage.base import (
    StorageBackend,
    StorageError,
    archive_name,
    check_name,
    parse_name,
)
from drydock.storage.local import LocalStorage
from drydock.storage.rclone import KINDS as REMOTE_KINDS
from drydock.storage.rclone import REMOTE_RESTORE_LATER, RcloneBackend
from drydock.storage.rclone_rc import RcloneDaemon

log = logging.getLogger("drydock.jobs")

WORKERS = 2
# compose.yaml gives drydock 90 s after SIGTERM; uvicorn's own graceful shutdown comes first.
SHUTDOWN_WAIT = 45
RECOVERY_WAIT = 300  # how long startup recovery waits for an SSH host to connect
RECOVERY_RETRY = 2
ROLLBACK_RETRY = 60  # pause between rounds of RECOVERY_WAIT while a rollback's host is down
ROLLBACK_RAISED = (
    "The rollback did not finish. Remove what the restore left on the host by hand; see the "
    "drydock server log."
)
ROLLBACK_INCOMPLETE = (
    "The rollback could not undo everything the restore did; the lines above say what is "
    "left. Put it right by hand."
)
ROLLBACK_UNREACHABLE = (
    "The rollback could not reach the host. Drydock tries again while it runs, and holds "
    "the restore's containers, volumes and networks until the rollback is done."
)
# A task is working on the run, and its page polls the log.
ACTIVE_STATUSES = ("queued", "verifying", "running")
# Not finished yet: recover() interrupts these, and only these can end.
OPEN_STATUSES = (*ACTIVE_STATUSES, "awaiting_confirmation")
CONFIRM_TTL = timedelta(hours=24)  # a verified restore not confirmed by then is cancelled
EXPIRY_INTERVAL = 3600  # seconds between checks for such restores
MAX_AWAITING = 5  # restores verifying or awaiting confirmation at once (staged data)
MAX_RELOCK = 5  # times a backup waits again for containers replaced while it waited
MAX_WAIT_FOR = 256  # IDs read from a stopped entry's wait_for (rows are data)
NOT_CONFIRMED = "Not confirmed within 24 hours."
INVALID_HOOKS = "The job's hooks are not valid. Edit the job again."
HOOKS_CHANGED = "The job's hooks changed while this run waited. Start it again."
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{12,64}")
LOCK_SCOPE_RE = re.compile(r"d[0-9a-f]{32}|[0-9]{1,18}")  # what lock_scope returns
# Startup recovery removes only these from the staging directory, which may be a shared disk.
STAGING_NAME_RE = re.compile(r"member-[0-9a-f]{32}|probe-[0-9a-f]{32}\.tar|upload-[0-9a-f]{32}")
# Only the names drydock writes: ASCII, no leading zero (run IDs start at 1).
LOG_NAME_RE = re.compile(r"([1-9][0-9]{0,17})\.log")
# Test connection's file (storage.rclone): removed at startup only, as no run tracks it.
CHECK_RE = re.compile(r"check-[0-9a-f]{32}")
# Scratch files renamed for removal; no run uses them, so they can go at any time.
TRASH_RE = re.compile(r"trash-[0-9a-f]{32}")
FINISHED_STATUSES = ("done", "failed", "cancelled", "interrupted")
PRUNE_BATCH = 500  # runs per transaction: the write lock is held only that long
PRUNE_MAX_BATCHES = 20  # per pass; the next pass continues
# Journal keys the run page turns into "put this right by hand" (routes/runs.py).
HAND_FIX_KEYS = ("leftover", "not_renamed", "tags_left", "abandoned", "rollback_incomplete")
SAFE_ERRORS = (
    capture.CaptureError,
    ArchiveError,
    StorageError,
    HostUnavailable,
    docker_client.DockerUnavailable,
    docker.errors.DockerException,
    requests.RequestException,
    OSError,
    VerifyError,
    restore_plan.PlanError,
    hostpaths.HostPathError,
    restore_apply.ApplyError,
    stacks.StackError,
    hooks.HookError,
)
UNDECRYPTABLE_STORAGE = "The storage settings cannot be decrypted with the configured secret keys."
UNEXPECTED_RETENTION = "Unexpected error in drydock. See the drydock server log."
RETENTION_CANCELLED = "Cancelled before it deleted everything."


class DispatchError(Exception):
    """A run cannot start or continue. The message is safe to show."""


@dataclass(frozen=True)
class RunPlan:
    """What a run needs from the database, loaded once when it starts."""

    run_id: int
    job_id: int
    job: capture.CaptureJob
    host: Host  # detached
    storage_target_id: int
    storage_root: str
    targets: tuple[str, ...]  # the container refs of a container job; () for a stack
    target_type: str = "container"
    target: str = ""  # job.target as stored: the container ref or the Compose project
    project: str | None = None  # stacks only
    pre_hook_ids: tuple[int, ...] = ()
    post_hook_ids: tuple[int, ...] = ()
    pre_hooks: tuple[hooks.Hook, ...] = ()  # the rows as loaded, compared after the locks
    post_hooks: tuple[hooks.Hook, ...] = ()
    storage_kind: str = "local"
    # A remote target's decrypted settings, secrets included: never in a repr or a log.
    storage_config: dict[str, Any] | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    running: bool  # also true while paused
    stop_timeout: int = DEFAULT_STOP_TIMEOUT
    paused: bool = False
    service: str | None = None  # its Compose service
    wait_for: tuple[str, ...] = ()  # IDs that must be healthy before it starts
    providers: tuple[str, ...] = ()  # the containers whose namespaces it joins (container:)


@dataclass(frozen=True)
class RestoreSource:
    """Where a restore run's archive is, and its runs.plan document."""

    storage_target_id: int
    archive: str
    root: str
    doc: dict[str, Any]


@dataclass
class ActiveRun:
    run_id: int
    job_id: int | None  # None for a restore
    cancel: threading.Event = field(default_factory=threading.Event)
    task: asyncio.Task[None] | None = None
    started: bool = False  # holds its container locks; cancel no longer interrupts the task
    abandoned: bool = False  # shutdown gave up waiting for it (see _abandon)


def job_targets(job: Job) -> list[str]:
    """The containers a container job backs up. Stack jobs are discovered at run time
    (Dispatcher._targets)."""
    return [job.target]


def stopped_entry(host_id: int, target: Target) -> dict[str, Any]:
    """An entry of stopped_containers_json or paused_containers_json. Unpauses ignore
    wait_for."""
    entry: dict[str, Any] = {"host_id": host_id, "id": target.id, "name": target.name}
    if target.wait_for:
        entry["wait_for"] = list(target.wait_for)
    return entry


def entry_wait_for(entry: dict[str, Any]) -> tuple[str, ...]:
    """The IDs a stopped entry waits for; () unless it is a short list of short IDs."""
    value = entry.get("wait_for")
    if (
        isinstance(value, list)
        and len(value) <= MAX_WAIT_FOR
        and all(isinstance(item, str) and 0 < len(item) <= 64 for item in value)
    ):
        return tuple(value)
    return ()


def pending(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The entries recovery still has to undo: not those drydock gave up on (_mark_left)."""
    return [entry for entry in entries if not entry.get("abandoned")]


def run_entries(text: str | None) -> list[dict[str, Any]]:
    """The entries of a stopped or paused list on a run row. Rows are data: anything that
    is not an entry drydock wrote is left out."""
    try:
        value = json.loads(text or "[]")
    except ValueError, RecursionError:
        return []
    return [
        item
        for item in (value if isinstance(value, list) else [])
        if isinstance(item, dict)
        and type(item.get("host_id")) is int
        and isinstance(item.get("id"), str)
        and item["id"]
        and isinstance(item.get("name"), str)
    ]


def hook_ids(text: str | None) -> tuple[int, ...]:
    """A job's pre_hooks or post_hooks: a JSON list of hook IDs. Raises DispatchError."""
    try:
        value = json.loads(text or "[]")
    except ValueError, RecursionError:
        raise DispatchError(INVALID_HOOKS) from None
    if (
        not isinstance(value, list)
        or len(value) > hooks.MAX_HOOKS_PER_PHASE
        or not all(type(item) is int for item in value)
    ):
        raise DispatchError(INVALID_HOOKS)
    return tuple(value)


def name_key(scope: int | str, kind: str, name: str) -> str:
    """The lock key of a container, volume or network name on a daemon (see lock_scope)."""
    return f"name:{scope}:{kind}:{name}"


def lock_scope(info: Any, host_id: int) -> str:
    """The scope of name keys on the daemon whose /info this is: from its ID, so every host
    entry for one daemon (a socket proxy and an SSH tunnel, say) locks the same names. The
    host entry's ID when the daemon reports none."""
    daemon = info.get("ID") if isinstance(info, dict) else None
    if isinstance(daemon, str) and daemon:
        return "d" + hashlib.sha256(daemon.encode()).hexdigest()[:32]
    return str(host_id)


def scoped(keys: Sequence[str], host_id: int, scope: str) -> list[str]:
    """A plan's lock keys (restore.plan names them by host entry) in the daemon's scope."""
    prefix = f"name:{host_id}:"
    return sorted(
        {
            f"name:{scope}:{key.removeprefix(prefix)}" if key.startswith(prefix) else key
            for key in keys
        }
    )


def journal_scope(host_id: int, doc: dict[str, Any]) -> int | str:
    """The scope a restore's journal was locked under; its host entry for an older one."""
    scope = doc.get("lock_scope")
    return scope if isinstance(scope, str) and LOCK_SCOPE_RE.fullmatch(scope) else host_id


def lock_subject(key: str) -> str:
    """How the log names a lock key: 'container 0123456789ab' or 'volume data'."""
    if key.startswith("name:"):
        _, _, kind, name = key.split(":", 3)
        return f"{kind} {name}"
    return f"container {key[:12]}"


def backup_keys(
    scope: int | str, targets: Sequence[Target], project: str | None = None
) -> list[str]:
    """The lock keys of a backup: each container's ID and its name, and for a stack the
    key of its Compose project."""
    keys = {t.id for t in targets} | {name_key(scope, "container", t.name) for t in targets}
    if project:
        keys.add(name_key(scope, "project", project))
    return sorted(keys)


def json_object(text: str | None) -> dict[str, Any]:
    """A JSON object column (runs.plan, the journal); anything else reads as empty."""
    try:
        document = json.loads(text or "{}")
    except ValueError:
        return {}
    return document if isinstance(document, dict) else {}


def journal_entries(doc: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = doc.get(key)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def journal_keys(host_id: int, doc: dict[str, Any]) -> set[str]:
    """The lock keys a rollback of this journal needs, the same kinds a restore's plan
    takes: the IDs and names of the originals and of the containers the restore created,
    the names of the volumes and networks it created or wrote, and the Compose projects it
    touched. A run that would reuse one of them waits until the rollback is done with it."""
    scope = journal_scope(host_id, doc)
    keys: set[str] = set()
    for item in journal_entries(doc, "originals") + journal_entries(doc, "created"):
        if isinstance(item.get("id"), str) and item["id"]:
            keys.add(item["id"])
        if isinstance(item.get("name"), str) and item["name"]:
            keys.add(name_key(scope, "container", item["name"]))
    for item in journal_entries(doc, "networks"):
        if isinstance(item.get("name"), str) and item["name"]:
            keys.add(name_key(scope, "network", item["name"]))
    for kind in ("volumes_created", "volumes"):
        value = doc.get(kind)
        for volume in value if isinstance(value, list) else []:
            if isinstance(volume, str) and volume:
                keys.add(name_key(scope, "volume", volume))
    projects = doc.get("projects")
    for project in projects if isinstance(projects, list) else []:
        if isinstance(project, str) and project:
            keys.add(name_key(scope, "project", project))
    return keys


def journal_host(doc: dict[str, Any]) -> int | None:
    """The host entry a journal's restore ran on; None if it names none."""
    try:
        return int(doc["host_id"])
    except KeyError, TypeError, ValueError:
        return None


def needs_rollback(doc: dict[str, Any]) -> bool:
    # abandoned: drydock gave up on the rollback (the host entry is gone, or the rollback
    # raised); what the restore left is removed by hand.
    if doc.get("rolled_back") or doc.get("abandoned"):
        return False
    return any(doc.get(key) for key in ("originals", "created", "networks", "volumes_created"))


def archive_facts(staged: restore_verify.Staged) -> restore_plan.ArchiveFacts:
    """What pass 1 learned about the archive, as the planner takes it."""
    verification = staged.verification
    loaded_ids = {
        entry.id: frozenset(verification.images[entry.data_member].ids)
        for entry in staged.manifest.images
        if entry.saved and entry.data_member in verification.images
    }
    return restore_plan.ArchiveFacts(
        loaded_ids=loaded_ids,
        setid_members=frozenset(m for m, facts in verification.data.items() if facts.setid),
    )


def check_confirmed(
    plan: restore_plan.RestorePlan,
    host_name: str,
    confirmed: dict[str, Any],
    choice: restore_plan.Choice,
) -> None:
    """Refuses a fresh plan that is not what the user confirmed."""
    fresh = json.loads(json.dumps(restore_plan.summary(plan, host_name)))
    if restore_plan.summary_core(fresh) != restore_plan.summary_core(confirmed):
        raise DispatchError("The plan changed since it was confirmed. Plan the restore again.")
    if not {flag.key for flag in plan.risk} <= choice.acknowledged:
        raise DispatchError("Not every flagged field was acknowledged. Plan the restore again.")


def names_container(ref: str, info: dict[str, Any]) -> bool:
    """Whether ref names this container: its exact name, its ID, or an ID prefix of at least
    12 hex characters. Docker falls back to any ID prefix when no container has the name,
    so a job for "db" could otherwise back up whichever container's ID starts with db."""
    if info["Name"].lstrip("/") == ref or info["Id"] == ref:
        return True
    return CONTAINER_ID_RE.fullmatch(ref) is not None and info["Id"].startswith(ref)


def own_refusal(mode: str, name: str) -> str:
    """Why a running container of drydock's own deployment is refused in this mode."""
    if mode == "pause":
        return (
            f"Container {name} belongs to drydock's own deployment. Pausing it would cut "
            "drydock off from Docker, so pause mode refuses it."
        )
    if mode == "live":
        return (
            f"Container {name} belongs to drydock's own deployment, which drydock does not "
            "back up while it runs (its archive would hold drydock's own secrets)."
        )
    return (
        f"Container {name} belongs to drydock's own deployment. Stopping it would cut "
        "drydock off from Docker, so stop mode refuses it."
    )


class Dispatcher:
    def __init__(
        self,
        settings: Settings,
        sessions: sessionmaker[Session],
        crypto: Crypto,
        hosts: HostManager,
        *,
        enabled: bool,
        workers: int = WORKERS,
        on_end: Callable[[int], None] | None = None,
        rclone: RcloneDaemon | None = None,
    ) -> None:
        self.settings = settings
        self._rclone = rclone  # remote storage transfers; None leaves them refused
        # Told the ID of each run whose end was committed (notify.Notifier.run_ended).
        self._on_end = on_end
        self._sessions = sessions
        self._crypto = crypto
        self._hosts = hosts
        self._enabled = enabled  # only the process holding the data directory lock runs jobs
        self._closing = False
        # Set first by shutdown(): recovery's health waits end and the rest start at once.
        self._stopping = threading.Event()
        self._executor = ThreadPoolExecutor(workers, thread_name_prefix="drydock-run")
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._owners: dict[str, str] = {}  # lock key: who holds it, for the log
        self._active: dict[int, ActiveRun] = {}
        self._jobs: set[int] = set()  # jobs with a queued or running run
        self._last_stamp: dict[str, datetime] = {}
        self._stamp_lock = threading.Lock()
        self._pending_restarts: dict[int, list[tuple[int, dict[str, Any]]]] = {}
        self._pending_unpauses: dict[int, list[tuple[int, dict[str, Any]]]] = {}
        self._pending_rollbacks: dict[int, list[tuple[int, dict[str, Any]]]] = {}
        self._background: set[asyncio.Task[None]] = set()

    # PUBLIC API

    def _check_open(self) -> None:
        if not self._enabled:
            raise DispatchError(
                "This drydock process does not hold the data directory lock, so it runs no jobs."
            )
        if self._closing:
            raise DispatchError("Drydock is shutting down.")

    async def submit(self, job_id: int, triggered_by: str | None, *, fired: bool = False) -> int:
        """Queues a run of the job and returns its ID. Raises DispatchError. fired: a
        scheduled fire, recorded on the job with the run (jobs.scheduler)."""
        self._check_open()
        # Checked and claimed on the event loop, so two quick clicks cannot both pass.
        if job_id in self._jobs:
            raise DispatchError("This job already has a run in progress.")
        self._jobs.add(job_id)
        try:
            run_id = await run_blocking(self._create_run, job_id, triggered_by, fired)
        except BaseException:
            self._jobs.discard(job_id)
            raise
        active = ActiveRun(run_id, job_id)
        self._active[run_id] = active
        active.task = asyncio.create_task(self._execute(active, job_id), name=f"run-{run_id}")
        return run_id

    async def submit_restore(
        self, storage_target_id: int, archive: str, triggered_by: str | None
    ) -> int:
        """Creates a restore run and verifies the archive in the background. Returns the run
        ID. Raises DispatchError."""
        self._check_open()
        run_id, expired = await run_blocking(
            self._create_restore_run, storage_target_id, archive, triggered_by
        )
        await run_blocking(self._expired, expired)
        if run_id is None:
            raise DispatchError("Too many restores are awaiting confirmation. Discard one first.")
        active = ActiveRun(run_id, None, started=True)  # no lock: cancel only sets the event
        self._active[run_id] = active
        active.task = asyncio.create_task(self._verify_restore(active), name=f"run-{run_id}")
        return run_id

    async def execute_restore(
        self,
        run_id: int,
        choice: restore_plan.Choice,
        triggered_by: str | None,
        *,
        seen: dict[str, Any] | None = None,
    ) -> None:
        """Runs a restore awaiting confirmation, with the user's choice. Raises
        DispatchError if it is not awaiting confirmation (it runs at most once), or if seen
        (the stored choice and summary the user confirmed) is given and no longer stored."""
        self._check_open()
        await run_blocking(self._confirm_restore, run_id, choice, seen)
        active = ActiveRun(run_id, None)
        self._active[run_id] = active
        active.task = asyncio.create_task(
            self._execute_restore(active, triggered_by), name=f"run-{run_id}"
        )

    async def discard_restore(self, run_id: int) -> bool:
        """Cancels a restore awaiting confirmation and removes its staged data. False if it
        was not awaiting confirmation."""
        if not await run_blocking(self._discard, run_id):
            return False
        await self._remove_staged(run_id)
        return True

    def cancel(self, run_id: int) -> bool:
        """Asks a run to stop. Call on the event loop. False if it is not active."""
        active = self._active.get(run_id)
        if active is None:
            return False
        active.cancel.set()
        if not active.started and active.task is not None:
            active.task.cancel()  # still waiting for a container lock or resolving targets
        return True

    async def wait(self, run_id: int) -> None:
        """Waits until the run has finished (used by tests)."""
        active = self._active.get(run_id)
        if active is not None and active.task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.shield(active.task)

    # LIFECYCLE

    def recover(self) -> None:
        """Startup recovery, under the flock and before any run starts. Blocking.

        Runs not finished yet become interrupted, staging is emptied and partial uploads in
        local storage are removed (rclone, not started yet, would be needed for remote
        storage: the log of an interrupted upload names what it may have left). Containers
        those runs paused are unpaused and those they stopped started again (also what an
        earlier start had not finished with when drydock stopped again), and the journals
        of interrupted restores (now or at an earlier start that drydock stopped before the
        rollback was done) rolled back, by start() once their hosts are reachable. Orphaned
        helpers are removed by the host manager's reaper on first contact with each host.
        """
        interrupted: list[tuple[int, list[dict[str, Any]], list[dict[str, Any]]]] = []
        restores: list[tuple[int, dict[str, Any]]] = []
        skipped_hooks: dict[int, list[str]] = {}
        uploading: set[int] = set()  # backups to remote storage that may have been uploading
        with self._sessions() as db, db.begin():
            for run in db.scalars(select(Run).where(Run.status.in_(OPEN_STATUSES))):
                if run.kind == "restore":
                    # Never restarted from stopped_containers_json: the journal says what
                    # its originals need.
                    interrupted.append((run.id, [], []))
                    restores.append((run.id, json_object(run.restore_originals_json)))
                else:
                    interrupted.append(
                        (
                            run.id,
                            pending(run_entries(run.stopped_containers_json)),
                            pending(run_entries(run.paused_containers_json)),
                        )
                    )
                    if run.status == "running":  # its pre-hooks may have run
                        skipped_hooks[run.id] = self._post_hook_names(db, run.job_id)
                        job = db.get(Job, run.job_id) if run.job_id is not None else None
                        target = db.get(StorageTarget, job.storage_target_id) if job else None
                        if target is not None and target.kind != "local":
                            uploading.add(run.id)
                run.status = "interrupted"
                run.error = "Drydock stopped before the run finished."
                run.finished_at = utcnow()
            # Unpauses and starts an earlier start did not finish because drydock stopped
            # again (the host was unreachable) are tried again: that start held their
            # locks until it stopped. Not the entries it gave up on (marked abandoned),
            # nor those of failed or cancelled runs, whose locks were released.
            retried: list[tuple[int, list[dict[str, Any]], list[dict[str, Any]]]] = []
            just_ended = {run_id for run_id, _, _ in interrupted}
            for run in db.scalars(
                select(Run).where(
                    Run.kind == "backup",
                    Run.status == "interrupted",
                    or_(Run.stopped_containers_json != "[]", Run.paused_containers_json != "[]"),
                )
            ):
                stopped = pending(run_entries(run.stopped_containers_json))
                paused = pending(run_entries(run.paused_containers_json))
                if run.id not in just_ended and (stopped or paused):
                    retried.append((run.id, stopped, paused))
            # A rollback an earlier start did not finish because drydock stopped again is
            # tried again: that start held the restore's locks until it stopped, so the
            # journal still describes the host. Failed and cancelled restores are not: their
            # locks were released after the rollback, so another run may have changed the
            # host since. Done runs keep their committed journals on purpose.
            just_interrupted = {run_id for run_id, _ in restores}
            for run in db.scalars(
                select(Run).where(Run.kind == "restore", Run.status == "interrupted")
            ):
                doc = json_object(run.restore_originals_json)
                if (
                    run.id not in just_interrupted
                    and needs_rollback(doc)
                    and journal_host(doc) is not None  # an earlier start logged it incomplete
                ):
                    restores.append((run.id, doc))
            targets = list(db.scalars(select(StorageTarget)))
        for run_id, _, _ in interrupted:
            RunLog(log_path(self.settings.data_dir, run_id))(
                "Interrupted: drydock stopped before the run finished."
            )
            log.warning("Run %d was interrupted by a restart of drydock", run_id)
            if run_id in uploading:
                RunLog(log_path(self.settings.data_dir, run_id))(
                    "If its upload had started, a partial file may be left in the remote "
                    "storage folder: the archive name, possibly shortened, then .<8 hex>"
                    ".partial. Drydock does not list it; remove it by hand."
                )
            self._ended_notice(run_id)
            if names := skipped_hooks.get(run_id):
                # Not run here: nothing records whether the pre-hook phase was entered.
                RunLog(log_path(self.settings.data_dir, run_id))(
                    f"The job's post-hooks ({', '.join(names)}) did not run. If its pre-hooks "
                    "ran, undo what they changed by hand."
                )
                log.warning("Run %d: its post-hooks did not run", run_id)
        for run_id, _, _ in retried:
            note(
                RunLog(log_path(self.settings.data_dir, run_id)),
                "Drydock started again; trying again to unpause and start what this run left "
                "paused or stopped.",
            )
        for run_id, stopped, paused in interrupted + retried:
            for entry in stopped:
                self._pending_restarts.setdefault(entry["host_id"], []).append((run_id, entry))
            for entry in paused:
                self._pending_unpauses.setdefault(entry["host_id"], []).append((run_id, entry))
        for run_id, doc in restores:
            if not doc:
                continue  # apply never started: nothing to roll back
            host_id = journal_host(doc)
            if host_id is None:
                RunLog(log_path(self.settings.data_dir, run_id))(
                    "The restore journal is incomplete; nothing to roll back."
                )
                log.error("Run %d: the restore journal names no host", run_id)
                continue
            if needs_rollback(doc):
                self._pending_rollbacks.setdefault(host_id, []).append((run_id, doc))
        clean_staging(self.settings.staging_dir)
        for target in targets:
            with contextlib.suppress(StorageError, CryptoError, OSError, ValueError):
                removed = LocalStorage(self._root(target), self.settings).remove_partials()
                if removed:
                    log.warning("Storage %s: removed %d partial upload(s)", target.id, removed)

    async def start(self) -> None:
        """Unpauses and starts the containers that interrupted runs had paused or stopped,
        and rolls back the journals of interrupted restores, in the background. Also starts
        the expiry of restores awaiting confirmation.

        Their locks are taken here, before any request is served, and held until recovery
        is done with them: a run on one of them would otherwise find it stopped and capture
        it without stopping it, while recovery starts it in the middle of the capture, or
        meet a restore's leftovers halfway through their rollback.
        """
        restarts, self._pending_restarts = self._pending_restarts, {}
        unpauses, self._pending_unpauses = self._pending_unpauses, {}
        held: set[str] = set()
        for host_id in dict.fromkeys([*unpauses, *restarts]):
            to_unpause, to_start = unpauses.get(host_id, []), restarts.get(host_id, [])
            keys = sorted({str(entry["id"]) for _, entry in to_unpause + to_start} - held)
            await self._hold_for_recovery(keys)
            held.update(keys)
            self._spawn(self._recover_after_crash(host_id, to_unpause, to_start, keys))
        rollbacks, self._pending_rollbacks = self._pending_rollbacks, {}
        for host_id, docs in rollbacks.items():
            wanted: set[str] = set()
            for _, doc in docs:
                wanted |= journal_keys(host_id, doc)
            keys = sorted(wanted - held)
            await self._hold_for_recovery(keys)
            held.update(keys)
            self._spawn(self._rollback_after_crash(host_id, docs, keys))
        self._spawn(self._expiry_loop())

    async def _hold_for_recovery(self, keys: list[str]) -> None:
        for key in keys:
            await self._locks[key].acquire()  # free: nothing runs yet
            self._owners[key] = "startup recovery"

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    # MAINTENANCE (scheduled hourly by jobs.scheduler)

    async def clean_staging_now(self) -> None:
        """Scratch files go only while no run is active: the check and the renames to trash
        names run on the event loop, where every run registers before it starts, so none
        starts in between; the slow deletes then run on a thread. A staged restore
        directory goes once its run is finished or gone; the directories of runs newer than
        the snapshot are kept."""
        open_ids, newest = await run_blocking(self._open_restores)
        staging = self.settings.staging_dir
        if not self._active:
            trash_scratch(staging)  # renames only: cheap enough for the event loop
        await run_blocking(
            clean_staging,
            staging,
            scratch=False,
            keep=lambda run_id: run_id in open_ids or run_id > newest,
        )

    def prune_history(self, days: int) -> int:
        """Deletes finished runs older than days (see kept_run for the ones it never
        deletes), then their log files, then any log file without a run row (left by a
        crash between the two). Works in short transactions of PRUNE_BATCH runs, at most
        PRUNE_MAX_BATCHES per pass, so requests and runs never wait long for the write lock.
        Audited. Blocking. Returns the number of runs deleted."""
        cutoff = utcnow() - timedelta(days=days)
        pruned, after = 0, 0
        for _ in range(PRUNE_MAX_BATCHES):
            with self._sessions() as db, db.begin():
                rows = db.execute(
                    select(
                        Run.id,
                        Run.status,
                        Run.stopped_containers_json,
                        Run.paused_containers_json,
                        Run.restore_originals_json,
                    )
                    .where(
                        Run.id > after,
                        Run.status.in_(FINISHED_STATUSES),
                        func.coalesce(Run.finished_at, Run.created_at) < cutoff,
                    )
                    .order_by(Run.id)
                    .limit(PRUNE_BATCH)
                ).all()
                if not rows:
                    break
                after = rows[-1].id
                doomed = [row.id for row in rows if not kept_run(row)]
                if doomed:
                    db.execute(delete(Run).where(Run.id.in_(doomed)))
            for run_id in doomed:
                remove_file(log_path(self.settings.data_dir, run_id))
            pruned += len(doomed)
            if len(rows) < PRUNE_BATCH:
                break
        if pruned:
            with self._sessions() as db, db.begin():
                audit.record(
                    db,
                    actor=None,
                    action="runs.prune",
                    details={"runs": pruned, "days": days, "cutoff": cutoff.isoformat()},
                )
        self._sweep_logs()
        return pruned

    def _sweep_logs(self) -> None:
        """Removes log files with no run row. The directory is listed before the rows are
        read: a run's row is committed before its log is first written."""
        directory = log_dir(self.settings.data_dir)
        try:
            names = [path.name for path in directory.iterdir()]
        except FileNotFoundError:
            return
        found = {int(m[1]): name for name in names if (m := LOG_NAME_RE.fullmatch(name))}
        rows: set[int] = set()
        for batch in itertools.batched(found, PRUNE_BATCH, strict=False):
            with self._sessions() as db:  # one short transaction per batch
                rows.update(db.scalars(select(Run.id).where(Run.id.in_(batch))))
        for run_id, name in found.items():
            if run_id not in rows:
                remove_file(directory / name)

    def _open_restores(self) -> tuple[set[int], int]:
        """The open restore runs, and the newest run ID now."""
        with self._sessions() as db:
            open_ids = set(
                db.scalars(
                    select(Run.id).where(Run.kind == "restore", Run.status.in_(OPEN_STATUSES))
                )
            )
            return open_ids, db.scalar(select(func.max(Run.id))) or 0

    async def shutdown(self) -> None:
        """Cancels every run and waits SHUTDOWN_WAIT for them. Runs that do not stop in
        time are abandoned (see _abandon)."""
        self._closing = True
        self._stopping.set()  # a recovery thread cannot be cancelled, only told to hurry
        for task in list(self._background):
            task.cancel()
        tasks = []
        for active in list(self._active.values()):
            self.cancel(active.run_id)
            if active.task is not None:
                tasks.append(active.task)
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=SHUTDOWN_WAIT)
            # A worker stuck in a blocking call: restart from the run row instead.
            for active in [a for a in list(self._active.values()) if a.task in pending]:
                active.abandoned = True
                await run_blocking(self._abandon, active.run_id)
        self._executor.shutdown(wait=False, cancel_futures=True)

    # EXECUTION

    async def _execute(self, active: ActiveRun, job_id: int) -> None:
        run_id = active.run_id
        run_log = RunLog(log_path(self.settings.data_dir, run_id))
        held: list[str] = []
        try:
            plan = await run_blocking(self._load_plan, run_id, job_id)
            if plan.job.encrypted:
                run_log.add_secrets(self._crypto.job_passphrases(uuid.UUID(plan.job.uuid)))
            subject = (
                f"Compose project {plan.project}"
                if plan.project is not None
                else ", ".join(plan.targets)
            )
            run_log(
                f"Backup of {subject} on host {plan.host.name}, scope "
                f"{plan.job.scope}, consistency mode {plan.job.consistency_mode}."
            )
            if plan.pre_hooks or plan.post_hooks:
                run_log(f"Hooks: {len(plan.pre_hooks)} before, {len(plan.post_hooks)} after.")
            await self._hosts.first_attempt(plan.host)
            url = self._hosts.docker_url(plan.host)
            await self._hosts.ready(plan.host.id)  # the startup reap must not hit our helper
            handle = await run_blocking(docker_client.open_client, url)
            try:
                scope = await run_blocking(self._lock_scope, handle, plan.host.id)
                targets, held = await self._lock_targets(handle, plan, scope, run_log)
                active.started = True
                await run_blocking(self._mark_running, run_id)
                loop = asyncio.get_running_loop()
                failure: Exception | None = None
                stored_problem: str | None = None
                try:
                    stored_problem = await loop.run_in_executor(
                        self._executor, self._backup, plan, handle, targets, active.cancel, run_log
                    )
                except Exception as exc:
                    failure = exc
                if not active.abandoned:
                    await self._end_backup(active, plan.host.id, run_log, failure, stored_problem)
            finally:
                self._release(held)
                await run_blocking(handle.close)
        except BaseException as exc:
            # Abandoned by shutdown: the run stays open for startup recovery (_abandon).
            if not active.abandoned:
                await self._ended(active, run_log, exc)
            if not isinstance(exc, Exception | asyncio.CancelledError):
                raise
        finally:
            self._active.pop(run_id, None)
            self._jobs.discard(active.job_id)

    async def _ended(self, active: ActiveRun, run_log: RunLog, exc: BaseException) -> None:
        """Records the end of a run that raised exc. Messages of unexpected errors stay in
        the server log, never in the run row the UI shows."""
        run_id = active.run_id
        if isinstance(exc, asyncio.CancelledError):
            await self._finish_quietly(run_id, run_log, "cancelled", "The run was cancelled.")
            return
        if active.cancel.is_set():
            status = "cancelled"
            message = "Drydock is shutting down." if self._closing else "The run was cancelled."
            if isinstance(exc, DispatchError) and str(exc):
                # Such as the containers it could not start again: they stay on the row.
                message = f"{message} {exc}"
        else:
            status, message = "failed", self._error_text(run_id, exc)
        await self._finish_quietly(run_id, run_log, status, run_log.redact(message))

    def _error_text(self, run_id: int, exc: BaseException) -> str:
        """What the run row says about exc. Messages of unexpected errors stay in the
        server log."""
        if isinstance(exc, (DispatchError, *SAFE_ERRORS)):
            return str(exc) or type(exc).__name__
        log.error("Run %d failed", run_id, exc_info=exc)
        return f"Unexpected error ({type(exc).__name__}). See the drydock server log."

    async def _end_backup(
        self,
        active: ActiveRun,
        host_id: int,
        run_log: RunLog,
        failure: Exception | None,
        stored_problem: str | None,
    ) -> None:
        """Ends a backup once _backup is done; failure is what it raised, stored_problem
        what it returned (a post-hook or retention failed). What it could not
        unpause or start again is tried again first (_undo), while the run still holds its
        locks. Whatever is left then fails the run, also when the capture failed or the run
        was cancelled: the DispatchError names those containers after the capture's own
        error (_ended puts a cancel's note first instead)."""
        run_id = active.run_id
        paused, stopped = await run_blocking(self._lists, run_id)
        if paused or stopped:
            await self._undo(
                host_id,
                [(run_id, entry) for entry in paused],
                [(run_id, entry) for entry in stopped],
                active,
            )
            if active.abandoned:
                return  # drydock is shutting down: the run stays open for startup recovery
            paused, stopped = await run_blocking(self._lists, run_id)
        problems = leftover_problems(
            [entry["name"] for entry in stopped],
            [entry["name"] for entry in paused],
            stored=failure is None,
        )
        if stored_problem is not None:
            problems.append(stored_problem)
        if failure is not None and not problems:
            raise failure
        if problems:
            first = (
                [self._error_text(run_id, failure)]
                if failure is not None and not active.cancel.is_set()
                else []
            )
            raise DispatchError(" ".join([*first, *problems])) from failure
        await run_blocking(self._finish, run_id, run_log, "done", None)

    async def _lock_targets(
        self, handle: DockerHandle, plan: RunPlan, scope: str, run_log: RunLog
    ) -> tuple[list[Target], list[str]]:
        """Resolves the job's containers and takes the lock of each one's ID and name.

        Once the locks are held the containers are inspected again by the job's refs: a
        run that held them may have stopped or started them, or (an overwrite restore)
        replaced one with a new container of the same name. Then the keys differ, and the
        run waits again for the new ones. A stack is discovered again too, so a member
        added, removed or recreated meanwhile makes it wait again.
        """
        targets = await self._resolve_unlocked(handle, plan, scope, run_log)
        for attempt in range(MAX_RELOCK + 1):
            keys = backup_keys(scope, targets, plan.project)
            held = await self._acquire(keys, plan.run_id, run_log)
            try:
                targets, unordered = await run_blocking(self._targets, handle, plan, run_log)
            except BaseException:
                self._release(held)
                raise
            if backup_keys(scope, targets, plan.project) == held:
                if unordered:  # once, for the members this run backs up
                    run_log(
                        f"The containers of Compose project {plan.project} record no "
                        "dependency order; they stop and start in name order."
                    )
                return targets, held
            self._release(held)
            if attempt == MAX_RELOCK:
                break
            replaced = [
                target
                for target in targets
                if target.id not in held
                and (plan.project is None or name_key(scope, "container", target.name) in held)
            ]
            for target in replaced:
                run_log(
                    f"Container {target.name} was replaced while this run waited; waiting again."
                )
            if plan.project is not None and not replaced:
                run_log(
                    f"Compose project {plan.project} changed while this run waited; waiting again."
                )
        raise DispatchError(
            "The job's containers kept changing while this run waited for them. Try again."
        )

    async def _resolve_unlocked(
        self, handle: DockerHandle, plan: RunPlan, scope: str, run_log: RunLog
    ) -> list[Target]:
        """The first resolve, before any lock is held. An overwrite restore renames the
        original before it creates the new container, so for most of its run no container
        has the name. If a run holds the name of one of the job's containers, this waits
        for it and resolves again instead of failing (for a stack: a run that holds its
        project, which a stack restore does while the project is empty or half renamed).
        Never holds a name key while waiting for another key, so the sorted lock order is
        kept."""
        if plan.project is not None:
            names = {name_key(scope, "project", plan.project)}
        else:
            names = {name_key(scope, "container", ref) for ref in plan.targets}
        for _ in range(MAX_RELOCK):
            try:
                return (await run_blocking(self._targets, handle, plan, run_log))[0]
            except capture.CaptureError:
                busy = sorted(
                    key
                    for key in names
                    if (lock := self._locks.get(key)) is not None and lock.locked()
                )
                if not busy:
                    raise
                self._release(await self._acquire(busy, plan.run_id, run_log))
        return (await run_blocking(self._targets, handle, plan, run_log))[0]

    async def _acquire(self, keys: list[str], run_id: int, run_log: RunLog) -> list[str]:
        held: list[str] = []
        try:
            for key in keys:
                lock = self._locks[key]
                if lock.locked():
                    owner = self._owners.get(key, "another run")
                    run_log(f"Waiting for {owner} to finish with {lock_subject(key)}.")
                await lock.acquire()
                held.append(key)
                self._owners[key] = f"run {run_id}"
        except BaseException:
            self._release(held)
            raise
        return held

    def _release(self, keys: list[str]) -> None:
        for key in keys:
            self._owners.pop(key, None)
            self._locks[key].release()

    def _lock_scope(self, handle: DockerHandle, host_id: int) -> str:
        """The scope of the name keys a run on this daemon takes (see lock_scope)."""
        return lock_scope(handle.client.api.info(), host_id)

    def _targets(
        self, handle: DockerHandle, plan: RunPlan, run_log: RunLog
    ) -> tuple[list[Target], bool]:
        """The run's containers, in start order: the job's refs, or for a stack the
        project's members discovered now, with the IDs each must wait for. Also whether the
        stack fell back to name order (stacks.unordered). Blocking."""
        if plan.project is None:
            return self._resolve(handle, plan, plan.targets, run_log), False
        api = handle.client.api
        ids = stacks.discover(api, plan.project, self._hosts.instance_id)
        if not ids:
            raise capture.CaptureError(
                f"Compose project {plan.project} has no containers on host {plan.host.name}."
            )
        infos = []
        for cid in ids:
            try:
                infos.append(api.inspect_container(cid))
            except docker.errors.NotFound:
                raise capture.CaptureError(
                    f"Container {cid[:12]} does not exist on host {plan.host.name}."
                ) from None
        members = stacks.order(infos)
        healthy = {member.id: member.healthy for member in members}
        targets = self._resolve(handle, plan, [member.id for member in members], run_log)
        ordered = [replace(t, wait_for=healthy.get(t.id, ())) for t in targets]
        return ordered, stacks.unordered(infos)

    def _resolve(
        self, handle: DockerHandle, plan: RunPlan, refs: Sequence[str], run_log: RunLog
    ) -> list[Target]:
        """The containers refs name, and their state. Records env values as secrets."""
        api = handle.client.api
        mode = plan.job.consistency_mode
        own = own_container(api)
        own_labels = ((own or {}).get("Config") or {}).get("Labels") or {}
        own_project = own_labels.get(PROJECT_LABEL)
        targets: dict[str, Target] = {}
        for ref in refs:
            try:
                info = api.inspect_container(ref)
            except docker.errors.NotFound:
                info = None
            if info is None or not names_container(ref, info):
                raise capture.CaptureError(
                    f"Container {ref} does not exist on host {plan.host.name}."
                )
            run_log.add_secrets(env_values(info["Config"].get("Env")))
            state = info.get("State") or {}
            running = bool(state.get("Running"))  # also true while paused
            paused = bool(state.get("Paused"))
            name = info["Name"].lstrip("/")
            if (
                mode == "stop"
                and running
                and not paused
                and (info.get("HostConfig") or {}).get("AutoRemove")
            ):
                raise capture.CaptureError(
                    f"Container {name} is removed when it stops (--rm), so stop mode cannot "
                    "back it up."
                )
            labels = info["Config"].get("Labels") or {}
            ours = own is not None and (
                info["Id"] == own["Id"]
                or (own_project is not None and labels.get(PROJECT_LABEL) == own_project)
            )
            if running and ours:
                raise capture.CaptureError(own_refusal(mode, name))
            service = labels.get(SERVICE_LABEL)
            targets.setdefault(
                info["Id"],
                Target(
                    info["Id"],
                    name,
                    running,
                    stop_timeout(info),
                    paused=paused,
                    service=service if isinstance(service, str) and service else None,
                    providers=namespace_refs(info),
                ),
            )
        return list(targets.values())

    def _backup(
        self,
        plan: RunPlan,
        handle: DockerHandle,
        targets: list[Target],
        cancel: threading.Event,
        run_log: RunLog,
    ) -> str | None:
        """The blocking part of a run, on a worker thread. targets are in start order.

        Returns what went wrong once the archive was stored (a post-hook or retention
        failed), as the sentence the run row shows. What it
        could not unpause or start again stays in the run's lists, for _end_backup."""
        api = handle.client.api
        host_id = plan.host.id
        mode = plan.job.consistency_mode
        # Before anything changes: hooks edited or attached while the run waited, hooks
        # bound elsewhere, and hook containers that are not running targets refuse the run.
        pre_hooks, post_hooks = self._check_hooks(plan)
        pre = hooks.resolve(pre_hooks, targets)
        post = hooks.resolve(post_hooks, targets)
        if mode != "live":
            for target in targets:
                if target.paused:
                    run_log(f"Container {target.name} is paused; it stays paused.")
                elif not target.running:
                    run_log(f"Container {target.name} is not running; it stays stopped.")
        acting = [t for t in targets if t.running and not t.paused]
        to_stop = acting if mode == "stop" else []
        to_pause = acting if mode == "pause" else []
        if to_stop:
            check_namespaces(api, targets, to_stop)
        created_at = self._stamp(plan.job.uuid)
        name = archive_name(plan.job.uuid, plan.job.name, created_at, plan.job.encrypted)
        storage = self._backend(plan)
        if isinstance(storage, LocalStorage):
            partial = storage.new_partial()  # written in place, then published
        else:
            # Before anything changes: a target without a host key fails here.
            run_log.add_secrets(storage.secrets())
            partial = self.settings.staging_dir / f"upload-{uuid.uuid4().hex}"
        # Forward order, so recovery starts dependencies first.
        self._set_stopped(plan.run_id, [stopped_entry(host_id, t) for t in to_stop])
        self._set_paused(plan.run_id, [stopped_entry(host_id, t) for t in to_pause])
        stopped: list[Target] = []  # in the order of the calls: reverse order
        paused: list[Target] = []
        restart_failed: list[str] = []
        unpause_failed: list[str] = []
        post_error: str | None = None
        entered = False  # before_data ran: post-hooks run from here on
        started_again = False

        def start_again() -> None:
            nonlocal restart_failed, unpause_failed, started_again
            if started_again:
                return
            started_again = True
            # Until a pass returns, all it had to undo counts as failed: an unexpected error
            # in one pass neither skips the other nor clears the lists on the row.
            unpause_failed = [t.name for t in paused]
            restart_failed = [t.name for t in stopped]
            # Forward order: dependencies first, and the lists stay in forward order.
            try:
                if cancel.is_set() and paused:
                    note(run_log, "Cancelled. Unpausing the paused containers again.")
                unpause_failed = unpause(api, list(reversed(paused)), run_log)
            finally:
                try:
                    if cancel.is_set() and stopped:
                        note(run_log, "Cancelled. Starting the stopped containers again.")
                    starting = list(reversed(stopped))
                    if cancel.is_set():  # a cancel never waits for health
                        starting = [replace(t, wait_for=()) for t in starting]
                    restart_failed = restart(api, starting, run_log, cancel=cancel)
                finally:
                    if to_pause:
                        self._set_paused(
                            plan.run_id,
                            [
                                stopped_entry(host_id, t)
                                for t in reversed(paused)
                                if t.name in unpause_failed
                            ],
                        )
                    if to_stop:
                        self._set_stopped(
                            plan.run_id,
                            [
                                stopped_entry(host_id, t)
                                for t in reversed(stopped)
                                if t.name in restart_failed
                            ],
                        )

        def before_data() -> None:
            nonlocal entered
            entered = True  # even if a pre-hook fails: it may have changed state
            hooks.run_all(api, pre, phase="pre", cancel=cancel, log=run_log)
            for target in reversed(to_stop):
                if cancel.is_set():
                    raise Cancelled("The run was cancelled.")
                run_log(f"Stopping container {target.name}.")
                stopped.append(target)  # first: a stop that fails or times out may still stop it
                api.stop(target.id, timeout=target.stop_timeout)
            for target in reversed(to_pause):
                if cancel.is_set():
                    raise Cancelled("The run was cancelled.")
                run_log(f"Pausing container {target.name}.")
                paused.append(target)
                api.pause(target.id)
            if mode == "live":
                run_log(
                    "Live mode: the data is read while the containers run, so the backup is "
                    "crash-consistent at best."
                )

        def after_hooks() -> None:
            nonlocal post_error
            if not entered or not post:
                return
            # Paused containers keep their health; restarted ones may need a moment.
            restarted = {t.id for t in stopped if t.name not in restart_failed}
            waiting = list(dict.fromkeys(cid for _, cid, _ in post if cid in restarted))
            if waiting and not cancel.is_set():
                stacks.wait_healthy(
                    api, waiting, time.monotonic() + stacks.HEALTH_WAIT, cancel, run_log
                )
            try:
                hooks.run_all(
                    api,
                    post,
                    phase="post",
                    cancel=cancel,
                    log=run_log,
                    keep_going=True,
                    on_cancel="wait",
                    budget=hooks.POST_HOOK_BUDGET,
                )
            except hooks.HookError as exc:
                post_error = str(exc)  # run_all logged each failure already
            except Exception:
                log.exception("Run %d: a post-hook failed", plan.run_id)
                post_error = "Unexpected error in drydock. See the drydock server log."

        try:
            try:
                env = capture.CaptureEnv(
                    handle=handle,
                    host_name=plan.host.name,
                    helper_image=self.settings.helper_image,
                    instance_id=self._hosts.instance_id,
                    staging_dir=self.settings.staging_dir,
                    crypto=self._crypto,
                )
                _, result = capture.capture(
                    env,
                    plan.job,
                    [t.id for t in targets],
                    partial,
                    cancel=cancel,
                    log=run_log,
                    created_at=created_at,
                    before_data=before_data,
                    on_abort=start_again,  # before the helper is removed, which can be slow
                    secrets=run_log.add_secrets,
                )
            finally:
                # If the capture failed too, its exception wins; the post error is logged.
                try:
                    start_again()
                finally:
                    after_hooks()
            self._check_storage(plan)
            if isinstance(storage, LocalStorage):
                stored = storage.publish(partial, name)
            else:
                # The containers run again and the post-hooks ran: only the upload is left.
                where = options.location(plan.storage_kind, plan.storage_config or {})
                run_log(f"Uploading {name} to {where}.")
                try:
                    stored = storage.put(partial, name, None, cancel)
                except StorageError as exc:
                    run_log(f"Upload failed: {exc}")  # a cancelled run's row drops the reason
                    raise
        finally:
            partial.unlink(missing_ok=True)
        run_log(f"Stored {stored.name} ({result.size} bytes), sha256 {result.sha256}.")
        self._record_backup(plan, stored.name, result.size, result.sha256, result.encrypted)
        if post_error is not None:
            run_log("Retention skipped: a post-hook failed.")
            return f"The backup was stored, but a post-hook failed: {post_error}"
        error = self._retain(plan, storage, stored.name, cancel, run_log)
        if error is None:
            return None
        return f"The backup was stored, but retention did not finish: {error}"

    def _retain(
        self,
        plan: RunPlan,
        storage: StorageBackend,
        stored: str,
        cancel: threading.Event,
        run_log: RunLog,
    ) -> str | None:
        """Deletes the job's archives its retention policy does not keep, once a backup is
        stored. Never the archive just stored, nor one an open restore names. An archive
        that cannot be deleted does not stop the others, and a cancel stops before the next
        one. Returns what kept it from finishing, or None."""
        try:
            with self._sessions() as db:
                row = db.execute(
                    select(Job.retention, Job.timezone).where(Job.id == plan.job_id)
                ).first()
            if row is None:
                run_log("Retention skipped: the job was deleted.")
                return None
            policy = retention.parse(row.retention)
            tz = self._retention_zone(row.timezone) if policy.mode == "gfs" else UTC
            names = [o.name for o in storage.list("drydock-")]
            doomed = retention.select_for_deletion(names, policy, utcnow(), plan.job.uuid, tz)
        except (retention.PolicyError, StorageError, OSError) as exc:
            return str(exc)
        except Exception:
            log.exception("Run %d: retention failed", plan.run_id)
            return UNEXPECTED_RETENTION
        failed: list[str] = []
        for name in doomed:
            if cancel.is_set():
                return RETENTION_CANCELLED
            if name == stored:
                continue
            try:
                self._delete_archive(plan, storage, name, run_log)
            except (StorageError, OSError) as exc:
                failed.append(str(exc))
            except Exception:
                log.exception("Run %d: retention could not delete %s", plan.run_id, name)
                failed.append(UNEXPECTED_RETENTION)
        if failed:
            count = "1 archive" if len(failed) == 1 else f"{len(failed)} archives"
            return f"{count} could not be deleted. {failed[0]}"
        return None

    def _check_hooks(self, plan: RunPlan) -> tuple[tuple[hooks.Hook, ...], tuple[hooks.Hook, ...]]:
        """The job's hooks, read again once the locks are held (blocking, worker thread).

        The run may have waited for its locks for a long time: a hook edited, detached or
        attached meanwhile refuses this run instead of running in its old or new form, and
        every hook must still be bound to the run's host and target (check_binding)."""
        with self._sessions() as db:
            job = db.get(Job, plan.job_id)
            if job is None:
                raise DispatchError("The job was deleted while this run waited.")
            if (hook_ids(job.pre_hooks), hook_ids(job.post_hooks)) != (
                plan.pre_hook_ids,
                plan.post_hook_ids,
            ):
                raise hooks.HookError(HOOKS_CHANGED)
            if not plan.pre_hook_ids and not plan.post_hook_ids:
                return (), ()
            _, _, pre_hooks, post_hooks = self._hook_rows(db, job)
        if (pre_hooks, post_hooks) != (plan.pre_hooks, plan.post_hooks):
            raise hooks.HookError(HOOKS_CHANGED)
        for hook in (*pre_hooks, *post_hooks):
            hooks.check_binding(
                hook, host_id=plan.host.id, target_type=plan.target_type, target=plan.target
            )
        return pre_hooks, post_hooks

    def _stamp(self, job_uuid: str) -> datetime:
        """Archive times have one-second resolution; never reuse one for the same job."""
        with self._stamp_lock:
            now = datetime.now(UTC).replace(microsecond=0)
            last = self._last_stamp.get(job_uuid)
            if last is not None and now <= last:
                now = last + timedelta(seconds=1)
            self._last_stamp[job_uuid] = now
            return now

    # RESTORES

    async def _verify_restore(self, active: ActiveRun) -> None:
        """Pass 1 on the executor. Holds no lock and opens no Docker client: nothing touches
        a host before the archive is verified."""
        run_id = active.run_id
        run_log = RunLog(log_path(self.settings.data_dir, run_id))
        try:
            source = await run_blocking(self._load_restore, run_id)
            run_log.add_secrets(self._passphrases(source.archive))
            storage = LocalStorage(source.root, self.settings)
            loop = asyncio.get_running_loop()
            staged = await loop.run_in_executor(
                self._executor,
                functools.partial(
                    restore_verify.verify_archive,
                    storage,
                    source.storage_target_id,
                    source.archive,
                    self._crypto,
                    self.settings.staging_dir,
                    run_id,
                    cancel=active.cancel,
                    log=run_log,
                ),
            )
            run_log.add_secrets(restore_verify.secret_values(staged))
            await run_blocking(self._verified, run_id, staged.verification, run_log)
        except BaseException as exc:
            await self._ended(active, run_log, exc)
            await self._remove_staged(run_id)
            if not isinstance(exc, Exception | asyncio.CancelledError):
                raise
        finally:
            self._active.pop(run_id, None)

    async def _execute_restore(self, active: ActiveRun, triggered_by: str | None) -> None:
        run_id = active.run_id
        run_log = RunLog(log_path(self.settings.data_dir, run_id))
        held: list[str] = []
        try:
            run_log(f"Confirmed by {triggered_by}.")
            source = await run_blocking(self._load_restore, run_id)
            choice = restore_plan.Choice.from_dict(source.doc.get("choice"))
            confirmed = source.doc.get("summary")
            if not isinstance(confirmed, dict):
                raise DispatchError("The restore has no confirmed plan. Plan the restore again.")
            run_log.add_secrets(self._passphrases(source.archive))
            staged = await run_blocking(
                restore_verify.load_staged,
                restore_verify.restore_dir(self.settings.staging_dir, run_id),
                self._crypto,
            )
            run_log.add_secrets(restore_verify.secret_values(staged))
            verified = staged.verification
            if (verified.storage_target_id, verified.archive) != (
                source.storage_target_id,
                source.archive,
            ):
                raise VerifyError(restore_verify.GONE)
            host = await run_blocking(self._load_host, choice.host_id)
            if host is None:
                raise DispatchError("The host no longer exists.")
            run_log(f"Restore of {source.archive} on host {host.name}, mode {choice.mode}.")
            await self._hosts.first_attempt(host)
            url = self._hosts.docker_url(host)
            await self._hosts.ready(host.id)  # the startup reap must not hit our helpers
            handle = await run_blocking(docker_client.open_client, url)
            try:
                scope = await run_blocking(self._lock_scope, handle, host.id)
                facts = archive_facts(staged)
                lookup = restore_plan.lookups(staged.manifest, staged.configs, choice)
                plan = await run_blocking(
                    self._plan_restore, handle, host, staged, choice, lookup, facts
                )
                check_confirmed(plan, host.name, confirmed, choice)
                held = await self._acquire(scoped(plan.lock_keys, host.id, scope), run_id, run_log)
                active.started = True
                # Plan again: a run that held the locks may have changed the target.
                plan = await run_blocking(
                    self._plan_restore, handle, host, staged, choice, lookup, facts
                )
                check_confirmed(plan, host.name, confirmed, choice)
                if not set(scoped(plan.lock_keys, host.id, scope)) <= set(held):
                    raise DispatchError(
                        "The target changed while the restore waited. Plan it again."
                    )
                if active.cancel.is_set():
                    raise Cancelled("The run was cancelled.")
                await run_blocking(self._mark_running, run_id)
                await self._apply(active, handle, plan, staged, source, scope, run_log)
                # The journal stays: the run page warns about anything it left over.
                await run_blocking(self._finish, run_id, run_log, "done", None)
            finally:
                self._release(held)
                await run_blocking(handle.close)
        except BaseException as exc:
            # Abandoned by shutdown: its journal is left for startup recovery to roll back.
            if not active.abandoned:
                await self._ended(active, run_log, exc)
            if not isinstance(exc, Exception | asyncio.CancelledError):
                raise
        finally:
            self._active.pop(run_id, None)
            await self._remove_staged(run_id)

    def _plan_restore(
        self,
        handle: DockerHandle,
        host: Host,
        staged: restore_verify.Staged,
        choice: restore_plan.Choice,
        lookup: restore_plan.Lookup,
        facts: restore_plan.ArchiveFacts,
    ) -> restore_plan.RestorePlan:
        """The plan against the target's current state (read-only Docker calls)."""
        target = restore_apply.inspect_target(
            handle,
            lookup,
            host_id=host.id,
            host_name=host.name,
            helper_image=self.settings.helper_image,
        )
        return restore_plan.build_plan(staged.manifest, staged.configs, target, choice, facts)

    async def _apply(
        self,
        active: ActiveRun,
        handle: DockerHandle,
        plan: restore_plan.RestorePlan,
        staged: restore_verify.Staged,
        source: RestoreSource,
        scope: str,
        run_log: RunLog,
    ) -> None:
        """Runs the plan on the executor. If it fails, rolls its journal back while the
        locks are still held, then raises. The journal records the scope of the locks, so
        startup recovery takes the same ones."""
        run_id = active.run_id
        opener = functools.partial(
            restore_verify.open_verified,
            LocalStorage(source.root, self.settings),
            staged,
            self._crypto,
            active.cancel,
        )
        env = restore_apply.ApplyEnv(
            handle, self.settings.helper_image, self._hosts.instance_id, run_id
        )
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                self._executor,
                functools.partial(
                    restore_apply.apply,
                    env,
                    plan,
                    staged,
                    opener,
                    cancel=active.cancel,
                    log=run_log,
                    journal=functools.partial(self._set_scoped_journal, run_id, scope),
                ),
            )
        except BaseException:
            if not active.abandoned:
                await self._roll_back(active, handle, plan.host_id, run_log)
            raise

    async def _roll_back(
        self, active: ActiveRun, handle: DockerHandle, host_id: int, run_log: RunLog
    ) -> None:
        doc = await run_blocking(self._journal, active.run_id)
        if not doc or doc.get("rolled_back"):
            return
        await self._roll_back_journal(host_id, active.run_id, doc, handle, run_log, active)

    async def _roll_back_journal(
        self,
        host_id: int,
        run_id: int,
        doc: dict[str, Any],
        handle: DockerHandle,
        run_log: RunLog,
        active: ActiveRun | None = None,
    ) -> bool:
        """Rolls the journal back and stores the result; the caller holds its locks.

        While the rollback cannot reach Docker (rollback_unreachable), it is tried again
        with a new client every ROLLBACK_RETRY seconds, for as long as drydock runs: once
        the locks are released, other runs may change the host and the journal would no
        longer describe it. A rollback that raises, or that cannot undo something for
        another reason, is marked abandoned and never tried again. False when it gave up
        waiting: drydock is shutting down (the journal is left for startup recovery, and
        the active run is abandoned) or the host entry was deleted.
        """
        reported = False
        own: DockerHandle | None = None  # the clients opened here, closed here
        try:
            while True:
                try:
                    doc = await run_blocking(
                        restore_apply.rollback, handle.client.api, doc, run_log
                    )
                except Exception:
                    log.exception("The rollback of run %d failed", run_id)
                    run_log(ROLLBACK_RAISED)
                    doc = {**doc, "abandoned": True}
                else:
                    if doc.get("rollback_incomplete") and not doc.get("rollback_unreachable"):
                        run_log(ROLLBACK_INCOMPLETE)
                        doc = {**doc, "abandoned": True}
                await run_blocking(self._set_journal, run_id, doc)
                if not doc.get("rollback_unreachable"):
                    return True
                if not reported:
                    reported = True
                    log.error("Run %d: the rollback could not reach host %d", run_id, host_id)
                    run_log(ROLLBACK_UNREACHABLE)
                if own is not None:
                    await run_blocking(own.close)
                    own = None
                own = await self._reconnect(host_id, run_id, doc, active)
                if own is None:
                    return False
                handle = own
        finally:
            if own is not None:
                await run_blocking(own.close)

    async def _reconnect(
        self, host_id: int, run_id: int, doc: dict[str, Any], active: ActiveRun | None
    ) -> DockerHandle | None:
        """A new client for a rollback that could not reach Docker, after ROLLBACK_RETRY
        seconds and for as long as it takes. None when drydock shuts down first or the host
        entry is deleted (the journal is then marked abandoned)."""
        while True:
            await asyncio.sleep(ROLLBACK_RETRY)
            if self._closing:
                if active is not None:
                    active.abandoned = True  # the run stays running: the next start rolls back
                return None
            handle, _ = await self._connect_with_retry(host_id)
            if handle is not None:
                return handle
            if await run_blocking(self._load_host, host_id) is None:
                await self._abandon_rollbacks(host_id, [(run_id, doc)])
                return None

    async def _remove_staged(self, run_id: int) -> None:
        try:
            await run_blocking(restore_verify.remove_restore_dir, self.settings.staging_dir, run_id)
        except OSError:
            log.exception("Could not remove the staged data of run %d", run_id)

    def _passphrases(self, archive: str) -> list[str]:
        """The passphrases an archive may be encrypted with: secrets of its run log."""
        try:
            job_uuid = parse_name(archive).job_uuid
        except StorageError:
            raise DispatchError("The archive name is not valid.") from None
        return list(self._crypto.job_passphrases(job_uuid))

    async def _expiry_loop(self) -> None:
        """Cancels restores not confirmed within CONFIRM_TTL and removes their staged
        data, so verified archives do not sit in the staging directory indefinitely."""
        while True:
            await asyncio.sleep(EXPIRY_INTERVAL)
            try:
                expired = await run_blocking(self._expire_now)
                await run_blocking(self._expired, expired)
            except Exception:
                log.exception("Could not expire the restores awaiting confirmation")

    # RECOVERY

    async def _connect_with_retry(self, host_id: int) -> tuple[DockerHandle | None, str]:
        """A client for startup recovery, retried for RECOVERY_WAIT seconds while the host
        (an SSH tunnel) comes up, or until drydock shuts down. None and the last error if it
        never does."""
        deadline = time.monotonic() + RECOVERY_WAIT
        error = "unknown host"
        while True:
            host = await run_blocking(self._load_host, host_id)
            if host is None:
                return None, error
            try:
                url = self._hosts.docker_url(host)
                return await run_blocking(docker_client.open_client, url), error
            except (HostUnavailable, docker_client.DockerUnavailable) as exc:
                error = str(exc)
                if self._closing or time.monotonic() > deadline:
                    return None, error
                await asyncio.sleep(RECOVERY_RETRY)

    async def _rollback_after_crash(
        self, host_id: int, items: list[tuple[int, dict[str, Any]]], keys: list[str]
    ) -> None:
        """Rolls back the journals of interrupted restores, then releases their locks
        (taken by start()).

        The locks stay held until the rollbacks have run: while the host is unreachable it
        is tried again, every ROLLBACK_RETRY seconds after each RECOVERY_WAIT, for as long
        as drydock runs, and so is a rollback that loses the host halfway through. If the
        host entry is deleted meanwhile, the journals are marked abandoned instead.
        """
        try:
            reported = False
            while True:
                handle, error = await self._connect_with_retry(host_id)
                if handle is not None:
                    break
                if await run_blocking(self._load_host, host_id) is None:
                    await self._abandon_rollbacks(host_id, items)
                    return
                if not reported:
                    reported = True
                    log.error("Recovery: cannot reach host %d to roll back: %s", host_id, error)
                    for run_id, _ in items:
                        run_log = RunLog(log_path(self.settings.data_dir, run_id))
                        run_log(
                            f"Recovery could not reach the host to roll back the restore: {error}"
                        )
                        run_log(
                            "Drydock keeps trying while it runs, and holds the restore's "
                            "containers, volumes and networks until the rollback is done."
                        )
                await asyncio.sleep(ROLLBACK_RETRY)
            try:
                # The startup reap first: a crashed run's orphaned helper still mounts the
                # volumes it created, and rollback keeps a volume a container uses.
                await self._hosts.ready(host_id)
                for n, (run_id, doc) in enumerate(items):
                    run_log = RunLog(log_path(self.settings.data_dir, run_id))
                    run_log("Rolling back the interrupted restore.")
                    if not await self._roll_back_journal(host_id, run_id, doc, handle, run_log):
                        if not self._closing:  # the host entry was deleted
                            await self._abandon_rollbacks(host_id, items[n + 1 :])
                        return
            finally:
                await run_blocking(handle.close)
        finally:
            self._release(keys)

    async def _abandon_rollbacks(
        self, host_id: int, items: list[tuple[int, dict[str, Any]]]
    ) -> None:
        """The host entry is gone, so no rollback can run: says so once and marks each
        journal abandoned, so later starts do not try again."""
        log.error("Recovery: host %d no longer exists; its restores are not rolled back", host_id)
        for run_id, doc in items:
            RunLog(log_path(self.settings.data_dir, run_id))(
                "The host no longer exists, so drydock cannot roll back the restore. Remove "
                "what it left on the host by hand."
            )
            await run_blocking(self._set_journal, run_id, {**doc, "abandoned": True})

    async def _recover_after_crash(
        self,
        host_id: int,
        unpauses: list[tuple[int, dict[str, Any]]],
        restarts: list[tuple[int, dict[str, Any]]],
        keys: list[str],
    ) -> None:
        """Unpauses and starts the containers, then releases their locks (taken by
        start())."""
        try:
            await self._undo(host_id, unpauses, restarts)
        finally:
            self._release(keys)

    async def _undo(
        self,
        host_id: int,
        unpauses: list[tuple[int, dict[str, Any]]],
        restarts: list[tuple[int, dict[str, Any]]],
        active: ActiveRun | None = None,
    ) -> None:
        """Unpauses, then starts, what runs left paused or stopped on the host; the caller
        holds their locks. Every unpause first, then every start, each run's entries in
        their (forward) order. A run's lists keep exactly the entries that are left.

        While the host is unreachable (no client, or a pass failed and Docker stopped
        answering), what is left is tried again with a new client every ROLLBACK_RETRY
        seconds after each RECOVERY_WAIT, for as long as drydock runs, as a rollback is:
        once the locks are released another run may change those containers. What Docker
        refused while it answered, or everything once the host entry is deleted, is marked
        abandoned (_mark_left) and left to the user. If drydock shuts down first the
        entries stay as they are, and the active run (a backup's own retry) is abandoned:
        it stays open, so the next start tries again.
        """
        reported = False
        while True:
            handle, error = await self._connect_with_retry(host_id)
            if handle is not None:
                try:
                    api = handle.client.api
                    unpauses, restarts, raised = await self._undo_pass(api, unpauses, restarts)
                    if not unpauses and not restarts:
                        return
                    down = None if raised else await run_blocking(unreachable, api)
                finally:
                    await run_blocking(handle.close)
                if down is None:
                    await run_blocking(self._mark_left, unpauses, restarts)
                    return
                error = down
            elif await run_blocking(self._load_host, host_id) is None:
                self._unreached(unpauses, restarts, error)
                log.error("Recovery: host %d no longer exists: %s", host_id, error)
                await run_blocking(self._mark_left, unpauses, restarts)
                return
            if self._closing:
                if active is not None:
                    active.abandoned = True
                    note(
                        RunLog(log_path(self.settings.data_dir, active.run_id)),
                        "Drydock is shutting down; startup recovery unpauses and starts the "
                        "rest again.",
                    )
                return
            if not reported:
                reported = True
                log.error("Recovery: cannot reach host %d: %s", host_id, error)
                self._unreached(unpauses, restarts, error)
                for run_id in by_run(unpauses + restarts):
                    note(
                        RunLog(log_path(self.settings.data_dir, run_id)),
                        "Drydock keeps trying while it runs, and holds those containers until "
                        "they are unpaused and started again.",
                    )
            await asyncio.sleep(ROLLBACK_RETRY)

    async def _undo_pass(
        self,
        api: Any,
        unpauses: list[tuple[int, dict[str, Any]]],
        restarts: list[tuple[int, dict[str, Any]]],
    ) -> tuple[list[tuple[int, dict[str, Any]]], list[tuple[int, dict[str, Any]]], bool]:
        """One try at every entry: the entries left, and whether a pass raised. An
        unexpected error in one pass neither skips the other nor clears its run's list."""
        raised = False
        left_unpauses: list[tuple[int, dict[str, Any]]] = []
        for run_id, entries in by_run(unpauses).items():
            run_log = RunLog(log_path(self.settings.data_dir, run_id))
            targets = [Target(e["id"], e["name"], True, paused=True) for e in entries]
            try:
                failed = await run_blocking(unpause, api, targets, run_log)
            except Exception:
                log.exception("Run %d: unpausing its containers failed", run_id)
                raised, failed = True, [e["name"] for e in entries]
            left = [e for e in entries if e["name"] in failed]
            await run_blocking(self._set_paused, run_id, left)
            left_unpauses += [(run_id, e) for e in left]
        left_restarts: list[tuple[int, dict[str, Any]]] = []
        for run_id, entries in by_run(restarts).items():
            run_log = RunLog(log_path(self.settings.data_dir, run_id))
            targets = [
                Target(e["id"], e["name"], True, wait_for=entry_wait_for(e)) for e in entries
            ]
            # A health wait ends when shutdown begins, so the rest still start before
            # drydock exits. Three arguments when nothing waits: restart is looked up
            # now, and tests patch it with a three-argument fake.
            extra = (self._stopping,) if any(t.wait_for for t in targets) else ()
            try:
                failed = await run_blocking(restart, api, targets, run_log, *extra)
            except Exception:
                log.exception("Run %d: starting its containers failed", run_id)
                raised, failed = True, [e["name"] for e in entries]
            left = [e for e in entries if e["name"] in failed]
            await run_blocking(self._set_stopped, run_id, left)
            left_restarts += [(run_id, e) for e in left]
        return left_unpauses, left_restarts, raised

    def _unreached(
        self,
        unpauses: list[tuple[int, dict[str, Any]]],
        restarts: list[tuple[int, dict[str, Any]]],
        error: str,
    ) -> None:
        for run_id, entry in unpauses:
            note(
                RunLog(log_path(self.settings.data_dir, run_id)),
                f"Recovery could not reach the host to unpause {entry['name']}: {error}",
            )
        for run_id, entry in restarts:
            note(
                RunLog(log_path(self.settings.data_dir, run_id)),
                f"Recovery could not reach the host to start {entry['name']}: {error}",
            )

    def _mark_left(
        self,
        unpauses: list[tuple[int, dict[str, Any]]],
        restarts: list[tuple[int, dict[str, Any]]],
    ) -> None:
        """Marks what is left abandoned: drydock gave up on it, so no later start tries
        again (the locks are released, and the user was told to put it right)."""
        for run_id, entries in by_run(unpauses).items():
            self._set_paused(run_id, [{**e, "abandoned": True} for e in entries])
        for run_id, entries in by_run(restarts).items():
            self._set_stopped(run_id, [{**e, "abandoned": True} for e in entries])

    def _abandon(self, run_id: int) -> None:
        """Shutdown fallback for a run whose worker did not stop in time. Takes no locks: the
        stuck run still holds them, and no new run starts while drydock shuts down.

        A backup's paused and stopped containers are unpaused and started from the run row,
        without waiting for health. The run stays open and its lists stay as they are: the
        stuck worker may still be inside a stop or pause call that completes after this, so
        the next startup marks the run interrupted and does both again."""
        run_log = RunLog(log_path(self.settings.data_dir, run_id))
        with self._sessions() as db:
            run = db.get(Run, run_id)
            stopped = run_entries(run.stopped_containers_json) if run else []
            paused = run_entries(run.paused_containers_json) if run else []
            doc = (
                json_object(run.restore_originals_json)
                if run is not None and run.kind == "restore"
                else {}
            )
        if doc and not doc.get("rolled_back"):
            # Apply may still be changing the host, so rolling back now could race it. The
            # run stays running; the next startup marks it interrupted and rolls it back.
            run_log(
                "Drydock stopped before the rollback finished; startup recovery will roll it back."
            )
            log.warning("Run %d: leaving the rollback to startup recovery", run_id)
            return
        if run is None or run.kind == "restore":
            if run is not None:
                self._finish(run_id, run_log, "cancelled", "Drydock is shutting down.")
            return
        to_unpause: dict[int, list[Target]] = {}
        to_start: dict[int, list[Target]] = {}
        for entry in paused:
            to_unpause.setdefault(entry["host_id"], []).append(
                Target(entry["id"], entry["name"], True, paused=True)
            )
        for entry in stopped:
            to_start.setdefault(entry["host_id"], []).append(
                Target(entry["id"], entry["name"], True)
            )
        for host_id in dict.fromkeys([*to_unpause, *to_start]):
            host = self._load_host(host_id)
            try:
                if host is None:
                    raise HostUnavailable("The host no longer exists.")
                with docker_client.open_client(self._hosts.docker_url(host)) as handle:
                    unpause(handle.client.api, to_unpause.get(host_id, []), run_log)
                    restart(handle.client.api, to_start.get(host_id, []), run_log)
            except SAFE_ERRORS as exc:
                run_log(f"Could not unpause or start the containers: {exc}")
        run_log(
            "Drydock stopped while the run was still working; startup recovery checks its "
            "containers again."
        )
        log.warning("Run %d: leaving the run open for startup recovery", run_id)

    # DATABASE

    def _create_run(self, job_id: int, triggered_by: str | None, fired: bool = False) -> int:
        with self._sessions() as db, db.begin():
            job = db.get(Job, job_id)
            if job is None:
                raise DispatchError("The job does not exist.")
            if not job.enabled:
                raise DispatchError("The job is disabled.")
            run = Run(job_id=job.id, kind="backup", status="queued", triggered_by=triggered_by)
            if fired:
                job.last_fired_at = utcnow()
            db.add(run)
            db.flush()
            return run.id

    def _load_plan(self, run_id: int, job_id: int) -> RunPlan:
        with self._sessions() as db:
            job = db.get(Job, job_id)
            if job is None:
                raise DispatchError("The job no longer exists.")
            host = db.get(Host, job.host_id)
            target = db.get(StorageTarget, job.storage_target_id)
            if host is None or target is None:
                raise DispatchError("The job's host or storage no longer exists.")
            if not target.enabled:
                raise DispatchError(f"Storage {target.name} is disabled.")
            root, config = "", None
            if target.kind == "local":
                root = self._storage_root(target)
            elif target.kind in REMOTE_KINDS:
                config = self._remote_config(target)
            else:
                raise StorageError(f"Transfers to {target.kind} storage arrive in a later release.")
            pre_ids, post_ids, pre_hooks, post_hooks = self._hook_rows(db, job)
            stack = job.target_type == "stack"
            project = job.target if stack else None
            db.expunge(host)
            return RunPlan(
                run_id=run_id,
                job_id=job.id,
                job=capture.CaptureJob(
                    uuid=job.uuid,
                    name=job.name,
                    scope=job.scope,  # type: ignore[arg-type]
                    consistency_mode=job.consistency_mode,
                    images_reference_only_if_pullable=job.images_reference_only_if_pullable,
                    encrypted=job.encrypted,
                    target_type=job.target_type,
                    project=project,
                ),
                host=host,
                storage_target_id=target.id,
                storage_root=root,
                targets=() if stack else tuple(job_targets(job)),
                target_type=job.target_type,
                target=job.target,
                project=project,
                pre_hook_ids=pre_ids,
                post_hook_ids=post_ids,
                pre_hooks=pre_hooks,
                post_hooks=post_hooks,
                storage_kind=target.kind,
                storage_config=config,
            )

    def _check_storage(self, plan: RunPlan) -> None:
        """Before the archive is stored: while the run waited and captured, its storage may
        have been disabled or pointed elsewhere. Raises DispatchError."""
        with self._sessions() as db:
            target = db.get(StorageTarget, plan.storage_target_id)
            if target is None:
                raise DispatchError("The job's storage no longer exists.")
            if not target.enabled:
                raise DispatchError(f"Storage {target.name} was disabled while this run worked.")
            if plan.storage_config is None:
                same = self._storage_root(target) == plan.storage_root
            else:
                same = self._remote_config(target) == plan.storage_config
            if not same:
                raise DispatchError(
                    "The storage settings changed while this run worked. Start it again."
                )

    def _remote_config(self, target: StorageTarget) -> dict[str, Any]:
        try:
            config = json.loads(self._crypto.decrypt(target.config_enc))
        except CryptoError:
            raise DispatchError(UNDECRYPTABLE_STORAGE) from None
        except ValueError:
            config = None
        if not isinstance(config, dict):
            raise DispatchError("The storage settings are not valid. Edit the storage again.")
        return config

    def _backend(self, plan: RunPlan) -> LocalStorage | RcloneBackend:
        if plan.storage_config is None:
            return LocalStorage(plan.storage_root, self.settings)
        if self._rclone is None:
            raise StorageError("Remote storage is not available in this drydock process.")
        return RcloneBackend(
            self._rclone, plan.storage_kind, plan.storage_config, self.settings.staging_dir
        )

    def _hook_rows(
        self, db: Session, job: Job
    ) -> tuple[tuple[int, ...], tuple[int, ...], tuple[hooks.Hook, ...], tuple[hooks.Hook, ...]]:
        """The job's pre- and post-hook IDs and the hooks they name, in run order. Raises
        DispatchError for an invalid list or a hook that no longer exists, and HookError for
        a hook row that is not valid."""
        pre_ids, post_ids = hook_ids(job.pre_hooks), hook_ids(job.post_hooks)
        wanted = set(pre_ids) | set(post_ids)
        rows = (
            {row.id: row for row in db.scalars(select(HookRow).where(HookRow.id.in_(wanted)))}
            if wanted
            else {}
        )
        for hook_id in (*pre_ids, *post_ids):
            if hook_id not in rows:
                raise DispatchError(
                    f"Hook {hook_id} of this job no longer exists. Edit the job again."
                )
        built = {hook_id: hooks.Hook.from_row(rows[hook_id]) for hook_id in sorted(wanted)}
        return (
            pre_ids,
            post_ids,
            tuple(built[hook_id] for hook_id in pre_ids),
            tuple(built[hook_id] for hook_id in post_ids),
        )

    def _post_hook_names(self, db: Session, job_id: int | None) -> list[str]:
        """The names of the job's post-hooks, for recovery's notice that they did not run.
        Empty when the job, its list or its hooks are gone."""
        job = db.get(Job, job_id) if job_id is not None else None
        if job is None:
            return []
        try:
            ids = hook_ids(job.post_hooks)
        except DispatchError:
            return []
        if not ids:
            return []
        names = dict(db.execute(select(HookRow.id, HookRow.name).where(HookRow.id.in_(ids))).all())
        return [names[hook_id] for hook_id in ids if hook_id in names]

    def _root(self, target: StorageTarget) -> str:
        """A local target's directory. Restores read only these until remote ones download
        first."""
        if target.kind != "local":
            raise StorageError(REMOTE_RESTORE_LATER)
        return str(json.loads(self._crypto.decrypt(target.config_enc))["path"])

    def _storage_root(self, target: StorageTarget) -> str:
        try:
            return self._root(target)
        except CryptoError:
            raise DispatchError(UNDECRYPTABLE_STORAGE) from None

    def _create_restore_run(
        self, storage_target_id: int, archive: str, triggered_by: str | None
    ) -> tuple[int | None, list[int]]:
        """The new restore run's ID (None when too many restores are pending), and the IDs
        of the restores that expired meanwhile."""
        try:
            check_name(archive)
        except StorageError:
            raise DispatchError("The archive name is not valid.") from None
        with self._sessions() as db, db.begin():
            target = db.get(StorageTarget, storage_target_id)
            if target is None:
                raise DispatchError("The storage does not exist.")
            if target.kind != "local":  # see _delete_archive before lifting this
                raise DispatchError(REMOTE_RESTORE_LATER)
            expired = self._expire_stale(db)
            pending = db.scalar(
                select(func.count())
                .select_from(Run)
                .where(
                    Run.kind == "restore",
                    Run.status.in_(("verifying", "awaiting_confirmation")),
                )
            )
            if pending >= MAX_AWAITING:
                return None, expired
            source = {"storage_target_id": storage_target_id, "archive": archive}
            run = Run(
                job_id=None,
                kind="restore",
                status="verifying",
                triggered_by=triggered_by,
                archive_name=archive,
                plan=json.dumps({"source": source}),
            )
            db.add(run)
            db.flush()
            return run.id, expired

    def _expire_stale(self, db: Session) -> list[int]:
        """Cancels the restores awaiting confirmation for longer than CONFIRM_TTL, in the
        caller's transaction. Returns their IDs; see _expired."""
        cutoff = utcnow() - CONFIRM_TTL
        runs = db.scalars(
            select(Run).where(
                Run.kind == "restore",
                Run.status == "awaiting_confirmation",
                Run.created_at < cutoff,
            )
        ).all()
        for run in runs:
            run.status = "cancelled"
            run.error = NOT_CONFIRMED
            run.finished_at = utcnow()
        return [run.id for run in runs]

    def _expire_now(self) -> list[int]:
        with self._sessions() as db, db.begin():
            return self._expire_stale(db)

    def _expired(self, run_ids: list[int]) -> None:
        """After _expire_stale committed: the final log line, and the staged data removed."""
        for run_id in run_ids:
            log.info("Restore run %d was not confirmed in time", run_id)
            try:
                RunLog(log_path(self.settings.data_dir, run_id))(f"Run cancelled: {NOT_CONFIRMED}")
                restore_verify.remove_restore_dir(self.settings.staging_dir, run_id)
            except OSError:
                log.exception("Could not clean up expired restore run %d", run_id)

    def _load_restore(self, run_id: int) -> RestoreSource:
        with self._sessions() as db:
            run = db.get(Run, run_id)
            if run is None or run.kind != "restore":
                raise DispatchError("The restore no longer exists.")
            doc = json_object(run.plan)
            source = doc.get("source")
            source = source if isinstance(source, dict) else {}
            target_id, archive = source.get("storage_target_id"), source.get("archive")
            if type(target_id) is not int or not isinstance(archive, str):
                raise DispatchError("The restore names no archive.")
            target = db.get(StorageTarget, target_id)
            if target is None:
                raise DispatchError("The storage no longer exists.")
            return RestoreSource(target_id, archive, self._storage_root(target), doc)

    def _verified(
        self, run_id: int, verification: restore_verify.Verification, run_log: RunLog
    ) -> None:
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is None or run.status != "verifying":
                raise DispatchError("The restore was stopped while it was verified.")
            doc = json_object(run.plan)
            doc.update(signed=verification.signed, encrypted=verification.encrypted)
            run.plan = json.dumps(doc)
            run.size = verification.identity.size
            run.status = "awaiting_confirmation"
            # Before the commit: once the status changes, the log page stops polling.
            run_log("Verified. Choose how to restore it on the restore page.")

    def _confirm_restore(
        self, run_id: int, choice: restore_plan.Choice, seen: dict[str, Any] | None
    ) -> None:
        """Moves a planned restore awaiting confirmation to queued, exactly once. Compared
        in the same transaction, so a plan stored after the user saw it cannot slip in."""
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            doc = json_object(run.plan) if run is not None else {}
            if (
                run is None
                or run.kind != "restore"
                or run.status != "awaiting_confirmation"
                or not isinstance(doc.get("summary"), dict)
            ):
                raise DispatchError("This restore is not awaiting confirmation.")
            stored = {"choice": doc.get("choice"), "summary": doc.get("summary")}
            if seen is not None and stored != seen:
                raise DispatchError("The plan changed since you viewed it. Review it again.")
            doc["choice"] = choice.to_dict()
            run.plan = json.dumps(doc)
            run.status = "queued"

    def _discard(self, run_id: int) -> bool:
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is None or run.kind != "restore" or run.status != "awaiting_confirmation":
                return False
            run.status = "cancelled"
            run.error = "Discarded."
            run.finished_at = utcnow()
            RunLog(log_path(self.settings.data_dir, run_id))("Run cancelled: Discarded.")
            return True

    def _journal(self, run_id: int) -> dict[str, Any]:
        with self._sessions() as db:
            run = db.get(Run, run_id)
            return json_object(run.restore_originals_json if run is not None else None)

    def _set_journal(self, run_id: int, doc: dict[str, Any]) -> None:
        """Persists the restore journal in its own transaction. Safe from worker threads."""
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is not None:
                run.restore_originals_json = json.dumps(doc)

    def _set_scoped_journal(self, run_id: int, scope: str, doc: dict[str, Any]) -> None:
        """apply's journal, with the scope of the name keys the run holds."""
        self._set_journal(run_id, {**doc, "lock_scope": scope})

    def _load_host(self, host_id: int) -> Host | None:
        with self._sessions() as db:
            host = db.get(Host, host_id)
            if host is not None:
                db.expunge(host)
            return host

    def _mark_running(self, run_id: int) -> None:
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is not None:
                run.status = "running"
                run.started_at = utcnow()

    def _lists(self, run_id: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """The run's paused and stopped lists."""
        with self._sessions() as db:
            run = db.get(Run, run_id)
            if run is None:
                return [], []
            return run_entries(run.paused_containers_json), run_entries(run.stopped_containers_json)

    def _set_stopped(self, run_id: int, entries: list[dict[str, Any]]) -> None:
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is not None:
                run.stopped_containers_json = json.dumps(entries)

    def _set_paused(self, run_id: int, entries: list[dict[str, Any]]) -> None:
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is not None:
                run.paused_containers_json = json.dumps(entries)

    def _record_backup(
        self, plan: RunPlan, name: str, size: int, sha256: str, encrypted: bool
    ) -> None:
        with self._sessions() as db, db.begin():
            db.add(
                Backup(
                    job_id=plan.job_id,
                    storage_target_id=plan.storage_target_id,
                    name=name,
                    size=size,
                    sha256=sha256,
                    signed=True,
                    encrypted=encrypted,
                )
            )
            run = db.get(Run, plan.run_id)
            if run is not None:
                run.archive_name, run.size, run.sha256 = name, size, sha256

    def _retention_zone(self, name: str | None) -> zoneinfo.ZoneInfo:
        """The job's time zone (else TZ) for GFS days. Raises PolicyError for a name that is
        not a listed zone (edited by hand), never naming a path."""
        name = name or self.settings.tz
        if name not in zoneinfo.available_timezones():
            raise retention.PolicyError("The job's time zone is not known.")
        return zoneinfo.ZoneInfo(name)

    def _delete_archive(
        self, plan: RunPlan, storage: StorageBackend, name: str, run_log: RunLog
    ) -> None:
        """Deletes one archive for retention, with its catalog row, audited.

        Local storage: one transaction. The write lock (BEGIN IMMEDIATE) orders it with
        _create_restore_run, so a restore of name is either seen here or created once name
        is gone. The row and the audit event roll back if the archive cannot be deleted;
        an archive already gone still loses its row.

        Remote storage: the network delete holds no transaction, so it never holds the
        write lock that every request needs. Nothing orders it with a restore, which is
        safe only while restores from remote storage are refused (_create_restore_run)."""
        if not isinstance(storage, LocalStorage):
            with self._sessions() as db:
                busy = restore_uses(db, name)
            if not busy:
                delete_or_gone(storage, name)
                with self._sessions() as db, db.begin():
                    self._forget_archive(db, plan, name)
        else:
            with self._sessions() as db, db.begin():
                busy = restore_uses(db, name)
                if not busy:
                    self._forget_archive(db, plan, name)
                    delete_or_gone(storage, name)
        if busy:
            run_log(f"Retention: kept {name}, an open restore uses it.")
        else:
            run_log(f"Retention: deleted {name}.")

    def _forget_archive(self, db: Session, plan: RunPlan, name: str) -> None:
        db.execute(
            delete(Backup).where(
                Backup.storage_target_id == plan.storage_target_id, Backup.name == name
            )
        )
        audit.record(
            db,
            actor=None,
            action="backup.retention_delete",
            target=f"job:{plan.job_id}",
            details={
                "run_id": plan.run_id,
                "storage_target_id": plan.storage_target_id,
                "archive": name,
            },
        )

    def _finish(self, run_id: int, run_log: RunLog, status: str, error: str | None) -> None:
        with self._sessions() as db, db.begin():
            run = db.get(Run, run_id)
            if run is None or run.status not in OPEN_STATUSES:
                return
            run.status = status
            run.error = error
            run.finished_at = utcnow()
            backup = run.kind == "backup"  # restores have no job to notify for
            # Before the commit: once the status changes, the log page stops polling.
            run_log(f"Run {status}." if error is None else f"Run {status}: {error}")
        if backup:
            self._ended_notice(run_id)

    def _ended_notice(self, run_id: int) -> None:
        """After a run's end is committed: queues its notifications. Never raises."""
        if self._on_end is None:
            return
        try:
            self._on_end(run_id)
        except Exception:
            log.exception("Could not queue the notifications of run %d", run_id)

    async def _finish_quietly(
        self, run_id: int, run_log: RunLog, status: str, error: str | None
    ) -> None:
        try:
            await run_blocking(self._finish, run_id, run_log, status, error)
        except Exception:
            log.exception("Could not record the end of run %d", run_id)


# HELPERS


def by_run(items: list[tuple[int, dict[str, Any]]]) -> dict[int, list[dict[str, Any]]]:
    """Recovery items grouped by run, each run's entries in their order."""
    grouped: dict[int, list[dict[str, Any]]] = {}
    for run_id, entry in items:
        grouped.setdefault(run_id, []).append(entry)
    return grouped


def leftover_problems(stopped: list[str], paused: list[str], *, stored: bool) -> list[str]:
    """What a backup's error says about the containers drydock could not start or unpause
    again."""
    lead = "The backup was stored, but drydock" if stored else "Drydock"
    problems = []
    if stopped:
        them = "it" if len(stopped) == 1 else "them"
        problems.append(f"{lead} could not start {', '.join(stopped)} again. Start {them} by hand.")
    if paused:
        them = "it" if len(paused) == 1 else "them"
        problems.append(f"{lead} could not unpause {', '.join(paused)}. Unpause {them} by hand.")
    return problems


def unreachable(api) -> str | None:
    """Why Docker does not answer (a ping), or None if it does."""
    try:
        api.ping()
    except (docker.errors.DockerException, requests.RequestException) as exc:
        return str(exc) or type(exc).__name__
    return None


def namespace_refs(info: dict[str, Any]) -> tuple[str, ...]:
    """The containers whose network, IPC or PID namespace this one joins: container:<ref>
    modes (Compose writes service:<name> as container:<id>)."""
    host = info.get("HostConfig")
    host = host if isinstance(host, dict) else {}
    refs = []
    for key in stacks.CONTAINER_MODE_KEYS:
        mode = host.get(key)
        if isinstance(mode, str) and mode.startswith("container:"):
            refs.append(mode.removeprefix("container:"))
    return tuple(dict.fromkeys(refs))


def names_target(ref: str, target: Target) -> bool:
    """Whether a container: ref names this target: its name, its ID or an ID prefix."""
    return ref in (target.id, target.name) or (
        CONTAINER_ID_RE.fullmatch(ref) is not None and target.id.startswith(ref)
    )


def check_namespaces(api, targets: Sequence[Target], to_stop: Sequence[Target]) -> None:
    """Stop mode, before anything changes: refuses a run that Docker could not undo, or that
    would cut off a container it leaves running. Raises CaptureError.

    Docker starts a container in another one's namespace (container:<ref>) only while that
    one runs, so a target whose provider is not running would not start again. And a
    container that stays running in the namespace of a target drydock stops keeps the old
    namespace when the target starts again, with nothing but loopback left in it.
    Providers that the run stops too are fine: they start first (stacks.order)."""
    stopping = {t.id for t in to_stop}
    for target in to_stop:
        for ref in target.providers:
            if any(names_target(ref, other) for other in to_stop):
                continue
            try:
                info = api.inspect_container(ref)
            except docker.errors.NotFound:
                info = None
            if isinstance(info, dict) and (info.get("State") or {}).get("Running"):
                continue
            if isinstance(info, dict):
                name = str(info.get("Name", ref)).lstrip("/")
            else:
                name = ref[:12] if CONTAINER_ID_RE.fullmatch(ref) else ref
            raise capture.CaptureError(
                f"Container {target.name} shares the namespaces of container {name}, which is "
                f"not running, so drydock could not start {target.name} again after stopping "
                f"it. Start {name} first, or use pause mode."
            )
    known = {t.id: t for t in targets}
    for summary in api.containers():  # running and paused ones
        cid = summary.get("Id") if isinstance(summary, dict) else None
        if not isinstance(cid, str) or cid in stopping:
            continue
        if cid in known:
            name, refs = known[cid].name, known[cid].providers
        else:
            try:
                info = api.inspect_container(cid)
            except docker.errors.NotFound:
                continue  # removed meanwhile
            name, refs = str(info.get("Name", cid[:12])).lstrip("/"), namespace_refs(info)
        for ref in refs:
            target = next((t for t in to_stop if names_target(ref, t)), None)
            if target is not None:
                raise capture.CaptureError(
                    f"Container {name} shares the namespaces of {target.name} but this run "
                    f"does not stop it, so stopping {target.name} would cut {name} off until "
                    "it is restarted. Back them up in one stack job, or use pause mode."
                )


def restart(
    api, targets: list[Target], run_log: RunLog, cancel: threading.Event | None = None
) -> list[str]:
    """Starts each container again, in order. Never raises; returns the names that failed.

    Before a container whose wait_for is set, its dependencies get until HEALTH_WAIT after
    the call began to report healthy; then it starts anyway. Once cancel is set, the rest
    start without waiting.

    Recovery and shutdown logs start without the container's secrets, and Docker's error
    text is not trusted to leave them out, so they are looked up first.
    """
    failed = []
    say = functools.partial(note, run_log)
    deadline = time.monotonic() + stacks.HEALTH_WAIT
    for target in targets:
        if target.wait_for and not (cancel is not None and cancel.is_set()):
            stacks.wait_healthy(api, target.wait_for, deadline, cancel, say)
        with contextlib.suppress(docker.errors.DockerException, requests.RequestException):
            info = api.inspect_container(target.id)
            run_log.add_secrets(env_values((info.get("Config") or {}).get("Env")))
        try:
            api.start(target.id)
        except (docker.errors.DockerException, requests.RequestException) as exc:
            detail = run_log.redact(str(exc))
            say(f"Could not start container {target.name} again: {detail}")
            log.error("Could not restart container %s: %s", target.name, detail)
            failed.append(target.name)
        else:
            say(f"Started container {target.name} again.")
    return failed


def unpause(api, targets: list[Target], run_log: RunLog) -> list[str]:
    """Unpauses each container, in order. Never raises; returns the names that failed. A
    container that is gone or no longer paused is not a failure. Secrets are looked up
    first, as in restart."""
    failed = []
    say = functools.partial(note, run_log)
    for target in targets:
        try:
            info = api.inspect_container(target.id)
        except docker.errors.NotFound:
            say(f"Container {target.name} no longer exists.")
            continue
        except docker.errors.DockerException, requests.RequestException:
            info = None  # try the unpause anyway; its error is logged
        if isinstance(info, dict):
            run_log.add_secrets(env_values((info.get("Config") or {}).get("Env")))
            if not (info.get("State") or {}).get("Paused"):
                say(f"Container {target.name} is not paused any more.")
                continue
        try:
            api.unpause(target.id)
        except (docker.errors.DockerException, requests.RequestException) as exc:
            # Unpaused or removed meanwhile: Docker answers 500 "is not paused" (not 409)
            # or 404, so the container is looked at again rather than the status code.
            now = paused_now(api, target.id)
            if now is None:
                say(f"Container {target.name} no longer exists.")
            elif not now:
                say(f"Container {target.name} is not paused any more.")
            else:
                detail = run_log.redact(str(exc))
                say(f"Could not unpause container {target.name}: {detail}")
                log.error("Could not unpause container %s: %s", target.name, detail)
                failed.append(target.name)
        else:
            say(f"Unpaused container {target.name}.")
    return failed


def paused_now(api, container_id: str) -> bool | None:
    """Whether the container is paused: None if it no longer exists, True if its state
    cannot be read (an unpause that failed then counts as failed)."""
    try:
        info = api.inspect_container(container_id)
    except docker.errors.NotFound:
        return None
    except docker.errors.DockerException, requests.RequestException:
        return True
    state = info.get("State") if isinstance(info, dict) else None
    return bool(state.get("Paused")) if isinstance(state, dict) else True


def note(run_log: RunLog, message: str) -> None:
    """Writes a run log line in a loop that undoes stops and pauses. A log that cannot be
    written (a full disk) goes to the server log instead, so the loop still reaches every
    container."""
    try:
        run_log(message)
    except OSError as exc:
        log.error(
            "Could not write to %s: %s. The line: %s", run_log.path, exc, run_log.redact(message)
        )


def restore_uses(db: Session, name: str) -> bool:
    """Whether an open restore names the archive."""
    return bool(
        db.scalar(
            select(func.count())
            .select_from(Run)
            .where(
                Run.kind == "restore",
                Run.status.in_(OPEN_STATUSES),
                Run.archive_name == name,
            )
        )
    )


def delete_or_gone(storage: StorageBackend, name: str) -> None:
    """Deletes the archive; one that is already gone counts as deleted."""
    try:
        storage.delete(name)
    except StorageError:
        if any(o.name == name for o in storage.list(name)):
            raise


def clean_staging(
    staging: Path, *, scratch: bool = True, keep: Callable[[int], bool] = lambda run_id: False
) -> None:
    """Removes drydock's own scratch files (unless not scratch), its trash files, and the
    staged restore directories of the runs keep does not claim, from the staging
    directory, and nothing else. A name it cannot remove is logged and skipped."""
    if not staging.is_dir() or staging.is_symlink():
        return
    with os.scandir(staging) as entries:
        for entry in entries:
            scratch_name = STAGING_NAME_RE.fullmatch(entry.name) or CHECK_RE.fullmatch(entry.name)
            if scratch_name and entry.is_file(follow_symlinks=False):
                if scratch:
                    remove_file(Path(entry.path))
            elif TRASH_RE.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                remove_file(Path(entry.path))
            elif (
                restore_verify.RESTORE_DIR_RE.fullmatch(entry.name)
                and entry.is_dir(follow_symlinks=False)
                and not keep(int(entry.name.removeprefix("restore-")))
            ):
                shutil.rmtree(entry.path, ignore_errors=True)


def trash_scratch(staging: Path) -> None:
    """Renames drydock's scratch files to trash names, for clean_staging to delete."""
    if not staging.is_dir() or staging.is_symlink():
        return
    with os.scandir(staging) as entries:
        for entry in entries:
            if STAGING_NAME_RE.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                try:
                    Path(entry.path).rename(staging / f"trash-{uuid.uuid4().hex}")
                except OSError as exc:
                    log.warning("Could not clear %s: %s", entry.path, exc.strerror)


def remove_file(path: Path) -> None:
    """Deletes a file; one that cannot be deleted is logged, never raised."""
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("Could not delete %s: %s", path, exc.strerror)


def kept_run(row: Any) -> bool:
    """A finished run that pruning keeps: one startup recovery may still act on (containers
    to start or unpause again, or an interrupted restore whose journal it rolls back or
    finishes, as recover() does), or whose page lists something to put right by hand."""
    if run_entries(row.stopped_containers_json) or run_entries(row.paused_containers_json):
        return True
    journal = json_object(row.restore_originals_json)
    if row.status == "interrupted" and needs_rollback(journal) and journal_host(journal):
        return True
    return any(journal.get(key) for key in (*HAND_FIX_KEYS, "compose_problem"))
