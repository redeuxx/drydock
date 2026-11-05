"""Backup jobs: list and view (every role), run now (operator), edit (admin), and reveal the
passphrase of a job's encrypted archives (superadmin, recent auth, audited).

A job backs up one container or one Compose project (a stack) in one consistency mode, and
runs hooks before and after its data read: the form takes hook names, one per line, and the
job stores their IDs in run order. Admins only attach existing hooks (the library is edited
by superadmins, routes/hooks.py), and every save checks each attached hook against the
job's host and target (hooks.check_binding), so a job never moves away from where a
superadmin bound its hooks. Viewers see hook names only.

The passphrase is derived from the secret key and the job's UUID and never stored. Only
the POST below ever puts it in a response; no GET does.
"""

import functools
import json
import re
import uuid
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from typing import Annotated, Any

import anyio.from_thread
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.config import known_zones
from drydock.db import get_db
from drydock.engine import stacks
from drydock.feed import WORST  # a sequence's row shows its first run found in this order
from drydock.hosts import inventory
from drydock.jobs import mounts, retention, scheduler
from drydock.jobs import targets as job_targets
from drydock.jobs.dispatcher import Dispatcher, DispatchError, binds
from drydock.jobs.hooks import MAX_HOOKS_PER_PHASE, HookError, check_binding
from drydock.models import (
    CONSISTENCY_MODES,
    SCOPES,
    TARGET_TYPES,
    Hook,
    Host,
    Job,
    JobNotification,
    JobTarget,
    NotificationTarget,
    Run,
    StorageTarget,
    UpdatePolicy,
    utcnow,
)
from drydock.routes.auth import FormStr, client_ip
from drydock.routes.hosts import DOCKER_ERRORS, INVENTORY_TIMEOUT, manager, open_host, release
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.storage.rclone import KINDS as REMOTE_KINDS
from drydock.templating import render, see_other

router = APIRouter(prefix="/jobs")
EDIT = "jobs/edit.html"  # the job's edit page; job_page renders detail.html otherwise

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Operator = Annotated[Auth, Depends(require_role(Role.operator))]
Admin = Annotated[Auth, Depends(require_role(Role.admin))]
Superadmin = Annotated[Auth, Depends(require_role(Role.superadmin))]

# Free text: archive names use a slug of it, never the name itself.
JOB_NAME_RE = re.compile(r"[^\x00-\x1f\x7f]{1,64}")
CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
BACKUP_KINDS = ("local", *sorted(REMOTE_KINDS))  # storage kinds a job may back up to
RECENT_RUNS = 20
SCOPE_LABELS = {
    "config": "Configuration (inspect data, compose files and .env)",
    "data": "Data (volumes and bind mounts)",
    "image": "Images",
    "all": "Everything",
}
TARGET_LABELS = {"container": "One container", "stack": "A Compose project (stack)"}
MODE_LABELS = {
    "stop": "Stop: stop the containers while their data is read, then start them again",
    "pause": (
        "Pause: freeze the containers while their data is read; they keep running and their"
        " uptime is unchanged"
    ),
    "live": "Live: read the data while the containers run (crash-consistent at best)",
}
LIVE_WARNING = (
    "Live mode reads files while the containers write them, so the backup is"
    " crash-consistent at best. Databases may not restore cleanly; prefer stop or pause, or a"
    " pre-hook that dumps the database to a file."
)
PROJECT_ERROR = (
    "Enter the Compose project name: 1 to 63 lowercase letters, digits, '_' or '-', as docker"
    " compose ls shows it."
)
TOO_MANY_HOOKS = (
    f"A job can run at most {MAX_HOOKS_PER_PHASE} hooks before and {MAX_HOOKS_PER_PHASE} after."
)
PHASES = (("pre_hooks", "before"), ("post_hooks", "after"))
RETENTION_LABELS = {
    "last": "Keep the newest backups",
    "age": "Keep backups for a number of days",
    "gfs": "Keep daily, weekly, monthly and yearly backups",
}
RETENTION_COUNTS = "Enter whole numbers for the retention counts."
MAX_NOTIFICATIONS = 20
PREVIEW_COUNT = 5


SCHEDULE_PRESETS = {
    "manual": "Only when started by hand",
    "0 * * * *": "Every hour",
    "0 */6 * * *": "Every 6 hours",
    "0 3 * * *": "Every day at 03:00",
    "0 3 * * 0": "Every Sunday at 03:00",
    "0 3 1 * *": "On the 1st of every month at 03:00",
    "custom": "Custom (a cron expression)",
}
DEFAULT_SCHEDULE = "0 3 * * *"  # what a new job offers: a nightly backup


def preset_of(cron: str) -> str:
    """The preset a stored cron shows as in the form: "manual" without one, else "custom"."""
    if not cron:
        return "manual"
    return cron if cron in SCHEDULE_PRESETS and cron != "manual" else "custom"


def schedule_label(cron: str | None) -> str:
    """How the job list names a schedule: the preset's words, else the cron in words, else
    the cron itself."""
    preset = preset_of(cron or "")
    if preset != "custom":
        return SCHEDULE_PRESETS[preset]
    return scheduler.describe(cron or "") or f"cron {cron}"


def scheduled(cron: str, preset: str | None) -> str:
    """The cron a form means: a known preset, or the typed one for "custom" and for clients
    that send no preset (older forms and scripts)."""
    if preset is None or preset == "custom" or preset not in SCHEDULE_PRESETS:
        return " ".join(cron.split())
    return "" if preset == "manual" else preset


@dataclass
class JobForm:
    name: str = ""
    host_id: str = ""
    target: str = ""
    storage_target_id: str = ""
    scope: str = "all"
    images_reference_only_if_pullable: bool = False
    encrypted: bool = True
    enabled: bool = True
    target_type: str = "container"
    consistency_mode: str = "stop"
    # Copy the data on the host first; False in copy_first_sent: a client that predates it,
    # keep the stored choice.
    copy_first: bool = False
    copy_first_sent: bool = True
    pre_hooks: str = ""  # hook names, one per line, as typed
    post_hooks: str = ""
    # The retention policy: its mode and every mode's numbers, as typed. Only the chosen
    # mode's numbers are read.
    retention_mode: str = "last"
    keep_last: str = str(retention.DEFAULT_KEEP_LAST)
    max_age_days: str = "30"
    daily: str = "7"
    weekly: str = "4"
    monthly: str = "12"
    yearly: str = "0"
    cron: str = DEFAULT_SCHEDULE  # empty: started by hand only
    cron_preset: str = DEFAULT_SCHEDULE  # the schedule list's choice; see SCHEDULE_PRESETS
    timezone: str = ""  # empty: drydock's TZ
    schedule_sent: bool = True  # False: a client that predates schedules; keep the stored one
    # Notification target IDs, as typed; False: a client that predates them, keep the stored.
    notify_success: list[str] = dataclass_field(default_factory=list)
    notify_failure: list[str] = dataclass_field(default_factory=list)
    notifications_sent: bool = True
    # Mounts whose data the job leaves out ("bind:<path>", "volume:<name>"); False: a
    # client that predates them, keep the stored list.
    skip_mounts: list[str] = dataclass_field(default_factory=list)
    skip_mounts_sent: bool = True
    # The second and later targets (type, target), backed up after the first in this order;
    # False: a client that predates them, keep the stored ones.
    extra: list[tuple[str, str]] = dataclass_field(default_factory=list)
    extra_sent: bool = True

    @classmethod
    def from_job(cls, job: Job, db: Session) -> JobForm:
        try:
            policy = retention.parse(job.retention).to_dict()
        except retention.PolicyError:
            policy = {}  # shown with the defaults; saving stores a valid one
        numbers = {k: str(v) for k, v in policy.items() if k != "mode"}
        return cls(
            name=job.name,
            host_id=str(job.host_id),
            target=job.target,
            storage_target_id=str(job.storage_target_id),
            scope=job.scope,
            images_reference_only_if_pullable=job.images_reference_only_if_pullable,
            encrypted=job.encrypted,
            enabled=job.enabled,
            target_type=job.target_type,
            consistency_mode=job.consistency_mode,
            copy_first=job.copy_first,
            pre_hooks="\n".join(hook_names(db, hook_ids(job.pre_hooks))),
            post_hooks="\n".join(hook_names(db, hook_ids(job.post_hooks))),
            retention_mode=policy.get("mode", "last"),
            **numbers,
            cron=job.cron or "",
            cron_preset=preset_of(job.cron or ""),
            timezone=job.timezone or "",
            notify_success=[str(n.target_id) for n in attachments(db, job.id) if n.on_success],
            notify_failure=[str(n.target_id) for n in attachments(db, job.id) if n.on_failure],
            skip_mounts=sorted(mounts.stored(job.skip_mounts)),
            extra=[(s.target_type, s.target) for s in job_targets.of(db, job)[1:]],
        )


def submitted(
    notify_success: list[str] | None = None,
    notify_failure: list[str] | None = None,
    cron_preset: str | None = None,
    skip_mounts: list[str] | None = None,
    extra_target_type: list[str] | None = None,
    extra_target: list[str] | None = None,
    **values: str,
) -> JobForm:
    cron = scheduled(values["cron"], cron_preset)
    return JobForm(
        name=values["name"].strip(),
        host_id=values["host_id"].strip(),
        target=values["target"].strip(),
        storage_target_id=values["storage_target_id"].strip(),
        scope=values["scope"].strip(),
        images_reference_only_if_pullable=values["images_reference_only_if_pullable"] == "1",
        encrypted=values["encrypted"] == "1",
        enabled=values["enabled"] == "1",
        # Empty means the default, so clients that predate stacks keep working.
        target_type=values["target_type"].strip() or "container",
        consistency_mode=values["consistency_mode"].strip() or "stop",
        copy_first=values["copy_first"] == "1",
        copy_first_sent=values["copy_first_sent"] == "1",
        pre_hooks=values["pre_hooks"],
        post_hooks=values["post_hooks"],
        # Empty: a client that predates retention. A new job gets the default policy and
        # an edit keeps the stored one, which a reset could turn into deletions.
        retention_mode=values["retention_mode"].strip(),
        keep_last=values["keep_last"].strip(),
        max_age_days=values["max_age_days"].strip(),
        daily=values["daily"].strip(),
        weekly=values["weekly"].strip(),
        monthly=values["monthly"].strip(),
        yearly=values["yearly"].strip(),
        # The form always sends schedule=1, so an empty cron there means "by hand only".
        cron=cron,
        cron_preset=preset_of(cron),
        timezone=values["timezone"].strip(),
        schedule_sent=values["schedule"] == "1",
        # The form always sends notifications=1, so no boxes there means "none".
        notify_success=[v.strip() for v in notify_success or []],
        notify_failure=[v.strip() for v in notify_failure or []],
        notifications_sent=values["notifications"] == "1",
        skip_mounts=[v.strip() for v in skip_mounts or []],
        skip_mounts_sent=values["skip_mounts_sent"] == "1",
        # A row left empty is dropped, which is how a target is removed.
        extra=[
            (kind.strip() or "container", name.strip())
            for kind, name in zip(extra_target_type or [], extra_target or [], strict=False)
            if name.strip()
        ],
        extra_sent=values["extra_targets_sent"] == "1",
    )


def as_id(value: str) -> int | None:
    # str.isdigit() also accepts non-ASCII digits such as superscripts, which int() rejects.
    return int(value) if value.isascii() and value.isdigit() and len(value) <= 9 else None


# NOTIFICATIONS


def attachments(db: Session, job_id: int) -> list[JobNotification]:
    return list(db.scalars(select(JobNotification).where(JobNotification.job_id == job_id)))


def notification_ids(db: Session, form: JobForm) -> tuple[str | None, dict[int, tuple[bool, bool]]]:
    """An error, or the targets to attach as {target ID: (on success, on failure)}."""
    chosen: dict[int, tuple[bool, bool]] = {}
    for value, success in [(v, True) for v in form.notify_success] + [
        (v, False) for v in form.notify_failure
    ]:
        target_id = as_id(value)
        if target_id is None:
            return "Choose notification targets from the list.", {}
        on_success, on_failure = chosen.get(target_id, (False, False))
        chosen[target_id] = (on_success or success, on_failure or not success)
    if len(chosen) > MAX_NOTIFICATIONS:
        return f"A job can notify at most {MAX_NOTIFICATIONS} targets.", {}
    if chosen:
        found = set(
            db.scalars(select(NotificationTarget.id).where(NotificationTarget.id.in_(chosen)))
        )
        if found != set(chosen):
            return "A chosen notification target no longer exists.", {}
    return None, chosen


def set_notifications(db: Session, job_id: int, chosen: dict[int, tuple[bool, bool]]) -> None:
    db.execute(delete(JobNotification).where(JobNotification.job_id == job_id))
    for target_id, (on_success, on_failure) in chosen.items():
        db.add(
            JobNotification(
                job_id=job_id, target_id=target_id, on_success=on_success, on_failure=on_failure
            )
        )


def notification_names(db: Session, job_id: int) -> list[str]:
    """Each attached target as "name (success, failure)", by name."""
    rows = db.execute(
        select(NotificationTarget.name, JobNotification.on_success, JobNotification.on_failure)
        .join(JobNotification, JobNotification.target_id == NotificationTarget.id)
        .where(JobNotification.job_id == job_id)
        .order_by(NotificationTarget.name)
    ).all()
    return [
        f"{name} ({', '.join(w for w, on in (('success', s), ('failure', f)) if on)})"
        for name, s, f in rows
    ]


# HOOK LISTS


def hook_ids(text: str | None) -> list[int]:
    """A stored hook list (a JSON array of hook IDs in run order), or [] if it is not one."""
    try:
        ids = json.loads(text or "[]")
    except ValueError, RecursionError:
        return []
    if not isinstance(ids, list):
        return []
    if not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
        return []
    return ids


def hook_names(db: Session, ids: list[int]) -> list[str]:
    """The current names of the hooks with these IDs, in list order."""
    if not ids:
        return []
    names = dict(db.execute(select(Hook.id, Hook.name).where(Hook.id.in_(ids))).all())
    return [names[i] for i in ids if i in names]


def attached(db: Session, job: Job) -> list[tuple[str, Hook]]:
    """The job's hooks as (phase, hook): the "before" ones, then the "after" ones, in order."""
    result = []
    for column, phase in PHASES:
        ids = hook_ids(getattr(job, column))
        rows = {h.id: h for h in db.scalars(select(Hook).where(Hook.id.in_(ids)))} if ids else {}
        result += [(phase, rows[i]) for i in ids if i in rows]
    return result


def available(db: Session, job: Job) -> list[Hook]:
    """The hooks bound to this job's host and one of its targets, which it can attach as
    it is."""
    specs = job_targets.of(db, job) if job.id is not None else []
    return [
        row
        for row in db.scalars(select(Hook).where(Hook.host_id == job.host_id).order_by(Hook.name))
        if any(binds(row, job.host_id, s.target_type, s.target) for s in specs)
    ]


def lookup_hooks(db: Session, text: str) -> tuple[list[str], list[Hook]]:
    """The problems with one phase's hook names and the hooks they name, in order."""
    # Split on line feeds only: str.splitlines() also splits on U+0085, U+2028 and U+2029,
    # which hook names may hold. Names never hold a carriage return or a line feed.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    names = [line.strip() for line in lines if line.strip()]
    if len(names) > MAX_HOOKS_PER_PHASE:
        return [TOO_MANY_HOOKS], []
    errors: list[str] = []
    found: list[Hook] = []
    for name in names:
        row = db.scalar(select(Hook).where(Hook.name == name))  # NOCASE, like the column
        if row is None:
            errors.append(f"There is no hook named {name}.")
        elif any(row.id == other.id for other in found):
            errors.append(f"Hook {name} is listed twice.")
        else:
            found.append(row)
    return errors, found


# VALIDATION


def form_policy(form: JobForm) -> retention.Policy:
    """The retention policy the form describes. Raises retention.PolicyError."""
    if form.retention_mode not in retention.MODES:
        raise retention.PolicyError("Choose how long to keep backups.")
    numbers = {}
    for field in retention.MODE_FIELDS[form.retention_mode]:
        value = as_id(getattr(form, field) or "0")
        if value is None:
            raise retention.PolicyError(RETENTION_COUNTS)
        numbers[field] = value
    return retention.Policy(mode=form.retention_mode, **numbers)


def check_target(form: JobForm) -> str | None:
    return check_one(form.target_type, form.target)


def check_one(target_type: str, target: str) -> str | None:
    if target_type not in TARGET_TYPES:
        return "Choose what to back up."
    if target_type == "stack":
        return None if stacks.PROJECT_RE.fullmatch(target) else PROJECT_ERROR
    if not CONTAINER_RE.fullmatch(target):
        return "Enter a container name or ID, for example web or 3f2a9c1b7d0e."
    return None


def check_schedule(form: JobForm, default_tz: str) -> str | None:
    if not form.schedule_sent:
        return None
    try:
        if form.timezone:
            scheduler.zone(form.timezone)
        if form.cron:
            scheduler.checked(form.cron, form.timezone or default_tz, utcnow())
    except scheduler.CronError as exc:
        return str(exc)
    return None


def validate(
    db: Session, form: JobForm, default_tz: str, job_id: int | None = None
) -> tuple[list[str], list[int], list[int]]:
    """Returns the errors and the IDs of the pre- and post-hooks, in run order."""
    errors = []
    if not JOB_NAME_RE.fullmatch(form.name):
        errors.append("Name must be 1 to 64 characters.")
    else:
        query = select(Job.id).where(Job.name == form.name)
        if job_id is not None:
            query = query.where(Job.id != job_id)
        if db.scalar(query) is not None:
            errors.append("A job with that name exists.")
    host_id = as_id(form.host_id)
    host_ok = host_id is not None and db.get(Host, host_id) is not None
    if not host_ok:
        errors.append("Choose a host.")
    target_error = check_target(form)
    if target_error:
        errors.append(target_error)
    all_targets = [(form.target_type, form.target), *(form.extra if form.extra_sent else [])]
    if form.extra_sent:
        for kind, name in form.extra:
            if (error := check_one(kind, name)) is not None:
                errors.append(f"{name}: {error}")
                target_error = target_error or error
        if len(all_targets) > job_targets.MAX_TARGETS:
            errors.append(
                f"A job backs up at most {job_targets.MAX_TARGETS} containers and stacks."
            )
        if len(set(all_targets)) != len(all_targets):
            errors.append("Each container or stack can be in a job once.")
    storage_id = as_id(form.storage_target_id)
    storage = db.get(StorageTarget, storage_id) if storage_id is not None else None
    if storage is None:
        errors.append("Choose a storage target.")
    elif storage.kind not in BACKUP_KINDS:
        errors.append(
            f"Backups to {storage.kind} storage arrive in a later release: choose another storage."
        )
    if form.scope not in SCOPES:
        errors.append("Choose a scope.")
    if form.consistency_mode not in CONSISTENCY_MODES:
        errors.append("Choose a consistency mode.")
    elif form.copy_first_sent and form.copy_first and form.consistency_mode == "live":
        errors.append("Copying the data on the host first needs stop or pause mode.")
    try:
        if form.retention_mode:
            form_policy(form)
    except retention.PolicyError as exc:
        errors.append(str(exc))
    if schedule_error := check_schedule(form, default_tz):
        errors.append(schedule_error)
    if form.skip_mounts_sent and (skip_error := mounts.check(form.skip_mounts)[1]):
        errors.append(skip_error)
    if form.notifications_sent and (notify_error := notification_ids(db, form)[0]):
        errors.append(notify_error)
    pre_errors, pre = lookup_hooks(db, form.pre_hooks)
    post_errors, post = lookup_hooks(db, form.post_hooks)
    errors += pre_errors + post_errors
    if host_ok and target_error is None:
        # On every save, whatever changed: a hook is never silently re-aimed or dropped.
        # With several targets, a hook runs for the one it is bound to.
        if not form.extra_sent and job_id is not None:
            job_row = db.get(Job, job_id)
            if job_row is not None:
                all_targets += [(s.target_type, s.target) for s in job_targets.of(db, job_row)[1:]]
        for row in pre + post:
            failures = []
            for kind, name in all_targets:
                try:
                    check_binding(row, host_id=host_id, target_type=kind, target=name)
                except HookError as exc:
                    failures.append(str(exc))
                else:
                    break
            else:
                if failures and failures[0] not in errors:
                    errors.append(failures[0])
    return errors, [h.id for h in pre], [h.id for h in post]


def apply(job: Job, form: JobForm, pre_ids: list[int], post_ids: list[int]) -> None:
    job.name = form.name
    job.host_id = int(form.host_id)
    job.target_type = form.target_type
    job.target = form.target
    job.storage_target_id = int(form.storage_target_id)
    job.scope = form.scope
    job.consistency_mode = form.consistency_mode
    if form.copy_first_sent:
        job.copy_first = form.copy_first
    job.images_reference_only_if_pullable = form.images_reference_only_if_pullable
    job.encrypted = form.encrypted
    job.enabled = form.enabled
    job.pre_hooks = json.dumps(pre_ids)
    job.post_hooks = json.dumps(post_ids)
    if form.retention_mode:
        job.retention = form_policy(form).to_json()
    if form.schedule_sent:
        job.cron = form.cron or None
        job.timezone = form.timezone or None
    if form.skip_mounts_sent:
        job.skip_mounts = json.dumps(mounts.check(form.skip_mounts)[0])
    job.updated_at = utcnow()


def summary(job: Job, db: Session) -> dict[str, Any]:
    """Audit details, with the attached hooks by their names at this moment."""
    return {
        "name": job.name,
        "host_id": job.host_id,
        "target_type": job.target_type,
        "target": job.target,
        "storage_target_id": job.storage_target_id,
        "scope": job.scope,
        "consistency_mode": job.consistency_mode,
        "copy_first": job.copy_first,
        "images_reference_only_if_pullable": job.images_reference_only_if_pullable,
        "encrypted": job.encrypted,
        "enabled": job.enabled,
        "pre_hooks": hook_names(db, hook_ids(job.pre_hooks)),
        "post_hooks": hook_names(db, hook_ids(job.post_hooks)),
        "retention": job.retention,
        "cron": job.cron,
        "timezone": job.timezone,
        "skip_mounts": sorted(mounts.stored(job.skip_mounts)),
        "more_targets": [s.label for s in job_targets.of(db, job)[1:]]
        if job.id is not None
        else [],
        "notifications": notification_names(db, job.id) if job.id is not None else [],
    }


# SCHEDULES


def fire_text(fire: datetime) -> str:
    local = f"{fire:%a %Y-%m-%d %H:%M %Z}"
    return local if not fire.utcoffset() else f"{local} ({fire.astimezone(UTC):%H:%M} UTC)"


def upcoming(cron: str, tz: str, count: int) -> tuple[list[str], str | None]:
    """The next count fire times as text (within scheduler.HORIZON), or the error that
    stops the expression."""
    now = utcnow()
    try:
        trigger = scheduler.trigger(cron, tz, until=now + scheduler.HORIZON)
    except scheduler.CronError as exc:
        return [], str(exc)
    fires = scheduler.next_fires(trigger, now, count)
    return [fire_text(f) for f in fires], None if fires else scheduler.NEVER


def describe_schedule(job: Job, default_tz: str) -> str:
    if not job.cron:
        return "None: started by hand only."
    tz = job.timezone or default_tz
    fires, error = upcoming(job.cron, tz, 1)
    if error:
        return f"{job.cron} ({tz}). Not valid, so it does not run: {error}"
    if not job.enabled:
        return f"{job.cron} ({tz}). The job is disabled."
    return f"{job.cron} ({tz}). Next run {fires[0]}."


def refresh_schedules(request: Request) -> None:
    """After a job change is committed: the scheduler reloads (no restart needed)."""
    anyio.from_thread.run(request.app.state.scheduler.rebuild)


def valid_retention(job: Job) -> bool:
    try:
        retention.parse(job.retention)
    except retention.PolicyError:
        return False
    return True


def describe_retention(job: Job) -> str:
    try:
        return retention.parse(job.retention).describe()
    except retention.PolicyError:
        return "Not valid: nothing is deleted until the job is saved again."


def get_job(db: Session, job_id: int) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404)
    return job


def dispatcher(request: Request) -> Dispatcher:
    return request.app.state.dispatcher


@functools.cache
def sorted_zones() -> tuple[str, ...]:
    return tuple(sorted(known_zones()))


def choices(request: Request, db: Session) -> dict[str, Any]:
    return {
        "default_tz": request.app.state.settings.tz,
        "zones": sorted_zones(),
        "schedule_presets": SCHEDULE_PRESETS,
        "mount_label": mounts.label,
        "notification_targets": db.scalars(
            select(NotificationTarget).order_by(NotificationTarget.name)
        ).all(),
        "hosts": db.scalars(select(Host).order_by(Host.name)).all(),
        # Only the kinds drydock can back up to so far.
        "targets": db.scalars(
            select(StorageTarget)
            .where(StorageTarget.kind.in_(BACKUP_KINDS))
            .order_by(StorageTarget.name)
        ).all(),
        "scope_labels": SCOPE_LABELS,
        "mode_labels": MODE_LABELS,
        "target_labels": TARGET_LABELS,
        "live_warning": LIVE_WARNING,
        "retention_labels": RETENTION_LABELS,
    }


def job_page(
    request: Request,
    db: Session,
    auth: Auth,
    job: Job,
    status_code: int = 200,
    template: str = "jobs/detail.html",
    **context: Any,
) -> Response:
    """The job page (summary and recent runs), or with template="jobs/edit.html" its edit
    page (the form, the passphrase and deleting the job)."""
    if template == EDIT:
        context.setdefault("form", JobForm.from_job(job, db))
    context.setdefault("skip_mounts", sorted(mounts.stored(job.skip_mounts)))
    context.setdefault("errors", [])
    context.setdefault("error", None)
    context.setdefault("blank_rows", 0)
    context.setdefault("specs", job_targets.of(db, job))
    context.setdefault("passphrases", None)
    runs = db.scalars(
        select(Run).where(Run.job_id == job.id).order_by(Run.id.desc()).limit(RECENT_RUNS)
    ).all()
    return render(
        request,
        template,
        status_code,
        auth=auth,
        job=job,
        host=db.get(Host, job.host_id),
        storage=db.get(StorageTarget, job.storage_target_id),
        runs=runs,
        hooks=attached(db, job),
        retention_text=describe_retention(job),
        retention_invalid=not valid_retention(job),
        schedule_text=describe_schedule(job, request.app.state.settings.tz),
        notifications=notification_names(db, job.id),
        # Only admins see hook containers; viewers and operators see names.
        available_hooks=available(db, job)
        if template == EDIT and auth.user.role >= Role.admin
        else [],
        **choices(request, db),
        **context,
    )


# LIST AND CREATE


@router.get("")
def list_jobs(request: Request, auth: Viewer, db: Session = Depends(get_db)) -> Response:
    jobs = db.scalars(select(Job).order_by(Job.name)).all()
    hosts = {h.id: h.name for h in db.scalars(select(Host))}
    targets = {t.id: t.name for t in db.scalars(select(StorageTarget))}
    # A job's newest sequence starts at its newest run of the job's own target; its row
    # shows the worst run of that sequence, so a failed first target is not hidden.
    starts = dict(
        db.execute(
            select(Run.job_id, func.max(Run.id))
            .where(Run.target_uuid.is_(None))
            .group_by(Run.job_id)
        ).all()
    )
    last_runs: dict[int, Run] = {}
    for job_id, start in starts.items():
        if job_id is None or start is None:
            continue
        latest = db.scalars(
            select(Run).where(Run.job_id == job_id, Run.id >= start).order_by(Run.id)
        ).all()
        last_runs[job_id] = min(
            latest, key=lambda r: WORST.index(r.status) if r.status in WORST else 99
        )
    rows = [
        (j, hosts.get(j.host_id), targets.get(j.storage_target_id), last_runs.get(j.id))
        for j in jobs
    ]
    return render(
        request,
        "jobs/list.html",
        auth=auth,
        rows=rows,
        scope_labels=SCOPE_LABELS,
        schedule_label=schedule_label,
        retention_short=retention.short,
        extra_counts=dict(
            db.execute(select(JobTarget.job_id, func.count()).group_by(JobTarget.job_id)).all()
        ),
    )


@router.get("/new")
def new_job_form(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    return render(
        request,
        "jobs/new.html",
        auth=auth,
        form=JobForm(),
        errors=[],
        available_hooks=[],
        **choices(request, db),
    )


def host_inventory(
    request: Request, db: Session, host_id: str, wanted: bool
) -> tuple[Host | None, list[inventory.ProjectGroup] | None, str | None]:
    """The host the form names and, when wanted, its inventory (None if not read) and the
    error that stopped it. Reads the host like its inventory page does; the session's
    lock is released first."""
    ident = as_id(host_id)
    host = db.get(Host, ident) if ident is not None else None
    if host is None or not wanted:
        return host, None, None
    host = release(db, host)  # no lock while waiting on the network
    try:
        with open_host(request, host, INVENTORY_TIMEOUT) as handle:
            return host, inventory.list_inventory(handle.client, manager(request).instance_id), None
    except DOCKER_ERRORS as exc:
        return host, None, str(exc) or type(exc).__name__


@router.get("/target-options")
def target_options(
    request: Request,
    auth: Admin,
    host_id: str = Query("", max_length=20),
    db: Session = Depends(get_db),
) -> Response:
    """The Compose projects and containers on a host (#target-options), suggested in the
    job form's target fields as the host changes. Also a page of its own. Reads the host
    like its inventory does and writes nothing."""
    names: list[tuple[str, str]] = []
    host, groups, error = host_inventory(request, db, host_id, True)
    if groups is not None:
        # Both kinds, labelled: every target row of the form shares this one list.
        projects = sorted({g.project for g in groups if g.project})
        names = [(p, "Compose project") for p in projects] + [
            (n, "container") for n in sorted(c.name for g in groups for c in g.containers)
        ]
    return render(
        request, "jobs/target_options.html", auth=auth, host=host, names=names, error=error
    )


@router.get("/mount-options")
def mount_options(
    request: Request,
    auth: Admin,
    host_id: str = Query("", max_length=20),
    target_type: str = Query("container", max_length=16),
    target: str = Query("", max_length=255),
    extra_target_type: Annotated[list[str], Query()] = [],  # noqa: B006
    extra_target: Annotated[list[str], Query()] = [],  # noqa: B006
    skip_mounts: Annotated[list[str], Query()] = [],  # noqa: B006 (sliced and checked below)
    db: Session = Depends(get_db),
) -> Response:
    """The target's bind mounts and volumes (#mount-options) as tick boxes, the ones in
    skip_mounts ticked. Ticked keys the host no longer shows stay listed, so saving never
    drops them silently. Reads the host like its inventory does and writes nothing."""
    skipped = sorted({k for k in skip_mounts[: mounts.MAX_SKIPS] if mounts.key_error(k) is None})
    found: list[mounts.Choice] | None = None
    extra = [
        (kind, name.strip())
        for kind, name in zip(extra_target_type, extra_target, strict=False)
        if name.strip()
    ]
    pairs = [(target_type, target.strip()), *extra[: job_targets.MAX_TARGETS]]
    pairs = [(kind, name) for kind, name in pairs if kind in TARGET_TYPES and name]
    host, groups, error = host_inventory(request, db, host_id, bool(pairs))
    if groups is not None:
        merged: dict[str, mounts.Choice] = {}
        for kind, name in pairs:
            for choice in mounts.choices(groups, kind, name) or []:
                merged.setdefault(choice.key, choice)
        found = sorted(merged.values(), key=lambda c: c.key) if merged else None
    known = {c.key for c in found or []}
    return render(
        request,
        "jobs/mount_options.html",
        auth=auth,
        host=host,
        found=found,
        others=[k for k in skipped if k not in known],
        skipped=set(skipped),
        error=error,
        label=mounts.label,
    )


@router.get("/cron-preview")
def cron_preview(
    request: Request,
    auth: Admin,
    cron: str = Query("", max_length=200),
    timezone: str = Query("", max_length=64),
    cron_preset: str | None = Query(None, max_length=200),
) -> Response:
    """The next fire times of a schedule (#cron-preview), as the scheduler computes them.
    Also a page of its own. The job form loads it as the fields change."""
    cron = scheduled(cron, cron_preset)
    tz = timezone.strip() or request.app.state.settings.tz
    try:
        scheduler.zone(tz)  # also without a cron: saving checks it
        fires, error = upcoming(cron, tz, PREVIEW_COUNT) if cron else ([], None)
    except scheduler.CronError as exc:
        fires, error = [], str(exc)
    return render(
        request, "jobs/cron_preview.html", auth=auth, cron=cron, tz=tz, fires=fires, error=error
    )


@router.post("")
def create_job(
    request: Request,
    auth: Admin,
    name: FormStr = "",
    host_id: FormStr = "",
    target: FormStr = "",
    storage_target_id: FormStr = "",
    scope: FormStr = "",
    images_reference_only_if_pullable: FormStr = "",
    encrypted: FormStr = "",
    enabled: FormStr = "",
    target_type: FormStr = "",
    consistency_mode: FormStr = "",
    copy_first: FormStr = "",
    copy_first_sent: FormStr = "",
    pre_hooks: FormStr = "",
    post_hooks: FormStr = "",
    retention_mode: FormStr = "",
    keep_last: FormStr = "",
    max_age_days: FormStr = "",
    daily: FormStr = "",
    weekly: FormStr = "",
    monthly: FormStr = "",
    yearly: FormStr = "",
    cron: FormStr = "",
    cron_preset: Annotated[str | None, Form()] = None,
    timezone: FormStr = "",
    schedule: FormStr = "",
    notify_success: Annotated[list[str] | None, Form()] = None,
    notify_failure: Annotated[list[str] | None, Form()] = None,
    notifications: FormStr = "",
    skip_mounts: Annotated[list[str] | None, Form()] = None,
    skip_mounts_sent: FormStr = "",
    extra_target_type: Annotated[list[str] | None, Form()] = None,
    extra_target: Annotated[list[str] | None, Form()] = None,
    extra_targets_sent: FormStr = "",
    add_target: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    form = submitted(
        name=name,
        host_id=host_id,
        target=target,
        storage_target_id=storage_target_id,
        scope=scope,
        images_reference_only_if_pullable=images_reference_only_if_pullable,
        encrypted=encrypted,
        enabled=enabled,
        target_type=target_type,
        consistency_mode=consistency_mode,
        copy_first=copy_first,
        copy_first_sent=copy_first_sent,
        pre_hooks=pre_hooks,
        post_hooks=post_hooks,
        retention_mode=retention_mode,
        keep_last=keep_last,
        max_age_days=max_age_days,
        daily=daily,
        weekly=weekly,
        monthly=monthly,
        yearly=yearly,
        cron=cron,
        cron_preset=cron_preset,
        timezone=timezone,
        schedule=schedule,
        notify_success=notify_success,
        notify_failure=notify_failure,
        notifications=notifications,
        skip_mounts=skip_mounts,
        skip_mounts_sent=skip_mounts_sent,
        extra_target_type=extra_target_type,
        extra_target=extra_target,
        extra_targets_sent=extra_targets_sent,
    )
    if not form.retention_mode:
        form.retention_mode, form.keep_last = "last", str(retention.DEFAULT_KEEP_LAST)
    if add_target:
        db.rollback()
        return render(
            request,
            "jobs/new.html",
            auth=auth,
            form=form,
            errors=[],
            available_hooks=[],
            blank_rows=1,
            **choices(request, db),
        )
    errors, pre_ids, post_ids = validate(db, form, request.app.state.settings.tz)
    if errors:
        db.rollback()
        return render(
            request,
            "jobs/new.html",
            422,
            auth=auth,
            form=form,
            errors=errors,
            available_hooks=[],
            **choices(request, db),
        )
    job = Job(uuid=str(uuid.uuid4()))
    apply(job, form, pre_ids, post_ids)
    db.add(job)
    db.flush()
    if form.extra_sent:
        job_targets.replace_extra(db, job, form.extra)
        db.flush()
    if form.notifications_sent:
        set_notifications(db, job.id, notification_ids(db, form)[1])
        db.flush()
    audit.record(
        db,
        actor=auth.user.username,
        action="job.create",
        target=f"job:{job.id}",
        ip=client_ip(request),
        details=summary(job, db) | {"uuid": job.uuid},
    )
    db.commit()
    refresh_schedules(request)
    return see_other(request, f"/jobs/{job.id}")


# VIEW AND EDIT


@router.get("/{job_id}/edit")
def edit_job(request: Request, job_id: int, auth: Admin, db: Session = Depends(get_db)) -> Response:
    return job_page(request, db, auth, get_job(db, job_id), template=EDIT)


@router.get("/{job_id}")
def view_job(
    request: Request, job_id: int, auth: Viewer, db: Session = Depends(get_db)
) -> Response:
    return job_page(request, db, auth, get_job(db, job_id))


@router.post("/{job_id}")
def update_job(
    request: Request,
    job_id: int,
    auth: Admin,
    name: FormStr = "",
    host_id: FormStr = "",
    target: FormStr = "",
    storage_target_id: FormStr = "",
    scope: FormStr = "",
    images_reference_only_if_pullable: FormStr = "",
    encrypted: FormStr = "",
    enabled: FormStr = "",
    target_type: FormStr = "",
    consistency_mode: FormStr = "",
    copy_first: FormStr = "",
    copy_first_sent: FormStr = "",
    pre_hooks: FormStr = "",
    post_hooks: FormStr = "",
    retention_mode: FormStr = "",
    keep_last: FormStr = "",
    max_age_days: FormStr = "",
    daily: FormStr = "",
    weekly: FormStr = "",
    monthly: FormStr = "",
    yearly: FormStr = "",
    cron: FormStr = "",
    cron_preset: Annotated[str | None, Form()] = None,
    timezone: FormStr = "",
    schedule: FormStr = "",
    notify_success: Annotated[list[str] | None, Form()] = None,
    notify_failure: Annotated[list[str] | None, Form()] = None,
    notifications: FormStr = "",
    skip_mounts: Annotated[list[str] | None, Form()] = None,
    skip_mounts_sent: FormStr = "",
    extra_target_type: Annotated[list[str] | None, Form()] = None,
    extra_target: Annotated[list[str] | None, Form()] = None,
    extra_targets_sent: FormStr = "",
    add_target: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    job = get_job(db, job_id)
    form = submitted(
        name=name,
        host_id=host_id,
        target=target,
        storage_target_id=storage_target_id,
        scope=scope,
        images_reference_only_if_pullable=images_reference_only_if_pullable,
        encrypted=encrypted,
        enabled=enabled,
        target_type=target_type,
        consistency_mode=consistency_mode,
        copy_first=copy_first,
        copy_first_sent=copy_first_sent,
        pre_hooks=pre_hooks,
        post_hooks=post_hooks,
        retention_mode=retention_mode,
        keep_last=keep_last,
        max_age_days=max_age_days,
        daily=daily,
        weekly=weekly,
        monthly=monthly,
        yearly=yearly,
        cron=cron,
        cron_preset=cron_preset,
        timezone=timezone,
        schedule=schedule,
        notify_success=notify_success,
        notify_failure=notify_failure,
        notifications=notifications,
        skip_mounts=skip_mounts,
        skip_mounts_sent=skip_mounts_sent,
        extra_target_type=extra_target_type,
        extra_target=extra_target,
        extra_targets_sent=extra_targets_sent,
    )
    if add_target:
        db.rollback()
        return job_page(request, db, auth, job, 200, EDIT, form=form, blank_rows=1)
    errors, pre_ids, post_ids = validate(db, form, request.app.state.settings.tz, job.id)
    if errors:
        db.rollback()
        return job_page(request, db, auth, job, 422, EDIT, form=form, errors=errors)
    before = summary(job, db)
    apply(job, form, pre_ids, post_ids)
    if form.extra_sent:
        job_targets.replace_extra(db, job, form.extra)
        db.flush()
    if form.notifications_sent:
        set_notifications(db, job.id, notification_ids(db, form)[1])
        db.flush()
    after = summary(job, db)
    audit.record(
        db,
        actor=auth.user.username,
        action="job.update",
        target=f"job:{job.id}",
        ip=client_ip(request),
        details={k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]},
    )
    db.commit()
    refresh_schedules(request)
    return see_other(request, f"/jobs/{job.id}")


@router.post("/{job_id}/delete")
def delete_job(
    request: Request, job_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    job = get_job(db, job_id)
    active = db.scalar(
        select(func.count())
        .select_from(Run)
        .where(Run.job_id == job.id, Run.status.in_(("queued", "running")))
    )
    if active:
        db.rollback()
        error = "This job has a run in progress. Cancel it or wait for it to finish."
        return job_page(request, db, auth, job, 409, EDIT, error=error)
    # An update policy would quietly lose its backup first.
    policies = db.scalars(
        select(UpdatePolicy.name).where(UpdatePolicy.backup_job_id == job.id)
    ).all()
    if policies:
        db.rollback()
        error = (
            f"Update policies back up with this job first: {', '.join(policies)}. "
            "Change them first."
        )
        return job_page(request, db, auth, get_job(db, job_id), 409, EDIT, error=error)
    audit.record(
        db,
        actor=auth.user.username,
        action="job.delete",
        target=f"job:{job.id}",
        ip=client_ip(request),
        details=summary(job, db) | {"uuid": job.uuid},
    )
    db.delete(job)
    db.commit()
    refresh_schedules(request)
    return see_other(request, "/jobs")


# RUN NOW


@router.post("/{job_id}/run")
def run_job(
    request: Request, job_id: int, auth: Operator, db: Session = Depends(get_db)
) -> Response:
    job = get_job(db, job_id)
    username = auth.user.username
    # Release the write lock without expiring job: the dispatcher writes the run row in
    # its own transaction, and touching an expired object would take the lock again.
    db.expunge(job)
    db.rollback()
    try:
        run_id = anyio.from_thread.run(dispatcher(request).submit, job.id, username)
        error = None
    except DispatchError as exc:
        run_id, error = None, str(exc)
    audit.record(
        db,
        actor=auth.user.username,
        action="job.run",
        target=f"job:{job.id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"run_id": run_id} if error is None else {"error": error},
    )
    db.commit()
    if error is not None:
        response = job_page(request, db, auth, job, 409, error=error)
        # Run now on the jobs list lands here too: show the URL of the page shown.
        response.headers["HX-Replace-Url"] = f"/jobs/{job.id}"
        return response
    return see_other(request, f"/runs/{run_id}")


# PASSPHRASE


@router.post("/{job_id}/passphrase")
def reveal_passphrase(
    request: Request, job_id: int, auth: Superadmin, db: Session = Depends(get_db)
) -> Response:
    """Shows the passphrases for this job's archives, newest secret key first."""
    require_recent_auth(auth)
    job = get_job(db, job_id)
    # Each target's archives carry its own UUID, so each has its own passphrase.
    crypto = request.app.state.crypto
    specs = job_targets.of(db, job)
    passphrases = [(s.label, crypto.job_passphrases(uuid.UUID(s.uuid))) for s in specs]
    audit.record(
        db,
        actor=auth.user.username,
        action="job.passphrase_reveal",
        target=f"job:{job.id}",
        ip=client_ip(request),
        details={
            "name": job.name,
            "uuids": [s.uuid for s in specs],
            "candidates": len(passphrases[0][1]),
        },
    )
    db.commit()
    return job_page(request, db, auth, job, template=EDIT, passphrases=passphrases)
