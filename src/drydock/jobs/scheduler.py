"""Cron schedules for jobs: APScheduler 3 (AsyncIOScheduler, MemoryJobStore) on the event loop.

A job with a cron expression and enabled runs on it, in its own time zone (jobs.timezone,
or drydock's TZ when unset). The schedule lives only in memory: it is built from the jobs
table at startup and rebuilt after every job create, edit or delete, and only the process
holding the data directory lock starts it (main.lifespan). Each fire submits a run through
the dispatcher, which already keeps a job to one queued or running run and runs that touch
the same containers one after another, so a scheduled run never overlaps a manual one.

Expressions are standard five-field crontab. APScheduler 3 numbers the days of the week
from Monday = 0, while cron uses Sunday = 0 (and 7), so the day-of-week field is rewritten
as day names first (normalize). Cron runs a job when either a restricted day of the month
or a restricted day of the week matches, APScheduler only when both do, so an expression
restricting both is refused rather than run on fewer days than the user expects.

Lateness: every job has coalesce, max_instances=1 and misfire_grace_time=MISFIRE_GRACE,
so a fire the process was too busy for runs once if it is less than an hour late. For the
time drydock was not running, start() compares each job's last fire (jobs.last_fired_at,
or its last edit) with its fire times since: a fire missed less than MISFIRE_GRACE ago runs
once, an older one is logged and audited as missed and does not run.

System jobs: every MAINTENANCE_EVERY (first MAINTENANCE_FIRST after start) the scheduler
reaps orphaned helpers on every reachable host (helpers in use are skipped), cleans the
staging directory (Dispatcher.clean_staging_now), prunes finished runs older than
DRYDOCK_RUN_HISTORY_DAYS with their log files (Dispatcher.prune_history) and deletes
expired uploads (restore.uploads.expire). Each step's failure is logged and does not stop
the others.
"""

import asyncio
import contextlib
import logging
import re
import zoneinfo
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from drydock import audit
from drydock.config import Settings, known_zones
from drydock.hosts.client import run_blocking
from drydock.hosts.manager import HostManager
from drydock.jobs.dispatcher import Dispatcher, DispatchError
from drydock.models import Job, UpdatePolicy, utcnow
from drydock.restore import uploads

log = logging.getLogger("drydock.scheduler")

MISFIRE_GRACE = 3600  # seconds
MAINTENANCE_ID = "system:maintenance"  # job schedules use their job ID, digits only
MAINTENANCE_EVERY = timedelta(hours=1)
MAINTENANCE_FIRST = timedelta(minutes=5)
UPDATE_PREFIX = "update:"
TRIGGERED_BY = "the schedule"  # has a space, so no username can look like it
CRON_MAX = 100
CRON_RE = re.compile(r"[0-9A-Za-z*/,\- ]{1,100}")
DAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
CRON_FIELDS = "Enter five cron fields: minute, hour, day of month, month and day of week."
BOTH_DAYS = (
    "Restrict the day of the month or the day of the week, not both: cron would run on "
    "either day, drydock only on days that match both."
)
BAD_WEEKDAY = "The day of the week must use 0 to 7 (0 and 7 are Sunday) or sun to sat."
NEVER = "This schedule never runs: no date matches it."
# How far ahead a schedule must fire: a leap-day schedule fires at least every 8 years.
# Every search for a fire time is bounded by an end date, since APScheduler would otherwise
# search up to the year 9999 for a date that never comes (0 0 31 2 *), on the event loop.
HORIZON = timedelta(days=366 * 9)


class CronError(ValueError):
    """A cron expression or time zone is not valid. The message is safe to show."""


# EXPRESSIONS


def normalize(expr: str) -> str:
    """The expression with its day-of-week field as day names. Raises CronError."""
    fields = expr.split()
    if len(fields) != 5 or not CRON_RE.fullmatch(" ".join(fields)):
        raise CronError(CRON_FIELDS)
    minute, hour, dom, month, dow = fields
    if dow == "*":
        return " ".join(fields)
    if dom != "*":
        raise CronError(BOTH_DAYS)
    days = weekdays(dow)
    return " ".join((minute, hour, dom, month, ",".join(DAYS[d] for d in sorted(days))))


def weekdays(field: str) -> set[int]:
    """The days (0 = Sunday) a cron day-of-week field names: lists, ranges, steps, 0 to 7
    and sun to sat."""
    days: set[int] = set()
    for part in field.lower().split(","):
        base, slash, step = part.partition("/")
        if slash and not (step.isdigit() and 1 <= int(step) <= 7):
            raise CronError(BAD_WEEKDAY)
        if base == "*":
            low, high = 0, 6
        elif "-" in base:
            first, _, last = base.partition("-")
            low, high = weekday(first), weekday(last)
        elif slash:
            raise CronError(BAD_WEEKDAY)  # "1/2": cron implementations disagree on it
        else:
            low = high = weekday(base)
        if low > high:
            raise CronError(BAD_WEEKDAY)
        days.update(day % 7 for day in range(low, high + 1, int(step or 1)))
    return days


def weekday(value: str) -> int:
    if value in DAYS:
        return DAYS.index(value)
    if len(value) == 1 and value in "01234567":
        return int(value)
    raise CronError(BAD_WEEKDAY)


def zone(name: str) -> zoneinfo.ZoneInfo:
    # Checked against the list, never handed to ZoneInfo as a path.
    if name not in known_zones():
        raise CronError(f"Unknown time zone {name[:64]}. Use a name such as Europe/Berlin.")
    return zoneinfo.ZoneInfo(name)


def trigger(expr: str, tz: str, *, until: datetime | None = None) -> CronTrigger:
    """The trigger for a crontab expression in a time zone. Raises CronError.

    until bounds every search of the trigger: pass it everywhere except for the trigger the
    scheduler runs, whose schedules are checked to fire within HORIZON (checked)."""
    tzinfo = zone(tz)
    try:
        cron = CronTrigger.from_crontab(normalize(expr), timezone=tzinfo)
    except ValueError as exc:
        if isinstance(exc, CronError):
            raise
        raise CronError(f"The cron expression is not valid: {exc}") from None
    cron.end_date = until
    return cron


def checked(expr: str, tz: str, now: datetime) -> None:
    """Raises CronError unless the schedule is valid and fires within HORIZON of now."""
    if trigger(expr, tz, until=now + HORIZON).get_next_fire_time(None, now) is None:
        raise CronError(NEVER)


def next_fires(cron: CronTrigger, now: datetime, count: int) -> list[datetime]:
    """The next count fire times after now, exactly as the scheduler computes them. Give it a
    trigger bounded with until."""
    fires: list[datetime] = []
    fire = None
    while len(fires) < count:
        fire = cron.get_next_fire_time(fire, fire or now)
        if fire is None:
            break
        fires.append(fire)
    return fires


def first_fire(cron: CronTrigger, after: datetime, until: datetime) -> datetime | None:
    """The first fire time later than after and not later than until."""
    fire = cron.get_next_fire_time(None, after + timedelta(microseconds=1))
    return fire if fire is not None and fire <= until else None


# DESCRIPTIONS

MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June", "July", "August", "September",
    "October", "November", "December",
)  # fmt: skip
WEEKDAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def describe(expr: str) -> str | None:
    """A cron expression in the words the schedule presets use ("Every Sunday at 03:00"),
    or None for one that is not valid or too unusual to say plainly."""
    try:
        normalize(expr)
        minute, hour, dom, month, dow = expr.split()
        return times(minute, hour, *on_days(dom, month, dow))
    except ValueError:  # CronError too
        return None


def on_days(dom: str, month: str, dow: str) -> tuple[str, str]:
    """The days as a sentence start ("Every Sunday") and as a tail (" on Sunday")."""
    months = "" if month == "*" else spoken(values(month, 1, 12, MONTHS), month_name)
    if dom != "*":
        dates = f"the {spoken(values(dom, 1, 31), ordinal)} of {months or 'every month'}"
        return f"On {dates}", f" on {dates}"
    within = f" in {months}" if months else ""
    days = weekdays(dow) if dow != "*" else set()
    if len(days) in (0, 7):
        return f"Every day{within}", within
    # Monday first, so the working week reads as one range.
    names = spoken(sorted((day - 1) % 7 for day in days), WEEKDAY_NAMES.__getitem__)
    return f"Every {names}{within}", f" on {names}{within}"


def times(minute: str, hour: str, start: str, tail: str) -> str:
    """The whole description: the times of day, joined to the days. ValueError for
    combinations without a plain wording."""
    every_minutes, every_hours = step(minute, 60), step(hour, 24)
    if hour == "*" and (minute == "*" or every_minutes):
        return f"Every {f'{every_minutes} minutes' if every_minutes else 'minute'}{tail}"
    minutes = values(minute, 0, 59)
    past = "" if minutes == [0] else " at " + spoken(minutes, lambda m: f":{m:02d}", ranges=False)
    if hour == "*" or every_hours:
        return f"Every {f'{every_hours} hours' if every_hours else 'hour'}{past}{tail}"
    hours = values(hour, 0, 23)
    clock = [f"{h:02d}:{m:02d}" for h in hours for m in minutes]
    if len(clock) <= 4:
        return f"{start} at {spoken(clock, str, ranges=False)}"
    if len(minutes) == 1 and hours == list(range(hours[0], hours[-1] + 1)):
        return f"Every hour from {clock[0]} to {clock[-1]}{tail}"
    raise ValueError(hour)


def step(field: str, cycle: int) -> int | None:
    """n for a "*/n" that divides the cycle evenly (so it repeats the same across midnight or
    the hour), None for no step. ValueError for any other step."""
    if "/" not in field:
        return None
    base, _, n = field.partition("/")
    if base != "*" or not n.isdigit() or not 1 < int(n) < cycle or cycle % int(n):
        raise ValueError(field)
    return int(n)


def values(field: str, low: int, high: int, names: tuple[str, ...] = ()) -> list[int]:
    """The numbers a field of values and ranges names. ValueError for steps and wildcards."""
    found: set[int] = set()
    for part in field.lower().split(","):
        first, _, last = part.partition("-")
        a, b = (names.index(x) + low if x in names else int(x) for x in (first, last or first))
        if not low <= a <= b <= high:
            raise ValueError(field)
        found.update(range(a, b + 1))
    return sorted(found)


def spoken(items: list, word: Callable[[Any], str], ranges: bool = True) -> str:
    """Words for sorted values: runs of three or more as "a to c", the rest listed."""
    groups: list[list] = []
    for item in items:
        if ranges and groups and item == groups[-1][-1] + 1:
            groups[-1].append(item)
        else:
            groups.append([item])
    words: list[str] = []
    for group in groups:
        if len(group) >= 3:
            words.append(f"{word(group[0])} to {word(group[-1])}")
        else:
            words.extend(map(word, group))
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def month_name(n: int) -> str:
    return MONTH_NAMES[n - 1]


def ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


# THE SCHEDULER


@dataclass(frozen=True)
class Spec:
    job_id: int  # the job's ID, or the update policy's (kind "update")
    cron: str
    tz: str
    since: datetime  # its last fire, or its last edit: fires before it are not missed
    kind: str = "job"

    @property
    def key(self) -> str:
        """Its scheduler job ID: a job's own ID, "update:<id>" for an update policy."""
        return str(self.job_id) if self.kind == "job" else f"{UPDATE_PREFIX}{self.job_id}"

    @property
    def what(self) -> str:
        return f"Job {self.job_id}" if self.kind == "job" else f"Update policy {self.job_id}"


class Scheduler:
    def __init__(
        self,
        settings: Settings,
        sessions: sessionmaker[Session],
        dispatcher: Dispatcher,
        hosts: HostManager,
    ) -> None:
        self._settings = settings
        self._sessions = sessions
        self._dispatcher = dispatcher
        self._hosts = hosts
        self._scheduler = AsyncIOScheduler(
            jobstores={"default": MemoryJobStore()},
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": MISFIRE_GRACE,
            },
            timezone=zoneinfo.ZoneInfo(settings.tz),
        )
        self._specs: dict[str, tuple[str, str]] = {}  # by Spec.key
        self._reload = asyncio.Lock()  # rebuilds apply in the order they load
        self._maintaining: asyncio.Task[Any] | None = None
        self.running = False

    async def start(self) -> None:
        """Catches up on fires missed while drydock was down, then starts. Call only in the
        process holding the data directory lock, after the dispatcher started.

        Catch-up covers the fires up to now and the scheduler the ones after it, so a fire
        while catch-up runs is neither lost nor run twice. A job whose catch-up fails is
        logged and still scheduled."""
        now = utcnow()
        specs = await run_blocking(self._load, now)
        for spec in specs:
            try:
                await self._catch_up(spec, now)
            except Exception:
                log.exception("Catch-up of %s failed", spec.what.lower())
        self._apply(specs, now)
        self._scheduler.add_job(
            self._maintain,
            IntervalTrigger(seconds=MAINTENANCE_EVERY.total_seconds(), timezone=UTC),
            id=MAINTENANCE_ID,
            name="maintenance",
            next_run_time=now + MAINTENANCE_FIRST,
        )
        self._scheduler.start()
        self.running = True

    async def rebuild(self) -> None:
        """Reloads the schedules from the jobs table. A no-op until start(). The edit that
        asked for it is already saved, so a failure is logged, not raised."""
        if not self.running:
            return
        async with self._reload:
            try:
                self._apply(await run_blocking(self._load, utcnow()))
            except Exception:
                log.exception("Could not reload the schedules")

    async def shutdown(self) -> None:
        """Stops the schedules, and maintenance in progress, before the dispatcher closes
        and the data directory lock is released."""
        if self.running:
            self.running = False
            self._scheduler.shutdown(wait=False)
        task = self._maintaining
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def next_run_time(self, job_id: int) -> datetime | None:
        job = self._scheduler.get_job(str(job_id)) if self.running else None
        return job.next_run_time if job is not None else None

    def next_update_time(self, policy_id: int) -> datetime | None:
        job = self._scheduler.get_job(f"{UPDATE_PREFIX}{policy_id}") if self.running else None
        return job.next_run_time if job is not None else None

    def _apply(self, specs: list[Spec], now: datetime | None = None) -> None:
        """Adds, replaces and removes scheduler jobs. An unchanged one keeps its next run.
        With now (at start), each first fire is the first one after now."""
        wanted = {spec.key: spec for spec in specs}
        for job in self._scheduler.get_jobs():
            if job.id != MAINTENANCE_ID and job.id not in wanted:
                job.remove()
                self._specs.pop(job.id, None)
        for key, spec in wanted.items():
            cron, tz = spec.cron, spec.tz
            if self._specs.get(key) == (cron, tz):
                continue
            schedule = trigger(cron, tz)
            first = {}
            if now is not None:
                fire = schedule.get_next_fire_time(None, now + timedelta(microseconds=1))
                if fire is not None:
                    first["next_run_time"] = fire
            self._scheduler.add_job(
                self._fire if spec.kind == "job" else self._fire_update,
                schedule,
                args=[spec.job_id],
                id=key,
                name=spec.what.lower(),
                replace_existing=True,
                **first,
            )
            self._specs[key] = (cron, tz)

    async def _fire(self, job_id: int) -> None:
        """Submits a scheduled run. The run row and jobs.last_fired_at are written in one
        transaction, so a fire is never recorded without its run; a refused fire (the job
        already runs, or was disabled) still counts as handled."""
        try:
            run_id = await self._dispatcher.submit(job_id, TRIGGERED_BY, fired=True)
        except DispatchError as exc:
            await run_blocking(self._mark_fired, job_id, None)
            log.warning("Scheduled run of job %d did not start: %s", job_id, exc)
            return
        log.info("Scheduled run %d of job %d", run_id, job_id)

    async def _fire_update(self, policy_id: int) -> None:
        """Submits a scheduled update; like _fire, a refused one still counts as fired."""
        try:
            run_id = await self._dispatcher.submit_policy(policy_id, TRIGGERED_BY)
        except DispatchError as exc:
            log.warning("Scheduled update of policy %d did not start: %s", policy_id, exc)
            return
        finally:
            await run_blocking(self._mark_update_fired, policy_id, None)
        log.info("Scheduled update run %d of policy %d", run_id, policy_id)

    async def _maintain(self) -> None:
        self._maintaining = asyncio.current_task()
        days = self._settings.run_history_days
        steps = (
            ("helper reaper", self._hosts.reap_all),
            ("staging cleanup", self._dispatcher.clean_staging_now),
            ("run history pruning", lambda: run_blocking(self._dispatcher.prune_history, days)),
            ("upload expiry", lambda: run_blocking(uploads.expire, self._sessions, self._settings)),
        )
        for name, step in steps:
            if not self.running:
                return  # shutting down
            try:
                result = await step()
            except Exception:
                log.exception("The scheduled %s failed", name)
                continue
            if isinstance(result, int) and result:
                log.info("Pruned %d run(s) older than %d days", result, days)

    async def _catch_up(self, spec: Spec, now: datetime) -> None:
        """Runs the latest fire missed less than MISFIRE_GRACE ago, or else logs and audits
        the first fire missed since the job's last fire or edit."""
        cron = trigger(spec.cron, spec.tz, until=now)
        since = min(spec.since, now)  # a clock that went back must not hide misses
        grace = now - timedelta(seconds=MISFIRE_GRACE)
        recent = first_fire(cron, max(since, grace), now)
        if recent is not None:
            log.warning("%s missed its run at %s; starting it now", spec.what, recent)
            await (self._fire if spec.kind == "job" else self._fire_update)(spec.job_id)
            return
        missed = first_fire(cron, since, now)
        if missed is not None:
            log.warning(
                "%s missed its run at %s while drydock was stopped; more than %d seconds "
                "ago, so it does not run now",
                spec.what,
                missed,
                MISFIRE_GRACE,
            )
            mark = self._mark_fired if spec.kind == "job" else self._mark_update_fired
            await run_blocking(mark, spec.job_id, missed)

    # DATABASE

    def _load(self, now: datetime) -> list[Spec]:
        """The enabled jobs with a valid schedule. One that is not valid (edited by hand) or
        never fires is logged and left out."""
        with self._sessions() as db:
            rows = db.scalars(select(Job).where(Job.enabled, Job.cron.is_not(None))).all()
        specs = []
        for job in rows:
            tz = job.timezone or self._settings.tz
            try:
                checked(job.cron or "", tz, now)
            except CronError as exc:
                log.error("Job %d has no valid schedule, so it does not run: %s", job.id, exc)
                continue
            since = max(job.updated_at, job.last_fired_at or job.updated_at)
            specs.append(Spec(job.id, job.cron or "", tz, since))
        with self._sessions() as db:
            policies = db.scalars(select(UpdatePolicy).where(UpdatePolicy.enabled)).all()
        for policy in policies:
            tz = policy.timezone or self._settings.tz
            try:
                checked(policy.cron, tz, now)
            except CronError as exc:
                log.error("Update policy %d has no valid schedule: %s", policy.id, exc)
                continue
            since = max(policy.updated_at, policy.last_fired_at or policy.updated_at)
            specs.append(Spec(policy.id, policy.cron, tz, since, kind="update"))
        return specs

    def _mark_update_fired(self, policy_id: int, missed: datetime | None) -> None:
        """Records a policy's fire (or a missed fire found at startup, audited)."""
        with self._sessions() as db, db.begin():
            policy = db.get(UpdatePolicy, policy_id)
            if policy is None:
                return
            policy.last_fired_at = utcnow()
            if missed is not None:
                audit.record(
                    db,
                    actor=None,
                    action="update.schedule_missed",
                    target=f"update_policy:{policy.id}",
                    outcome="failure",
                    details={"name": policy.name, "missed": missed.isoformat()},
                )

    def _mark_fired(self, job_id: int, missed: datetime | None) -> None:
        """Records a fire (or a missed fire found at startup, audited)."""
        with self._sessions() as db, db.begin():
            job = db.get(Job, job_id)
            if job is None:
                return
            job.last_fired_at = utcnow()
            if missed is not None:
                details: dict[str, Any] = {"name": job.name, "missed": missed.isoformat()}
                audit.record(
                    db,
                    actor=None,
                    action="job.schedule_missed",
                    target=f"job:{job.id}",
                    outcome="failure",
                    details=details,
                )
