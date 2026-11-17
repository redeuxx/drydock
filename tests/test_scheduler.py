"""Schedules: cron normalization, previews across DST, the job form, rebuilding without a
restart, fires missed while drydock was down or late while it ran, and no overlap with
manual runs. The backup itself is test_jobs' blocking stand-in."""

import re
import sqlite3
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from anyio import sleep as anyio_sleep
from apscheduler.events import EVENT_JOB_MISSED
from apscheduler.job import Job as SchedulerJob

from drydock.config import Settings
from drydock.db import make_engine
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.jobs import scheduler
from drydock.jobs.scheduler import BOTH_DAYS, NEVER, CronError, Scheduler, normalize, trigger
from drydock.models import utcnow
from drydock.routes.jobs import fire_text
from drydock.routes.schedule_rows import FIELDS, Row
from tests.conftest import Browser, add_user, make_settings, running, sqlite_ts
from tests.docker_support import wait_until
from tests.test_jobs import (  # noqa: F401
    add_host,
    add_job,
    add_storage,
    fake_docker,
    run_status,
    start_run,
)
from tests.test_restore_schema import alembic_to
from tests.test_routes import FakeDocker
from tests.test_stacks_schema import add_job as add_job_row
from tests.test_stacks_schema import add_parents, sequence, table_sql, version
from tests.test_update_policies import policy_form

pytestmark = pytest.mark.anyio

SCHEDULED = "SELECT COUNT(*) FROM runs WHERE triggered_by = 'the schedule'"


# EXPRESSIONS


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("0 3 * * 0", "0 3 * * sun"),
        ("0 3 * * 7", "0 3 * * sun"),
        ("0  3 *\t* 1-5", "0 3 * * mon,tue,wed,thu,fri"),
        ("0 3 * * 5-7", "0 3 * * sun,fri,sat"),
        ("0 3 * * */2", "0 3 * * sun,tue,thu,sat"),
        ("0 3 * * 1-5/2", "0 3 * * mon,wed,fri"),
        ("0 3 * * MON,wed", "0 3 * * mon,wed"),
        ("0 3 * * 0,7", "0 3 * * sun"),
        ("*/15 * * * *", "*/15 * * * *"),
        ("0 3 1 * *", "0 3 1 * *"),
    ],
)
def test_day_of_week_follows_cron(expr: str, expected: str) -> None:
    assert normalize(expr) == expected


@pytest.mark.parametrize(
    "expr",
    [
        "0 3 * *",
        "0 3 * * * *",
        "0 3 1 * 1",
        "0 3 * * 8",
        "0 3 * * 1/2",
        "0 3 * * 5-1",
        "0 3 * * 1/0",
        "0 3 * * ¹",
        "0 3 * * 0;rm",
        "61 * * * *",
        "",
        "0 3 * * " + "1," * 60 + "1",
    ],
)
def test_invalid_expressions_are_refused(expr: str) -> None:
    with pytest.raises(CronError):
        trigger(expr, "UTC")


def test_unknown_time_zones_are_refused() -> None:
    # localtime: Python 3.14's available_timezones() lists Debian's link to /etc/localtime.
    for name in ("Mars/Olympus", "../../etc/passwd", "/etc/localtime", "localtime", ""):
        with pytest.raises(CronError, match="Unknown time zone"):
            trigger("0 3 * * *", name)


def test_sunday_at_three_across_a_dst_change() -> None:
    cron = trigger("0 3 * * 0", "America/New_York")
    fires = scheduler.next_fires(cron, datetime(2026, 3, 1, tzinfo=UTC), 3)
    assert [f.strftime("%a %H:%M") for f in fires] == ["Sun 03:00"] * 3
    # EST, then EDT from 2026-03-08: the same local time, an hour earlier in UTC.
    assert [f.astimezone(UTC).strftime("%m-%d %H:%M") for f in fires] == [
        "03-01 08:00",
        "03-08 07:00",
        "03-15 07:00",
    ]
    # Numeric 0 alone would have meant Monday to APScheduler.
    assert fire_text(fires[0]) == "Sun 2026-03-01 03:00 EST (08:00 UTC)"


def test_skipped_and_repeated_local_times() -> None:
    """As docs/backups.md says: a skipped time runs an hour later, a repeated one twice."""
    cron = trigger("30 2 * * *", "Europe/Berlin")
    spring = scheduler.next_fires(cron, datetime(2026, 3, 29, tzinfo=UTC), 1)
    assert [f.astimezone(UTC).strftime("%m-%d %H:%M") for f in spring] == ["03-29 01:30"]
    # A skipped 02:00 is 03:00: one run, so the preview lists it once.
    both = scheduler.next_fires(
        trigger("0 2-3 * * *", "Europe/Berlin"), datetime(2026, 3, 29, tzinfo=UTC), 3
    )
    assert [f.astimezone(UTC).strftime("%m-%d %H:%M") for f in both] == [
        "03-29 01:00",
        "03-30 00:00",
        "03-30 01:00",
    ]
    autumn = scheduler.next_fires(cron, datetime(2026, 10, 25, tzinfo=UTC), 2)
    assert [f.astimezone(UTC).strftime("%m-%d %H:%M") for f in autumn] == [
        "10-25 00:30",
        "10-25 01:30",
    ]


@pytest.mark.parametrize(
    ("tz", "change"),
    [
        ("America/Chicago", datetime(2026, 11, 1, 7, tzinfo=UTC)),  # back an hour
        ("Australia/Lord_Howe", datetime(2026, 4, 4, 15, tzinfo=UTC)),  # back 30 minutes
        ("Antarctica/Troll", datetime(2026, 10, 25, 1, tzinfo=UTC)),  # back two hours
    ],
)
@pytest.mark.parametrize("expr", ["0 * * * *", "*/15 * * * *", "30 1 * * *"])
def test_the_scheduler_moves_forward_through_a_repeated_hour(
    tz: str, change: datetime, expr: str
) -> None:
    """APScheduler's Job._get_run_times loops while the next fire is not in the future, so
    a trigger that returned a fire again, or an earlier one, would hang the event loop.
    Its own arithmetic is in UTC; a local time plus a timedelta loses the fold."""
    cron = trigger(expr, tz)
    now = change - timedelta(hours=4)
    fires = [cron.get_next_fire_time(None, now)]
    while len(fires) < 40:
        fire = cron.get_next_fire_time(fires[-1], fires[-1].astimezone(UTC))
        assert fire is not None and fire.astimezone(UTC) > fires[-1].astimezone(UTC)
        fires.append(fire)

    class Stub:
        _get_run_times = SchedulerJob._get_run_times
        trigger = cron
        next_run_time = fires[0]

    late = fires[-1].astimezone(UTC)
    assert Stub()._get_run_times(late)[: len(fires)] == fires


def test_a_schedule_that_never_runs_is_refused_quickly() -> None:
    now = datetime(2026, 10, 20, tzinfo=UTC)
    for expr in ("0 0 31 2 *", "0 0 31 2,4,6,9,11 *", "0 0 30 2 *"):
        timings = []
        for _ in range(5):
            started = time.perf_counter()
            with pytest.raises(CronError, match="never runs"):
                scheduler.checked(expr, "UTC", now)
            timings.append(time.perf_counter() - started)
        # Best of 5: a GC pass or CPU steal on a busy runner cannot fail it, unbounded still does.
        assert min(timings) < 0.05, expr  # unbounded: up to 0.2 s each
    scheduler.checked("0 0 29 2 *", "UTC", now)  # a leap day still runs, in 2028


def test_first_fire_is_strictly_after() -> None:
    cron = trigger("0 3 * * *", "UTC")
    at3 = datetime(2026, 10, 20, 3, tzinfo=UTC)
    assert scheduler.first_fire(cron, at3, at3 + timedelta(hours=1)) is None
    assert scheduler.first_fire(cron, at3 - timedelta(seconds=1), at3) == at3


# THE JOB FORM


def scheduled(cron: str, tz: str = "") -> dict[str, str]:
    return {"schedule": "1", "cron": cron, "timezone": tz}


async def test_form_preview_and_rebuild_without_restart(admin: Browser) -> None:
    base = {"host_id": str(add_host(admin)), "storage_id": str(await add_storage(admin))}
    sched = admin.app.state.scheduler
    # The form sends schedule=1, so clearing the cron there clears the schedule.
    for path in ("/jobs/new",):
        assert 'name="schedule" value="1"' in (await admin.get(path)).text
    job_id = await add_job(admin, "weekly", **scheduled("0 3 * * 0", "America/New_York"), **base)
    assert 'name="schedule" value="1"' in (await admin.get(f"/jobs/{job_id}/edit")).text
    assert admin.sql("SELECT cron, timezone FROM jobs WHERE id = ?", (job_id,)) == [
        ("0 3 * * 0", "America/New_York")
    ]
    # The scheduler has it at once, and the preview shows the time APScheduler will use.
    first = sched.next_run_time(job_id)
    assert first is not None and first.strftime("%a %H:%M") == "Sun 03:00"
    preview = await admin.get(
        "/jobs/cron-preview", params={"cron": "0 3 * * 0", "timezone": "America/New_York"}
    )
    assert preview.status_code == 200 and fire_text(first) in preview.text
    page = await admin.get(f"/jobs/{job_id}")
    assert f"Every Sunday at 03:00 (America/New_York). Next run {fire_text(first)}." in page.text

    # Editing changes the schedule with no restart; an empty time zone means TZ (UTC here).
    form = {
        "name": "weekly",
        "host_id": base["host_id"],
        "target": "web",
        "storage_target_id": base["storage_id"],
        "scope": "config",
        "encrypted": "1",
        "enabled": "1",
    }
    response = await admin.post(f"/jobs/{job_id}", form | scheduled("30 4 * * *"))
    assert response.status_code == 303, response.text
    moved = sched.next_run_time(job_id)
    assert moved is not None and moved.astimezone(UTC).strftime("%H:%M") == "04:30"
    details = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'job.update' ORDER BY id DESC LIMIT 1"
    )[0][0]
    assert '"cron": {"from": "0 3 * * 0", "to": "30 4 * * *"}' in details

    # A client that sends no schedule fields keeps the schedule.
    response = await admin.post(f"/jobs/{job_id}", form | {"name": "weekly2"})
    assert response.status_code == 303, response.text
    assert admin.sql("SELECT cron FROM jobs WHERE id = ?", (job_id,)) == [("30 4 * * *",)]
    assert sched.next_run_time(job_id) == moved

    # A time zone alone reschedules.
    response = await admin.post(f"/jobs/{job_id}", form | scheduled("30 4 * * *", "Asia/Tokyo"))
    assert response.status_code == 303, response.text
    tokyo = sched.next_run_time(job_id)
    assert tokyo is not None and tokyo.astimezone(UTC).strftime("%H:%M") == "19:30"

    # Disabled or cleared: off the schedule. Deleted: gone.
    response = await admin.post(f"/jobs/{job_id}", form | {"enabled": ""} | scheduled("30 4 * * *"))
    assert response.status_code == 303 and sched.next_run_time(job_id) is None
    page = await admin.get(f"/jobs/{job_id}")
    assert "Every day at 04:30 (UTC). The job is disabled." in page.text
    response = await admin.post(f"/jobs/{job_id}", form | scheduled(""))
    assert response.status_code == 303 and sched.next_run_time(job_id) is None
    assert admin.sql("SELECT cron, timezone FROM jobs WHERE id = ?", (job_id,)) == [(None, None)]
    assert "None: started by hand only." in (await admin.get(f"/jobs/{job_id}")).text
    response = await admin.post(f"/jobs/{job_id}", form | scheduled("0 3 * * *"))
    assert sched.next_run_time(job_id) is not None
    assert (await admin.post(f"/jobs/{job_id}/delete")).status_code == 303
    assert sched.next_run_time(job_id) is None

    # Refused input.
    for fields, message in (
        (scheduled("0 3 1 * 1"), BOTH_DAYS),
        (scheduled("0 3 * * 9"), "0 to 7"),
        (scheduled("0 3 * *"), "Enter five cron fields"),
        (scheduled("0 3 * * *", "Mars/Olympus"), "Unknown time zone Mars/Olympus"),
        (scheduled("", "Mars/Olympus"), "Unknown time zone Mars/Olympus"),
        (scheduled("0 0 31 2 *"), NEVER),
        (scheduled("", "<b>" + "x" * 500), "Unknown time zone &lt;b&gt;" + "x" * 61 + "."),
    ):
        response = await admin.post(
            "/jobs",
            {
                "name": "bad",
                "host_id": base["host_id"],
                "target": "web",
                "storage_target_id": base["storage_id"],
            }
            | fields,
        )
        assert response.status_code == 422 and message in response.text, fields

    for params, text in (
        ({"cron": ""}, "runs only when started by hand"),
        ({"cron": "0 3 1 * 1"}, BOTH_DAYS),
        ({"cron": "0 3 * * *", "timezone": "Nowhere"}, "Unknown time zone Nowhere"),
        ({"cron": "0 3 * * *"}, "Next runs in UTC"),
        ({"cron": "0 0 31 2 *"}, NEVER),
        ({"cron": "", "timezone": "Nowhere"}, "Unknown time zone Nowhere"),
    ):
        response = await admin.get("/jobs/cron-preview", params=params)
        assert response.status_code == 200 and text in response.text, params


async def test_a_job_without_a_time_zone_follows_tz(tmp_path: Path) -> None:
    (tmp_path / "storage").mkdir()
    settings = make_settings(
        tmp_path / "data", DRYDOCK_LOCAL_STORAGE_ROOTS=str(tmp_path / "storage"), TZ="Asia/Tokyo"
    )
    async with running(settings) as browser:
        await browser.setup()
        job_id = await add_job(browser, "tokyo", **scheduled("0 3 * * *"))
        fire = browser.app.state.scheduler.next_run_time(job_id)
        assert fire is not None and fire.astimezone(UTC).strftime("%H:%M") == "18:00"
        page = await browser.get(f"/jobs/{job_id}")
        assert "Every day at 03:00 (Asia/Tokyo). Next run" in page.text
        assert "JST (18:00 UTC)" in page.text
        preview = await browser.get("/jobs/cron-preview", params={"cron": "0 3 * * *"})
        assert "Next runs in Asia/Tokyo" in preview.text


async def test_preview_is_for_admins_only(admin: Browser) -> None:
    await add_user(admin, "op", "operator")
    await admin.login("op")
    response = await admin.get("/jobs/cron-preview", params={"cron": "0 3 * * *"})
    assert response.status_code == 403


# MISSED AND LATE FIRES


@pytest.fixture
def restartable(monkeypatch, fake_docker: dict) -> None:  # noqa: F811
    """Restarts with hosts in the database reap them first: against the fake daemon."""

    async def fake_connect(url: str, *args, **kwargs) -> FakeDocker:
        return FakeDocker()

    monkeypatch.setattr(docker_client, "connect", fake_connect)
    monkeypatch.setattr(helper, "reap", lambda client, instance_id: 0)


async def scheduled_job(browser: Browser, name: str, cron: str, since: datetime) -> int:
    """A job on cron (UTC) whose schedule was last edited, and never fired, at since."""
    job_id = await add_job(browser, name, **scheduled(cron, "UTC"))
    browser.sql(
        "UPDATE jobs SET updated_at = ?, last_fired_at = NULL WHERE id = ?",
        (sqlite_ts(since), job_id),
    )
    return job_id


async def test_missed_fires_at_startup(settings: Settings, restartable: None, caplog) -> None:
    now = utcnow()
    recent, old = now - timedelta(minutes=10), now - timedelta(hours=2)
    async with running(settings) as browser:
        await browser.setup()
        # Every hour at the minute 10 minutes ago: that fire was missed recently.
        hourly = await scheduled_job(
            browser, "hourly", f"{recent.minute} * * * *", now - timedelta(hours=3)
        )
        # Daily, 2 hours ago: missed longer ago than the grace time.
        daily = await scheduled_job(
            browser, "daily", f"{old.minute} {old.hour} * * *", now - timedelta(hours=3)
        )
        # Edited after its last fire time: nothing was missed.
        edited = await scheduled_job(browser, "edited", f"{old.minute} {old.hour} * * *", now)
    assert browser.sql(SCHEDULED) == [(0,)]

    async with running(settings) as browser:
        assert browser.sql("SELECT job_id FROM runs WHERE triggered_by = 'the schedule'") == [
            (hourly,)
        ]
        missed = browser.sql(
            "SELECT target, outcome FROM audit_events WHERE action = 'job.schedule_missed'"
        )
        assert missed == [(f"job:{daily}", "failure")]
        fired = dict(browser.sql("SELECT id, last_fired_at FROM jobs"))
        assert fired[hourly] is not None and fired[daily] is not None and fired[edited] is None
    assert f"Job {hourly} missed its run at" in caplog.text and "starting it now" in caplog.text
    assert f"Job {daily} missed its run at" in caplog.text and "does not run now" in caplog.text
    assert f"Job {edited} missed" not in caplog.text

    # Restarted again within the hour: neither runs a second time, nor is logged again.
    async with running(settings) as browser:
        assert browser.sql(SCHEDULED) == [(1,)]
        assert browser.sql(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'job.schedule_missed'"
        ) == [(1,)]


async def test_a_late_fire_runs_once_within_the_grace_time(
    admin: Browser,
    fake_docker: dict,  # noqa: F811
    monkeypatch,
) -> None:
    sched = admin.app.state.scheduler
    aps = sched._scheduler
    fires: list[int] = []
    real_fire = Scheduler._fire

    async def counted(self: Scheduler, job_id: int) -> None:
        fires.append(job_id)
        await real_fire(self, job_id)

    # Before the jobs are added: each binds _fire when it is added.
    monkeypatch.setattr(Scheduler, "_fire", counted)
    missed: list[str] = []
    aps.add_listener(lambda event: missed.append(event.job_id), EVENT_JOB_MISSED)
    now = datetime.now(UTC)

    # Every 5 minutes, 30 minutes late: the 6 fires it skipped coalesce into one.
    job_id = await add_job(admin, "late", **scheduled("*/5 * * * *", "UTC"))
    aps.modify_job(str(job_id), next_run_time=now - timedelta(minutes=30))
    await wait_until(lambda: admin.sql(SCHEDULED) == [(1,)], 10, "the late run")
    await wait_until(lambda: sched.next_run_time(job_id) > now, 10, "the next fire")
    await anyio_sleep(0.5)  # a second call (no coalescing) would be logged as refused
    assert fires == [job_id] and admin.sql(SCHEDULED) == [(1,)]
    assert admin.sql("SELECT last_fired_at IS NOT NULL FROM jobs WHERE id = ?", (job_id,)) == [(1,)]

    # Two hours late (daily, at a time with no fire since): APScheduler reports it missed.
    old = now - timedelta(hours=2)
    daily_id = await add_job(admin, "too late", **scheduled(f"{old.minute} {old.hour} * * *"))
    aps.modify_job(str(daily_id), next_run_time=old)
    await wait_until(lambda: str(daily_id) in missed, 10, "the missed event")
    assert fires == [job_id] and admin.sql(SCHEDULED) == [(1,)]


async def test_a_scheduled_fire_never_overlaps_a_manual_run(
    admin: Browser,
    fake_docker: dict,  # noqa: F811
    caplog,
) -> None:
    job_id = await add_job(admin, "busy", **scheduled("0 3 * * *", "UTC"))
    run_id = await start_run(admin, job_id)
    await admin.app.state.scheduler._fire(job_id)
    assert admin.sql("SELECT id FROM runs WHERE job_id = ?", (job_id,)) == [(run_id,)]
    assert "did not start: This job already has a run in progress." in caplog.text
    assert admin.sql("SELECT last_fired_at IS NOT NULL FROM jobs WHERE id = ?", (job_id,)) == [(1,)]


async def test_a_scheduled_run_waits_for_another_jobs_run_on_its_container(
    admin: Browser,
    fake_docker: dict,  # noqa: F811
) -> None:
    base = {"host_id": str(add_host(admin)), "storage_id": str(await add_storage(admin))}
    manual = await add_job(admin, "manual", **base)
    timed = await add_job(admin, "timed", **scheduled("0 3 * * *", "UTC"), **base)
    first = await start_run(admin, manual)
    await wait_until(lambda: run_status(admin, first) == "running", 10, "the manual run")
    await admin.app.state.scheduler._fire(timed)
    second = admin.sql("SELECT id FROM runs WHERE job_id = ?", (timed,))[0][0]
    await anyio_sleep(0.5)
    assert run_status(admin, second) == "queued"  # same container: it waits
    await admin.post(f"/runs/{first}/cancel")
    await wait_until(lambda: run_status(admin, second) == "running", 10, "the scheduled run")


async def test_a_hand_edited_schedule_is_skipped(
    settings: Settings, restartable: None, caplog
) -> None:
    async with running(settings) as browser:
        await browser.setup()
        job_id = await add_job(browser, "edited", **scheduled("0 3 * * *", "UTC"))
        never = await add_job(browser, "never", **scheduled("0 3 * * *", "UTC"))
        fine = await add_job(browser, "fine", **scheduled("0 3 * * *", "UTC"))
        browser.sql("UPDATE jobs SET cron = '0 3 * * 9' WHERE id = ?", (job_id,))
        browser.sql("UPDATE jobs SET cron = '0 0 31 2 *' WHERE id = ?", (never,))
    async with running(settings) as browser:
        assert browser.app.state.scheduler.running
        assert browser.app.state.scheduler.next_run_time(job_id) is None
        assert browser.app.state.scheduler.next_run_time(never) is None
        assert browser.app.state.scheduler.next_run_time(fine) is not None  # the rest load
        await browser.login("admin")
        page = await browser.get(f"/jobs/{job_id}")
        assert "Not valid, so it does not run" in page.text
    assert f"Job {job_id} has no valid schedule" in caplog.text


# MIGRATION


def test_migration_0007_adds_and_drops_the_schedule_columns(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0006")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            add_job_row(conn, 1)
            conn.commit()
        alembic_to(engine, "0007")
        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute("SELECT cron, timezone, last_fired_at FROM jobs").fetchall() == [
                (None, None, None)
            ]
            assert version(conn) == [("0007",)]
        alembic_to(engine, "0006", down=True)
        with closing(sqlite3.connect(path)) as conn:
            sql = table_sql(conn, "jobs") or ""
            assert "cron" not in sql and "last_fired_at" not in sql and "timezone" not in sql
            assert conn.execute("SELECT id FROM jobs").fetchall() == [(1,)]
            assert sequence(conn, "jobs") == [(1,)]
    finally:
        engine.dispose()


# SCHEDULE ROWS AND TIME ZONES IN THE FORM


def stored_schedule(browser: Browser, job_id: int) -> tuple:
    return browser.sql("SELECT cron, timezone FROM jobs WHERE id = ?", (job_id,))[0]


async def test_an_older_clients_preset_or_typed_cron_is_kept(admin: Browser) -> None:
    preset = await add_job(
        admin, "preset", schedule="1", cron_preset="0 */6 * * *", cron="1 2 3 4 *"
    )
    assert stored_schedule(admin, preset) == ("0 */6 * * *", None)
    custom = await add_job(admin, "custom", schedule="1", cron_preset="custom", cron="15 4 * * mon")
    assert stored_schedule(admin, custom)[0] == "15 4 * * mon"
    manual = await add_job(admin, "manual", schedule="1", cron_preset="manual", cron="15 4 * * mon")
    assert stored_schedule(admin, manual)[0] is None
    page = (await admin.get(f"/jobs/{preset}/edit")).text
    assert '<option value="hours" selected>' in page and '<option value="6" selected>' in page


async def test_clients_without_a_preset_keep_the_typed_cron(admin: Browser) -> None:
    job_id = await add_job(admin, "script", schedule="1", cron="30 1 * * *")
    assert stored_schedule(admin, job_id)[0] == "30 1 * * *"
    page = (await admin.get(f"/jobs/{job_id}/edit")).text
    assert '<option value="days" selected>' in page and 'value="01:30"' in page


async def test_a_new_job_offers_a_nightly_schedule_and_every_zone(admin: Browser) -> None:
    page = (await admin.get("/jobs/new")).text
    assert '<option value="days" selected>' in page and 'name="sched_time" value="03:00"' in page
    assert page.count('name="sched_day"') == 7 and page.count("checked") >= 7
    assert '<option value="Europe/Berlin">Europe/Berlin</option>' in page
    assert 'value="localtime"' not in page
    job_id = await add_job(
        admin, "zoned", schedule="1", cron_preset="0 3 * * *", timezone="Asia/Tokyo"
    )
    assert stored_schedule(admin, job_id) == ("0 3 * * *", "Asia/Tokyo")


async def test_the_preview_follows_the_preset(admin: Browser) -> None:
    response = await admin.get(
        "/jobs/cron-preview", params={"cron_preset": "0 3 1 * *", "cron": "0 0 * * *"}
    )
    assert "03:00" in response.text and "00:00" not in response.text


async def test_a_zone_no_longer_listed_stays_selected(admin: Browser) -> None:
    job_id = await add_job(admin, "old-zone", schedule="1", cron_preset="0 3 * * *")
    admin.sql("UPDATE jobs SET timezone = 'Mars/Olympus' WHERE id = ?", (job_id,))
    page = (await admin.get(f"/jobs/{job_id}/edit")).text
    assert '<option value="Mars/Olympus" selected>Mars/Olympus (no longer listed)</option>' in page


@pytest.mark.parametrize(
    ("expr", "words"),
    [
        ("0 1 * * 0", "Every Sunday at 01:00"),
        ("0 3 * * *", "Every day at 03:00"),
        ("0 3 1 * *", "On the 1st of every month at 03:00"),
        ("0 */6 * * *", "Every 6 hours"),
        ("0 * * * *", "Every hour"),
        ("30 * * * 6,0", "Every hour at :30 on Saturday and Sunday"),
        ("*/15 * * * *", "Every 15 minutes"),
        ("* * * * *", "Every minute"),
        ("15 2 * * 1-5", "Every Monday to Friday at 02:15"),
        ("0 22 * * mon,wed,fri", "Every Monday, Wednesday and Friday at 22:00"),
        ("0 0,12 * * *", "Every day at 00:00 and 12:00"),
        ("0 9-17 * * 1-5", "Every hour from 09:00 to 17:00 on Monday to Friday"),
        ("0 4 1,15 * *", "On the 1st and 15th of every month at 04:00"),
        ("0 4 22 jan,jul *", "On the 22nd of January and July at 04:00"),
        ("0 4 * 6-8 7", "Every Sunday in June to August at 04:00"),
        ("0 4 * * 0-6", "Every day at 04:00"),
    ],
)
def test_a_cron_is_described_in_words(expr: str, words: str) -> None:
    assert scheduler.describe(expr) == words


@pytest.mark.parametrize(
    "expr", ["*/7 * * * *", "0 */5 * * *", "5/10 * * * *", "0 3 */2 * *", "0 3 1 * 1", "nonsense"]
)
def test_an_unusual_or_bad_cron_has_no_description(expr: str) -> None:
    assert scheduler.describe(expr) is None


# SEVERAL SCHEDULES


def rows(*specs: dict[str, str]) -> dict:
    """Form fields for schedule rows as the form sends them; "days" is a string of day
    digits (0 = Sunday), every day when left out."""
    defaults = {
        "sched_repeat": "days",
        "sched_time": "03:00",
        "sched_every": "6",
        "sched_minute": "0",
        "sched_dom": "1",
        "sched_cron": "",
    }
    form: dict = {"schedule": "1", "schedule_rows": "1", "sched_row": [], "sched_day": []}
    form |= {name: [] for name in FIELDS}
    for key, spec in enumerate(specs):
        form["sched_row"].append(str(key))
        for name, value in defaults.items():
            form[name].append(spec.get(name, value))
        form["sched_day"] += [f"{key}:{day}" for day in spec.get("days", "0123456")]
    return form


def test_several_lines_fire_on_any_of_them() -> None:
    now = datetime(2026, 11, 16, tzinfo=UTC)  # a Monday
    until = now + timedelta(days=3)
    both = trigger("0 3 * * *\n30 1 * * *", "UTC", until=until)
    fires = [f"{f:%a %H:%M}" for f in scheduler.next_fires(both, now, 4)]
    assert fires == ["Mon 01:30", "Mon 03:00", "Tue 01:30", "Tue 03:00"]
    # Two lines naming the same minute fire once.
    same = trigger("0 3 * * *\n0 3 * * 1", "UTC", until=until)
    assert [f"{f:%a}" for f in scheduler.next_fires(same, now, 2)] == ["Mon", "Tue"]
    with pytest.raises(CronError, match=re.escape(f"0 0 31 2 *: {NEVER}")):
        scheduler.checked("0 3 * * *\n0 0 31 2 *", "UTC", now)
    with pytest.raises(CronError, match="at most 10 schedules"):
        trigger("\n".join(["0 3 * * *"] * 11), "UTC")
    words = scheduler.describe("0 3 * * *\n0 12 * * 1-5")
    assert words == "Every day at 03:00; Every Monday to Friday at 12:00"
    assert scheduler.describe("0 3 * * *\n*/7 * * * *") is None


@pytest.mark.parametrize(
    ("line", "repeat", "canonical"),
    [
        ("0 3 * * *", "days", "0 3 * * *"),
        ("15 2 * * 1-5", "days", "15 2 * * 1,2,3,4,5"),
        ("0 4 * * sun", "days", "0 4 * * 0"),
        ("30 */6 * * *", "hours", "30 */6 * * *"),
        ("0 * * * 6,0", "hours", "0 * * * 0,6"),
        ("0 3 15 * *", "monthly", "0 3 15 * *"),
        ("0 3 31 * *", "cron", "0 3 31 * *"),
        ("*/15 * * * *", "cron", "*/15 * * * *"),
        ("0 */5 * * *", "cron", "0 */5 * * *"),
        ("0 9-17 * * *", "cron", "0 9-17 * * *"),
        ("0 4 * 6-8 *", "cron", "0 4 * 6-8 *"),
    ],
)
def test_a_stored_line_opens_as_the_row_that_shows_it(
    line: str, repeat: str, canonical: str
) -> None:
    row = Row.of(line)
    assert row.repeat == repeat and row.line() == canonical
    assert scheduler.describe(canonical) == scheduler.describe(line)


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (Row("days", days=[]), "Tick at least one day"),
        (Row("days", time="25:00"), "Enter a time of day"),
        (Row("days", time="3:00; rm"), "Enter a time of day"),
        (Row("hours", every="5"), "Choose every 1, 2"),
        (Row("hours", minute="60"), "minute past the hour"),
        (Row("monthly", dom="29"), "from 1 to 28"),
        (Row("cron", cron=" "), "Enter a cron expression"),
        (Row("weekly"), "Choose how often"),
    ],
)
def test_a_row_says_what_is_wrong(row: Row, message: str) -> None:
    with pytest.raises(CronError, match=message):
        row.line()


async def test_a_job_runs_on_every_one_of_its_schedules(admin: Browser) -> None:
    job_id = await add_job(admin, "twice", **rows({}, {"sched_time": "12:30", "days": "12345"}))
    assert stored_schedule(admin, job_id)[0] == "0 3 * * *\n30 12 * * 1,2,3,4,5"
    fire = admin.app.state.scheduler.next_run_time(job_id)
    assert fire is not None and f"{fire:%H:%M}" in ("03:00", "12:30")
    page = (await admin.get(f"/jobs/{job_id}")).text
    assert "Every day at 03:00; Every Monday to Friday at 12:30 (UTC). Next run" in page
    edit = (await admin.get(f"/jobs/{job_id}/edit")).text
    assert edit.count('name="sched_row"') == 2 and 'value="12:30"' in edit
    assert 'value="1:6" aria-label="Sat">' in edit
    assert 'value="1:5" aria-label="Fri" checked>' in edit
    manual = await add_job(admin, "by hand", **rows())
    assert stored_schedule(admin, manual)[0] is None


async def test_add_and_remove_send_the_form_back_unsaved(admin: Browser) -> None:
    form = {"name": "draft"} | rows({}, {"sched_time": "12:00"})
    added = await admin.post("/jobs", form | {"add_schedule": "1"})
    assert added.status_code == 200 and added.text.count('name="sched_row"') == 3
    removed = await admin.post("/jobs", form | {"remove_schedule": "0"})
    assert removed.status_code == 200 and removed.text.count('name="sched_row"') == 1
    assert 'value="12:00"' in removed.text and 'value="03:00"' not in removed.text
    job_id = await add_job(admin, "kept", **rows({}))
    edited = await admin.post(f"/jobs/{job_id}", form | {"name": "kept", "add_schedule": "1"})
    assert edited.status_code == 200 and edited.text.count('name="sched_row"') == 3
    assert admin.sql("SELECT name, cron FROM jobs") == [("kept", "0 3 * * *")]
    # An older client's long cron list is refused, never rendered row by row.
    many = "0 * * * *\n" * 2000  # under the 64 KiB body limit, urlencoded
    legacy = {"name": "long", "schedule": "1", "cron": many, "add_schedule": "1"}
    long = await admin.post("/jobs", legacy)
    assert long.status_code == 200 and long.text.count('name="sched_row"') == 11


async def test_the_preview_names_each_schedule_and_its_problems(admin: Browser) -> None:
    monthly = {"sched_repeat": "monthly", "sched_dom": "15"}
    hourly = {"sched_repeat": "hours", "sched_every": "12", "sched_minute": "5"}
    for specs, text in (
        ((monthly, hourly), "On the 15th of every month at 03:00; Every 12 hours at :05."),
        (({}, {"days": ""}), "Schedule 2: Tick at least one day of the week."),
        (({"sched_repeat": "cron", "sched_cron": "0 3 1 * 1"},), BOTH_DAYS),
        (({},) * 11, "at most 10 schedules"),
        ((), "runs only when started by hand"),
    ):
        response = await admin.get("/jobs/cron-preview", params=rows(*specs))
        assert response.status_code == 200 and text in response.text, specs


async def test_an_update_policy_takes_several_schedules(admin: Browser) -> None:
    host_id = add_host(admin, "policy-host")
    specs = ({"sched_time": "04:00", "days": "0"}, {"sched_repeat": "monthly", "sched_dom": "2"})
    created = await admin.post("/updates", policy_form(host_id) | rows(*specs))
    assert created.status_code == 303, created.text
    assert admin.sql("SELECT cron FROM update_policies") == [("0 4 * * 0\n0 3 2 * *",)]
    listed = (await admin.get("/updates")).text
    assert "Every Sunday at 04:00; On the 2nd of every month at 03:00" in listed
    empty = await admin.post("/updates", policy_form(host_id, name="none") | rows())
    assert empty.status_code == 422 and "Add a schedule." in empty.text
    more = policy_form(host_id, name="more") | rows() | {"add_schedule": "1"}
    added = await admin.post("/updates", more)
    assert added.status_code == 200 and added.text.count('name="sched_row"') == 1
