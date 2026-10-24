"""Schedules: cron normalization, previews across DST, the job form, rebuilding without a
restart, fires missed while drydock was down or late while it ran, and no overlap with
manual runs. The backup itself is test_jobs' blocking stand-in."""

import sqlite3
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from anyio import sleep as anyio_sleep
from apscheduler.events import EVENT_JOB_MISSED

from drydock.config import Settings
from drydock.db import make_engine
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.jobs import scheduler
from drydock.jobs.scheduler import BOTH_DAYS, NEVER, CronError, Scheduler, normalize, trigger
from drydock.models import utcnow
from drydock.routes.jobs import fire_text
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
    for name in ("Mars/Olympus", "../../etc/passwd", "/etc/localtime", ""):
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
    """As the README says: a skipped time runs an hour later, a repeated one twice."""
    cron = trigger("30 2 * * *", "Europe/Berlin")
    spring = scheduler.next_fires(cron, datetime(2026, 3, 29, tzinfo=UTC), 1)
    assert [f.astimezone(UTC).strftime("%m-%d %H:%M") for f in spring] == ["03-29 01:30"]
    autumn = scheduler.next_fires(cron, datetime(2026, 10, 25, tzinfo=UTC), 2)
    assert [f.astimezone(UTC).strftime("%m-%d %H:%M") for f in autumn] == [
        "10-25 00:30",
        "10-25 01:30",
    ]


def test_a_schedule_that_never_runs_is_refused_quickly() -> None:
    now = datetime(2026, 10, 20, tzinfo=UTC)
    for expr in ("0 0 31 2 *", "0 0 31 2,4,6,9,11 *", "0 0 30 2 *"):
        started = time.perf_counter()
        with pytest.raises(CronError, match="never runs"):
            scheduler.checked(expr, "UTC", now)
        assert time.perf_counter() - started < 0.05, expr  # unbounded: up to 0.2 s each
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
    assert 'name="schedule" value="1"' in (await admin.get(f"/jobs/{job_id}")).text
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
    assert f"0 3 * * 0 (America/New_York). Next run {fire_text(first)}." in page.text

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
    assert "30 4 * * * (UTC). The job is disabled." in page.text
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
        assert "0 3 * * * (Asia/Tokyo). Next run" in page.text and "JST (18:00 UTC)" in page.text
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
