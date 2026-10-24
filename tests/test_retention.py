"""Retention: the selection tables, policy validation, the job form and its audit, and the
dispatcher deleting archives (and their catalog rows) after a stored backup."""

import json
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from drydock.db import make_engine
from drydock.jobs import retention
from drydock.jobs.dispatcher import RETENTION_CANCELLED
from drydock.jobs.retention import Policy, PolicyError, select_for_deletion
from drydock.jobs.runlog import RunLog
from drydock.storage.base import StorageError, archive_name
from drydock.storage.local import LocalStorage
from tests.conftest import Browser
from tests.test_jobs import add_host, add_job, add_storage
from tests.test_restore_schema import alembic_to
from tests.test_stacks_schema import add_job as add_job_row
from tests.test_stacks_schema import add_parents, sequence, table_sql, version

JOB = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
OTHER = "0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"
NOW = datetime(2026, 10, 20, 12, tzinfo=UTC)


def at(stamp: str, job: str = JOB) -> str:
    return archive_name(job, "web", datetime.fromisoformat(stamp).replace(tzinfo=UTC), False)


def kept(stamps: list[str], policy: Policy) -> set[str]:
    names = [at(s) for s in stamps]
    doomed = set(select_for_deletion(names, policy, NOW, JOB))
    return {s for s, n in zip(stamps, names, strict=True) if n not in doomed}


# SELECTION


@pytest.mark.parametrize("count", [0, 1, 3, 10])
@pytest.mark.parametrize("keep", [1, 3, 7])
def test_keep_last_keeps_min_n_count(count: int, keep: int) -> None:
    stamps = [(NOW - timedelta(hours=h)).replace(tzinfo=None).isoformat() for h in range(count)]
    survivors = kept(stamps, Policy(mode="last", keep_last=keep))
    assert survivors == set(stamps[:keep])  # the newest ones
    assert len(survivors) == min(keep, count)


GFS_TABLES = [
    # Day boundary: the newest backup of each UTC day.
    (
        {"daily": 2},
        [
            "2026-03-12T00:00:01",
            "2026-03-11T12:00:00",
            "2026-03-11T00:00:00",
            "2026-03-10T23:59:59",
        ],
        {"2026-03-12T00:00:01", "2026-03-11T12:00:00"},
    ),
    (
        {"daily": 3},
        [
            "2026-03-12T00:00:01",
            "2026-03-11T12:00:00",
            "2026-03-11T00:00:00",
            "2026-03-10T23:59:59",
        ],
        {"2026-03-12T00:00:01", "2026-03-11T12:00:00", "2026-03-10T23:59:59"},
    ),
    # Week boundary: ISO weeks start on Monday (2026-03-01 is a Sunday).
    (
        {"weekly": 2},
        [
            "2026-03-09T00:00:00",
            "2026-03-04T10:00:00",
            "2026-03-02T00:00:00",
            "2026-03-01T23:59:59",
        ],
        {"2026-03-09T00:00:00", "2026-03-04T10:00:00"},
    ),
    (
        {"weekly": 3},
        [
            "2026-03-09T00:00:00",
            "2026-03-04T10:00:00",
            "2026-03-02T00:00:00",
            "2026-03-01T23:59:59",
        ],
        {"2026-03-09T00:00:00", "2026-03-04T10:00:00", "2026-03-01T23:59:59"},
    ),
    # An ISO week across New Year: 2026-12-31 and 2027-01-01 are both in 2026-W53.
    (
        {"weekly": 2},
        ["2027-01-01T08:00:00", "2026-12-31T08:00:00", "2026-12-27T08:00:00"],
        {"2027-01-01T08:00:00", "2026-12-27T08:00:00"},
    ),
    # Month boundary.
    (
        {"monthly": 2},
        [
            "2026-03-01T01:00:00",
            "2026-02-15T00:00:00",
            "2026-02-01T00:00:00",
            "2026-01-31T23:00:00",
        ],
        {"2026-03-01T01:00:00", "2026-02-15T00:00:00"},
    ),
    # Year boundary.
    (
        {"yearly": 2},
        [
            "2026-06-01T00:00:00",
            "2026-01-01T00:00:00",
            "2025-12-31T23:59:59",
            "2025-01-01T00:00:00",
        ],
        {"2026-06-01T00:00:00", "2025-12-31T23:59:59"},
    ),
    # One backup fills a day and a week at once; the counts are of periods with a backup.
    (
        {"daily": 1, "weekly": 1},
        ["2026-03-11T12:00:00", "2026-03-11T06:00:00", "2026-03-10T06:00:00"],
        {"2026-03-11T12:00:00"},
    ),
    (
        {"daily": 2, "monthly": 3},
        [
            "2026-03-11T12:00:00",
            "2026-03-10T12:00:00",
            "2026-03-09T12:00:00",
            "2026-02-20T12:00:00",
            "2026-02-10T12:00:00",
            "2025-11-30T12:00:00",
            "2025-10-30T12:00:00",
        ],
        {
            "2026-03-11T12:00:00",
            "2026-03-10T12:00:00",
            "2026-02-20T12:00:00",
            "2025-11-30T12:00:00",
        },
    ),
]


@pytest.mark.parametrize(("counts", "stamps", "expected"), GFS_TABLES)
def test_gfs_tables(counts: dict[str, int], stamps: list[str], expected: set[str]) -> None:
    assert kept(stamps, Policy(mode="gfs", **counts)) == expected


def test_max_age_keeps_younger_and_the_cutoff_itself() -> None:
    stamps = ["2026-10-20T11:00:00", "2026-10-13T12:00:00", "2026-10-13T11:59:59"]
    assert kept(stamps, Policy(mode="age", max_age_days=7)) == set(stamps[:2])


@pytest.mark.parametrize(
    "policy",
    [
        Policy(mode="last", keep_last=1),
        Policy(mode="age", max_age_days=1),
        Policy(mode="gfs", yearly=1),
        Policy(mode="gfs", daily=1),
    ],
)
def test_the_newest_backup_always_survives(policy: Policy) -> None:
    # Every backup is years older than "now": an age policy alone would delete them all.
    stamps = ["2020-01-03T00:00:00", "2020-01-02T00:00:00", "2020-01-01T00:00:00"]
    assert "2020-01-03T00:00:00" in kept(stamps, policy)
    # A clock that went backwards: "now" before every backup changes nothing either.
    names = [at(s) for s in stamps]
    early = datetime(2000, 1, 1, tzinfo=UTC)
    assert at(stamps[0]) not in select_for_deletion(names, policy, early, JOB)


def test_nothing_outside_the_jobs_prefix_is_selected() -> None:
    old = "2020-01-01T00:00:00"
    mine = [at("2026-10-20T00:00:00"), at(old)]
    renamed = archive_name(JOB, "renamed job", datetime(2021, 1, 1, tzinfo=UTC), True)
    foreign = [
        at(old, job=OTHER),
        archive_name(OTHER, "web", datetime(2019, 1, 1, tzinfo=UTC), True),
        # A slug that holds this job's UUID, of another job: the UUID before the stamp counts.
        f"drydock-{JOB}-{OTHER}-20190101T000000Z.tar.zst",
        ".partial-" + "0" * 32,
        "notes.txt",
        f"drydock-web-{JOB}-20190101T000000Z.tar.zst.bak",
        f"drydock-web-{JOB}-20191301T000000Z.tar.zst",  # month 13
    ]
    doomed = select_for_deletion(
        [*mine, renamed, *foreign], Policy(mode="last", keep_last=1), NOW, JOB
    )
    assert doomed == [at(old), renamed]  # oldest first; a renamed job's archives are its own
    assert select_for_deletion(foreign, Policy(mode="last", keep_last=1), NOW, JOB) == []


# POLICIES


@pytest.mark.parametrize(
    "doc",
    [
        {"mode": "last", "keep_last": 0},
        {"mode": "last", "keep_last": -1},
        {"mode": "last", "keep_last": 1001},
        {"mode": "last", "keep_last": True},
        {"mode": "last", "keep_last": "7"},
        {"mode": "last", "keep_last": 7.0},
        {"mode": "age", "max_age_days": 0},
        {"mode": "gfs"},
        {"mode": "gfs", "daily": 0, "weekly": 0},
        {"mode": "gfs", "daily": -1, "weekly": 4},
        {"mode": "last", "keep_last": 7, "extra": 1},
        {"mode": "forever"},
        {"keep_last": 7},
        [],
        None,
    ],
)
def test_invalid_policies_are_rejected(doc: object) -> None:
    with pytest.raises(PolicyError):
        retention.from_dict(doc)
    with pytest.raises(PolicyError):
        retention.parse(json.dumps(doc))


def test_policy_round_trip_and_default() -> None:
    assert retention.parse(retention.DEFAULT_JSON) == Policy()
    assert Policy().keep_last == retention.DEFAULT_KEEP_LAST >= 1
    gfs = Policy(mode="gfs", daily=7, weekly=4)
    assert retention.parse(gfs.to_json()) == gfs
    assert gfs.to_dict() == {"mode": "gfs", "daily": 7, "weekly": 4, "monthly": 0, "yearly": 0}
    assert gfs.describe() == (
        "The newest backup of each of the last 7 days, 4 weeks. The newest backup always stays."
    )
    for text in ("", "{", "[1]", '{"mode": "last", "keep_last": 1e400}'):
        with pytest.raises(PolicyError):
            retention.parse(text)


# THE JOB FORM


@pytest.mark.anyio
async def test_job_form_stores_validates_and_audits_the_policy(admin: Browser) -> None:
    base = {"host_id": str(add_host(admin)), "storage_id": str(await add_storage(admin))}
    job_id = await add_job(admin, "default", **base)
    assert admin.sql("SELECT retention FROM jobs WHERE id = ?", (job_id,)) == [
        (retention.DEFAULT_JSON,)
    ]

    for bad, message in (
        ({"retention_mode": "last", "keep_last": "0"}, "Keep between 1 and 1000 backups."),
        ({"retention_mode": "last", "keep_last": ""}, "Keep between 1 and 1000 backups."),
        ({"retention_mode": "last", "keep_last": "-3"}, "Enter whole numbers"),
        ({"retention_mode": "last", "keep_last": "²"}, "Enter whole numbers"),
        ({"retention_mode": "age", "max_age_days": "0"}, "Keep backups for 1 to 36500 days."),
        ({"retention_mode": "gfs", "daily": "0", "weekly": ""}, "Keep at least one daily"),
        ({"retention_mode": "forever"}, "Choose how long to keep backups."),
    ):
        response = await admin.post(
            "/jobs",
            {
                "name": "bad",
                "host_id": base["host_id"],
                "target": "web",
                "storage_target_id": base["storage_id"],
                "scope": "config",
            }
            | bad,
        )
        assert response.status_code == 422 and message in response.text, bad
    assert admin.sql("SELECT COUNT(*) FROM jobs WHERE name = 'bad'") == [(0,)]

    # Only the chosen mode's numbers are read: junk in the others is ignored.
    gfs = {"retention_mode": "gfs", "daily": "7", "weekly": "4", "monthly": "", "yearly": "1"}
    gfs_id = await add_job(admin, "gfs", keep_last="junk", **gfs, **base)
    stored = admin.sql("SELECT retention FROM jobs WHERE id = ?", (gfs_id,))[0][0]
    assert json.loads(stored) == {"mode": "gfs", "daily": 7, "weekly": 4, "monthly": 0, "yearly": 1}
    page = await admin.get(f"/jobs/{gfs_id}")
    assert "The newest backup of each of the last 7 days, 4 weeks, 1 year." in page.text
    assert 'name="weekly" value="4"' in page.text

    response = await admin.post(
        f"/jobs/{job_id}",
        {
            "name": "default",
            "host_id": base["host_id"],
            "target": "web",
            "storage_target_id": base["storage_id"],
            "scope": "config",
            "encrypted": "1",
            "enabled": "1",
            "retention_mode": "age",
            "max_age_days": "30",
        },
    )
    assert response.status_code == 303, response.text
    details = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'job.update' AND target = ?",
        (f"job:{job_id}",),
    )
    assert [json.loads(d) for (d,) in details] == [
        {
            "retention": {
                "from": retention.DEFAULT_JSON,
                "to": '{"max_age_days": 30, "mode": "age"}',
            }
        }
    ]

    # An edit from a client that predates retention keeps the stored policy.
    response = await admin.post(
        f"/jobs/{job_id}",
        {
            "name": "default renamed",
            "host_id": base["host_id"],
            "target": "web",
            "storage_target_id": base["storage_id"],
            "scope": "config",
            "encrypted": "1",
            "enabled": "1",
        },
    )
    assert response.status_code == 303, response.text
    assert admin.sql("SELECT name, retention FROM jobs WHERE id = ?", (job_id,)) == [
        ("default renamed", '{"max_age_days": 30, "mode": "age"}')
    ]

    # A stored policy that is not valid is shown as such, on the summary and the edit form.
    admin.sql("UPDATE jobs SET retention = 'nonsense' WHERE id = ?", (job_id,))
    page = await admin.get(f"/jobs/{job_id}")
    assert page.status_code == 200 and "Not valid: nothing is deleted" in page.text
    assert "The stored retention policy is not valid" in page.text


# THE DISPATCHER


@pytest.mark.anyio
async def test_dispatcher_deletes_what_the_policy_drops(admin: Browser, tmp_path: Path) -> None:
    storage_id = await add_storage(admin)
    job_id = await add_job(admin, "web", storage_id=str(storage_id))
    admin.sql("UPDATE jobs SET retention = ? WHERE id = ?", (Policy(keep_last=2).to_json(), job_id))
    job_uuid = admin.sql("SELECT uuid FROM jobs WHERE id = ?", (job_id,))[0][0]
    root = admin.settings.local_storage_roots[0]
    day = datetime(2026, 10, 1, tzinfo=UTC)
    names = [archive_name(job_uuid, "web", day + timedelta(days=d), True) for d in range(5)]
    other = archive_name(str(uuid.uuid4()), "web", day - timedelta(days=30), True)
    for name in [*names, other]:
        (root / name).write_bytes(b"x")
        admin.sql(
            "INSERT INTO backups (job_id, storage_target_id, name, size, sha256, signed,"
            " encrypted, created_at) VALUES (?, ?, ?, 1, ?, 1, 1, '2026-10-01 00:00:00')",
            (job_id, storage_id, name, "0" * 64),
        )
    # An open restore of the oldest archive keeps it.
    admin.sql(
        "INSERT INTO runs (kind, status, stopped_containers_json, archive_name, created_at)"
        " VALUES ('restore', 'awaiting_confirmation', '[]', ?, '2026-10-01 00:00:00')",
        (names[0],),
    )
    dispatcher = admin.app.state.dispatcher
    storage = LocalStorage(root, admin.settings)
    plan = SimpleNamespace(
        job_id=job_id, run_id=99, storage_target_id=storage_id, job=SimpleNamespace(uuid=job_uuid)
    )
    run_log = RunLog(tmp_path / "run.log")
    go = threading.Event()

    # The archive just stored survives even when the policy would drop it (an older stamp).
    assert dispatcher._retain(plan, storage, names[1], go, run_log) is None
    left = {p.name for p in root.iterdir()}
    assert left == {names[0], names[1], names[3], names[4], other}
    assert {n for (n,) in admin.sql("SELECT name FROM backups")} == left
    log_text = (tmp_path / "run.log").read_text()
    assert f"Retention: deleted {names[2]}." in log_text
    assert f"Retention: kept {names[0]}, an open restore uses it." in log_text
    audited = admin.sql(
        "SELECT actor, target, details FROM audit_events WHERE action = 'backup.retention_delete'"
    )
    assert [(a, t, json.loads(d)["archive"]) for a, t, d in audited] == [
        (None, f"job:{job_id}", names[2])
    ]

    # A policy that is not valid fails retention and deletes nothing.
    admin.sql("UPDATE jobs SET retention = 'nonsense' WHERE id = ?", (job_id,))
    assert dispatcher._retain(plan, storage, names[4], go, run_log) == (
        "The retention policy is not valid."
    )
    assert {p.name for p in root.iterdir()} == left

    # A cancel stops it before the next deletion.
    admin.sql("UPDATE jobs SET retention = ? WHERE id = ?", (Policy(keep_last=1).to_json(), job_id))
    cancelled = threading.Event()
    cancelled.set()
    assert dispatcher._retain(plan, storage, names[4], cancelled, run_log) == RETENTION_CANCELLED
    assert {p.name for p in root.iterdir()} == left

    # An archive that cannot be deleted keeps its row and does not stop the others.
    class Stuck(LocalStorage):
        def delete(self, name: str) -> None:
            if name == names[1]:
                raise StorageError(f"{name} cannot be deleted.")
            super().delete(name)

    stuck = Stuck(root, admin.settings)
    assert dispatcher._retain(plan, stuck, names[4], go, run_log) == (
        f"1 archive could not be deleted. {names[1]} cannot be deleted."
    )
    left = {names[0], names[1], names[4], other}
    assert {p.name for p in root.iterdir()} == left
    assert {n for (n,) in admin.sql("SELECT name FROM backups")} == left

    # An archive already gone (removed meanwhile) still loses its catalog row.
    (root / names[1]).unlink()
    dispatcher._delete_archive(plan, storage, names[1], run_log)
    assert {n for (n,) in admin.sql("SELECT name FROM backups")} == left - {names[1]}
    audited = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'backup.retention_delete' ORDER BY id"
    )
    assert [json.loads(d)["archive"] for (d,) in audited] == [names[2], names[3], names[1]]


# MIGRATION


def test_migration_0006_adds_the_default_policy_and_downgrades(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0005")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            add_job_row(conn, 1)
            add_job_row(conn, 2)
            conn.execute("DELETE FROM jobs WHERE id = 2")
            conn.commit()
        alembic_to(engine, "head")
        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute("SELECT id, retention FROM jobs").fetchall() == [
                (1, retention.DEFAULT_JSON)
            ]
            assert retention.parse(retention.DEFAULT_JSON) == Policy()
            assert sequence(conn, "jobs") == [(2,)]
        alembic_to(engine, "0005", down=True)
        with closing(sqlite3.connect(path)) as conn:
            assert "retention" not in (table_sql(conn, "jobs") or "")
            assert conn.execute("SELECT id FROM jobs").fetchall() == [(1,)]
            assert sequence(conn, "jobs") == [(2,)]
            assert version(conn) == [("0005",)]
    finally:
        engine.dispose()


def test_gfs_days_follow_the_jobs_time_zone() -> None:
    from zoneinfo import ZoneInfo

    # 22:30 and 23:30 UTC on 2026-03-10 are one UTC day, but 23:30 and 00:30 in Berlin.
    stamps = ["2026-03-10T23:30:00", "2026-03-10T22:30:00"]
    names = [at(s) for s in stamps]
    policy = Policy(mode="gfs", daily=2)
    assert select_for_deletion(names, policy, NOW, JOB) == [names[1]]
    assert select_for_deletion(names, policy, NOW, JOB, ZoneInfo("Europe/Berlin")) == []


@pytest.mark.anyio
async def test_dispatcher_gfs_days_use_the_jobs_time_zone(admin: Browser, tmp_path: Path) -> None:
    storage_id = await add_storage(admin)
    job_id = await add_job(admin, "web", storage_id=str(storage_id))
    policy = Policy(mode="gfs", daily=2).to_json()
    admin.sql("UPDATE jobs SET retention = ? WHERE id = ?", (policy, job_id))
    job_uuid = admin.sql("SELECT uuid FROM jobs WHERE id = ?", (job_id,))[0][0]
    root = admin.settings.local_storage_roots[0]
    # One UTC day, but two days in Berlin (23:30 and 00:30 local).
    names = [
        archive_name(job_uuid, "web", datetime(2026, 3, 10, hour, 30, tzinfo=UTC), True)
        for hour in (22, 23)
    ]
    for name in names:
        (root / name).write_bytes(b"x")
    dispatcher = admin.app.state.dispatcher
    storage = LocalStorage(root, admin.settings)
    plan = SimpleNamespace(
        job_id=job_id, run_id=99, storage_target_id=storage_id, job=SimpleNamespace(uuid=job_uuid)
    )
    run_log = RunLog(tmp_path / "run.log")
    go = threading.Event()

    admin.sql("UPDATE jobs SET timezone = 'Europe/Berlin' WHERE id = ?", (job_id,))
    assert dispatcher._retain(plan, storage, names[1], go, run_log) is None
    assert {p.name for p in root.iterdir()} == set(names)
    # A hand-edited zone fails retention with a fixed message, deleting nothing.
    admin.sql("UPDATE jobs SET timezone = 'Europe' WHERE id = ?", (job_id,))
    assert dispatcher._retain(plan, storage, names[1], go, run_log) == (
        "The job's time zone is not known."
    )
    # No zone: TZ (UTC in tests), so both are one day and the older one goes.
    admin.sql("UPDATE jobs SET timezone = NULL WHERE id = ?", (job_id,))
    assert dispatcher._retain(plan, storage, names[1], go, run_log) is None
    assert {p.name for p in root.iterdir()} == {names[1]}
