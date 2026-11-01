import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
import sqlalchemy.exc
from sqlalchemy import Engine, event

from drydock import db as db_module
from drydock.config import Settings
from drydock.db import make_engine, make_sessionmaker
from drydock.models import Backup, Hook, Host, Job, Run, StorageTarget
from tests.conftest import running
from tests.test_restore_schema import alembic_to

pytestmark = pytest.mark.anyio

INSERT_HOST = "INSERT INTO hosts (name, kind, enabled) VALUES (?, 'local', 1)"
INSERT_STORAGE = (
    "INSERT INTO storage_targets (name, kind, config_enc, enabled, created_at)"
    " VALUES (?, 'local', 'x', 1, '2026-10-15 00:00:00')"
)
INSERT_JOB = (
    "INSERT INTO jobs (uuid, name, host_id, storage_target_id, target_type, target, scope,"
    " consistency_mode, images_reference_only_if_pullable, encrypted, enabled, created_at,"
    " updated_at) VALUES (?, ?, 1, 1, ?, 'web', 'all', ?, 0, 0, 1,"
    " '2026-10-15 00:00:00', '2026-10-15 00:00:00')"
)
INSERT_RUN = (
    "INSERT INTO runs (job_id, kind, status, stopped_containers_json, created_at)"
    " VALUES (?, 'backup', 'done', '[]', '2026-10-15 00:00:00')"
)
INSERT_BACKUP = (
    "INSERT INTO backups (job_id, storage_target_id, name, size, sha256, signed, encrypted,"
    " created_at) VALUES (?, 1, ?, 1, 'x', 1, 0, '2026-10-15 00:00:00')"
)
CHECKS_0005 = (
    "target_type IN ('container', 'stack')",
    "consistency_mode IN ('stop', 'pause', 'live')",
)
CHECKS_0004 = ("target_type IN ('container')", "consistency_mode IN ('stop')")


# HELPERS


def table_sql(conn: sqlite3.Connection, table: str) -> str | None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return None if row is None else row[0]


def index_names(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ?", (table,)
    )
    return {name for (name,) in rows}


def sequence(conn: sqlite3.Connection, table: str) -> list[tuple[int]]:
    return conn.execute("SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)).fetchall()


def version(conn: sqlite3.Connection) -> list[tuple[str]]:
    return conn.execute("SELECT version_num FROM alembic_version").fetchall()


def add_job(conn: sqlite3.Connection, n: int, target_type: str = "container", mode: str = "stop"):
    return conn.execute(INSERT_JOB, (f"uuid-{n}", f"job-{n}", target_type, mode)).lastrowid


def add_parents(conn: sqlite3.Connection) -> None:
    conn.execute(INSERT_HOST, ("local",))
    conn.execute(INSERT_STORAGE, ("store",))


def foreign_keys(engine: Engine) -> int:
    with engine.connect() as connection:
        return connection.exec_driver_sql("PRAGMA foreign_keys").scalar()


def add_orm_parents(engine: Engine) -> tuple[int, int]:
    with make_sessionmaker(engine)() as db, db.begin():
        host = Host(name="local", kind="local", docker_url="tcp://proxy:2375")
        storage = StorageTarget(name="store", kind="local", config_enc="x")
        db.add_all([host, storage])
    return host.id, storage.id


def new_job(host_id: int, storage_id: int, n: int, **fields) -> Job:
    return Job(
        uuid=f"uuid-{n}",
        name=f"job-{n}",
        host_id=host_id,
        storage_target_id=storage_id,
        target="web",
        scope="all",
        **fields,
    )


# SCHEMA AT HEAD


async def test_jobs_checks_allow_stacks_and_every_mode(settings: Settings) -> None:
    async with running(settings) as browser:
        with closing(browser.db()) as conn:
            sql = table_sql(conn, "jobs")
            assert sql is not None
            for check in CHECKS_0005:
                assert check in sql
            assert "AUTOINCREMENT" in sql
            assert {"ix_jobs_host_id", "ix_jobs_storage_target_id"} <= index_names(conn, "jobs")
            columns = {row[1]: row for row in conn.execute("PRAGMA table_info(jobs)")}
            for name in ("pre_hooks", "post_hooks"):
                assert columns[name][3] == 1  # NOT NULL
                assert columns[name][4] == "'[]'"
            assert "DEFAULT '[]'" in sql

            add_parents(conn)
            for n, (target_type, mode) in enumerate((("stack", "pause"), ("container", "live"))):
                add_job(conn, n, target_type, mode)
            for n, (target_type, mode) in enumerate((("swarm", "stop"), ("stack", "freeze"))):
                with pytest.raises(sqlite3.IntegrityError):
                    add_job(conn, 10 + n, target_type, mode)
            conn.commit()
            rows = conn.execute("SELECT pre_hooks, post_hooks FROM jobs").fetchall()
            assert rows == [("[]", "[]"), ("[]", "[]")]


async def test_hooks_table_and_timeout_check(settings: Settings) -> None:
    async with running(settings) as browser:
        sessionmaker = browser.app.state.sessionmaker
        with sessionmaker() as db, db.begin():
            host = Host(name="local", kind="local", docker_url="tcp://proxy:2375")
            db.add(host)
        with sessionmaker() as db, db.begin():
            hook = Hook(name="Flush", host_id=host.id, container="web", argv_json='["sync"]')
            db.add(hook)
        with sessionmaker() as db:
            stored = db.get(Hook, hook.id)
            assert stored is not None
            assert (stored.user, stored.workdir, stored.timeout_s) == ("", "", 300)
            assert stored.project is None
            assert stored.log_output is False
            assert stored.argv_json == '["sync"]'
            assert stored.created_at.tzinfo is not None

        bad = (
            {"name": "zero", "host_id": host.id, "timeout_s": 0},
            {"name": "long", "host_id": host.id, "timeout_s": 3601},
            {"name": "flush", "host_id": host.id},  # NOCASE unique
            {"name": "nohost", "host_id": None},
        )
        for fields in bad:
            with pytest.raises(sqlalchemy.exc.IntegrityError), sessionmaker() as db, db.begin():
                db.add(Hook(container="web", argv_json="[]", **fields))
        with sessionmaker() as db, db.begin():
            db.add(
                Hook(name="max", host_id=host.id, container="web", argv_json="[]", timeout_s=3600)
            )

        with pytest.raises(sqlalchemy.exc.IntegrityError), sessionmaker() as db, db.begin():
            db.delete(db.get(Host, host.id))  # RESTRICT while a hook names it

        with closing(browser.db()) as conn:
            sql = table_sql(conn, "hooks")
            assert sql is not None
            assert "AUTOINCREMENT" in sql
            assert "ck_hooks_timeout" in sql
            assert "ON DELETE RESTRICT" in sql
            assert "ix_hooks_host_id" in index_names(conn, "hooks")
            assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone() == (1,)


async def test_runs_gain_paused_containers_json(settings: Settings) -> None:
    async with running(settings) as browser:
        with browser.app.state.sessionmaker() as db, db.begin():
            run = Run(kind="backup", status="queued")
            db.add(run)
        with closing(browser.db()) as conn:
            row = conn.execute(
                "SELECT paused_containers_json, stopped_containers_json FROM runs WHERE id = ?",
                (run.id,),
            ).fetchone()
            assert row == ("[]", "[]")
            conn.execute(
                "INSERT INTO runs (kind, status, stopped_containers_json, created_at)"
                " VALUES ('backup', 'done', '[]', '2026-10-15 00:00:00')"
            )
            conn.commit()
            assert conn.execute("SELECT paused_containers_json FROM runs").fetchall() == [
                ("[]",),
                ("[]",),
            ]


# UPGRADE


def test_upgrade_keeps_job_links_and_ids(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0004")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            for n in range(1, 4):
                add_job(conn, n)
            conn.execute("DELETE FROM jobs WHERE id = 3")
            conn.execute(INSERT_RUN, (1,))
            conn.execute(INSERT_RUN, (1,))
            conn.execute("DELETE FROM runs WHERE id = 2")  # seq above max(id): a rebuild shows
            conn.execute(INSERT_BACKUP, (1, "a.tar"))
            conn.commit()
            runs_sequence = sequence(conn, "runs")
            assert runs_sequence == [(2,)]

        alembic_to(engine, "head")

        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute("SELECT job_id FROM runs").fetchall() == [(1,)]
            assert conn.execute("SELECT job_id FROM backups").fetchall() == [(1,)]
            assert add_job(conn, 4) == 4
            conn.commit()
            sql = table_sql(conn, "jobs")
            assert sql is not None
            for check in CHECKS_0005:
                assert check in sql
            assert "AUTOINCREMENT" in sql
            assert {"ix_jobs_host_id", "ix_jobs_storage_target_id"} <= index_names(conn, "jobs")
            old = conn.execute("SELECT pre_hooks, post_hooks FROM jobs WHERE id = 1").fetchone()
            assert old == ("[]", "[]")
            assert sequence(conn, "runs") == runs_sequence
            assert conn.execute(INSERT_RUN, (1,)).lastrowid == 3
            conn.commit()
            assert version(conn) == [("0011",)]
        assert foreign_keys(engine) == 1
    finally:
        engine.dispose()


def test_upgrade_of_emptied_jobs_keeps_sequence(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0004")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            for n in range(2):
                add_job(conn, n)
            conn.execute("DELETE FROM jobs")
            conn.commit()

        alembic_to(engine, "head")

        with closing(sqlite3.connect(path)) as conn:
            assert sequence(conn, "jobs") == [(2,)]
            assert add_job(conn, 5) == 3
            conn.commit()
    finally:
        engine.dispose()


# FOREIGN KEY CHECK AND ONE TRANSACTION


def test_migration_with_a_dangling_link_aborts(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0004")
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute(INSERT_RUN, (99,))
            conn.commit()
            jobs_before = table_sql(conn, "jobs")

        with pytest.raises(RuntimeError, match="foreign keys"):
            alembic_to(engine, "head")

        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [("0004",)]
            assert table_sql(conn, "jobs") == jobs_before
            assert table_sql(conn, "hooks") is None
            runs = table_sql(conn, "runs")
            assert runs is not None
            assert "paused_containers_json" not in runs
            assert conn.execute("SELECT job_id FROM runs").fetchall() == [(99,)]
        assert foreign_keys(engine) == 1
    finally:
        engine.dispose()


def test_upgrade_from_0003_runs_both_revisions_in_one_transaction(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0003")
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute(INSERT_RUN, (99,))
            conn.commit()
            runs_before = table_sql(conn, "runs")

        with pytest.raises(RuntimeError, match="foreign keys"):
            alembic_to(engine, "head")

        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [("0003",)]
            assert table_sql(conn, "runs") == runs_before  # 0004's rebuild rolled back too
        assert foreign_keys(engine) == 1
    finally:
        engine.dispose()


def test_startup_without_pending_migrations_skips_the_check(tmp_path: Path) -> None:
    engine = make_engine(tmp_path / "schema.db")
    statements: list[str] = []

    def record(_conn, _cursor, statement, _params, _context, _many) -> None:
        statements.append(statement)

    try:
        alembic_to(engine, "0004")
        event.listen(engine, "before_cursor_execute", record)
        db_module.migrate(engine)
        assert "PRAGMA foreign_key_check" in statements  # 0005 ran, so the check ran

        statements.clear()
        db_module.migrate(engine)
        assert statements  # the listener still sees what migrate executes
        assert "PRAGMA foreign_key_check" not in statements
    finally:
        event.remove(engine, "before_cursor_execute", record)
        engine.dispose()


# DOWNGRADE


def test_downgrade_drops_stack_jobs_and_keeps_ids(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "head")
        host_id, storage_id = add_orm_parents(engine)
        with make_sessionmaker(engine)() as db, db.begin():
            container_job = new_job(host_id, storage_id, 1, consistency_mode="live")
            stack_job = new_job(
                host_id, storage_id, 2, target_type="stack", consistency_mode="pause"
            )
            db.add_all([container_job, stack_job])
        with make_sessionmaker(engine)() as db, db.begin():
            db.add_all(
                [
                    Run(job_id=container_job.id, kind="backup", status="done"),
                    Run(job_id=stack_job.id, kind="backup", status="done"),
                    Backup(
                        job_id=stack_job.id,
                        storage_target_id=storage_id,
                        name="stack.tar",
                        size=1,
                        sha256="x",
                    ),
                    Hook(name="flush", host_id=host_id, container="web", argv_json="[]"),
                ]
            )
        assert (container_job.id, stack_job.id) == (1, 2)
        with closing(sqlite3.connect(path)) as conn:
            conn.execute(INSERT_RUN, (1,))
            conn.execute("DELETE FROM runs WHERE id = 3")  # seq above max(id): a rebuild shows
            conn.commit()
            runs_sequence = sequence(conn, "runs")
            assert runs_sequence == [(3,)]

        alembic_to(engine, "0004", down=True)

        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [("0004",)]
            assert conn.execute("SELECT id, consistency_mode FROM jobs").fetchall() == [(1, "stop")]
            assert conn.execute("SELECT id, job_id FROM runs ORDER BY id").fetchall() == [
                (1, 1),
                (2, None),
            ]
            assert conn.execute("SELECT job_id FROM backups").fetchall() == [(None,)]
            assert table_sql(conn, "hooks") is None
            runs = table_sql(conn, "runs")
            assert runs is not None
            assert "paused_containers_json" not in runs
            assert {"ix_runs_job_id", "ix_runs_status"} <= index_names(conn, "runs")
            assert sequence(conn, "runs") == runs_sequence
            assert conn.execute(INSERT_RUN, (1,)).lastrowid == 4
            jobs = table_sql(conn, "jobs")
            assert jobs is not None
            for check in CHECKS_0004:
                assert check in jobs
            assert "pre_hooks" not in jobs
            assert "post_hooks" not in jobs
            assert "AUTOINCREMENT" in jobs
            assert {"ix_jobs_host_id", "ix_jobs_storage_target_id"} <= index_names(conn, "jobs")
            assert add_job(conn, 3) == 3
            conn.commit()
        assert foreign_keys(engine) == 1
    finally:
        engine.dispose()


def test_downgrade_refuses_while_a_run_lists_paused_containers(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "head")
        with closing(sqlite3.connect(path)) as conn:
            conn.execute(
                "INSERT INTO runs (kind, status, stopped_containers_json, paused_containers_json,"
                " created_at) VALUES ('backup', 'running', '[]', '[{\"id\": \"abc\"}]',"
                " '2026-10-15 00:00:00')"
            )
            conn.execute(INSERT_RUN, (None,))  # a finished run alone never blocks
            conn.commit()

        with pytest.raises(RuntimeError, match="paused containers"):
            alembic_to(engine, "0004", down=True)

        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [("0011",)]
            runs = table_sql(conn, "runs")
            assert runs is not None
            assert "paused_containers_json" in runs
            assert table_sql(conn, "hooks") is not None
            conn.execute("UPDATE runs SET status = 'interrupted' WHERE status = 'running'")
            conn.commit()
        assert foreign_keys(engine) == 1

        alembic_to(engine, "0004", down=True)  # recovery has finished the run, so it may go
        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [("0004",)]
    finally:
        engine.dispose()
