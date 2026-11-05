import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

from drydock.config import Settings
from drydock.db import make_engine, make_sessionmaker
from drydock.models import Run
from tests.conftest import running

pytestmark = pytest.mark.anyio

INSERT_RUN = (
    "INSERT INTO runs (kind, status, stopped_containers_json, created_at)"
    " VALUES (?, ?, '[]', '2026-10-14 00:00:00')"
)


# HELPERS


def alembic_to(engine: Engine, revision: str, *, down: bool = False) -> None:
    """Moves the schema the way db.migrate does: through drydock's own connection."""
    cfg = Config()
    cfg.set_main_option("script_location", "drydock:migrations")
    with engine.connect() as connection:
        cfg.attributes["connection"] = connection
        if down:
            command.downgrade(cfg, revision)
        else:
            command.upgrade(cfg, revision)
        connection.commit()


def runs_sql(conn: sqlite3.Connection) -> str:
    return conn.execute("SELECT sql FROM sqlite_master WHERE name = 'runs'").fetchone()[0]


def index_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'runs'")
    return {name for (name,) in rows}


# SCHEMA AT HEAD


async def test_runs_checks_allow_restore_kind_and_new_statuses(settings: Settings) -> None:
    async with running(settings) as browser:
        with closing(browser.db()) as conn:
            sql = runs_sql(conn)
            assert "kind IN ('backup', 'restore'" in sql  # and 'update' since 0017
            assert "'verifying'" in sql
            assert "'awaiting_confirmation'" in sql
            assert "AUTOINCREMENT" in sql
            assert "REFERENCES jobs" in sql
            assert "ON DELETE SET NULL" in sql
            assert {"ix_runs_job_id", "ix_runs_status"} <= index_names(conn)

        with browser.app.state.sessionmaker() as db, db.begin():
            run = Run(kind="restore", job_id=None, status="awaiting_confirmation")
            db.add(run)
        with browser.app.state.sessionmaker() as db:
            stored = db.get(Run, run.id)
            assert stored is not None
            assert stored.job_id is None
            assert stored.plan is None
            assert stored.restore_originals_json == "{}"

        with closing(browser.db()) as conn:
            for kind, status in (("nope", "queued"), ("backup", "bogus")):
                with pytest.raises(sqlite3.IntegrityError):
                    conn.execute(INSERT_RUN, (kind, status))


# UPGRADE AND DOWNGRADE


def test_upgrade_keeps_existing_rows_and_ids(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0003")
        with closing(sqlite3.connect(path)) as conn:
            for _ in range(3):
                conn.execute(INSERT_RUN, ("backup", "done"))
            conn.execute("DELETE FROM runs WHERE id IN (2, 3)")
            conn.commit()

        alembic_to(engine, "head")

        with closing(sqlite3.connect(path)) as conn:
            new_id = conn.execute(INSERT_RUN, ("backup", "queued")).lastrowid
            conn.commit()
            assert new_id == 4
            old = conn.execute(
                "SELECT kind, status, restore_originals_json, plan FROM runs WHERE id = 1"
            ).fetchone()
            assert old == ("backup", "done", "{}", None)
            assert {"ix_runs_job_id", "ix_runs_status"} <= index_names(conn)
            assert "AUTOINCREMENT" in runs_sql(conn)
    finally:
        engine.dispose()


def test_downgrade_removes_restore_rows_without_reusing_ids(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "head")
        with make_sessionmaker(engine)() as db, db.begin():
            db.add(Run(kind="backup", status="done"))
        with make_sessionmaker(engine)() as db, db.begin():
            db.add(Run(kind="restore", status="awaiting_confirmation"))

        alembic_to(engine, "0003", down=True)

        with closing(sqlite3.connect(path)) as conn:
            rows = conn.execute("SELECT id, kind FROM runs").fetchall()
            assert rows == [(1, "backup")]
            sql = runs_sql(conn)
            assert "kind IN ('backup')" in sql
            assert "verifying" not in sql
            assert "restore_originals_json" not in sql
            assert {"ix_runs_job_id", "ix_runs_status"} <= index_names(conn)
            new_id = conn.execute(INSERT_RUN, ("backup", "queued")).lastrowid
            conn.commit()
            assert new_id == 3
    finally:
        engine.dispose()


# EMPTY TABLE ACROSS THE REBUILD
# Copying zero rows still leaves the rebuilt table a sequence row at 0, so the saved value
# has to win over it or the next run would get ID 1 again.


def runs_sequence_rows(conn: sqlite3.Connection) -> list[tuple[int]]:
    return conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'runs'").fetchall()


def test_upgrade_of_emptied_runs_keeps_sequence(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0003")
        with closing(sqlite3.connect(path)) as conn:
            for _ in range(2):
                conn.execute(INSERT_RUN, ("backup", "done"))
            conn.execute("DELETE FROM runs")
            conn.commit()

        alembic_to(engine, "head")

        with closing(sqlite3.connect(path)) as conn:
            assert runs_sequence_rows(conn) == [(2,)]
            new_id = conn.execute(INSERT_RUN, ("backup", "queued")).lastrowid
            conn.commit()
            assert new_id == 3
    finally:
        engine.dispose()


def test_downgrade_of_restore_only_runs_keeps_sequence(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "head")
        with make_sessionmaker(engine)() as db, db.begin():
            db.add(Run(kind="restore", status="running"))

        alembic_to(engine, "0003", down=True)

        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute("SELECT COUNT(*) FROM runs").fetchone() == (0,)
            assert runs_sequence_rows(conn) == [(1,)]
            new_id = conn.execute(INSERT_RUN, ("backup", "queued")).lastrowid
            conn.commit()
            assert new_id == 2
    finally:
        engine.dispose()


def test_restore_sequence_inserts_missing_row(tmp_path: Path) -> None:
    """Covers the fallback for a rebuild that leaves no sequence row at all."""
    cfg = Config()
    cfg.set_main_option("script_location", "drydock:migrations")
    migration = ScriptDirectory.from_config(cfg).get_revision("0004").module
    path = tmp_path / "seq.db"
    engine = make_engine(path)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, x INTEGER)"
            )
            migration.restore_sequence(connection, None)
            migration.restore_sequence(connection, 5)

        with closing(sqlite3.connect(path)) as conn:
            assert runs_sequence_rows(conn) == [(5,)]
            assert conn.execute("INSERT INTO runs (x) VALUES (1)").lastrowid == 6
    finally:
        engine.dispose()
