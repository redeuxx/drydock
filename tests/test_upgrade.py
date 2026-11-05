"""Upgrading a populated database from an earlier drydock version (tests/fixtures/upgrade).

Each fixture is a database that drydock itself wrote at that revision (tests/upgrade_fixture.py
says how). Migrating it must keep every row and ID, end at the head revision with the schema
the models describe, and leave an app that logs in, serves every page and decrypts every
stored secret with the same key.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from drydock.db import make_engine, migrate
from drydock.models import Base
from tests.conftest import make_settings, running
from tests.test_routes import GET_WRITE_EXEMPTIONS, api_routes, fill
from tests.upgrade_fixture import KEY, STORAGE_ROOT

pytestmark = pytest.mark.anyio

FIXTURES = sorted((Path(__file__).parent / "fixtures" / "upgrade").glob("*.sql"))
ENCRYPTED = {
    "hosts": "ssh_key_enc",
    "storage_targets": "config_enc",
    "notification_targets": "url_enc",
}


def head() -> str:
    cfg = Config()
    cfg.set_main_option("script_location", "drydock:migrations")
    return ScriptDirectory.from_config(cfg).get_current_head()


def rows(conn: sqlite3.Connection) -> dict[str, list[tuple]]:
    """Every row of drydock's tables, by table, primary key first. SQLite's own tables
    (sqlite_sequence) may change with a revision that adds a table."""
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
        " AND name != 'alembic_version' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {
        name: conn.execute(f'SELECT * FROM "{name}" ORDER BY 1, 2').fetchall()  # noqa: S608
        for (name,) in tables
    }


def test_the_head_revision_has_a_fixture() -> None:
    """So the next revision is tested against a database populated at this one."""
    assert head() in {path.stem for path in FIXTURES}


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda path: path.stem)
async def test_a_populated_database_upgrades(tmp_path: Path, fixture: Path) -> None:
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    db_path = data / "drydock.db"
    with closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(fixture.read_text())
        before = rows(conn)
        (old_revision,) = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    assert old_revision == fixture.stem

    engine = make_engine(db_path)
    try:
        migrate(engine)
        with engine.connect() as conn:
            assert compare_metadata(MigrationContext.configure(conn), Base.metadata) == []
    finally:
        engine.dispose()
    with closing(sqlite3.connect(db_path)) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone() == (head(),)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        after = rows(conn)
    for table, old in before.items():
        new = after[table]
        assert [r[0] for r in new] == [r[0] for r in old], f"{table} lost or renumbered rows"
        # A revision may add columns; the old ones keep their values.
        assert [r[: len(o)] for r, o in zip(new, old, strict=True)] == old, table

    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    settings = make_settings(
        data, DRYDOCK_SECRET_KEY=KEY, DRYDOCK_LOCAL_STORAGE_ROOTS=str(STORAGE_ROOT)
    )
    async with running(settings) as browser:
        assert (await browser.login("admin")).status_code == 303
        crypto = browser.app.state.crypto
        for table, column in ENCRYPTED.items():
            values = browser.sql(f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL')  # noqa: S608
            assert values, table
            for (value,) in values:
                crypto.decrypt(value)

        def first(statement: str) -> int:
            return browser.sql(statement)[0][0]

        ids = {
            # The local directory: listing the WebDAV target would go to the network.
            "storage_id": first("SELECT min(id) FROM storage_targets WHERE kind = 'local'"),
            "job_id": first("SELECT min(id) FROM jobs"),
            "hook_id": first("SELECT min(id) FROM hooks"),
            "run_id": first("SELECT min(id) FROM runs WHERE kind = 'backup'"),
            "restore_id": first("SELECT min(id) FROM runs WHERE kind = 'restore'"),
            "target_id": first("SELECT min(id) FROM notification_targets"),
        }
        viewer = first("SELECT id FROM users WHERE username = 'viewer'")
        hosts = [host_id for (host_id,) in browser.sql("SELECT id FROM hosts")]
        for method, path, _route in api_routes(browser.app):
            if method != "GET" or path in GET_WRITE_EXEMPTIONS:
                continue
            # /setup is gone once a superadmin exists; the log routes need a container.
            expected = 404 if path in ("/setup", "/logs/lines", "/logs/download") else 200
            for host_id in hosts if "{host_id}" in path else hosts[:1]:
                url = fill(path, viewer, host_id=host_id, container_id="a" * 64, **ids)
                response = await browser.get(url)
                assert response.status_code == expected, f"GET {url}: {response.status_code}"
