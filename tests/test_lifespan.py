import base64
import json
import logging
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

import drydock.main
from drydock.config import Settings
from drydock.models import Base
from tests.conftest import running

pytestmark = pytest.mark.anyio

SECOND_PROCESS = """
import asyncio, json
import asyncssh
import drydock.main as main
from drydock.config import load_settings
from drydock.hosts import ssh
from drydock.models import Host

hooks = []
main.run_startup_hooks = lambda app: hooks.append(1)
app = main.create_app(load_settings())
server_key = asyncssh.generate_private_key("ssh-ed25519")

async def go():
    async with app.router.lifespan_context(app):
        # A host edited through this process: only the primary may open its tunnel.
        host = Host(
            name="remote", kind="ssh", address="203.0.113.9", port=22, username="backup",
            enabled=True, known_host_line=ssh.known_host_line("203.0.113.9", 22, server_key),
        )
        ssh.generate_key(host, app.state.crypto)
        with app.state.sessionmaker() as db, db.begin():
            db.add(host)
        await app.state.hosts.reload(host.id)
        tunnels = len([t for t in asyncio.all_tasks() if t.get_name().startswith("ssh-host-")])
        await app.state.scheduler.rebuild()  # what a job edit through this process does
        print(json.dumps({
            "primary": app.state.primary, "hooks": len(hooks), "tunnels": tunnels,
            "scheduler": app.state.scheduler.running,
            "rclone": app.state.rclone.pid is not None,
        }))

asyncio.run(go())
"""


async def test_primary_process_runs_startup_hooks(settings: Settings, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(drydock.main, "run_startup_hooks", calls.append)
    async with running(settings) as browser:
        assert browser.app.state.primary is True
        assert calls == [browser.app]
        assert browser.app.state.scheduler.running


async def test_second_process_cannot_take_the_flock(settings: Settings, caplog) -> None:
    caplog.set_level(logging.INFO, logger="drydock")
    async with running(settings):
        env = os.environ | {
            "DRYDOCK_SECRET_KEY": "\n".join(
                base64.urlsafe_b64encode(k).decode() for k in settings.secret_keys
            ),
            "DRYDOCK_DATA_DIR": str(settings.data_dir),
            "DRYDOCK_BASE_URL": settings.base_url,
        }
        result = subprocess.run(
            [sys.executable, "-c", SECOND_PROCESS],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout.strip().splitlines()[-1])
    assert output == {
        "primary": False,
        "hooks": 0,
        "tunnels": 0,
        "scheduler": False,
        "rclone": False,
    }
    assert "ANOTHER DRYDOCK PROCESS HOLDS" in result.stderr


async def test_lock_is_released_on_shutdown(settings: Settings) -> None:
    async with running(settings) as browser:
        assert browser.app.state.primary
    async with running(settings) as browser:
        assert browser.app.state.primary


async def test_data_files_are_private(settings: Settings) -> None:
    async with running(settings):
        for name in ("drydock.db", "drydock.lock"):
            mode = stat.S_IMODE((settings.data_dir / name).stat().st_mode)
            assert mode == 0o600, name


async def test_sqlite_pragmas(admin) -> None:
    with admin.app.state.sessionmaker() as session:
        conn = session.connection()
        # Bound values (password hashes, CSRF tokens) stay out of logged exceptions.
        assert conn.engine.hide_parameters is True
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000


async def test_migration_matches_models(settings: Settings) -> None:
    async with running(settings):
        pass
    engine = create_engine(f"sqlite:///{Path(settings.data_dir) / 'drydock.db'}")
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
        collation = conn.exec_driver_sql(
            "SELECT sql FROM sqlite_master WHERE name = 'users'"
        ).scalar()
    engine.dispose()
    assert diff == []
    assert 'COLLATE "NOCASE"' in collation
