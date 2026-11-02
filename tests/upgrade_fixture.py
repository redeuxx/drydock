"""Writes a populated drydock database as SQL, for tests/test_upgrade.py.

Run it in the tests container with the drydock version to capture checked out, once per
release (or at an older commit, with this file copied in):

    python -m tests.upgrade_fixture tests/fixtures/upgrade <commit>

It writes <revision>.sql there, named after the alembic revision of the database it made.

The rows are made through the app's own routes where a route exists without contacting a
host or a storage server, and through its models for runs, the catalog and uploads, so
every encrypted and JSON column holds what that version writes. Everything is encrypted
with KEY; the users' password is tests.conftest.PASSWORD.
"""

import asyncio
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import timedelta
from pathlib import Path

from drydock import models
from drydock.models import Backup, Host, Run, utcnow
from tests.conftest import Browser, add_user, make_settings, running

KEY = "dXBncmFkZS1maXh0dXJlLWtleS10ZXN0cy1vbmx5ISE="  # test-only, base64 of 32 bytes
STORAGE_ROOT = Path("/tmp/drydock-upgrade/storage")  # noqa: S108 (tests container only)


def new_id(response) -> int:
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


async def populate(browser: Browser) -> None:
    assert (await browser.setup()).status_code == 303
    await add_user(browser, "ops", "operator")
    await add_user(browser, "viewer", "viewer")
    await add_user(browser, "second", "admin")
    local = new_id(
        await browser.post(
            "/hosts",
            {"kind": "local", "name": "local", "docker_url": "tcp://127.0.0.1:9", "enabled": "1"},
        )
    )
    new_id(
        await browser.post(
            "/hosts",
            {
                "kind": "ssh",
                "name": "remote",
                "address": "203.0.113.9",
                "port": "22",
                "username": "backup",
                "remote_socket_path": "/var/run/docker.sock",
                "key_source": "generate",
                "enabled": "1",
            },
        )
    )
    disk = new_id(
        await browser.post(
            "/storage", {"name": "backups", "path": str(STORAGE_ROOT), "enabled": "1"}
        )
    )
    new_id(
        await browser.post(
            "/storage",
            {
                "name": "nas",
                "kind": "webdav",
                "opt_url": "https://dav.example.com/remote.php/dav",
                "opt_pass": "fixture-dav-password",
                "enabled": "1",
            },
        )
    )
    new_id(
        await browser.post(
            "/hooks",
            {
                "name": "dump",
                "host_id": str(local),
                "container": "web",
                "argv": '["pg_dump", "-f", "/srv/dump.sql"]',
                "timeout_s": "300",
            },
        )
    )
    new_id(
        await browser.post(
            "/hooks",
            {
                "name": "app-flush",
                "host_id": str(local),
                "project": "app",
                "container": "db",
                "argv": '["sync"]',
                "timeout_s": "60",
            },
        )
    )
    ops = new_id(
        await browser.post(
            "/notifications",
            {
                "name": "ops",
                "kind": "ntfy",
                "ntfy_server": "http://127.0.0.1:9",
                "ntfy_topic": "backups",
                "enabled": "1",
            },
        )
    )
    web = new_id(
        await browser.post(
            "/jobs",
            {
                "name": "web backup",
                "host_id": str(local),
                "target": "web",
                "storage_target_id": str(disk),
                "scope": "all",
                "consistency_mode": "stop",
                "encrypted": "1",
                "enabled": "1",
                "pre_hooks": "dump",
                "retention_mode": "gfs",
                "daily": "7",
                "weekly": "4",
                "monthly": "12",
                "yearly": "0",
                "schedule": "1",
                "cron": "0 3 * * 0",
                "timezone": "Europe/Berlin",
                "notifications": "1",
                # Ignored by versions before 0011.
                "skip_mounts_sent": "1",
                "skip_mounts": "bind:/srv/web-cache",
                "notify_success": str(ops),
                "notify_failure": str(ops),
            },
        )
    )
    stack = new_id(
        await browser.post(
            "/jobs",
            {
                "name": "app stack",
                "host_id": str(local),
                "target_type": "stack",
                "target": "app",
                "storage_target_id": str(disk),  # remote storage jobs came after 0009
                "scope": "data",
                "consistency_mode": "pause",
                "enabled": "1",
                "post_hooks": "app-flush",
                "retention_mode": "last",
                "keep_last": "3",
                # Ignored by versions before 0014.
                "copy_first": "1",
                "copy_first_sent": "1",
                # Ignored by versions before 0013.
                "extra_targets_sent": "1",
                "extra_target_type": "container",
                "extra_target": "worker",
            },
        )
    )
    now = utcnow()
    with browser.app.state.sessionmaker() as db, db.begin():
        db.add_all(
            [
                Run(
                    job_id=web,
                    status="done",
                    triggered_by="the schedule",
                    archive_name="drydock-web-backup-fixture.tar.zst.age",
                    size=4096,
                    started_at=now - timedelta(minutes=5),
                    finished_at=now - timedelta(minutes=4),
                ),
                Run(
                    job_id=stack,
                    status="failed",
                    triggered_by="ops",
                    error="The host is unreachable.",
                    started_at=now - timedelta(minutes=3),
                    finished_at=now - timedelta(minutes=3),
                ),
                Run(
                    job_id=None,
                    kind="restore",
                    status="done",
                    triggered_by="admin",
                    archive_name="drydock-web-backup-fixture.tar.zst.age",
                    plan="{}",
                    started_at=now - timedelta(minutes=2),
                    finished_at=now - timedelta(minutes=1),
                ),
                Backup(
                    job_id=web,
                    storage_target_id=disk,
                    name="drydock-web-backup-fixture.tar.zst.age",
                    size=4096,
                    sha256="0" * 64,
                    encrypted=True,
                ),
            ]
        )
        if hasattr(models, "Upload"):  # added in revision 0010
            db.add(
                models.Upload(
                    user_id=1,
                    name="drydock-web-backup-fixture.tar.zst.age",
                    declared_size=4096,
                    received=4096,
                    # Where production keeps it. It never expires, so no test run
                    # deletes the row (or tries the file) depending on the date.
                    path="/data/staging/uploads/fixture",
                    status="complete",
                    expires_at=now + timedelta(days=36500),
                )
            )
        assert db.query(Host).count() == 2


async def main(folder: Path, commit: str) -> None:
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        settings = make_settings(
            Path(tmp) / "data",
            DRYDOCK_SECRET_KEY=KEY,
            DRYDOCK_LOCAL_STORAGE_ROOTS=str(STORAGE_ROOT),
        )
        async with running(settings) as browser:
            await populate(browser)
        with closing(sqlite3.connect(settings.data_dir / "drydock.db")) as conn:
            (revision,) = conn.execute("SELECT version_num FROM alembic_version").fetchone()
            lines = list(conn.iterdump())
    shutil.rmtree(STORAGE_ROOT.parent)
    header = [
        f"-- drydock at {commit}, alembic revision {revision}.",
        "-- Made by python -m tests.upgrade_fixture; secrets use its KEY. Do not edit.",
    ]
    out = folder / f"{revision}.sql"
    out.write_text("\n".join(header + lines) + "\n")
    print(f"{out}: revision {revision}, {len(lines)} statements")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]), sys.argv[2]))
