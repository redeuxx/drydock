"""Restores from remote storage (Phase 6e), over SFTP: the archive is downloaded whole into
the restore's staging directory, verified and applied from that copy, and removed when the
run ends. A disk too small fails before any download; cancel stops the download; and
retention never deletes an archive while a restore of it is being created.

The target state and apply are the fakes of tests/test_restore_dispatch.py, except that
apply here streams the archive through pass 2, which reads the downloaded copy.
"""

import os
import shutil
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from drydock.archive import writer
from drydock.jobs.dispatcher import DispatchError
from drydock.restore import apply as restore_apply
from drydock.restore import plan as p
from drydock.restore import verify as rv
from drydock.storage.base import StorageError, StoredObject, archive_name
from drydock.storage.rclone_rc import RcloneDaemon
from tests.conftest import Browser
from tests.docker_support import wait_until
from tests.rclone_support import SftpServer, needs_rclone
from tests.restore_support import TarEntry, build_archive, container_inspect, inner_tar
from tests.test_jobs import add_host, run_status
from tests.test_restore_dispatch import (
    WEB_ID,
    Fakes,
    confirm_plan,
    dispatcher,
    fakes,  # noqa: F401
    log_text,
    run_row,
    staged_dir,
    target_info,
    verified,
    web_archive,
)
from tests.test_sftp_storage import add_sftp

pytestmark = [pytest.mark.anyio, needs_rclone]

MiB = 1024 * 1024


def to_server(browser: Browser, server: SftpServer, name: str) -> Path:
    """Moves an archive build_archive wrote into the local root to the SFTP folder."""
    folder = server.root / "backups"
    folder.mkdir(exist_ok=True)
    shutil.move(browser.settings.local_storage_roots[0] / name, folder / name)
    return folder / name


def names(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


def staging(browser: Browser) -> list[str]:
    path = browser.settings.staging_dir
    return names(path) if path.is_dir() else []


def rc_methods(browser: Browser, monkeypatch) -> list[str]:
    """Records the rc methods the app's rclone is called with."""
    methods: list[str] = []
    real = RcloneDaemon.call

    def call(self, method, params=None, timeout=60.0):
        methods.append(method)
        return real(self, method, params, timeout)

    monkeypatch.setattr(RcloneDaemon, "call", call)
    return methods


@pytest.fixture
def streamed(fakes: Fakes, monkeypatch) -> list[str]:  # noqa: F811
    """apply through pass 2: opens the archive and re-hashes every member up to the last.
    Returns the last member of each archive streamed."""
    names: list[str] = []

    def apply(env, plan, staged, open_archive, *, cancel, log, journal) -> None:
        last = staged.verification.members[-1].name
        with open_archive() as reader:
            reader.advance_to(last)
        names.append(last)
        fakes.applied.append(plan)

    monkeypatch.setattr(restore_apply, "apply", apply)
    return names


# THE FULL RESTORE (EXIT CRITERION)


async def test_a_remote_archive_is_downloaded_verified_and_applied(
    admin: Browser,
    fakes: Fakes,  # noqa: F811
    streamed: list[str],
    sftp: SftpServer,
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_sftp(admin, sftp)
    fakes.target = target_info(host_id)
    name = web_archive(admin)
    remote = to_server(admin, sftp, name)
    response = await admin.post(
        "/restore/from-storage", {"storage_id": str(storage_id), "name": name}
    )
    assert response.status_code == 303, response.text
    (run_id,) = admin.sql("SELECT id FROM runs WHERE kind = 'restore'")[0]
    await dispatcher(admin).wait(run_id)
    assert run_status(admin, run_id) == "awaiting_confirmation", run_row(admin, run_id)
    copy = staged_dir(admin, run_id) / rv.DOWNLOAD_DIR / name
    assert copy.read_bytes() == remote.read_bytes()
    assert copy.stat().st_mode & 0o077 == 0
    assert run_row(admin, run_id)["size"] == remote.stat().st_size
    text = log_text(admin, run_id)
    assert f"Downloading {name} to the staging directory." in text
    assert f"Downloaded {remote.stat().st_size} bytes." in text
    assert sftp.password not in text and ":sftp," not in text
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    assert run_status(admin, run_id) == "done", run_row(admin, run_id)
    assert streamed and not staged_dir(admin, run_id).exists()
    assert staging(admin) == []
    assert sftp.files() == [name]  # restoring takes nothing away from the storage


async def test_pass_2_refuses_a_download_changed_since_pass_1(
    admin: Browser,
    fakes: Fakes,  # noqa: F811
    streamed: list[str],
    sftp: SftpServer,
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_sftp(admin, sftp)
    fakes.target = target_info(host_id)
    name = web_archive(admin)
    to_server(admin, sftp, name)
    run_id = await verified(admin, storage_id, name)
    copy = staged_dir(admin, run_id) / rv.DOWNLOAD_DIR / name
    data = copy.read_bytes()
    copy.unlink()
    copy.write_bytes(data)  # the same bytes in another file
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", rv.CHANGED_SINCE)
    assert streamed == [] and staging(admin) == []


# FREE SPACE AND CANCEL (EXIT CRITERIA)


async def test_too_little_free_space_fails_before_any_download(
    admin: Browser,
    fakes: Fakes,  # noqa: F811
    sftp: SftpServer,
    monkeypatch,
) -> None:
    storage_id = await add_sftp(admin, sftp)
    name = web_archive(admin)
    to_server(admin, sftp, name)
    real = shutil.disk_usage
    monkeypatch.setattr(
        writer.shutil, "disk_usage", lambda path: real(path)._replace(free=writer.RESERVE)
    )
    methods = rc_methods(admin, monkeypatch)
    run_id = await dispatcher(admin).submit_restore(storage_id, name, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"].startswith("Not enough free space in the staging directory:")
    assert "operations/stat" in methods and "operations/copyfile" not in methods
    assert staging(admin) == []
    assert fakes.opened == []


async def test_cancel_mid_download(admin: Browser, slow_sftp: SftpServer, monkeypatch) -> None:
    storage_id = await add_sftp(admin, slow_sftp)
    volume = inner_tar(
        [
            TarEntry("./", tarfile.DIRTYPE, mode=0o755),
            TarEntry("./blob", data=os.urandom(24 * MiB)),  # random: zstd cannot shrink it
        ]
    )
    container = container_inspect("web", id=WEB_ID, mounts=[("data", "/data")])
    name, _ = build_archive(
        admin.settings.local_storage_roots[0],
        admin.app.state.crypto,
        containers=[container],
        volumes={"data": volume},
    )
    to_server(admin, slow_sftp, name)
    methods = rc_methods(admin, monkeypatch)
    run_id = await dispatcher(admin).submit_restore(storage_id, name, "admin")
    folder = staged_dir(admin, run_id) / rv.DOWNLOAD_DIR
    await wait_until(
        lambda: folder.is_dir() and any(f.endswith(".partial") for f in names(folder)),
        30,
        "the download to start",
    )
    assert dispatcher(admin).cancel(run_id)
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("cancelled", "The run was cancelled.")
    assert staging(admin) == []
    assert slow_sftp.files() == [name]
    # The cancel stopped the transfer itself, not only what came after it.
    assert "job/stopgroup" in methods and "Downloaded " not in log_text(admin, run_id)


async def test_an_archive_that_fails_pass_1_after_downloading(
    admin: Browser,
    fakes: Fakes,  # noqa: F811
    sftp: SftpServer,
) -> None:
    storage_id = await add_sftp(admin, sftp)
    name = web_archive(admin)
    remote = to_server(admin, sftp, name)
    data = bytearray(remote.read_bytes())
    data[len(data) // 2] ^= 0xFF
    remote.write_bytes(bytes(data))
    run_id = await dispatcher(admin).submit_restore(storage_id, name, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed", row
    assert f"Downloaded {len(data)} bytes." in log_text(admin, run_id)
    assert fakes.opened == [] and staging(admin) == []
    assert sftp.files() == [name]


# RETENTION


async def test_retention_and_a_remote_restore_never_cross(admin: Browser, sftp: SftpServer) -> None:
    storage_id = await add_sftp(admin, sftp)
    worker = dispatcher(admin)
    name = archive_name("00000000-0000-4000-8000-000000000000", "web", datetime.now(UTC), False)
    deleted: list[str] = []

    class Remote:
        def delete(self, archive: str) -> None:
            # Mid-delete: a restore of the archive is refused, not created.
            with pytest.raises(DispatchError, match="Retention is deleting this archive"):
                worker._create_restore_run({"storage_target_id": storage_id}, archive, "admin")
            deleted.append(archive)

        def list(self, prefix: str = "") -> list:
            return []

    plan = SimpleNamespace(storage_target_id=storage_id, job_id=None, run_id=None)
    lines: list[str] = []
    worker._delete_archive(plan, Remote(), name, lines.append)
    assert deleted == [name] and lines == [f"Retention: deleted {name}."]
    assert worker._deleting == set()
    assert admin.sql("SELECT COUNT(*) FROM runs WHERE kind = 'restore'") == [(0,)]
    # Once the delete is over, a restore can be created, and retention then keeps it.
    run_id, _ = worker._create_restore_run({"storage_target_id": storage_id}, name, "admin")
    assert run_id is not None
    worker._delete_archive(plan, Remote(), name, lines.append)
    assert deleted == [name] and lines[-1] == f"Retention: kept {name}, an open restore uses it."


async def test_a_failed_retention_delete_releases_the_archive(
    admin: Browser, sftp: SftpServer
) -> None:
    storage_id = await add_sftp(admin, sftp)
    worker = dispatcher(admin)
    name = archive_name("00000000-0000-4000-8000-000000000000", "web", datetime.now(UTC), False)

    class Failing:
        def delete(self, archive: str) -> None:
            raise StorageError("The server denied access to the folder.")

        def list(self, prefix: str = "") -> list:
            return [StoredObject(name, 1, datetime.now(UTC))]

    plan = SimpleNamespace(storage_target_id=storage_id, job_id=None, run_id=None)
    with pytest.raises(StorageError):
        worker._delete_archive(plan, Failing(), name, lambda line: None)
    assert worker._deleting == set()
    run_id, _ = worker._create_restore_run({"storage_target_id": storage_id}, name, "admin")
    assert run_id is not None
