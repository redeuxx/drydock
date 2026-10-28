"""Backups to SFTP storage through the app (Phase 6c): runs with retention, cancel mid-upload,
"Test connection" and the host key field."""

import hashlib
import json
import os
import re
import shutil
from pathlib import Path

import asyncssh
import pytest

from drydock.archive.writer import ArchiveResult
from drydock.config import Settings
from drydock.engine import capture
from drydock.hosts import client as docker_client
from drydock.hosts.manager import HostManager
from drydock.jobs import runlog
from drydock.jobs.dispatcher import Dispatcher, Target
from drydock.models import Run
from drydock.routes import restore as restore_routes
from drydock.storage.rclone import NO_HOST_KEY, WRONG_KEY
from tests.conftest import Browser, add_user, running
from tests.docker_support import wait_until
from tests.rclone_support import SftpServer, needs_rclone, public_key
from tests.restore_support import build_archive
from tests.test_jobs import add_job, add_storage, run_status, start_run
from tests.test_routes import FakeDocker

pytestmark = [pytest.mark.anyio, needs_rclone]

FINISHED = ("done", "failed", "cancelled", "interrupted")


async def add_sftp(browser: Browser, server: SftpServer, name: str = "nas", **fields: str) -> int:
    form = {
        "name": name,
        "kind": "sftp",
        "enabled": "1",
        "opt_host": "127.0.0.1",
        "opt_port": str(server.port),
        "opt_host_keys": server.host_keys,
        "opt_user": server.user,
        "opt_pass": server.password,
        "folder": "backups",
    } | fields
    response = await browser.post("/storage", form)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


@pytest.fixture
def fake_host(monkeypatch, tmp_path: Path) -> dict:
    """Jobs back up container "web" (not running) through a fake daemon; capture writes a
    real archive of `size` random bytes into the staging file the dispatcher names."""
    state: dict = {"size": 1024}
    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", lambda url, timeout=60: FakeDocker())
    monkeypatch.setattr(
        Dispatcher,
        "_resolve",
        lambda self, handle, plan, refs, log: [Target("id-web", "web", False)],
    )

    def fake_capture(env, job, containers, out_path, *, cancel, log, before_data, **kwargs):
        before_data()
        if "during" in state:
            state["during"]()
        src = tmp_path / f"capture-{os.urandom(4).hex()}"
        src.mkdir()
        name, _ = build_archive(
            src,
            env.crypto,
            job_uuid=job.uuid,
            job_name=job.name,
            created_at=kwargs["created_at"],
            volumes={"data": os.urandom(state["size"])},
        )
        out_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(src / name, out_path)
        data = out_path.read_bytes()
        result = ArchiveResult(out_path, len(data), hashlib.sha256(data).hexdigest(), False, ())
        return None, result

    monkeypatch.setattr(capture, "capture", fake_capture)
    return state


async def finished(browser: Browser, run_id: int, timeout: float = 60) -> str:
    await wait_until(lambda: run_status(browser, run_id) in FINISHED, timeout, f"run {run_id}")
    return run_status(browser, run_id)


def run_log(browser: Browser, run_id: int) -> str:
    return runlog.log_path(browser.settings.data_dir, run_id).read_text()


def staged(browser: Browser) -> list[str]:
    staging = browser.settings.staging_dir
    return sorted(p.name for p in staging.iterdir()) if staging.is_dir() else []


# THE FULL CYCLE (EXIT CRITERION)


async def test_backups_to_sftp_with_retention(
    admin: Browser, sftp: SftpServer, fake_host: dict
) -> None:
    storage_id = await add_sftp(admin, sftp)
    job_id = await add_job(
        admin, storage_id=str(storage_id), encrypted="", retention_mode="last", keep_last="2"
    )
    stored = []
    for _ in range(3):
        run_id = await start_run(admin, job_id)
        assert await finished(admin, run_id) == "done", run_log(admin, run_id)
        (name,) = admin.sql("SELECT archive_name FROM runs WHERE id = ?", (run_id,))[0]
        stored.append(name)
    names = [n for (n,) in admin.sql("SELECT name FROM backups ORDER BY name")]
    assert names == stored[1:] and sftp.files() == names  # the oldest went
    log = run_log(admin, run_id)
    assert "Uploading" in log and f"Retention: deleted {stored[0]}." in log
    assert sftp.password not in log and ":sftp," not in log
    assert staged(admin) == []
    sizes = admin.sql("SELECT size, sha256 FROM backups ORDER BY name")
    for name, (size, digest) in zip(names, sizes, strict=True):
        data = (sftp.root / "backups" / name).read_bytes()
        assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
    # The listing reads the manifests through the ranged read and offers each archive
    # (tests/test_remote_restore.py restores them).
    listing = (await admin.get(f"/restore/storage/{storage_id}")).text
    assert listing.count("unverified preview</span>") == 2
    assert listing.count("Verify and restore") == 2 and "downloads it whole" in listing
    index = (await admin.get("/restore")).text
    assert f'href="/restore/storage/{storage_id}"' in index


async def test_cancel_mid_upload_cancels_the_run(
    admin: Browser, slow_sftp: SftpServer, fake_host: dict
) -> None:
    fake_host["size"] = 32 * 1024 * 1024
    storage_id = await add_sftp(admin, slow_sftp)
    job_id = await add_job(admin, storage_id=str(storage_id), encrypted="")
    run_id = await start_run(admin, job_id)
    await wait_until(lambda: any(f.endswith(".partial") for f in slow_sftp.files()), 60, "upload")
    response = await admin.post(f"/runs/{run_id}/cancel")
    assert response.status_code in (200, 303)
    assert await finished(admin, run_id, 40) == "cancelled"
    assert slow_sftp.files() == []
    assert admin.sql("SELECT COUNT(*) FROM backups") == [(0,)]
    assert "Upload failed: The transfer was cancelled." in run_log(admin, run_id)
    assert staged(admin) == []


async def test_a_storage_changed_mid_run_takes_no_archive(
    admin: Browser, sftp: SftpServer, fake_host: dict
) -> None:
    storage_id = await add_sftp(admin, sftp)
    job_id = await add_job(admin, storage_id=str(storage_id), encrypted="")
    fake_host["during"] = lambda: admin.sql(
        "UPDATE storage_targets SET enabled = 0 WHERE id = ?", (storage_id,)
    )
    run_id = await start_run(admin, job_id)
    assert await finished(admin, run_id) == "failed"
    (error,) = admin.sql("SELECT error FROM runs WHERE id = ?", (run_id,))[0]
    assert "was disabled while this run worked" in error
    assert sftp.files() == [] and staged(admin) == []


async def test_a_slow_remote_listing_stops_previewing(
    admin: Browser, sftp: SftpServer, fake_host: dict, monkeypatch
) -> None:
    storage_id = await add_sftp(admin, sftp)
    job_id = await add_job(admin, storage_id=str(storage_id), encrypted="")
    assert await finished(admin, await start_run(admin, job_id)) == "done"
    monkeypatch.setattr(restore_routes, "REMOTE_PREVIEW_BUDGET", -1.0)
    listing = (await admin.get(f"/restore/storage/{storage_id}")).text
    assert restore_routes.SLOW_STORAGE in listing and "unverified preview</span>" not in listing


async def test_startup_names_what_an_interrupted_upload_may_leave(
    settings: Settings, sftp: SftpServer
) -> None:
    async with running(settings) as browser:
        await browser.setup()
        storage_id = await add_sftp(browser, sftp)
        job_id = await add_job(browser, storage_id=str(storage_id), encrypted="")
        with browser.app.state.sessionmaker() as db, db.begin():
            run = Run(job_id=job_id, status="running")
            db.add(run)
            db.flush()
            run_id = run.id
    async with running(settings) as browser:
        assert run_status(browser, run_id) == "interrupted"
        assert ".partial. Drydock does not list it" in run_log(browser, run_id)


# TEST CONNECTION (EXIT CRITERION)


async def test_test_connection(admin: Browser, sftp: SftpServer) -> None:
    good = await add_sftp(admin, sftp, "good")
    page = (await admin.post(f"/storage/{good}/test")).text
    assert "Connected. The storage is writable." in page
    assert sftp.files() == []
    impostor = public_key(asyncssh.generate_private_key("ssh-ed25519"))
    bad = await add_sftp(admin, sftp, "bad", opt_host_keys=impostor)
    page = (await admin.post(f"/storage/{bad}/test")).text
    assert f"Test failed: {WRONG_KEY}".replace("'", "&#39;") in page
    assert "pin-host-key" not in page and sftp.password not in page
    rows = admin.sql(
        "SELECT outcome, details FROM audit_events WHERE action = 'storage.test' ORDER BY id"
    )
    assert [outcome for outcome, _ in rows] == ["success", "failure"]
    assert json.loads(rows[1][1])["error"] == WRONG_KEY
    assert sftp.password not in str(rows)


async def test_a_target_saved_before_host_keys_existed(
    admin: Browser, sftp: SftpServer, fake_host: dict
) -> None:
    storage_id = await add_sftp(admin, sftp)
    crypto = admin.app.state.crypto
    (blob,) = admin.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,))[0]
    config = json.loads(crypto.decrypt(blob))
    del config["options"]["host_keys"]
    admin.sql(
        "UPDATE storage_targets SET config_enc = ? WHERE id = ?",
        (crypto.encrypt(json.dumps(config)), storage_id),
    )
    page = (await admin.post(f"/storage/{storage_id}/test")).text
    assert "no valid host key" in page
    job_id = await add_job(admin, storage_id=str(storage_id), encrypted="")
    run_id = await start_run(admin, job_id)
    assert await finished(admin, run_id) == "failed"
    (error,) = admin.sql("SELECT error FROM runs WHERE id = ?", (run_id,))[0]
    assert error == NO_HOST_KEY
    assert sftp.files() == []


# THE HOST KEY FIELD


@pytest.mark.parametrize(
    "value",
    [
        "",
        "AAAAC3NzaC1lZDI1NTE5AAAAI",
        "ssh-ed25519 not-base64",
        "ssh-dss AAAAB3NzaC1kc3MAAACBAP",
        "nas.lan ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE8NUBuD0jIryuTnOOXNgmFnDijdSJ9G6cBrF3QDw+1S",
        ",",
    ],
)
async def test_the_host_key_is_checked(admin: Browser, sftp: SftpServer, value: str) -> None:
    response = await admin.post(
        "/storage",
        {
            "name": "nas",
            "kind": "sftp",
            "opt_host": "127.0.0.1",
            "opt_host_keys": value,
            "opt_user": "u",
            "opt_pass": "p",
        },
    )
    assert response.status_code == 422
    text = response.text.replace("&#39;", "'")
    assert "Host key: paste the server" in text or (value == "" and "Enter the host key" in text)
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


async def test_a_pasted_pub_file_is_normalised(admin: Browser, sftp: SftpServer) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.set_comment("root@nas")
    pasted = key.export_public_key("openssh").decode()
    storage_id = await add_sftp(admin, sftp, opt_host_keys=f" {pasted.strip()} , {sftp.host_keys}")
    (blob,) = admin.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,))[0]
    stored = json.loads(admin.app.state.crypto.decrypt(blob))["options"]["host_keys"]
    assert stored == f"{public_key(key)},{sftp.host_keys}"


@pytest.mark.parametrize(
    ("fields", "error"),
    [
        ({"opt_host": "::1"}, "host name or an IPv4 address"),
        ({"opt_user": "a]b"}, "without ]"),
        ({"folder": "x]y"}, "must not contain ]"),
    ],
)
async def test_values_a_connection_string_cannot_carry(
    admin: Browser, sftp: SftpServer, fields: dict, error: str
) -> None:
    form = {
        "name": "nas",
        "kind": "sftp",
        "opt_host": "127.0.0.1",
        "opt_host_keys": sftp.host_keys,
        "opt_user": "u",
        "opt_pass": "p",
    } | fields
    response = await admin.post("/storage", form)
    assert response.status_code == 422 and error in response.text
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


async def test_a_new_host_key_needs_the_secrets_again(admin: Browser, sftp: SftpServer) -> None:
    storage_id = await add_sftp(admin, sftp)
    impostor = public_key(asyncssh.generate_private_key("ssh-ed25519"))
    form = {
        "name": "nas",
        "kind": "sftp",
        "enabled": "1",
        "opt_host": "127.0.0.1",
        "opt_port": str(sftp.port),
        "opt_host_keys": impostor,
        "opt_user": sftp.user,
        "folder": "backups",
    }
    response = await admin.post(f"/storage/{storage_id}", form)
    assert response.status_code == 422 and "must be entered again" in response.text


# JOBS


async def test_jobs_may_use_sftp_storage(admin: Browser, sftp: SftpServer) -> None:
    storage_id = await add_sftp(admin, sftp, "nas-sftp")
    assert "nas-sftp" in (await admin.get("/jobs/new")).text
    await add_job(admin, storage_id=str(storage_id))


# FETCHING THE HOST KEY


def host_keys_value(html: str) -> str:
    match = re.search(r'name="opt_host_keys" value="([^"]*)"', html)
    assert match, "no host key field"
    return match[1]


def sftp_form(server: SftpServer, **fields: str) -> dict[str, str]:
    return {
        "name": "nas",
        "kind": "sftp",
        "enabled": "1",
        "opt_host": "127.0.0.1",
        "opt_port": str(server.port),
        "opt_user": server.user,
        "opt_pass": server.password,
        "folder": "backups",
    } | fields


async def test_fetching_fills_the_host_key_and_stores_nothing(
    admin: Browser, sftp: SftpServer
) -> None:
    response = await admin.post("/storage/host-key", sftp_form(sftp))
    assert response.status_code == 200
    assert host_keys_value(response.text) == sftp.host_keys
    assert sftp.host_key.get_fingerprint("sha256") in response.text
    assert "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" in response.text
    assert sftp.password not in response.text
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]
    ((outcome, details),) = admin.sql(
        "SELECT outcome, details FROM audit_events WHERE action = 'storage.hostkey_fetch'"
    )
    assert outcome == "success" and json.loads(details)["port"] == str(sftp.port)
    # Saving what was fetched trusts it.
    storage_id = await add_sftp(admin, sftp, opt_host_keys=host_keys_value(response.text))
    page = (await admin.post(f"/storage/{storage_id}/test")).text
    assert "Connected. The storage is writable." in page


async def test_fetching_on_the_edit_page_changes_nothing_until_saved(
    admin: Browser, sftp: SftpServer
) -> None:
    impostor = public_key(asyncssh.generate_private_key("ssh-ed25519"))
    storage_id = await add_sftp(admin, sftp, opt_host_keys=impostor)
    before = admin.sql("SELECT config_enc FROM storage_targets")
    response = await admin.post(f"/storage/host-key?storage_id={storage_id}", sftp_form(sftp))
    assert response.status_code == 200
    assert host_keys_value(response.text) == sftp.host_keys
    assert 'placeholder="unchanged"' in response.text  # the stored password is still there
    assert admin.sql("SELECT config_enc FROM storage_targets") == before
    for missing in (storage_id + 1, await add_storage(admin)):  # unknown, then local storage
        response = await admin.post(f"/storage/host-key?storage_id={missing}", sftp_form(sftp))
        assert response.status_code == 404


@pytest.mark.parametrize(
    ("fields", "error"),
    [
        ({"opt_port": "9"}, "Could not read the host key"),
        ({"opt_host": "::1"}, "host name or an IPv4 address"),
        ({"opt_host": ""}, "Enter the host"),
    ],
)
async def test_a_failed_fetch_says_why(
    admin: Browser, sftp: SftpServer, fields: dict, error: str
) -> None:
    form = sftp_form(sftp, opt_host_keys="ssh-ed25519 typed-before", **fields)
    response = await admin.post("/storage/host-key", form)
    assert response.status_code == 422 and error in response.text
    assert host_keys_value(response.text) == "ssh-ed25519 typed-before"  # left as it was
    assert sftp.password not in response.text
    (details,) = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'storage.hostkey_fetch'"
        " AND outcome = 'failure'"
    )[0]
    assert "error" in json.loads(details) and sftp.password not in details


async def test_only_superadmins_fetch_host_keys(admin: Browser, sftp: SftpServer) -> None:
    storage_id = await add_sftp(admin, sftp)
    await add_user(admin, "plain-admin", "admin")
    await admin.login("plain-admin")
    for path in ("/storage/host-key", f"/storage/host-key?storage_id={storage_id}"):
        assert (await admin.post(path, sftp_form(sftp))).status_code == 403
    assert "storage.hostkey_fetch" not in str(admin.sql("SELECT action FROM audit_events"))


async def test_fetching_needs_a_recent_password_check(admin: Browser, sftp: SftpServer) -> None:
    """It connects where the request says, like saving the form."""
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    response = await admin.post("/storage/host-key", sftp_form(sftp))
    assert response.status_code == 403
    assert "storage.hostkey_fetch" not in str(admin.sql("SELECT action FROM audit_events"))


async def test_fetching_is_for_sftp_only(admin: Browser, sftp: SftpServer) -> None:
    response = await admin.post("/storage/host-key", sftp_form(sftp, kind="smb"))
    assert response.status_code == 404
