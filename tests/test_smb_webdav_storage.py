"""SMB and WebDAV storage (Phase 6d), against the samba service and `rclone serve webdav`
over TLS: the full cycle through the app, the backend's cycle, WebDAV's partial uploads and
pinned certificates, what reaches rclone, the logs, and a 5 GB transfer each."""

import asyncio
import datetime
import hashlib
import json
import logging
import os
import shutil
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from drydock.restore import plan as p
from drydock.storage import certs
from drydock.storage.base import StorageError
from drydock.storage.rclone import (
    BAD_CONFIG,
    CANCELLED,
    NOT_HTTPS,
    UNTRUSTED,
    RcloneBackend,
    connection_string,
    settings_for,
)
from drydock.storage.rclone_rc import RcloneDaemon, RcloneError
from tests.conftest import Browser, add_user
from tests.docker_support import wait_until
from tests.rclone_support import (
    SmbShare,
    WebdavServer,
    certificate,
    needs_rclone,
    needs_samba,
)
from tests.test_jobs import add_host, add_job, run_status, start_run
from tests.test_rclone_backend import daemon, new_name, put, spy, staging, upload_file
from tests.test_remote_restore import streamed
from tests.test_restore_dispatch import (
    Fakes,
    confirm_plan,
    dispatcher,
    fakes,
    log_text,
    run_row,
    staged_dir,
    target_info,
    web_archive,
)
from tests.test_sftp_storage import fake_host, finished, run_log, staged

pytestmark = [pytest.mark.anyio, needs_rclone]
__all__ = ["daemon", "fake_host", "fakes", "staging", "streamed"]  # fixtures used here

MiB = 1024 * 1024
KINDS = [pytest.param("smb", marks=needs_samba), "webdav"]


class Remote:
    """The smb or webdav fixture behind one interface."""

    def __init__(self, kind: str, server: SmbShare | WebdavServer) -> None:
        self.kind, self.server = kind, server

    def config(self, **opts: str) -> dict:
        return self.server.config(**opts)

    def files(self) -> list[str]:
        return self.server.files()

    def path(self, name: str) -> Path:
        if isinstance(self.server, SmbShare):
            return self.server.path / name
        return self.server.root / "backups" / name

    @property
    def password(self) -> str:
        return self.server.password

    def form(self, name: str = "nas") -> dict[str, str]:
        config = self.config()
        fields = {f"opt_{k}": v for k, v in config["options"].items()}
        return {"name": name, "kind": self.kind, "enabled": "1", "folder": config["folder"]} | {
            k: v for k, v in fields.items() if k != "opt_set_modtime"
        }


@pytest.fixture(params=KINDS)
def remote(request) -> Remote:
    fixture = "smb" if request.param == "smb" else "webdav"
    return Remote(request.param, request.getfixturevalue(fixture))


def backend(daemon: RcloneDaemon, staging: Path, remote: Remote, **opts: str) -> RcloneBackend:
    return RcloneBackend(daemon, remote.kind, remote.config(**opts), staging)


async def add_remote(browser: Browser, remote: Remote, name: str = "nas") -> int:
    response = await browser.post("/storage", remote.form(name))
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


# THE FULL CYCLE (EXIT CRITERION)


async def test_backups_with_retention(admin: Browser, remote: Remote, fake_host: dict) -> None:
    storage_id = await add_remote(admin, remote)
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
    assert names == stored[1:] and remote.files() == names  # the oldest went
    log = run_log(admin, run_id)
    assert f"Retention: deleted {stored[0]}." in log
    assert remote.password not in log and f":{remote.kind}," not in log
    assert staged(admin) == []
    sizes = admin.sql("SELECT size, sha256 FROM backups ORDER BY name")
    for name, (size, digest) in zip(names, sizes, strict=True):
        data = remote.path(name).read_bytes()
        assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
    # The listing reads the manifests through the ranged read.
    listing = (await admin.get(f"/restore/storage/{storage_id}")).text
    assert listing.count("unverified preview</span>") == 2
    page = (await admin.post(f"/storage/{storage_id}/test")).text
    assert "Connected. The storage is writable." in page and remote.files() == names


# THE BACKEND


async def test_put_list_read_head_delete(
    daemon: RcloneDaemon, staging: Path, remote: Remote
) -> None:
    storage = backend(daemon, staging, remote)
    data = {new_name(): os.urandom(1000 + i) for i in range(2)}
    for name, body in data.items():
        stored = await put(storage, upload_file(staging, body), name)
        assert stored.size == len(body)
    listed = await asyncio.to_thread(storage.list)
    assert [o.name for o in listed] == sorted(data) and remote.files() == sorted(data)
    for name, body in data.items():
        assert await asyncio.to_thread(storage.read_head, name, 64) == body[:64]
        await asyncio.to_thread(storage.delete, name)
    assert await asyncio.to_thread(storage.list) == [] and remote.files() == []
    await asyncio.to_thread(storage.test)
    assert remote.files() == []


async def test_a_webdav_upload_is_invisible_until_complete(
    daemon: RcloneDaemon, staging: Path, slow_webdav: WebdavServer
) -> None:
    storage = RcloneBackend(daemon, "webdav", slow_webdav.config(), staging)
    name = new_name()
    upload = asyncio.create_task(put(storage, upload_file(staging, os.urandom(8 * MiB)), name))
    await wait_until(lambda: slow_webdav.files() != [], 30, "the upload to start")
    (partial,) = slow_webdav.files()
    assert partial.startswith(f"{name}.") and partial.endswith(".partial")
    assert await asyncio.to_thread(storage.list) == []
    await upload
    assert slow_webdav.files() == [name]


async def test_cancelling_a_webdav_upload_leaves_nothing(
    daemon: RcloneDaemon, staging: Path, slow_webdav: WebdavServer
) -> None:
    storage = RcloneBackend(daemon, "webdav", slow_webdav.config(), staging)
    cancel = threading.Event()
    upload = asyncio.create_task(
        put(storage, upload_file(staging, os.urandom(32 * MiB)), new_name(), cancel=cancel)
    )
    await wait_until(lambda: slow_webdav.files() != [], 30, "the upload to start")
    cancel.set()
    with pytest.raises(StorageError, match=CANCELLED):
        await upload
    assert slow_webdav.files() == []


@needs_samba
async def test_smb_errors_say_what_is_wrong(
    daemon: RcloneDaemon, staging: Path, smb: SmbShare
) -> None:
    wrong = RcloneBackend(daemon, "smb", smb.config(**{"pass": "not-it"}), staging)
    with pytest.raises(StorageError, match="refused the user name or password"):
        await asyncio.to_thread(wrong.test)
    config = smb.config()
    config["folder"] = "no-such-share/x"
    with pytest.raises(StorageError, match="share does not exist"):
        await asyncio.to_thread(RcloneBackend(daemon, "smb", config, staging).test)


# WEBDAV CERTIFICATES


async def test_an_unpinned_or_wrong_certificate_is_refused(
    daemon: RcloneDaemon, staging: Path, webdav: WebdavServer
) -> None:
    other, _ = certificate("other", ["127.0.0.1"], certificate("other CA", []))
    for config in (
        webdav.config(tls_cert=""),
        webdav.config(tls_cert=certs.pem(other)),
    ):
        storage = RcloneBackend(daemon, "webdav", config, staging)
        with pytest.raises(StorageError) as caught:
            await asyncio.to_thread(storage.test)
        assert str(caught.value) == UNTRUSTED
    assert webdav.files() == []


async def test_a_trusted_connection_never_serves_another_certificate(
    daemon: RcloneDaemon, staging: Path, webdav: WebdavServer
) -> None:
    """rclone caches a connection by its options: the pinned one must be among them."""
    good = RcloneBackend(daemon, "webdav", webdav.config(), staging)
    await asyncio.to_thread(good.test)
    other, _ = certificate("other", ["127.0.0.1"], certificate("other CA", []))
    bad = RcloneBackend(daemon, "webdav", webdav.config(tls_cert=certs.pem(other)), staging)
    with pytest.raises(StorageError, match="not trusted"):
        await asyncio.to_thread(bad.list)
    name = new_name()
    await put(good, upload_file(staging, b"zstd-bytes"), name)
    with pytest.raises(StorageError, match="not trusted"):
        await asyncio.to_thread(bad.read_head, name, 4)


async def test_the_certificate_reaches_rclone_only_as_a_trust_anchor(
    daemon: RcloneDaemon, staging: Path, webdav: WebdavServer, monkeypatch
) -> None:
    calls = spy(daemon, monkeypatch)
    storage = RcloneBackend(daemon, "webdav", webdav.config(), staging)
    name = new_name()
    await put(storage, upload_file(staging, b"zstd"), name)
    assert await asyncio.to_thread(storage.read_head, name, 4) == b"zstd"
    fingerprint = certs.fingerprint(webdav.cert)
    anchor = daemon.run_dir / "certs" / f"{fingerprint}.pem"
    assert anchor.read_text() == certs.pem(webdav.cert)
    assert oct(anchor.stat().st_mode & 0o777) == "0o600"
    for method, params in calls:
        text = json.dumps(params)
        assert "BEGIN CERTIFICATE" not in text and "tls_cert" not in text
        if method == "GET":
            assert f"description='drydock-cert-{fingerprint}'" in params["fs"]
        elif any(k in params for k in ("fs", "srcFs", "dstFs")):
            assert params["_config"] == {"CaCert": [str(anchor)]}
        else:
            assert "_config" not in params
    assert ("operations/movefile" in [m for m, _ in calls]) and webdav.files() == [name]


def test_webdav_needs_https_and_fixed_options() -> None:
    config = {"folder": "", "options": {"url": "http://dav.lan", "vendor": "other"}}
    with pytest.raises(StorageError, match=NOT_HTTPS):
        settings_for("webdav", config, lambda secret: secret)
    config["options"]["url"] = "https://dav.lan"
    values = settings_for("webdav", config, lambda secret: secret)
    assert values["auth_redirect"] == "false" and values["unix_socket"] == ""
    assert values["bearer_token_command"] == "" and values["headers"] == ""
    for planted in ({"headers": "Cookie,x"}, {"unix_socket": "/run/docker.sock"}):
        bad = {"folder": "", "options": config["options"] | planted}
        with pytest.raises(StorageError, match=BAD_CONFIG):
            settings_for("webdav", bad, lambda secret: secret)
    smb = {"folder": "s", "options": {"host": "nas", "use_kerberos": "true"}}
    with pytest.raises(StorageError, match=BAD_CONFIG):
        settings_for("smb", smb, lambda secret: secret)
    del smb["options"]["use_kerberos"]
    values = settings_for("smb", smb, lambda secret: secret)
    assert values["use_kerberos"] == "false" and values["kerberos_ccache"] == ""
    smb["options"]["host"] = "fd00::1"
    with pytest.raises(StorageError, match=BAD_CONFIG):
        settings_for("smb", smb, lambda secret: secret)


# FETCHING THE CERTIFICATE


def dav_form(server: WebdavServer, **fields: str) -> dict[str, str]:
    return {
        "name": "nas",
        "kind": "webdav",
        "enabled": "1",
        "opt_url": server.url,
        "opt_vendor": "other",
        "opt_user": server.user,
        "opt_pass": server.password,
        "folder": "backups",
    } | fields


async def test_fetching_fills_the_certificate_and_stores_nothing(
    admin: Browser, webdav: WebdavServer
) -> None:
    response = await admin.post("/storage/certificate", dav_form(webdav))
    assert response.status_code == 200, response.text
    assert certs.pem(webdav.cert).strip() in response.text
    assert certs.shown_fingerprint(webdav.cert) in response.text
    assert "saving trusts this certificate" in response.text
    assert webdav.password not in response.text
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]
    ((outcome, details),) = admin.sql(
        "SELECT outcome, details FROM audit_events WHERE action = 'storage.cert_fetch'"
    )
    assert outcome == "success"
    assert json.loads(details)["fingerprint"] == certs.shown_fingerprint(webdav.cert)
    # Saving what was fetched trusts it.
    form = dav_form(webdav, opt_tls_cert=certs.pem(webdav.cert))
    response = await admin.post("/storage", form)
    assert response.status_code == 303, response.text
    page = (await admin.post(f"{response.headers['location']}/test")).text
    assert "Connected. The storage is writable." in page


async def test_a_certificate_for_another_host_is_not_filled(admin: Browser, tmp_path: Path) -> None:
    from tests.rclone_support import webdav_server

    with webdav_server(tmp_path / "dav", hosts=("nas.lan",)) as server:
        response = await admin.post("/storage/certificate", dav_form(server))
        assert response.status_code == 422
        text = response.text.replace("&#39;", "'")
        assert "is not for 127.0.0.1: it lists nas.lan" in text
        assert "BEGIN CERTIFICATE" not in text
        saved = await admin.post("/storage", dav_form(server, opt_tls_cert=certs.pem(server.cert)))
        assert saved.status_code == 422 and "Server certificate: The certificate is not for" in (
            saved.text.replace("&#39;", "'")
        )


async def test_a_publicly_trusted_certificate_is_not_pinned(
    admin: Browser, webdav: WebdavServer, monkeypatch
) -> None:
    monkeypatch.setattr(certs, "fetch", lambda host, port: (webdav.cert, True))
    response = await admin.post("/storage/certificate", dav_form(webdav))
    assert response.status_code == 200
    assert "trusts it without pinning" in response.text
    assert "BEGIN CERTIFICATE" not in response.text


async def test_fetching_a_certificate_is_for_superadmins_and_webdav(
    admin: Browser, webdav: WebdavServer
) -> None:
    response = await admin.post("/storage/certificate", dav_form(webdav, kind="sftp"))
    assert response.status_code == 404
    await add_user(admin, "plain-admin", "admin")
    await admin.login("plain-admin")
    assert (await admin.post("/storage/certificate", dav_form(webdav))).status_code == 403
    assert "storage.cert_fetch" not in str(admin.sql("SELECT action FROM audit_events"))


# LOGS (EXIT CRITERION)


async def test_logs_hold_no_secret(
    daemon: RcloneDaemon, staging: Path, remote: Remote, caplog
) -> None:
    caplog.set_level(logging.INFO)
    storage = backend(daemon, staging, remote)
    name = new_name()
    await put(storage, upload_file(staging, b"zstd"), name)
    await asyncio.to_thread(storage.read_head, name, 4)
    wrong = backend(daemon, staging, remote, **{"pass": "nope-4c1d"})
    with pytest.raises(StorageError):
        await asyncio.to_thread(wrong.list)
    with pytest.raises(StorageError):
        await asyncio.to_thread(wrong.read_head, name, 4)
    await asyncio.sleep(1)  # rclone's log lines arrive through a pipe
    obscured = list(daemon._obscured.values())
    assert obscured
    for text in (caplog.text, *[r.getMessage() for r in caplog.records]):
        assert f":{remote.kind}," not in text and f"%3A{remote.kind}" not in text
        assert remote.password not in text and "nope-4c1d" not in text
        assert not any(value in text for value in obscured)


# 5 GB (EXIT CRITERION)


@pytest.mark.slow
async def test_five_gigabytes(daemon: RcloneDaemon, staging: Path, remote: Remote) -> None:
    storage = backend(daemon, staging, remote)
    local = staging / f"upload-{os.urandom(16).hex()}"
    digest = hashlib.sha256()
    block = os.urandom(MiB)
    with local.open("wb") as handle:
        for i in range(5 * 1024):
            chunk = block[i % 256 :] + block[: i % 256]  # every MiB differs
            digest.update(chunk)
            handle.write(chunk)
    name = new_name()
    stored = await put(storage, local, name)
    local.unlink()
    assert stored.size == 5 * 1024 * MiB
    remote_digest = hashlib.sha256()
    with remote.path(name).open("rb") as handle:
        while chunk := handle.read(8 * MiB):
            remote_digest.update(chunk)
    assert remote_digest.hexdigest() == digest.hexdigest()
    await asyncio.to_thread(storage.delete, name)


async def test_a_cold_ranged_read_fails_closed(
    daemon: RcloneDaemon, staging: Path, webdav: WebdavServer
) -> None:
    """The ranged GET cannot carry the certificate: without an rc call first it must not
    connect at all, rather than trust something else."""
    (webdav.root / "backups").mkdir()
    name = new_name()
    (webdav.root / "backups" / name).write_bytes(b"zstd")
    storage = RcloneBackend(daemon, "webdav", webdav.config(), staging)
    conn = connection_string("webdav", await asyncio.to_thread(storage._settings), "backups")
    with pytest.raises(RcloneError, match="unknown authority"):
        await asyncio.to_thread(daemon.read_range, conn, name, 4)
    assert await asyncio.to_thread(storage.read_head, name, 4) == b"zstd"


# CERTIFICATE CHECKS


def test_hosts_match_as_go_checks_them() -> None:
    ca = certificate("CA", [])
    by_ip, _ = certificate("nas", ["192.168.1.10"], ca)
    by_name, _ = certificate("nas", ["nas.example.com", "*.lan"], ca)
    assert certs.matches(by_ip, "192.168.1.10") and not certs.matches(by_ip, "nas.lan")
    assert certs.matches(by_name, "NAS.example.com.") and certs.matches(by_name, "x.lan")
    assert not certs.matches(by_name, "a.b.lan") and not certs.matches(by_name, "lan")
    assert not certs.matches(by_name, "192.168.1.10")
    assert certs.problem(by_ip, "192.168.1.10") is None
    assert "is not for nas.lan" in (certs.problem(by_ip, "nas.lan") or "")
    # An IP address listed as a DNS name: Go refuses it for that address, so drydock does.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "nas")])
    now = datetime.datetime.now(datetime.UTC)
    ip_as_name = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("192.168.1.10")]), False)
        .sign(key, hashes.SHA256())
    )
    assert not certs.matches(ip_as_name, "192.168.1.10")


async def test_changing_the_pinned_certificate_needs_the_secrets_again(
    admin: Browser, webdav: WebdavServer
) -> None:
    form = dav_form(webdav, opt_tls_cert=certs.pem(webdav.cert))
    response = await admin.post("/storage", form)
    assert response.status_code == 303
    storage_id = int(response.headers["location"].rsplit("/", 1)[1])
    other, _ = certificate("other", ["127.0.0.1"], certificate("other CA", []))
    for value in (certs.pem(other), ""):
        response = await admin.post(
            f"/storage/{storage_id}", form | {"opt_pass": "", "opt_tls_cert": value}
        )
        assert response.status_code == 422 and "must be entered again" in response.text
        assert stored(admin, storage_id)["options"]["tls_cert"] == certs.pem(webdav.cert)
    # The same certificate with other line endings is no change.
    crlf = certs.pem(webdav.cert).replace("\n", "\r\n")
    response = await admin.post(
        f"/storage/{storage_id}", form | {"opt_pass": "", "opt_tls_cert": crlf}
    )
    assert response.status_code == 303, response.text


async def test_a_webdav_target_saved_before_certificates_can_be_edited(
    admin: Browser, webdav: WebdavServer
) -> None:
    response = await admin.post("/storage", dav_form(webdav, opt_tls_cert=certs.pem(webdav.cert)))
    storage_id = int(response.headers["location"].rsplit("/", 1)[1])
    config = stored(admin, storage_id)
    del config["options"]["tls_cert"]
    crypto = admin.app.state.crypto
    admin.sql(
        "UPDATE storage_targets SET config_enc = ? WHERE id = ?",
        (crypto.encrypt(json.dumps(config)), storage_id),
    )
    form = dav_form(webdav, name="renamed", opt_pass="")
    response = await admin.post(f"/storage/{storage_id}", form)
    assert response.status_code == 303, response.text
    (details,) = admin.sql("SELECT details FROM audit_events WHERE action = 'storage.update'")[0]
    assert "options_changed" not in json.loads(details)


def stored(browser: Browser, storage_id: int) -> dict:
    (blob,) = browser.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,))[0]
    return json.loads(browser.app.state.crypto.decrypt(blob))


async def test_fetching_on_the_edit_page_changes_nothing_until_saved(
    admin: Browser, webdav: WebdavServer, sftp
) -> None:
    response = await admin.post("/storage", dav_form(webdav, opt_tls_cert=""))
    storage_id = int(response.headers["location"].rsplit("/", 1)[1])
    before = admin.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,))
    response = await admin.post(
        f"/storage/certificate?storage_id={storage_id}", dav_form(webdav, opt_pass="")
    )
    assert response.status_code == 200
    assert certs.pem(webdav.cert).strip() in response.text
    assert 'placeholder="unchanged"' in response.text
    assert admin.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,)) == before
    ((target,),) = admin.sql("SELECT target FROM audit_events WHERE action = 'storage.cert_fetch'")
    assert target == f"storage:{storage_id}"
    from tests.test_sftp_storage import add_sftp

    sftp_id = await add_sftp(admin, sftp, "nas-sftp")
    response = await admin.post(f"/storage/certificate?storage_id={sftp_id}", dav_form(webdav))
    assert response.status_code == 404


async def test_fetching_a_certificate_needs_a_recent_password_check(
    admin: Browser, webdav: WebdavServer
) -> None:
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    assert (await admin.post("/storage/certificate", dav_form(webdav))).status_code == 403
    assert "storage.cert_fetch" not in str(admin.sql("SELECT action FROM audit_events"))


# RESTORE (EXIT CRITERION, WITH 6E)


async def test_a_restore_downloads_verifies_and_applies(
    admin: Browser,
    fakes: Fakes,
    streamed: list[str],
    remote: Remote,
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_remote(admin, remote)
    fakes.target = target_info(host_id)
    name = web_archive(admin)
    copy = remote.path(name)
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(admin.settings.local_storage_roots[0] / name, copy)
    response = await admin.post(
        "/restore/from-storage", {"storage_id": str(storage_id), "name": name}
    )
    assert response.status_code == 303, response.text
    (run_id,) = admin.sql("SELECT id FROM runs WHERE kind = 'restore'")[0]
    await dispatcher(admin).wait(run_id)
    assert run_status(admin, run_id) == "awaiting_confirmation", run_row(admin, run_id)
    text = log_text(admin, run_id)
    assert f"Downloaded {copy.stat().st_size} bytes." in text
    assert remote.password not in text and f":{remote.kind}," not in text
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    assert run_status(admin, run_id) == "done", run_row(admin, run_id)
    assert streamed and not staged_dir(admin, run_id).exists()
    assert remote.files() == [name]
