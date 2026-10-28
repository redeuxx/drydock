"""RcloneBackend over SFTP (Phases 6c and 6e), against `rclone serve sftp` and a real rcd:
the full cycle, host key pinning, cancel, rclone's death, downloads, what reaches rclone,
and the logs."""

import asyncio
import json
import logging
import os
import re
import shutil
import signal
import threading
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import asyncssh
import httpx
import pytest

from drydock.archive import writer
from drydock.archive.writer import InsufficientSpace
from drydock.crypto import Crypto
from drydock.restore import verify
from drydock.storage.base import StorageError, archive_name
from drydock.storage.rclone import (
    BAD_CONFIG,
    CANCELLED,
    NO_HOST_KEY,
    UNKNOWN,
    WRONG_KEY,
    RcloneBackend,
    Reserved,
    connection_string,
    settings_for,
)
from drydock.storage.rclone_rc import READY_TIMEOUT, RcloneDaemon, RcloneError, log_record
from tests.docker_support import wait_until
from tests.rclone_support import SftpServer, needs_rclone, public_key, sftp_server
from tests.restore_support import build_archive

pytestmark = [pytest.mark.anyio, needs_rclone]

MiB = 1024 * 1024
HOST_KEY = public_key(asyncssh.generate_private_key("ssh-ed25519"))


@pytest.fixture
async def daemon(tmp_path: Path) -> AsyncIterator[RcloneDaemon]:
    """rclone as the app runs it: under the lifespan's umask 077, which files it makes keep."""
    umask = os.umask(0o077)
    rclone = RcloneDaemon(tmp_path / "rc")
    try:
        await rclone.start()
        yield rclone
    finally:
        await rclone.close()
        os.umask(umask)


@pytest.fixture
def staging(tmp_path: Path) -> Path:
    path = tmp_path / "staging"
    path.mkdir(mode=0o700)
    return path


def backend(daemon: RcloneDaemon, staging: Path, config: dict) -> RcloneBackend:
    return RcloneBackend(daemon, "sftp", config, staging)


def upload_file(staging: Path, data: bytes) -> Path:
    path = staging / f"upload-{uuid.uuid4().hex}"
    path.write_bytes(data)
    return path


def new_name() -> str:
    return archive_name(str(uuid.uuid4()), "web", datetime.now(UTC), False)


def names(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


async def put(storage: RcloneBackend, local: Path, name: str, **kwargs):
    cancel = kwargs.pop("cancel", None) or threading.Event()
    return await asyncio.to_thread(storage.put, local, name, kwargs.get("progress"), cancel)


def spy(daemon: RcloneDaemon, monkeypatch) -> list[tuple[str, dict]]:
    """Records every rc call and ranged read that reaches the daemon."""
    calls: list[tuple[str, dict]] = []
    real_call, real_read = daemon.call, daemon.read_range

    def call(method, params=None, timeout=60.0):
        calls.append((method, json.loads(json.dumps(params or {}))))
        return real_call(method, params, timeout)

    def read_range(fs, remote, max_bytes, timeout=60.0):
        calls.append(("GET", {"fs": fs, "remote": remote}))
        return real_read(fs, remote, max_bytes, timeout)

    monkeypatch.setattr(daemon, "call", call)
    monkeypatch.setattr(daemon, "read_range", read_range)
    return calls


# THE FULL CYCLE


@pytest.mark.parametrize("auth", ["password", "key", "key-passphrase"])
async def test_put_list_read_head_delete(
    daemon: RcloneDaemon, staging: Path, tmp_path: Path, auth: str
) -> None:
    with sftp_server(tmp_path / "sftp") as server:
        config = server.config(auth="password" if auth == "password" else "key")
        if auth == "key-passphrase":
            pem = server.client_key.export_private_key("openssh", "pp-7c1e").decode()
            config["options"] |= {"key_pem": pem, "key_file_pass": "pp-7c1e"}
        storage = backend(daemon, staging, config)
        src = tmp_path / "src"
        src.mkdir()
        name, manifest = build_archive(src, Crypto((os.urandom(32),)), job_name="web")
        local = upload_file(staging, (src / name).read_bytes())
        seen: list[int] = []
        stored = await put(storage, local, name, progress=seen.append)
        assert stored.name == name and stored.size == local.stat().st_size
        assert (server.root / "backups" / name).read_bytes() == local.read_bytes()
        assert seen == sorted(seen)
        listed = await asyncio.to_thread(storage.list)
        assert [(o.name, o.size) for o in listed] == [(name, stored.size)]
        assert await asyncio.to_thread(storage.list, "drydock-other") == []
        preview = await asyncio.to_thread(verify.preview, storage, name)
        assert preview.state == "manifest" and preview.manifest == manifest
        await asyncio.to_thread(storage.delete, name)
        assert server.files() == []
        with pytest.raises(StorageError, match="does not exist in storage"):
            await asyncio.to_thread(storage.delete, name)


async def test_an_absolute_folder_and_an_empty_one(
    daemon: RcloneDaemon, staging: Path, tmp_path: Path
) -> None:
    with sftp_server(tmp_path / "sftp") as server:
        for folder, where in (("/abs/dir", server.root / "abs" / "dir"), ("", server.root)):
            storage = backend(daemon, staging, server.config(folder))
            name = new_name()
            await put(storage, upload_file(staging, b"zstd"), name)
            assert (where / name).read_bytes() == b"zstd"
            assert await asyncio.to_thread(storage.read_head, name, 3) == b"zst"


async def test_put_never_replaces_an_existing_archive(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, sftp.config())
    name = new_name()
    await put(storage, upload_file(staging, b"first"), name)
    with pytest.raises(StorageError, match="already exists"):
        await put(storage, upload_file(staging, b"second"), name)
    assert (sftp.root / "backups" / name).read_bytes() == b"first"
    assert sftp.files() == [name]


async def test_put_takes_only_drydock_staging_files(
    daemon: RcloneDaemon, staging: Path, tmp_path: Path, sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, sftp.config())
    elsewhere = tmp_path / f"upload-{uuid.uuid4().hex}"
    elsewhere.write_bytes(b"x")
    for local in (elsewhere, staging / "drydock.db"):
        with pytest.raises(ValueError, match="staging"):
            await put(storage, local, new_name())
    link = staging / f"upload-{uuid.uuid4().hex}"
    link.symlink_to(elsewhere)
    with pytest.raises(StorageError, match="not a regular file"):
        await put(storage, link, new_name())
    assert sftp.files() == []


async def test_an_upload_is_invisible_until_complete(
    daemon: RcloneDaemon, staging: Path, slow_sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, slow_sftp.config())
    name = new_name()
    started = threading.Event()
    task = asyncio.create_task(
        put(
            storage,
            upload_file(staging, os.urandom(16 * MiB)),
            name,
            progress=lambda n: n > 0 and started.set(),
        )
    )
    await wait_until(started.is_set, 30, "the upload to start")
    assert await asyncio.to_thread(storage.list) == []
    with pytest.raises(StorageError, match="does not exist"):
        await asyncio.to_thread(storage.read_head, name, 10)
    (partial,) = slow_sftp.files()
    assert re.fullmatch(re.escape(name) + r"\.[0-9a-f]{8}\.partial", partial)
    await task
    assert slow_sftp.files() == [name]


# CANCEL AND RCLONE'S DEATH (EXIT CRITERIA)


async def test_cancel_mid_upload_stops_the_rclone_job(
    daemon: RcloneDaemon, staging: Path, slow_sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, slow_sftp.config())
    cancel = threading.Event()
    name = new_name()
    local = upload_file(staging, os.urandom(32 * MiB))
    task = asyncio.create_task(
        put(storage, local, name, cancel=cancel, progress=lambda n: n > 0 and cancel.set())
    )
    with pytest.raises(StorageError) as caught:
        await asyncio.wait_for(task, 40)
    assert str(caught.value) == CANCELLED  # the partial file is gone, or it would be named
    assert slow_sftp.files() == []
    # rclone is not wedged: the next upload works.
    await put(storage, upload_file(staging, b"after"), new_name())


async def test_a_cancel_before_the_upload_sends_nothing(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch
) -> None:
    storage = backend(daemon, staging, sftp.config())
    cancel = threading.Event()
    cancel.set()
    calls = spy(daemon, monkeypatch)
    with pytest.raises(StorageError, match="cancelled"):
        await put(storage, upload_file(staging, b"x"), new_name(), cancel=cancel)
    assert "operations/copyfile" not in [method for method, _ in calls]
    assert sftp.files() == []


async def test_rclone_killed_mid_upload(
    daemon: RcloneDaemon, staging: Path, slow_sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, slow_sftp.config())
    started = threading.Event()
    # 114 characters: rclone shortens the partial file's name, and put still finds it.
    name = archive_name(str(uuid.uuid4()), "x" * 40, datetime.now(UTC), True)
    assert len(name) > 100
    task = asyncio.create_task(
        put(
            storage,
            upload_file(staging, os.urandom(32 * MiB)),
            name,
            progress=lambda n: n > 0 and started.set(),
        )
    )
    await wait_until(started.is_set, 30, "the upload to start")
    (partial,) = slow_sftp.files()
    assert not partial.startswith(name)
    assert daemon.pid is not None
    os.kill(daemon.pid, signal.SIGKILL)
    with pytest.raises(StorageError, match="rclone restarted"):
        await asyncio.wait_for(task, READY_TIMEOUT + 30)
    assert name not in slow_sftp.files()
    # The kill left rclone's partial file behind; put removed it, or would have named it.
    assert slow_sftp.files() == []
    await put(storage, upload_file(staging, b"after"), new_name())


async def test_an_upload_that_completed_despite_a_failure_counts(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch
) -> None:
    """A stop or a restart noticed only after rclone renamed the file: the archive is
    complete, so put returns it rather than leave it uncatalogued."""
    storage = backend(daemon, staging, sftp.config())
    real_wait = storage._wait

    def late(*args):
        real_wait(*args)
        raise StorageError("rclone restarted during the transfer, so it did not finish.")

    monkeypatch.setattr(storage, "_wait", late)
    name = new_name()
    stored = await put(storage, upload_file(staging, b"zstd-complete"), name)
    assert stored.name == name and stored.size == len(b"zstd-complete")


# HOST KEYS (EXIT CRITERIA)


@pytest.mark.parametrize("key_type", ["ssh-ed25519", "ecdsa-sha2-nistp256"])
async def test_a_wrong_host_key_is_refused(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, key_type: str
) -> None:
    impostor = public_key(asyncssh.generate_private_key(key_type))
    storage = backend(daemon, staging, sftp.config(host_keys=impostor))
    for method, args in (("test", ()), ("list", ()), ("read_head", (new_name(), 10))):
        with pytest.raises(StorageError) as caught:
            await asyncio.to_thread(getattr(storage, method), *args)
        assert str(caught.value) == WRONG_KEY, method
    assert sftp.files() == []
    assert not list(staging.iterdir())  # test() removed its upload file


async def test_an_rsa_host_key_and_one_of_several_keys(
    daemon: RcloneDaemon, staging: Path, tmp_path: Path
) -> None:
    with sftp_server(tmp_path / "rsa", key_type="ssh-rsa") as server:
        other = public_key(asyncssh.generate_private_key("ssh-ed25519"))
        storage = backend(daemon, staging, server.config(host_keys=f"{other},{server.host_keys}"))
        await asyncio.to_thread(storage.test)
        assert server.files() == []


@pytest.mark.parametrize("host_keys", [None, "", "  ", ",", "ssh-ed25519 notbase64", "garbage"])
async def test_no_valid_host_key_is_refused_before_any_call(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch, host_keys: str | None
) -> None:
    config = sftp.config()
    if host_keys is None:
        del config["options"]["host_keys"]  # a target saved before 6c
    else:
        config["options"]["host_keys"] = host_keys
    storage = backend(daemon, staging, config)
    calls = spy(daemon, monkeypatch)
    for method, args in (("test", ()), ("list", ()), ("read_head", (new_name(), 10))):
        with pytest.raises(StorageError, match="no valid host key"):
            await asyncio.to_thread(getattr(storage, method), *args)
    with pytest.raises(StorageError, match="no valid host key"):
        storage.secrets()
    assert calls == []


# WHAT REACHES RCLONE


@pytest.mark.parametrize(
    "planted",
    [
        {"ssh": "touch /tmp/pwned"},
        {"known_hosts_file": "/etc/passwd"},
        {"shell_type": "unix"},
        {"pin_host_key": "true"},
        {"md5sum_command": "id"},
        {"key_file": "/data/drydock.db"},
        {"pass": 1},
    ],
)
def test_options_outside_the_allowlist_are_refused(planted: dict) -> None:
    config = {"folder": "", "options": {"host": "h", "host_keys": HOST_KEY, **planted}}
    with pytest.raises(StorageError, match=re.escape(BAD_CONFIG)):
        settings_for("sftp", config, lambda secret: secret)


def test_drydock_sets_the_security_options_last() -> None:
    config = {"folder": "", "options": {"host": "h", "host_keys": HOST_KEY, "user": "u"}}
    values = settings_for("sftp", config, lambda secret: secret)
    assert values["shell_type"] == "none" and values["known_hosts_file"] == ""
    assert values["pin_host_key"] == "false" and values["key_use_agent"] == "false"
    assert values["host_keys"] == HOST_KEY
    for kind in ("drive", "local", "s3"):
        with pytest.raises(StorageError, match="later release"):
            settings_for(kind, config, lambda secret: secret)


async def test_secrets_reach_rclone_only_obscured(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch
) -> None:
    pem = sftp.client_key.export_private_key("openssh", "pp-3d9a").decode()
    config = sftp.config(auth="key", key_pem=pem, key_file_pass="pp-3d9a")
    config["options"]["pass"] = sftp.password
    storage = backend(daemon, staging, config)
    calls = spy(daemon, monkeypatch)
    name = new_name()
    await put(storage, upload_file(staging, b"zstd"), name)
    await asyncio.to_thread(storage.read_head, name, 4)
    sent = [json.dumps(params) for method, params in calls if method != "core/obscure"]
    for secret in (sftp.password, "pp-3d9a"):
        assert not any(secret in text for text in sent)
        assert any(params == {"clear": secret} for _, params in calls)
    assert not any("\n" in params.get("fs", "") for method, params in calls if method == "GET")
    # Obscured once per secret: rclone's fs cache keeps hitting, and its config map stays small.
    obscures = [params["clear"] for method, params in calls if method == "core/obscure"]
    assert len(obscures) == len(set(obscures))
    other = backend(daemon, staging, config)
    await asyncio.to_thread(other.list)
    assert [m for m, _ in calls].count("core/obscure") == len(obscures)


# CONNECTION STRINGS


@pytest.mark.parametrize(("field", "value"), [("user", "a]b"), ("folder", "x]y")])
async def test_a_closing_bracket_is_refused_before_the_ranged_read(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch, field: str, value: str
) -> None:
    config = sftp.config()
    if field == "folder":
        config["folder"] = value
    else:
        config["options"][field] = value
    storage = backend(daemon, staging, config)
    calls = spy(daemon, monkeypatch)
    with pytest.raises(StorageError, match=r"\]"):
        await asyncio.to_thread(storage.read_head, new_name(), 10)
    assert "GET" not in [method for method, _ in calls]


def test_connection_strings_quote_every_value() -> None:
    conn = connection_string("sftp", {"user": "o'brien", "host": "h"}, "/f")
    assert conn == ":sftp,host='h',user='o''brien':/f"


async def test_quoting_round_trips(daemon: RcloneDaemon, staging: Path, tmp_path: Path) -> None:
    for user in ("o'brien", "a,b=c:d"):
        with sftp_server(tmp_path / uuid.uuid4().hex[:8], user=user) as server:
            storage = backend(daemon, staging, server.config("back ups/o'k#1?%41,x=y"))
            name = new_name()
            await put(storage, upload_file(staging, b"zstd-bytes"), name)
            assert await asyncio.to_thread(storage.read_head, name, 4) == b"zstd"
            assert (server.root / "back ups" / "o'k#1?%41,x=y" / name).is_file()


# LISTING AND TEST


async def test_list_ignores_partials_probes_and_strangers(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, sftp.config())
    assert await asyncio.to_thread(storage.list) == []  # the folder does not exist yet
    name = new_name()
    await put(storage, upload_file(staging, b"zstd"), name)
    folder = sftp.root / "backups"
    (folder / "notes.txt").write_bytes(b"x")
    (folder / f"{name}.0123abcd.partial").write_bytes(b"x")
    (folder / f".drydock-test-{uuid.uuid4().hex}").write_bytes(b"x")
    (folder / new_name()).mkdir()
    assert [o.name for o in await asyncio.to_thread(storage.list)] == [name]


async def test_the_test_leaves_nothing_behind(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, sftp.config())
    await asyncio.to_thread(storage.test)
    assert sftp.files() == [] and list(staging.iterdir()) == []
    config = sftp.config()
    config["options"]["pass"] = "not-the-password"
    wrong = backend(daemon, staging, config)
    with pytest.raises(StorageError, match="refused the user name, password or key"):
        await asyncio.to_thread(wrong.test)


# DOWNLOADS


async def get(storage: RcloneBackend, name: str, local: Path, **kwargs) -> int:
    cancel = kwargs.pop("cancel", None) or threading.Event()
    return await asyncio.to_thread(storage.get, name, local, kwargs.get("progress"), cancel)


async def test_get_downloads_into_staging(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, sftp.config())
    name, data = new_name(), os.urandom(3 * MiB)
    await put(storage, upload_file(staging, data), name)
    folder = staging / "restore-1" / "download"
    folder.mkdir(parents=True, mode=0o700)
    seen: list[int] = []
    assert await get(storage, name, folder / name, progress=seen.append) == len(data)
    assert (folder / name).read_bytes() == data and names(folder) == [name]
    assert (folder / name).stat().st_mode & 0o077 == 0
    assert seen == sorted(seen)
    with pytest.raises(StorageError, match="already in the staging directory"):
        await get(storage, name, folder / name)
    assert (folder / name).read_bytes() == data
    missing = new_name()
    with pytest.raises(StorageError, match="does not exist in storage"):
        await get(storage, missing, folder / missing)
    assert names(folder) == [name]
    # Restores read the download; reading in place is refused.
    with pytest.raises(StorageError, match="download in the staging directory"):
        storage.open(name)


async def test_get_writes_only_below_staging(
    daemon: RcloneDaemon, staging: Path, tmp_path: Path, sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, sftp.config())
    name = new_name()
    for local in (tmp_path / name, staging / ".." / name, staging / "x" / ".." / ".." / name):
        with pytest.raises(ValueError, match="staging"):
            await get(storage, name, local)
    with pytest.raises(StorageError, match="Invalid archive name"):
        await get(storage, name, staging / "../escape")
    assert not (tmp_path / name).exists()


async def test_get_checks_free_space_before_downloading(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch
) -> None:
    storage = backend(daemon, staging, sftp.config())
    name = new_name()
    await put(storage, upload_file(staging, os.urandom(MiB)), name)
    real = shutil.disk_usage
    monkeypatch.setattr(
        writer.shutil, "disk_usage", lambda path: real(path)._replace(free=writer.RESERVE)
    )
    calls = spy(daemon, monkeypatch)
    with pytest.raises(InsufficientSpace, match="Not enough free space in the staging"):
        await get(storage, name, staging / name)
    assert "operations/copyfile" not in [method for method, _ in calls]
    assert not any(n.startswith(name) for n in names(staging))
    # The archive's listed size is what counts: one byte short fails, exactly enough works.
    for free, works in ((MiB + writer.RESERVE - 1, False), (MiB + writer.RESERVE, True)):
        monkeypatch.setattr(
            writer.shutil, "disk_usage", lambda path, free=free: real(path)._replace(free=free)
        )
        if works:
            assert await get(storage, name, staging / name) == MiB
        else:
            with pytest.raises(InsufficientSpace):
                await get(storage, name, staging / name)


async def test_downloads_in_flight_count_against_free_space(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, monkeypatch
) -> None:
    storage = backend(daemon, staging, sftp.config())
    name = new_name()
    await put(storage, upload_file(staging, os.urandom(MiB)), name)
    free = shutil.disk_usage(staging).free
    monkeypatch.setattr(Reserved, "total", free)  # another download holds it all
    calls = spy(daemon, monkeypatch)
    with pytest.raises(InsufficientSpace):
        await get(storage, name, staging / name)
    assert "operations/copyfile" not in [method for method, _ in calls]
    monkeypatch.setattr(Reserved, "total", 0)
    assert await get(storage, name, staging / name) == MiB
    assert Reserved.total == 0  # released


async def test_a_download_larger_than_listed_is_stopped(
    daemon: RcloneDaemon, staging: Path, slow_sftp: SftpServer, monkeypatch
) -> None:
    """A remote that lists a small size and sends more must not fill the staging disk."""
    storage = backend(daemon, staging, slow_sftp.config())
    name = new_name()
    (slow_sftp.root / "backups").mkdir()
    (slow_sftp.root / "backups" / name).write_bytes(os.urandom(32 * MiB))
    real = storage._stat
    monkeypatch.setattr(storage, "_stat", lambda n, timeout=90.0: real(n, timeout) | {"Size": 1024})
    folder = staging / "download"
    folder.mkdir()
    with pytest.raises(StorageError, match="larger than it was listed"):
        await asyncio.wait_for(get(storage, name, folder / name), 40)
    assert names(folder) == []


async def test_cancel_mid_download_leaves_nothing(
    daemon: RcloneDaemon, staging: Path, slow_sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, slow_sftp.config())
    name = new_name()
    data = os.urandom(32 * MiB)
    (slow_sftp.root / "backups").mkdir()
    (slow_sftp.root / "backups" / name).write_bytes(data)  # the server throttles reads too
    folder = staging / "download"
    folder.mkdir()
    cancel = threading.Event()
    task = asyncio.create_task(
        get(storage, name, folder / name, cancel=cancel, progress=lambda n: n > 0 and cancel.set())
    )
    with pytest.raises(StorageError) as caught:
        await asyncio.wait_for(task, 40)
    assert str(caught.value) == CANCELLED
    assert names(folder) == []
    assert slow_sftp.files() == [name]


async def test_a_failed_download_removes_rclones_partial_file(
    daemon: RcloneDaemon, staging: Path, slow_sftp: SftpServer
) -> None:
    storage = backend(daemon, staging, slow_sftp.config())
    name = new_name()
    (slow_sftp.root / "backups").mkdir()
    (slow_sftp.root / "backups" / name).write_bytes(os.urandom(32 * MiB))
    folder = staging / "download"
    folder.mkdir()
    started = threading.Event()
    task = asyncio.create_task(
        get(storage, name, folder / name, progress=lambda n: n > 0 and started.set())
    )
    await wait_until(started.is_set, 30, "the download to start")
    (partial,) = names(folder)
    assert re.fullmatch(re.escape(name) + r"\.[0-9a-f]{8}\.partial", partial)
    assert daemon.pid is not None
    os.kill(daemon.pid, signal.SIGKILL)  # rclone cannot remove its partial file itself
    with pytest.raises(StorageError, match="rclone restarted"):
        await asyncio.wait_for(task, READY_TIMEOUT + 30)
    assert names(folder) == []


# LOGS


async def test_logs_hold_no_secret_and_no_connection_string(
    daemon: RcloneDaemon, staging: Path, sftp: SftpServer, caplog
) -> None:
    caplog.set_level(logging.INFO)
    config = sftp.config()
    storage = backend(daemon, staging, config)
    name = new_name()
    await put(storage, upload_file(staging, b"zstd"), name)
    with pytest.raises(StorageError):
        await asyncio.to_thread(storage.read_head, new_name(), 10)
    conn = connection_string("sftp", storage._settings(), "backups")
    # Without the rc credentials: rclone logs the path of a request that fails auth.
    async with httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(uds=str(daemon.socket_path)), base_url="http://rc"
    ) as client:
        response = await client.get("/" + quote(f"[{conn}]", safe="[]") + f"/{name}")
    assert response.status_code == 401
    wrong = backend(daemon, staging, config | {"options": config["options"] | {"pass": "nope"}})
    with pytest.raises(StorageError):
        await asyncio.to_thread(wrong.list)
    await asyncio.sleep(1)  # rclone's log lines arrive through a pipe
    obscured = list(daemon._obscured.values())
    assert obscured
    for text in (caplog.text, *[r.getMessage() for r in caplog.records]):
        assert ":sftp," not in text and "%3Asftp" not in text
        assert sftp.password not in text and "nope" not in text
        assert not any(value in text for value in obscured)


def test_log_record_redacts_connection_strings() -> None:
    line = (
        "2026/10/24 21:43:16 INFO  : /[:sftp,host='h',pass='SECRETOBSCURED']/a.tar.zst: @: "
        "Unauthorized request from "
    )
    _, _, text = log_record(line)
    assert "SECRETOBSCURED" not in text and "connection string redacted" in text
    _, _, cut = log_record("ERROR : rc: %5B%3Asftp%2Chost%3D%27h%27%2Cpass%3D%27SECRET")
    assert "SECRET" not in cut


def test_names_the_user_chose_never_pick_the_message() -> None:
    config = {"folder": "backups", "options": {"host": "quota-nas", "user": "u"}}
    storage = RcloneBackend(None, "sftp", config, Path("/nonexistent"))  # type: ignore[arg-type]
    error = storage._error(RcloneError(500, "dial tcp: lookup quota-nas: server misbehaving"))
    assert str(error) == UNKNOWN
    error = storage._error(RcloneError(500, "sftp: disk quota exceeded"))
    assert str(error) == "The remote storage is full."


def test_storage_errors_never_quote_rclone() -> None:
    assert "pin-host-key" not in WRONG_KEY and NO_HOST_KEY.startswith("This storage")
