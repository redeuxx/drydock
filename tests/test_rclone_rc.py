"""rclone rcd: a private unix socket, per-boot credentials, no config file, restart on death."""

import asyncio
import contextlib
import errno
import logging
import os
import re
import signal
import stat
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import uvloop

from drydock.config import Settings
from drydock.storage import rclone_rc
from drydock.storage.rclone_rc import (
    RCLONE_BINARY,
    RcloneDaemon,
    RcloneError,
    RcloneUnavailable,
    log_record,
)
from tests.conftest import running

pytestmark = pytest.mark.anyio
needs_rclone = pytest.mark.skipif(
    not RCLONE_BINARY.is_file(), reason=f"needs rclone in {RCLONE_BINARY}"
)


@pytest.fixture
async def daemon(tmp_path: Path) -> AsyncIterator[RcloneDaemon]:
    rclone = RcloneDaemon(tmp_path / "run")
    await rclone.start()
    try:
        yield rclone
    finally:
        await rclone.close()


async def call(rclone: RcloneDaemon, method: str, params: dict | None = None) -> dict:
    return await asyncio.to_thread(rclone.call, method, params)


async def post(rclone: RcloneDaemon, method: str) -> dict:
    """A call outside the allowlist, with the daemon's credentials."""
    return await asyncio.to_thread(rclone._post, method, {}, 10.0)


# PROC HELPERS


def socket_inodes(pid: int) -> set[str]:
    inodes = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        with contextlib.suppress(OSError):
            if match := re.fullmatch(r"socket:\[(\d+)\]", str(fd.readlink())):
                inodes.add(match[1])
    return inodes


def tcp_listener_inodes() -> set[str]:
    inodes = set()
    for name in ("tcp", "tcp6"):
        for line in Path(f"/proc/net/{name}").read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A":  # LISTEN
                inodes.add(fields[9])
    return inodes


def unix_socket_inode(path: Path) -> str | None:
    for line in Path("/proc/net/unix").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) == 8 and fields[7] == str(path):
            return fields[6]
    return None


# DAEMON


@needs_rclone
async def test_calls_reach_rclone(daemon: RcloneDaemon) -> None:
    assert await call(daemon, "rc/noop", {"a": 1}) == {"a": 1}


@needs_rclone
async def test_listens_only_on_a_private_unix_socket(daemon: RcloneDaemon) -> None:
    await call(daemon, "rc/noop")
    assert daemon.pid is not None
    assert stat.S_IMODE(daemon.socket_path.stat().st_mode) == 0o600
    inodes = socket_inodes(daemon.pid)
    assert unix_socket_inode(daemon.socket_path) in inodes
    assert not inodes & tcp_listener_inodes()


@needs_rclone
async def test_calls_need_the_per_boot_credentials(daemon: RcloneDaemon) -> None:
    await call(daemon, "rc/noop")
    transport = httpx.HTTPTransport(uds=str(daemon.socket_path))
    with httpx.Client(transport=transport, base_url="http://rclone") as client:
        for auth in (None, ("drydock", "wrong"), ("other", daemon._password)):
            for method in ("rc/noop", "config/listremotes", "operations/list"):
                assert client.post(f"/{method}", json={}, auth=auth).status_code == 401
    assert RcloneDaemon(daemon.run_dir)._password != daemon._password


@needs_rclone
async def test_no_secret_on_the_command_line_and_a_clean_environment(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    caplog.set_level(logging.INFO, logger="drydock.rclone")
    monkeypatch.setenv("DRYDOCK_SECRET_KEY", "not-for-rclone")
    monkeypatch.setenv("RCLONE_CONFIG_PLANTED_TYPE", "local")
    monkeypatch.setenv("RCLONE_RC_NO_AUTH", "true")
    rclone = RcloneDaemon(tmp_path / "run")
    await rclone.start()
    try:
        await call(rclone, "rc/noop")
        proc = Path(f"/proc/{rclone.pid}")
        argv = proc.joinpath("cmdline").read_bytes().split(b"\0")[:-1]
        assert argv == [
            str(RCLONE_BINARY).encode(),
            b"rcd",
            b"--rc-addr",
            f"unix://{rclone.socket_path}".encode(),
            b"--config",
            b"/dev/null",
            b"--log-level",
            b"INFO",
        ]
        environ = dict(
            item.split(b"=", 1) for item in proc.joinpath("environ").read_bytes().split(b"\0")[:-1]
        )
        assert set(environ) == {b"RCLONE_RC_USER", b"RCLONE_RC_PASS", b"TMPDIR"}
        # The configuration lives in memory only ("" is rclone's in-memory config), and the
        # planted remote never reached it. config/* is outside call()'s allowlist.
        assert (await post(rclone, "config/paths"))["config"] == ""
        assert await post(rclone, "config/listremotes") == {"remotes": []}
    finally:
        await rclone.close()
    assert "rclone: " in caplog.text
    assert rclone._password not in caplog.text


@needs_rclone
async def test_errors_keep_only_rclones_message(daemon: RcloneDaemon, caplog) -> None:
    caplog.set_level(logging.INFO, logger="drydock.rclone")
    # rclone's error body echoes the call's input, which holds obscured passwords.
    with pytest.raises(RcloneError) as info:
        await call(
            daemon, "operations/list", {"fs": ":sftp,host=h,pass=secret-value:", "remote": ""}
        )
    assert info.value.status == 500
    assert "obscured" in str(info.value)
    assert "secret-value" not in str(info.value)
    assert "secret-value" not in caplog.text


def test_the_input_dump_in_rclones_log_is_redacted() -> None:
    line = (
        "2026/10/22 12:00:00 ERROR : rc: writeError: failed to write JSON output from "
        'rc.Params{"fs":":sftp,pass=secret-value:"}: write: broken pipe\n'
    )
    level, _, text = log_record(line)
    assert level == logging.WARNING
    assert "secret-value" not in text
    assert text.endswith("failed to write JSON output from [input redacted]")
    assert log_record("NOTICE: Serving remote control\n")[0] == logging.INFO


@needs_rclone
async def test_rclone_restarts_after_sigkill(daemon: RcloneDaemon, caplog) -> None:
    caplog.set_level(logging.INFO, logger="drydock.rclone")
    await call(daemon, "rc/noop")
    first = daemon.pid
    assert first is not None
    os.kill(first, signal.SIGKILL)
    deadline = time.monotonic() + 15
    while daemon.pid in (None, first) and time.monotonic() < deadline:
        await asyncio.sleep(0.1)
    assert await call(daemon, "rc/noop", {"b": 2}) == {"b": 2}
    assert daemon.pid not in (None, first)
    assert "rclone exited with status -9" in caplog.text


@needs_rclone
async def test_close_stops_rclone(tmp_path: Path) -> None:
    rclone = RcloneDaemon(tmp_path / "run")
    await rclone.start()
    await call(rclone, "rc/noop")
    pid = rclone.pid
    await rclone.close()
    assert rclone.pid is None
    assert not Path(f"/proc/{pid}").exists()
    assert not rclone.socket_path.exists()
    with pytest.raises(RcloneUnavailable):
        rclone.call("rc/noop")


@needs_rclone
async def test_the_lifespan_runs_rclone(settings: Settings) -> None:
    async with running(settings) as browser:
        rclone = browser.app.state.rclone
        assert await call(rclone, "rc/noop", {"c": 3}) == {"c": 3}
        pid = rclone.pid
    assert rclone.pid is None
    assert not Path(f"/proc/{pid}").exists()


async def test_an_unstarted_daemon_refuses_calls(tmp_path: Path) -> None:
    """A second drydock process never starts rclone; its calls fail at once."""
    with pytest.raises(RcloneUnavailable, match="primary"):
        RcloneDaemon(tmp_path / "run").call("rc/noop")


async def test_a_missing_binary_is_reported(tmp_path: Path, caplog) -> None:
    rclone = RcloneDaemon(tmp_path / "run", binary=tmp_path / "missing")
    await rclone.start()
    try:
        assert rclone._task is not None
        await rclone._task  # gives up without retrying
        with pytest.raises(RcloneUnavailable, match="could not start"):
            rclone.call("rc/noop")
    finally:
        await rclone.close()
    assert "rclone could not start" in caplog.text


@needs_rclone
def test_runs_under_uvloop(tmp_path: Path) -> None:
    """Production runs uvicorn on uvloop, whose subprocess_exec takes fewer arguments."""

    async def noop() -> dict:
        rclone = RcloneDaemon(tmp_path / "run")
        await rclone.start()
        try:
            return await call(rclone, "rc/noop", {"u": 1})
        finally:
            await rclone.close()

    assert uvloop.run(noop()) == {"u": 1}


@needs_rclone
async def test_a_transient_spawn_failure_is_retried(tmp_path: Path, monkeypatch) -> None:
    real = asyncio.create_subprocess_exec
    failures = [OSError(errno.EMFILE, "Too many open files")]

    async def flaky(*args, **kwargs):
        if failures:
            raise failures.pop()
        return await real(*args, **kwargs)

    monkeypatch.setattr(rclone_rc.asyncio, "create_subprocess_exec", flaky)
    monkeypatch.setattr(rclone_rc, "BACKOFF_INITIAL", 0.05)
    rclone = RcloneDaemon(tmp_path / "run")
    await rclone.start()
    try:
        assert await call(rclone, "rc/noop", {"d": 4}) == {"d": 4}
        assert not failures
    finally:
        await rclone.close()


async def test_close_wakes_calls_waiting_for_rclone(tmp_path: Path) -> None:
    """A stand-in that never answers: the waiting call fails as soon as close() runs."""
    binary = tmp_path / "silent"
    binary.write_text("#!/bin/sh\nexec /bin/sleep 60\n")  # rclone's environment has no PATH
    binary.chmod(0o755)
    rclone = RcloneDaemon(tmp_path / "run", binary=binary)
    await rclone.start()
    waiting = asyncio.create_task(call(rclone, "rc/noop"))
    await asyncio.sleep(0.5)
    started = time.monotonic()
    await rclone.close()
    with pytest.raises(RcloneUnavailable, match="stopped"):
        await waiting
    assert time.monotonic() - started < 5


def test_method_names_are_checked(tmp_path: Path) -> None:
    rclone = RcloneDaemon(tmp_path / "run")
    for method in ("../rc/noop", "/rc/noop", "options/set", "config/dump", "core/command"):
        with pytest.raises(ValueError, match="allowed rc method"):
            rclone.call(method)
