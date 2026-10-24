"""rclone in tests: the pinned binary's `rclone serve sftp` as a stand-in SFTP server on
127.0.0.1 inside the tests container. Credentials reach it through its environment, its
host key is deleted once it listens, and it never runs without auth."""

import contextlib
import os
import re
import secrets
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import asyncssh
import pytest

from drydock.storage.rclone_rc import RCLONE_BINARY

needs_rclone = pytest.mark.skipif(
    not RCLONE_BINARY.is_file(), reason=f"needs rclone in {RCLONE_BINARY}"
)
SFTP_USER = "backup"
LISTENING_RE = re.compile(rb"SFTP server listening on 127\.0\.0\.1:(\d+)")
START_TIMEOUT = 10.0


def public_key(key: asyncssh.SSHKey) -> str:
    """ "type base64", as rclone's host_keys takes it."""
    return " ".join(key.export_public_key("openssh").decode().split()[:2])


@dataclass
class SftpServer:
    process: subprocess.Popen[bytes]
    port: int
    root: Path  # the served directory: the SFTP user's "/" and home
    log_path: Path
    user: str
    password: str
    host_key: asyncssh.SSHKey
    client_key: asyncssh.SSHKey

    @property
    def host_keys(self) -> str:
        return public_key(self.host_key)

    def config(self, folder: str = "backups", *, auth: str = "password", **opts: str) -> dict:
        """A stored config as storage.options.parse makes it."""
        values = {
            "host": "127.0.0.1",
            "port": str(self.port),
            "host_keys": self.host_keys,
            "user": self.user,
            "set_modtime": "true",
        }
        if auth == "password":
            values["pass"] = self.password
        else:
            values["key_pem"] = self.client_key.export_private_key("openssh").decode()
        return {"folder": folder, "options": values | opts}

    def files(self, folder: str = "backups") -> list[str]:
        where = self.root / folder
        return sorted(p.name for p in where.iterdir()) if where.is_dir() else []

    def log(self) -> str:
        return self.log_path.read_text(errors="replace")


@contextlib.contextmanager
def sftp_server(
    base: Path, *, user: str = SFTP_USER, bwlimit: str | None = None, key_type: str = "ssh-ed25519"
) -> Iterator[SftpServer]:
    base.mkdir(mode=0o700)
    root = base / "root"
    root.mkdir()
    host_key = asyncssh.generate_private_key(key_type)
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = base / "host_key"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(host_key.export_private_key("openssh"))
    (base / "authorized_keys").write_bytes(client_key.export_public_key("openssh"))
    password = secrets.token_urlsafe(24)
    argv = [
        str(RCLONE_BINARY),
        "serve",
        "sftp",
        str(root),
        "--addr",
        "127.0.0.1:0",
        "--key",
        str(key_path),
        "--authorized-keys",
        str(base / "authorized_keys"),
        "--config",
        "/dev/null",
        "--log-level",
        "INFO",
        # The server's VFS would serve listings from its directory cache, which misses a
        # file whose upload broke off; a real SFTP server lists the disk.
        "--dir-cache-time",
        "0s",
    ]
    if bwlimit:
        argv += ["--bwlimit", bwlimit]  # the server side: a per-call BwLimit does not throttle
    log_path = base / "serve.log"
    with log_path.open("wb") as log:  # a file, not a pipe nobody drains
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env={"RCLONE_USER": user, "RCLONE_PASS": password, "HOME": str(base)},
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT
        while not (match := LISTENING_RE.search(log_path.read_bytes())):
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"rclone serve sftp did not start:\n{log_path.read_text()}")
            time.sleep(0.05)
        key_path.unlink()  # loaded; no private key is left lying around
        yield SftpServer(
            process, int(match[1]), root, log_path, user, password, host_key, client_key
        )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
