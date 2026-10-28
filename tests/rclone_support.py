"""rclone in tests: the pinned binary's `rclone serve sftp` and `rclone serve webdav` (over
TLS, with a certificate from a throwaway CA) as stand-in servers on 127.0.0.1 inside the
tests container, and the compose file's samba service. Credentials reach the rclone servers
through their environment, private keys are deleted once they listen, and they never run
without auth."""

import contextlib
import datetime
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import asyncssh
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from drydock.storage.certs import pem
from drydock.storage.rclone_rc import RCLONE_BINARY

needs_rclone = pytest.mark.skipif(
    not RCLONE_BINARY.is_file(), reason=f"needs rclone in {RCLONE_BINARY}"
)
SFTP_USER = "backup"
LISTENING_RE = re.compile(rb"SFTP server listening on 127\.0\.0\.1:(\d+)")
WEBDAV_RE = re.compile(rb"https://127\.0\.0\.1:(\d+)/")
START_TIMEOUT = 10.0
SMB_HOST = os.environ.get("DRYDOCK_TEST_SMB_HOST", "")
SMB_SHARE_DIR = Path(os.environ.get("DRYDOCK_TEST_SMB_SHARE_DIR", "/nonexistent"))
SMB_PASS = os.environ.get("DRYDOCK_TEST_SMB_PASS", "")
needs_samba = pytest.mark.skipif(not SMB_HOST, reason="needs the compose file's samba service")


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


# WEBDAV


def certificate(
    name: str,
    hosts: list[str],
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    *,
    days: int = 1,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A certificate for hosts (IP addresses or DNS names), signed by issuer (a CA) or, as a
    CA itself, by its own key."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    names: list[x509.GeneralName] = []
    for host in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer[0].subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), True)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), False)
    return builder.sign(issuer[1] if issuer else key, hashes.SHA256()), key


@dataclass
class WebdavServer:
    process: subprocess.Popen[bytes]
    port: int
    root: Path  # the served directory
    log_path: Path
    user: str
    password: str
    cert: x509.Certificate  # the server's, signed by a throwaway CA nobody else trusts

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def config(self, folder: str = "backups", **opts: str) -> dict:
        """A stored config as storage.options.parse makes it, the certificate pinned."""
        values = {
            "url": self.url,
            "tls_cert": pem(self.cert),
            "vendor": "other",
            "user": self.user,
            "pass": self.password,
        }
        return {"folder": folder, "options": values | opts}

    def files(self, folder: str = "backups") -> list[str]:
        where = self.root / folder
        return sorted(p.name for p in where.iterdir()) if where.is_dir() else []

    def log(self) -> str:
        return self.log_path.read_text(errors="replace")


@contextlib.contextmanager
def webdav_server(
    base: Path, *, bwlimit: str | None = None, hosts: tuple[str, ...] = ("127.0.0.1",)
) -> Iterator[WebdavServer]:
    base.mkdir(mode=0o700)
    root = base / "root"
    root.mkdir()
    ca = certificate("drydock test CA", [])
    cert, key = certificate("nas", list(hosts), ca)
    cert_path, key_path = base / "cert.pem", base / "key.pem"
    cert_path.write_text(pem(cert))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    user, password = "backup", secrets.token_urlsafe(24)
    argv = [
        str(RCLONE_BINARY),
        "serve",
        "webdav",
        str(root),
        "--addr",
        "127.0.0.1:0",
        "--cert",
        str(cert_path),
        "--key",
        str(key_path),
        "--config",
        "/dev/null",
        "--log-level",
        "INFO",
        "--dir-cache-time",
        "0s",
    ]
    if bwlimit:
        argv += ["--bwlimit", bwlimit]
    log_path = base / "serve.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env={"RCLONE_USER": user, "RCLONE_PASS": password, "HOME": str(base)},
        )
    try:
        deadline = time.monotonic() + START_TIMEOUT
        while not (match := WEBDAV_RE.search(log_path.read_bytes())):
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"rclone serve webdav did not start:\n{log_path.read_text()}")
            time.sleep(0.05)
        key_path.unlink()
        yield WebdavServer(process, int(match[1]), root, log_path, user, password, cert)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


# SMB


@dataclass
class SmbShare:
    """A folder of its own in the samba service's share, removed afterwards."""

    folder: str  # in the share
    user: str = "drydock"
    password: str = SMB_PASS

    def config(self, **opts: str) -> dict:
        values = {
            "host": SMB_HOST,
            "port": "445",
            "user": self.user,
            "pass": self.password,
            "domain": "WORKGROUP",
        }
        return {"folder": f"backups/{self.folder}", "options": values | opts}

    @property
    def path(self) -> Path:
        return SMB_SHARE_DIR / self.folder

    def files(self) -> list[str]:
        return sorted(p.name for p in self.path.iterdir()) if self.path.is_dir() else []


@contextlib.contextmanager
def smb_share() -> Iterator[SmbShare]:
    share = SmbShare(f"t-{uuid.uuid4().hex[:12]}")
    try:
        yield share
    finally:
        shutil.rmtree(share.path, ignore_errors=True)
