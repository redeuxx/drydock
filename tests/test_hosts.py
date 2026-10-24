"""Host connectivity without a real daemon: API negotiation, keys, host key pinning, wiring."""

import ast
import asyncio
import base64
import json
import os
import socketserver
import stat
import textwrap
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import anyio
import asyncssh
import docker
import docker.errors
import pytest
import requests

from drydock.config import ConfigError, Settings
from drydock.crypto import Crypto
from drydock.hosts import client as docker_client
from drydock.hosts import helper, ssh
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.models import Host
from tests.conftest import Browser, make_settings, new_key, running

pytestmark = pytest.mark.anyio

SRC = Path(__file__).resolve().parents[1] / "src" / "drydock"


# FAKE DAEMON


class FakeDaemon:
    """A Docker API stand-in on a unix socket that records request paths."""

    def __init__(self, path: Path, version: dict) -> None:
        self.paths: list[str] = []
        daemon = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                daemon.paths.append(self.path)
                if self.path.endswith("/version"):
                    self.reply(200, json.dumps(version).encode(), "application/json")
                elif self.path.endswith("/_ping"):
                    self.reply(200, b"OK", "text/plain")
                else:
                    self.reply(404, b'{"message": "not found"}', "application/json")

            def reply(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = socketserver.ThreadingUnixStreamServer(str(path), Handler)
        self.server.daemon_threads = True
        self.url = f"unix://{path}"

    @contextmanager
    def serving(self) -> Iterator[FakeDaemon]:
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        try:
            yield self
        finally:
            self.server.shutdown()
            self.server.server_close()


def version(api: str, minimum: str = "1.24", engine: str = "99.0.0") -> dict:
    return {"ApiVersion": api, "MinAPIVersion": minimum, "Version": engine, "Arch": "amd64"}


# API VERSION NEGOTIATION


@pytest.mark.parametrize(
    ("server", "expected"),
    [("1.44", "1.44"), ("1.50", "1.50"), ("1.56", "1.56"), ("1.57", "1.56"), ("1.99", "1.56")],
)
def test_negotiation_caps_at_the_tested_version(tmp_path: Path, server: str, expected: str) -> None:
    with (
        FakeDaemon(tmp_path / "d.sock", version(server)).serving() as daemon,
        docker_client.open_client(daemon.url) as handle,
    ):
        assert handle.api_version == expected
        assert handle.client.api.api_version == expected
        assert handle.client.ping()
    # The version probe is unversioned; every later call uses the negotiated prefix.
    assert daemon.paths == ["/version", f"/v{expected}/_ping"]


def test_daemon_below_1_44_is_refused(tmp_path: Path) -> None:
    with (
        FakeDaemon(tmp_path / "d.sock", version("1.43", engine="24.0.9")).serving() as daemon,
        pytest.raises(docker_client.UnsupportedDaemon) as excinfo,
    ):
        docker_client.open_client(daemon.url)
    message = str(excinfo.value)
    assert "Docker Engine 24.0.9" in message
    assert "needs API 1.44 or newer" in message
    assert daemon.paths == ["/version"]


def test_daemon_that_dropped_1_56_is_refused(tmp_path: Path) -> None:
    with (
        FakeDaemon(tmp_path / "d.sock", version("1.70", minimum="1.60")).serving() as daemon,
        pytest.raises(docker_client.UnsupportedDaemon, match=r"requires API 1\.60"),
    ):
        docker_client.open_client(daemon.url)


@pytest.mark.parametrize("bad", [None, "", "1", "one.two", "1.44; DROP", 144])
def test_malformed_api_version_is_refused(bad: object) -> None:
    with pytest.raises(docker_client.UnsupportedDaemon, match="invalid API version"):
        docker_client.negotiate({"ApiVersion": bad})


@pytest.mark.parametrize("url", ["ssh://root@host", "npipe:////./pipe/docker", "file:///x"])
def test_only_socket_and_http_urls_are_accepted(url: str) -> None:
    with pytest.raises(docker_client.DockerUnavailable, match="Unsupported Docker URL"):
        docker_client.open_client(url)


def test_unreachable_daemon_is_a_clean_error(tmp_path: Path) -> None:
    with pytest.raises(docker_client.DockerUnavailable, match="Cannot reach"):
        docker_client.open_client(f"unix://{tmp_path / 'missing.sock'}")


def test_daemon_errors_do_not_echo_the_response_body(monkeypatch) -> None:
    """Whatever a Docker URL serves must not be reflected into pages or the audit log."""

    def answer_500(self, api_version: bool = True) -> dict:
        response = requests.Response()
        response.status_code = 500
        raise docker.errors.APIError("500", response=response, explanation="instance secret")

    monkeypatch.setattr(docker.APIClient, "version", answer_500)
    with pytest.raises(docker_client.DockerUnavailable) as excinfo:
        docker_client.read_version("tcp://127.0.0.1:9")
    assert "HTTP 500" in str(excinfo.value)
    assert "secret" not in str(excinfo.value)


def test_clients_ignore_proxy_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    with (
        FakeDaemon(tmp_path / "d.sock", version("1.56")).serving() as daemon,
        docker_client.open_client(daemon.url) as handle,
    ):
        assert handle.client.api.trust_env is False


# STATIC CHECKS


def source_trees() -> list[tuple[Path, ast.Module]]:
    return [(path, ast.parse(path.read_text())) for path in sorted(SRC.rglob("*.py"))]


def test_no_code_path_skips_host_key_verification() -> None:
    """known_hosts=None, auto-accepting validators and foreign SSH stacks are all banned.

    ssh.scan_host_key uses asyncssh.get_server_host_key, which only runs the key exchange
    so an admin can compare the fingerprint; it offers no credentials and trusts nothing.
    """
    connect_calls = 0
    for path, tree in source_trees():
        text = path.read_text()
        for banned in ("paramiko", "AutoAddPolicy", "StrictHostKeyChecking"):
            assert banned not in text, f"{path}: {banned}"
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "from_env":
                pytest.fail(f"{path}:{node.lineno}: docker.from_env() reads DOCKER_* variables")
            if isinstance(node, ast.keyword) and node.arg == "known_hosts":
                assert not (isinstance(node.value, ast.Constant) and node.value.value is None), (
                    f"{path}:{node.lineno}: known_hosts=None"
                )
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                assert node.name not in (
                    "validate_host_public_key",
                    "validate_host_ca_key",
                    "server_host_keys_handler",
                ), f"{path}:{node.lineno}: custom host key validation"
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name in ("connect", "connect_reverse", "create_connection", "listen"):
                    owner = func.value if isinstance(func, ast.Attribute) else None
                    if isinstance(owner, ast.Name) and owner.id == "asyncssh":
                        connect_calls += 1
                        keywords = {k.arg: k.value for k in node.keywords}
                        # Every connection uses client_options(), which pins the host key.
                        assert "options" in keywords, f"{path}:{node.lineno}"
                        assert "known_hosts" not in keywords, f"{path}:{node.lineno}"
                if name == "SSHClientConnectionOptions":
                    keywords = {k.arg: k.value for k in node.keywords}
                    assert "known_hosts" in keywords, f"{path}:{node.lineno}"
    assert connect_calls == 1


def test_client_options_pin_the_host_key_and_ignore_the_environment() -> None:
    server_key = asyncssh.generate_private_key("ssh-ed25519")
    target = ssh.SSHTarget(
        host_id=1,
        address="203.0.113.7",
        port=2222,
        username="backup",
        remote_socket_path="/run/user/1000/docker.sock",
        known_host_line=ssh.known_host_line("203.0.113.7", 2222, server_key),
        private_key=asyncssh.generate_private_key("ssh-ed25519"),
    )
    options = ssh.client_options(target)
    assert isinstance(options.known_hosts, asyncssh.SSHKnownHosts)
    assert options.known_hosts  # a falsy value would fall back to ~/.ssh/known_hosts
    trusted = options.known_hosts.match("203.0.113.7", "203.0.113.7", 2222)[0]
    assert {k.public_data for k in trusted} == {server_key.public_data}
    assert options.known_hosts.match("203.0.113.8", "203.0.113.8", 2222)[0] == []
    assert not options.agent_path  # asyncssh stores "no agent" as ""; SSH_AUTH_SOCK is unused
    assert options.x509_trusted_certs is None
    assert options.password_auth is False
    assert options.kbdint_auth is False
    assert options.preferred_auth == ["publickey"] or options.preferred_auth == ("publickey",)
    assert options.keepalive_interval > 0
    assert "private_key" not in repr(target)


@pytest.mark.parametrize(
    "line",
    [
        "203.0.113.8 {key}",  # another address
        "[203.0.113.7]:2223 {key}",  # another port
        "203.0.113.7 {key}",  # port 22 pattern for a 2222 host
        "* {key}",
        "@cert-authority [203.0.113.7]:2222 {key}",
        "[203.0.113.7]:2222 {key} extra",
        "",
    ],
)
def test_pinned_host_key_must_name_exactly_this_host(line: str) -> None:
    key = ssh.public_key_line(asyncssh.generate_private_key("ssh-ed25519"))
    with pytest.raises(ssh.SSHKeyError):
        ssh.pinned_known_hosts("203.0.113.7", 2222, line.format(key=key))


def test_known_host_line_format() -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    algorithm, data = ssh.public_key_line(key).split()[:2]
    assert ssh.known_host_line("h.example", 22, key) == f"h.example {algorithm} {data}"
    assert ssh.known_host_line("h.example", 2222, key) == f"[h.example]:2222 {algorithm} {data}"
    assert ssh.fingerprint(key).startswith("SHA256:")


# KEYS AT REST


def crypto() -> Crypto:
    return Crypto((base64.urlsafe_b64decode(new_key()),))


def test_generated_key_is_ed25519_and_stored_encrypted() -> None:
    box = crypto()
    host = Host(name="h", kind="ssh")
    public = ssh.generate_key(host, box)
    assert public.startswith("ssh-ed25519 ")
    assert "PRIVATE KEY" not in host.ssh_key_enc
    assert "openssh-key-v1" not in host.ssh_key_enc
    assert host.key_passphrase_enc is None
    key = ssh.host_private_key(host, box)
    assert ssh.public_key_line(key) == public


def test_pasted_key_with_passphrase() -> None:
    box = crypto()
    original = asyncssh.generate_private_key("ssh-ed25519")
    pem = original.export_private_key("openssh", "a long passphrase").decode()
    host = Host(name="h", kind="ssh")
    with pytest.raises(ssh.SSHKeyError, match="passphrase"):
        ssh.store_key(host, box, pem, None)
    with pytest.raises(ssh.SSHKeyError, match="passphrase"):
        ssh.store_key(host, box, pem, "wrong passphrase")
    public = ssh.store_key(host, box, pem, "a long passphrase")
    assert public == ssh.public_key_line(original)
    # Stored decrypted inside the Fernet token: no passphrase, and no KDF on every start.
    assert host.key_passphrase_enc is None
    assert ssh.kdf_rounds(box.decrypt(host.ssh_key_enc)) == 0
    assert ssh.public_key_line(ssh.host_private_key(host, box)) == public


def test_a_passphrase_for_an_unencrypted_key_is_dropped() -> None:
    """A browser may autofill the login password into the passphrase field."""
    box = crypto()
    pem = asyncssh.generate_private_key("ssh-ed25519").export_private_key("openssh").decode()
    host = Host(name="h", kind="ssh")
    ssh.store_key(host, box, pem, "autofilled login password")
    assert host.key_passphrase_enc is None
    assert "autofilled login password" not in box.decrypt(host.ssh_key_enc)


def with_kdf_rounds(pem: str, rounds: int) -> str:
    """Rewrites the bcrypt rounds of an encrypted OpenSSH key."""
    lines = pem.strip().splitlines()
    blob = bytearray(base64.b64decode("".join(lines[1:-1])))
    pos = len(ssh.OPENSSH_MAGIC)
    for _ in range(2):  # cipher name, KDF name
        pos += 4 + int.from_bytes(blob[pos : pos + 4])
    offset = pos + 8 + int.from_bytes(blob[pos + 4 : pos + 8])  # after the salt
    blob[offset : offset + 4] = rounds.to_bytes(4)
    body = textwrap.wrap(base64.b64encode(bytes(blob)).decode(), 70)
    return "\n".join([lines[0], *body, lines[-1]]) + "\n"


def test_keys_with_costly_passphrase_kdfs_are_refused() -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    pem = key.export_private_key("openssh", "passphrase", rounds=64).decode()
    assert ssh.kdf_rounds(pem) == 64
    assert ssh.kdf_rounds(with_kdf_rounds(pem, 1024)) == 1024
    hours = with_kdf_rounds(pem, 2**32 - 1)
    assert ssh.kdf_rounds(hours) == 2**32 - 1
    with pytest.raises(ssh.SSHKeyError, match="KDF rounds"):
        ssh.load_private_key(hours, "passphrase")  # refused before any KDF runs
    pkcs8 = key.export_private_key("pkcs8-pem", "passphrase").decode()
    with pytest.raises(ssh.SSHKeyError, match="PKCS#8"):
        ssh.load_private_key(pkcs8, "passphrase")


@pytest.mark.parametrize(
    "text",
    ["", "not a key", "x" * 20000, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== public@only"],
)
def test_unusable_pasted_keys_are_rejected(text: str) -> None:
    with pytest.raises(ssh.SSHKeyError):
        ssh.store_key(Host(name="h", kind="ssh"), crypto(), text, None)


# WIRING


async def test_fresh_install_has_no_hosts(tmp_path: Path) -> None:
    settings = make_settings(tmp_path / "data", DRYDOCK_LOCAL_DOCKER_URL="tcp://socket-proxy:2375")
    async with running(settings) as browser:
        assert (await browser.setup()).status_code == 303
        assert browser.sql("SELECT count(*) FROM hosts") == [(0,)]
    async with running(settings) as browser:
        assert browser.sql("SELECT count(*) FROM hosts") == [(0,)]


async def test_socket_directory_is_private(admin: Browser) -> None:
    hosts: HostManager = admin.app.state.hosts
    assert stat.S_IMODE(hosts.socket_dir.stat().st_mode) == 0o700
    assert hosts.socket_dir.stat().st_uid == os.getuid()


def test_stale_sockets_are_cleared(tmp_path: Path) -> None:
    directory = tmp_path / "hosts"
    directory.mkdir(mode=0o755)
    (directory / "3.sock").touch()
    ssh.prepare_socket_dir(directory)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert list(directory.iterdir()) == []


def test_symlinked_socket_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "hosts").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(RuntimeError):
        ssh.prepare_socket_dir(tmp_path / "hosts")


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"known_host_line": None}, "not been trusted"),
        ({"ssh_key_enc": None}, "No SSH key"),
        ({"ssh_key_enc": "gAAAAAgarbage"}, "cannot be decrypted"),
    ],
)
async def test_unusable_ssh_host_is_never_contacted(
    admin: Browser, monkeypatch, changes: dict, error: str
) -> None:
    calls = []
    monkeypatch.setattr(asyncssh, "connect", lambda *a, **k: calls.append(a))
    host = Host(
        name="remote",
        kind="ssh",
        address="203.0.113.9",
        port=22,
        username="backup",
        enabled=True,
        known_host_line="203.0.113.9 "
        + ssh.public_key_line(asyncssh.generate_private_key("ssh-ed25519")),
    )
    ssh.generate_key(host, admin.app.state.crypto)
    for name, value in changes.items():
        setattr(host, name, value)
    with admin.app.state.sessionmaker() as db, db.begin():
        db.add(host)
    hosts: HostManager = admin.app.state.hosts
    await hosts.reload(host.id)
    status = hosts.status(host)
    assert status.state == "error"
    assert error in status.error
    with pytest.raises(HostUnavailable, match=error):
        hosts.docker_url(host)
    assert calls == []


def trusted_ssh_host(admin: Browser, server_key: asyncssh.SSHKey) -> Host:
    host = Host(
        name="remote",
        kind="ssh",
        address="203.0.113.9",
        port=22,
        username="backup",
        enabled=True,
        known_host_line=ssh.known_host_line("203.0.113.9", 22, server_key),
    )
    ssh.generate_key(host, admin.app.state.crypto)
    with admin.app.state.sessionmaker() as db, db.begin():
        db.add(host)
    return host


def tunnel_tasks(host_id: int) -> list[asyncio.Task]:
    name = f"ssh-host-{host_id}"
    return [t for t in asyncio.all_tasks() if t.get_name() == name and not t.done()]


async def test_concurrent_reloads_leave_one_tunnel(admin: Browser, monkeypatch) -> None:
    async def never_answers(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(asyncssh, "connect", never_answers)
    host = trusted_ssh_host(admin, asyncssh.generate_private_key("ssh-ed25519"))
    hosts: HostManager = admin.app.state.hosts
    async with anyio.create_task_group() as group:
        for _ in range(5):
            group.start_soon(hosts.reload, host.id)
    assert len(tunnel_tasks(host.id)) == 1
    assert hosts.status(host).state == "connecting"
    await hosts.reload(host.id)
    assert len(tunnel_tasks(host.id)) == 1


@pytest.mark.parametrize(
    "failure",
    [
        asyncssh.KeyExchangeFailed("No matching server host key algorithm found"),
        ConnectionResetError(104, "Connection reset by peer"),  # what OpenSSH 10 does
    ],
)
@pytest.mark.parametrize(
    ("presented", "state"),
    [("another key", "hostkey_mismatch"), ("the pinned key", "disconnected")],
)
async def test_failed_key_exchange_is_a_mismatch_only_for_another_key(
    admin: Browser, monkeypatch, failure: Exception, presented: str, state: str
) -> None:
    """A pinned key makes asyncssh offer only its algorithm. A server that now presents a
    key of another type fails key exchange, which must count as a host key mismatch."""
    pinned = asyncssh.generate_private_key("ssh-ed25519")
    other = asyncssh.generate_private_key("ecdsa-sha2-nistp256")

    async def refuse(*args, **kwargs):
        raise failure

    async def scan(address: str, port: int) -> tuple[str, str]:
        key = other if presented == "another key" else pinned
        return ssh.known_host_line(address, port, key), ssh.fingerprint(key)

    monkeypatch.setattr(asyncssh, "connect", refuse)
    monkeypatch.setattr(ssh, "scan_host_key", scan)
    host = trusted_ssh_host(admin, pinned)
    hosts: HostManager = admin.app.state.hosts
    await hosts.reload(host.id)
    with anyio.fail_after(10):
        while hosts.status(host).state == "connecting":
            await anyio.sleep(0.05)
    assert hosts.status(host).state == state

    def mismatch_rows() -> list[tuple]:
        return admin.sql("SELECT details FROM audit_events WHERE action = 'host.hostkey_mismatch'")

    if state == "hostkey_mismatch":
        with anyio.fail_after(10):
            while not mismatch_rows():
                await anyio.sleep(0.05)
        assert json.loads(mismatch_rows()[0][0])["presented_fingerprint"] == ssh.fingerprint(other)
        assert tunnel_tasks(host.id) == [], "a mismatch stops the tunnel"
    else:
        assert mismatch_rows() == []
        assert len(tunnel_tasks(host.id)) == 1, "an ordinary failure is retried"


def test_helper_removal_never_raises() -> None:
    class Api:
        def remove_container(self, *args, **kwargs) -> None:
            raise requests.ConnectionError("the tunnel dropped")

    class Client:
        api = Api()

    helper.remove(Client(), "drydock-helper-x")  # type: ignore[arg-type]


def test_disabled_and_local_hosts(settings: Settings) -> None:
    hosts = HostManager(settings, None, crypto(), "instance")  # type: ignore[arg-type]
    local = Host(id=1, name="l", kind="local", docker_url="tcp://socket-proxy:2375", enabled=True)
    assert hosts.docker_url(local) == "tcp://socket-proxy:2375"
    local.enabled = False
    with pytest.raises(HostUnavailable, match="disabled"):
        hosts.docker_url(local)


# CONFIG


def test_helper_image_must_be_pinned_by_digest(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="pinned by digest"):
        make_settings(tmp_path, DRYDOCK_HELPER_IMAGE="busybox:latest")
    pinned = "registry.local/busybox:1.37.0@sha256:" + "a" * 64
    assert make_settings(tmp_path, DRYDOCK_HELPER_IMAGE=pinned).helper_image == pinned
    assert "@sha256:" in make_settings(tmp_path).helper_image


def test_run_dir_must_be_absolute(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="DRYDOCK_RUN_DIR"):
        make_settings(tmp_path, DRYDOCK_RUN_DIR="run")
