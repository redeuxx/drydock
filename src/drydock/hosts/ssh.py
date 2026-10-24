"""SSH access to remote Docker hosts.

Each SSH host gets one long-lived asyncssh connection that forwards a private unix socket,
/run/drydock/hosts/<id>.sock, to the Docker socket on the remote host. docker-py then talks
to that local socket as if the daemon were local.

Security rules, all enforced here:
- The private key exists only in memory. It is stored encrypted (drydock.crypto) and
  imported with import_private_key; nothing is ever written to disk.
- The host key is pinned. Connections use the stored known_hosts line and nothing else:
  no ~/.ssh/known_hosts, no ~/.ssh/config, no agent, no X.509 CAs and never
  known_hosts=None. A changed host key ends the tunnel until an admin trusts a new key.
- Only public key authentication is offered.
"""

import asyncio
import base64
import contextlib
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from drydock.crypto import Crypto
from drydock.models import Host

log = logging.getLogger("drydock.hosts.ssh")

DEFAULT_PORT = 22
DEFAULT_REMOTE_SOCKET = "/var/run/docker.sock"
CONNECT_TIMEOUT = 15
SCAN_TIMEOUT = 15
KEEPALIVE_INTERVAL = 15
KEEPALIVE_COUNT_MAX = 3
BACKOFF_INITIAL = 1.0
BACKOFF_MAX = 60.0
MAX_KEY_TEXT = 16384
# bcrypt rounds in an encrypted OpenSSH key. ssh-keygen uses 16 by default; a pasted key
# with 2^32 rounds would block a worker thread for days.
MAX_KDF_ROUNDS = 1024
OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
OPENSSH_MAGIC = b"openssh-key-v1\x00"
# The line to put in authorized_keys. restrict turns off pty, agent, X11 and forwarding;
# port-forwarding turns forwarding back on (sshd allows unix socket forwards only together
# with TCP forwards), and the forced command refuses shells, commands and subsystems.
# permitopen cannot narrow it further: OpenSSH 10 applies it to socket forwards as well.
AUTHORIZED_KEY_OPTIONS = 'restrict,port-forwarding,command="/bin/false"'
# Only AEAD ciphers. AES-GCM comes first: in the Phase 1 spike OpenSSL's AES-GCM moved
# volume data about 30% faster than asyncssh's chacha20-poly1305 (see README.md).
ENCRYPTION_ALGS = (
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
)
# Throughput per channel is at most window / round-trip time; 8 MiB keeps a 50 ms link
# above 150 MiB/s. Larger packets mean fewer per-packet costs in Python.
CHANNEL_WINDOW = 8 * 1024 * 1024
MAX_PACKET_SIZE = 256 * 1024
# Failures after the server answered that may hide a host key of another type. Refused or
# timed out connections never reached key exchange and are not rechecked.
HANDSHAKE_DROPS = (asyncssh.KeyExchangeFailed, asyncssh.ConnectionLost, ConnectionResetError)
KEY_ALGORITHMS = {
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
}


class SSHKeyError(ValueError):
    """A private key or host key line is unusable. The message is safe to show."""


# PRIVATE KEYS


def kdf_rounds(text: str) -> int:
    """The bcrypt rounds of an encrypted OpenSSH key, read before any KDF runs; 0 if none."""
    body = text.partition(OPENSSH_BEGIN)[2].partition(OPENSSH_END)[0]
    try:
        blob = base64.b64decode("".join(body.split()), validate=True)
    except ValueError:  # binascii.Error, or non-ASCII text
        return 0
    if not blob.startswith(OPENSSH_MAGIC):
        return 0
    fields, pos = [], len(OPENSSH_MAGIC)
    for _ in range(3):  # cipher name, KDF name, KDF options
        size = int.from_bytes(blob[pos : pos + 4])
        fields.append(blob[pos + 4 : pos + 4 + size])
        pos += 4 + size
    kdf_name, options = fields[1], fields[2]
    if kdf_name != b"bcrypt":
        return 0
    salt_size = int.from_bytes(options[:4])
    return int.from_bytes(options[4 + salt_size : 8 + salt_size])


def load_private_key(text: str, passphrase: str | None = None) -> asyncssh.SSHKey:
    if len(text) > MAX_KEY_TEXT:
        raise SSHKeyError("The private key is too large.")
    if "-----BEGIN ENCRYPTED PRIVATE KEY-----" in text:
        # PKCS#8 encryption sets its own PBKDF2 cost; convert to the OpenSSH format instead.
        raise SSHKeyError(
            "Encrypted PKCS#8 keys are not supported. Convert the key with "
            "ssh-keygen -p -f <file>, which writes the OpenSSH format."
        )
    if kdf_rounds(text) > MAX_KDF_ROUNDS:
        raise SSHKeyError(f"The key's passphrase uses more than {MAX_KDF_ROUNDS} KDF rounds.")
    try:
        key = asyncssh.import_private_key(text, passphrase or None)
    except asyncssh.KeyEncryptionError:
        raise SSHKeyError("The passphrase is wrong.") from None
    except (asyncssh.KeyImportError, ValueError) as exc:
        if "passphrase" in str(exc).lower():
            raise SSHKeyError("This key is encrypted; enter its passphrase.") from None
        raise SSHKeyError("This is not a supported private key.") from None
    if key.get_algorithm() not in KEY_ALGORITHMS:
        raise SSHKeyError("Use an ed25519, ECDSA or RSA key.")
    return key


def public_key_line(key: asyncssh.SSHKey) -> str:
    return key.export_public_key("openssh").decode("ascii").strip()


def save_key(host: Host, crypto: Crypto, key: asyncssh.SSHKey) -> str:
    """Stores the key unencrypted inside a Fernet token and returns its public key line.

    No passphrase is kept, so starting a tunnel never runs a passphrase KDF again.
    """
    host.ssh_key_enc = crypto.encrypt(key.export_private_key("openssh").decode("ascii"))
    host.key_passphrase_enc = None
    host.ssh_public_key = public_key_line(key)
    return host.ssh_public_key


def generate_key(host: Host, crypto: Crypto) -> str:
    """Creates a new ed25519 key for the host and returns its public key line."""
    return save_key(host, crypto, asyncssh.generate_private_key("ssh-ed25519", comment="drydock"))


def store_key(host: Host, crypto: Crypto, text: str, passphrase: str | None) -> str:
    """Stores a pasted private key (validated first) and returns its public key line."""
    return save_key(host, crypto, load_private_key(text, passphrase))


def host_private_key(host: Host, crypto: Crypto) -> asyncssh.SSHKey:
    """Decrypts and imports the host's key. Raises CryptoError or SSHKeyError."""
    if not host.ssh_key_enc:
        raise SSHKeyError("No SSH key is set for this host.")
    return load_private_key(crypto.decrypt(host.ssh_key_enc))


# HOST KEYS


def known_host_pattern(address: str, port: int) -> str:
    return address if port == DEFAULT_PORT else f"[{address}]:{port}"


def known_host_line(address: str, port: int, key: asyncssh.SSHKey) -> str:
    algorithm, data = public_key_line(key).split()[:2]
    return f"{known_host_pattern(address, port)} {algorithm} {data}"


def fingerprint(key: asyncssh.SSHKey) -> str:
    return key.get_fingerprint("sha256")


def line_fingerprint(line: str) -> str | None:
    """The SHA256 fingerprint of the key in a known_hosts line, or None if it is malformed."""
    try:
        return fingerprint(asyncssh.import_public_key(" ".join(line.split()[1:3])))
    except asyncssh.KeyImportError, ValueError:
        return None


def pinned_known_hosts(address: str, port: int, line: str) -> asyncssh.SSHKnownHosts:
    """The stored line, accepted only as a single plain entry for exactly this host and port.

    Changing a host's address or port therefore requires trusting its key again.
    """
    fields = line.split()
    if len(fields) != 3 or fields[0] != known_host_pattern(address, port):
        raise SSHKeyError("The trusted host key does not match this address and port.")
    try:
        return asyncssh.import_known_hosts(line)
    except asyncssh.KeyImportError, ValueError:
        raise SSHKeyError("The trusted host key is malformed.") from None


async def scan_host_key(address: str, port: int) -> tuple[str, str]:
    """Fetches the server's host key for an admin to compare: (known_hosts line, SHA256).

    Only the key exchange runs; no credentials are offered and nothing is trusted here.
    """
    key = await asyncio.wait_for(
        asyncssh.get_server_host_key(address, port, config=[]), SCAN_TIMEOUT
    )
    if key is None:
        raise SSHKeyError("The server did not present a host key.")
    return known_host_line(address, port, key), fingerprint(key)


# CONNECTIONS


@dataclass(frozen=True)
class SSHTarget:
    host_id: int
    address: str
    port: int
    username: str
    remote_socket_path: str
    known_host_line: str
    private_key: asyncssh.SSHKey = field(repr=False)


def client_options(target: SSHTarget) -> asyncssh.SSHClientConnectionOptions:
    return asyncssh.SSHClientConnectionOptions(
        username=target.username,
        client_keys=[target.private_key],
        known_hosts=pinned_known_hosts(target.address, target.port, target.known_host_line),
        # Nothing from ~/.ssh or the environment: no config, agent, CA bundles or tokens.
        config=[],
        agent_path=None,
        agent_forwarding=False,
        pkcs11_provider=None,
        x509_trusted_certs=None,
        x509_trusted_cert_paths=[],
        preferred_auth="publickey",
        password_auth=False,
        kbdint_auth=False,
        host_based_auth=False,
        gss_auth=False,
        gss_kex=False,
        gss_host=None,
        x11_forwarding=False,
        encryption_algs=list(ENCRYPTION_ALGS),
        window=CHANNEL_WINDOW,
        max_pktsize=MAX_PACKET_SIZE,
        connect_timeout=CONNECT_TIMEOUT,
        keepalive_interval=KEEPALIVE_INTERVAL,
        keepalive_count_max=KEEPALIVE_COUNT_MAX,
    )


def prepare_socket_dir(path: Path) -> None:
    """Creates the socket directory, owned by drydock with mode 0700, and clears old sockets."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != os.getuid():
        raise RuntimeError(f"{path} must be a directory owned by uid {os.getuid()}.")
    path.chmod(0o700)
    for stale in path.glob("*.sock"):
        stale.unlink(missing_ok=True)


class Tunnel:
    """One host's SSH connection and socket forward, reconnecting with capped backoff.

    States: connecting (first attempt), connected, disconnected (retrying),
    hostkey_mismatch and error. A host key mismatch or an unusable configuration stops
    the tunnel until it is reloaded.
    """

    def __init__(
        self,
        target: SSHTarget,
        socket_path: Path,
        on_connect: Callable[[Tunnel], None],
        on_mismatch: Callable[[Tunnel], None],
    ) -> None:
        self.target = target
        self.socket_path = socket_path
        self.state = "connecting"
        self.error: str | None = None
        self._on_connect = on_connect
        self._on_mismatch = on_mismatch
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"ssh-host-{self.target.host_id}")
        self._task.add_done_callback(self._finished)

    def _finished(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled() and (exc := task.exception()) is not None:
            log.error("Host %s: SSH tunnel stopped", self.target.host_id, exc_info=exc)
            self._set("error", "The SSH tunnel stopped unexpectedly; see the log.")

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        self.socket_path.unlink(missing_ok=True)

    async def _run(self) -> None:
        try:
            options = client_options(self.target)
        except SSHKeyError as exc:
            self._set("error", str(exc))
            return
        delay = BACKOFF_INITIAL
        while True:
            try:
                conn = await asyncssh.connect(
                    self.target.address, self.target.port, options=options
                )
            except asyncssh.HostKeyNotVerifiable:
                self._mismatch()
                return
            except HANDSHAKE_DROPS as exc:
                # A pinned key makes asyncssh offer only that key's algorithms. A server that
                # now has a key of another type fails key exchange instead of reporting a
                # mismatch, and OpenSSH often just drops the connection. Ask what it presents.
                if await self._presents_another_key():
                    self._mismatch()
                    return
                self._failed(exc)
            except (OSError, TimeoutError, asyncssh.Error) as exc:
                self._failed(exc)
            else:
                try:
                    async with conn:
                        await self._serve(conn)
                    delay = BACKOFF_INITIAL
                    self._set("disconnected", "The SSH connection was lost.")
                except (OSError, asyncssh.Error) as exc:
                    self._failed(exc)
            await asyncio.sleep(delay)
            delay = min(delay * 2, BACKOFF_MAX)

    async def _serve(self, conn: asyncssh.SSHClientConnection) -> None:
        self.socket_path.unlink(missing_ok=True)
        listener = await conn.forward_local_path(
            str(self.socket_path), self.target.remote_socket_path
        )
        try:
            self.socket_path.chmod(0o600)
            self._set("connected", None)
            log.info("Host %s: SSH tunnel connected", self.target.host_id)
            self._on_connect(self)
            await conn.wait_closed()
        finally:
            listener.close()
            self.socket_path.unlink(missing_ok=True)

    async def _presents_another_key(self) -> bool:
        try:
            _, presented = await scan_host_key(self.target.address, self.target.port)
        except OSError, TimeoutError, asyncssh.Error, SSHKeyError:
            return False
        return presented != line_fingerprint(self.target.known_host_line)

    def _mismatch(self) -> None:
        self._set(
            "hostkey_mismatch",
            "The host key presented by the server does not match the trusted key. "
            "Drydock will not connect until an admin trusts the new key.",
        )
        log.error("Host %s: host key mismatch, connection refused", self.target.host_id)
        self._on_mismatch(self)

    def _failed(self, exc: BaseException) -> None:
        message = str(exc) or type(exc).__name__
        if self.state != "disconnected" or self.error != message:
            log.warning("Host %s: SSH connection failed: %s", self.target.host_id, message)
        self._set("disconnected", message)

    def _set(self, state: str, error: str | None) -> None:
        self.state = state
        self.error = error
