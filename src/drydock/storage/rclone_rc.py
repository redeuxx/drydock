"""The rclone remote control daemon (`rclone rcd`), owned by the app lifespan.

Security rules, all enforced here:
- rcd listens only on a unix socket in the private run directory (owned by drydock, 0700),
  chmod 0600. Never a TCP address and never --rc-no-auth.
- Every call needs basic auth with a password made at random when drydock starts. The user
  and password reach rclone only through its environment (RCLONE_RC_USER, RCLONE_RC_PASS),
  so they never appear in ps or /proc/<pid>/cmdline. That environment holds only TMPDIR
  besides: no drydock secret key, and no RCLONE_* settings or remotes from the container's.
- --config /dev/null keeps rclone's configuration in memory, so no rclone.conf exists.
- The log level is INFO at most, and only allowlisted methods are called: options/set could
  raise it to DEBUG, which logs every call's parameters.
- rclone echoes a failed call's input, secrets included, in its error body and in one
  ERROR log line. Drydock keeps only the error message and redacts that line.
- --rc-serve makes GET /[<fs>]/<path> serve objects, honouring Range: the only ranged read
  rclone offers (read_head). It needs the same auth and gives nothing copyfile could not.
  read_range builds only remote-type connection strings and archive names, and log lines
  holding a connection string (rclone logs the path of a request that failed auth) are
  redacted.
- rclone takes RCLONE_<BACKEND>_* variables as option defaults, so its environment stays
  exactly the one below.

rclone is restarted with capped backoff whenever it exits. Calls are blocking, like the
storage backends that make them; call them from async code through run_blocking.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import secrets
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from drydock.hosts.ssh import prepare_socket_dir
from drydock.storage.base import NAME_RE

log = logging.getLogger("drydock.rclone")

RCLONE_BINARY = Path("/opt/rclone/rclone")  # pinned and checksummed in the image
LOG_LEVEL = "INFO"
RC_USER = "drydock"
# The rc methods PLAN.md Phase 6 uses. Never options/*, config/* (except the provider
# list) or core/command.
METHODS = frozenset(
    {
        "rc/noop",
        "config/providers",
        "core/obscure",
        "core/stats",
        "job/status",
        "job/stopgroup",
        "operations/copyfile",
        "operations/deletefile",
        "operations/list",
        "operations/stat",
    }
)
READY_TIMEOUT = 15.0  # for rclone to answer after a start, and for a call to wait for that
CALL_TIMEOUT = 60.0
STOP_TIMEOUT = 10.0
LOG_DRAIN_TIMEOUT = 5.0
BACKOFF_INITIAL = 1.0
BACKOFF_MAX = 60.0
STABLE_AFTER = 60.0  # an rclone that ran this long restarts without the built-up backoff
MAX_LOG_LINE = 2000
MAX_ERROR = 500
# rclone v1.75.2 fs/rc/rcserver: "rc: writeError: failed to write JSON output from %#v: %v",
# where %#v is the call's whole input.
INPUT_DUMP = "failed to write JSON output from "
# A connection string as rclone logs a served path, plain or percent-encoded. It holds the
# options, passwords obscured (reversibly). A cut line has no closing bracket.
CONNECTION_RE = re.compile(r"(?:\[|%5B)(?::|%3A)(?:sftp|smb|webdav|drive).*?(?:\]|%5D|$)", re.I)
# What read_range may serve: an inline remote of a remote type (never a local path, which
# would read drydock's own files) and an archive or test probe name.
SERVED_FS_RE = re.compile(r":(?:sftp|smb|webdav|drive),[^\]\x00-\x1f\x7f]*")
PROBE_RE = re.compile(r"\.drydock-test-[0-9a-f]{32}")
OBSCURED_RE = re.compile(r"[A-Za-z0-9_-]{22,8192}")
MAX_OBSCURED = 256  # cached obscured secrets
MAX_ERROR_BODY = 64 * 1024


class RcloneUnavailable(Exception):
    """rclone is not running or did not answer. The message is safe to show."""


class RcloneError(Exception):
    """rclone answered a call with an error. The message comes from rclone and the remote:
    untrusted, possibly quoting the call's parameters, and not for display as is."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class RcloneDaemon:
    def __init__(self, run_dir: Path, binary: Path = RCLONE_BINARY) -> None:
        self.run_dir = run_dir
        self.socket_path = run_dir / "rclone.sock"
        self.binary = binary
        self._password = secrets.token_urlsafe(32)
        self._client = httpx.Client(
            transport=httpx.HTTPTransport(uds=str(self.socket_path)),
            base_url="http://rclone",
            auth=httpx.BasicAuth(RC_USER, self._password),
            timeout=CALL_TIMEOUT,
            trust_env=False,  # no proxy variables, no .netrc
        )
        self._ready = threading.Event()  # set while rclone answers; calls run on threads
        # sha256 of a secret: its obscured form. rclone obscures with a random IV and keeps
        # every distinct inline config it sees for good (fs.NewFs overriddenConfig), so each
        # secret is obscured once. ponytail: no lock, a race only obscures twice.
        self._obscured: dict[bytes, str] = {}
        self._error: str | None = "rclone runs only in the primary drydock process."
        self._task: asyncio.Task[None] | None = None
        self._process: asyncio.subprocess.Process | None = None

    @property
    def pid(self) -> int | None:
        process = self._process
        return process.pid if process is not None and process.returncode is None else None

    # LIFECYCLE

    async def start(self) -> None:
        if self._task is not None:
            return
        # Refuses a run directory that is a symlink or someone else's; removes a stale socket.
        prepare_socket_dir(self.run_dir)
        self._error = None
        self._task = asyncio.create_task(self._supervise(), name="rclone")
        self._task.add_done_callback(self._finished)

    def _finished(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled() and (exc := task.exception()) is not None:
            log.error("rclone supervision stopped", exc_info=exc)
            self._error = "rclone stopped unexpectedly; see the log."

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # _finished logged it
                await self._task
        self._error = "rclone has stopped."
        self._ready.set()  # wakes waiting calls, which then see the error
        self._client.close()

    async def _supervise(self) -> None:
        delay = BACKOFF_INITIAL
        while True:
            started = time.monotonic()
            try:
                status = await self._run_once()
            except OSError as exc:
                log.warning("rclone failed: %s", exc)
                status = "failed"
            if status is None:
                return
            if time.monotonic() - started >= STABLE_AFTER:
                delay = BACKOFF_INITIAL
            log.warning("rclone exited with status %s; restarting in %.0f s", status, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, BACKOFF_MAX)

    async def _run_once(self) -> int | None:
        """Runs rclone until it exits and returns its status, or None if it cannot run."""
        self.socket_path.unlink(missing_ok=True)
        try:
            process = self._process = await asyncio.create_subprocess_exec(
                str(self.binary),
                "rcd",
                "--rc-addr",
                f"unix://{self.socket_path}",
                "--rc-serve",
                "--config",
                "/dev/null",
                "--log-level",
                LOG_LEVEL,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                # TMPDIR also places rclone's cache directory: the image's /tmp is read-only.
                env={
                    "RCLONE_RC_USER": RC_USER,
                    "RCLONE_RC_PASS": self._password,
                    "TMPDIR": tempfile.gettempdir(),
                },
                # No umask argument: uvloop (production) refuses it. rclone inherits the
                # lifespan's umask 077, and the socket is chmodded once rclone answers.
            )
        except (FileNotFoundError, PermissionError, NotADirectoryError) as exc:
            log.error("rclone could not start: %s", exc)
            self._error = f"rclone could not start: {exc.strerror or exc}."
            return None
        reader = asyncio.create_task(forward_log(process.stderr))
        try:
            if await self._wait_ready(process):
                self.socket_path.chmod(0o600)
                self._ready.set()
                log.info("rclone %s is ready", process.pid)
            elif process.returncode is None:
                log.error("rclone did not answer within %.0f s; killing it", READY_TIMEOUT)
                process.kill()
            return await process.wait()
        finally:
            self._ready.clear()
            if process.returncode is None:  # cancelled by close(), or the chmod failed
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), STOP_TIMEOUT)
                except TimeoutError:
                    process.kill()
                    await process.wait()
            # Another holder of the pipe would keep it open past rclone's exit.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(reader, LOG_DRAIN_TIMEOUT)
            self.socket_path.unlink(missing_ok=True)

    async def _wait_ready(self, process: asyncio.subprocess.Process) -> bool:
        deadline = time.monotonic() + READY_TIMEOUT
        while process.returncode is None and time.monotonic() < deadline:
            if self.socket_path.exists():
                try:
                    await asyncio.to_thread(self._post, "rc/noop", {}, 2.0)
                    return True
                except httpx.HTTPError, RcloneError:
                    pass
            await asyncio.sleep(0.1)
        return False

    # CALLS

    def call(
        self, method: str, params: Mapping[str, Any] | None = None, timeout: float = CALL_TIMEOUT
    ) -> dict[str, Any]:
        """Calls an rc method, waiting up to READY_TIMEOUT for rclone to be running."""
        if method not in METHODS:
            raise ValueError(f"Not an allowed rc method: {method!r}")
        self._wait_running()
        try:
            return self._post(method, dict(params or {}), timeout)
        except httpx.HTTPError as exc:
            raise RcloneUnavailable(f"rclone did not answer ({type(exc).__name__}).") from None
        except RuntimeError:  # the client was closed under this call
            raise RcloneUnavailable("rclone has stopped.") from None

    def obscure(self, secret: str) -> str:
        """rclone's obscured form of secret, the same string every time (see __init__)."""
        key = hashlib.sha256(secret.encode()).digest()
        if (cached := self._obscured.get(key)) is not None:
            return cached
        value = self.call("core/obscure", {"clear": secret}).get("obscured")
        if not isinstance(value, str) or not OBSCURED_RE.fullmatch(value):
            raise RcloneError(200, "core/obscure returned no value.")
        if len(self._obscured) >= MAX_OBSCURED:
            self._obscured.clear()
        self._obscured[key] = value
        return value

    def read_range(
        self, fs: str, remote: str, max_bytes: int, timeout: float = CALL_TIMEOUT
    ) -> bytes:
        """The first max_bytes of remote in the inline remote fs, through --rc-serve, within
        timeout in all (a server trickling bytes would never trip httpx's idle timeout)."""
        if (
            not SERVED_FS_RE.fullmatch(fs)
            or not (NAME_RE.fullmatch(remote) or PROBE_RE.fullmatch(remote))
            or max_bytes < 1
        ):
            raise ValueError("Not an allowed ranged read.")
        self._wait_running()
        # rclone ends the fs at the first "]" (SERVED_FS_RE has none) and decodes the rest.
        path = "/" + quote(f"[{fs}]", safe="[]") + "/" + remote
        headers = {"Range": f"bytes=0-{max_bytes - 1}"}
        deadline = time.monotonic() + timeout
        try:
            with self._client.stream("GET", path, headers=headers, timeout=timeout) as response:
                if response.status_code == 416:  # an empty object
                    return b""
                if response.status_code not in (200, 206):
                    body = read_some(response, MAX_ERROR_BODY, deadline)
                    raise RcloneError(response.status_code, error_text(body))
                return read_some(response, max_bytes, deadline)  # a server may ignore Range
        except httpx.HTTPError as exc:
            raise RcloneUnavailable(f"rclone did not answer ({type(exc).__name__}).") from None
        except RuntimeError:
            raise RcloneUnavailable("rclone has stopped.") from None

    def _wait_running(self) -> None:
        if self._error is None and not self._ready.wait(READY_TIMEOUT):
            raise RcloneUnavailable("rclone is not running; it is being restarted.")
        if self._error is not None:
            raise RcloneUnavailable(self._error)

    def _post(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        response = self._client.post(f"/{method}", json=params, timeout=timeout)
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code != 200 or not isinstance(body, dict):
            raise RcloneError(response.status_code, error_text(response.content))
        return body


def read_some(response: httpx.Response, limit: int, deadline: float) -> bytes:
    data = bytearray()
    for chunk in response.iter_bytes():
        data += chunk
        if len(data) >= limit:
            break
        if time.monotonic() > deadline:
            raise RcloneUnavailable("rclone did not answer in time.")
    return bytes(data[:limit])


def error_text(body: bytes) -> str:
    """Only the "error" field of an rclone error body: the rest echoes the call's input."""
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    return str(error or "no error message")[:MAX_ERROR]


async def forward_log(stream: asyncio.StreamReader | None) -> None:
    """Passes rclone's log lines on to drydock's log, ERROR lines as warnings."""
    while stream is not None:
        try:
            line = await stream.readline()
        except ValueError:  # a line over the stream's limit, already dropped
            continue
        if not line:
            return
        log.log(*log_record(line.decode("utf-8", "replace")))


def log_record(line: str) -> tuple[int, str, str]:
    text = redact_connections(line.rstrip())[:MAX_LOG_LINE]
    head, found, _ = text.partition(INPUT_DUMP)
    if found:
        text = f"{head}{INPUT_DUMP}[input redacted]"
    return (logging.WARNING if " ERROR " in text else logging.INFO), "rclone: %s", text


def redact_connections(text: str) -> str:
    return CONNECTION_RE.sub("[connection string redacted]", text)


class RedactConnections(logging.Filter):
    """httpx logs each request's URL at INFO, read_range's connection string included."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if CONNECTION_RE.search(message):
            record.msg, record.args = redact_connections(message), ()
        return True


# Whatever level the httpx logger is given (main sets WARNING).
logging.getLogger("httpx").addFilter(RedactConnections())
