"""Pre- and post-hooks: commands drydock runs with exec in a container around a backup.

A hook is a row of the hooks library (superadmin edits only, with recent auth, audited
with before and after values); a job lists the IDs of the hooks it runs before and after
its data read, in order. Admins attach existing hooks to jobs but never aim them: a
superadmin binds every hook to one host entry and to one target, either a container
(project unset: the hook attaches only to container jobs of that host whose target is
exactly hook.container) or a Compose project (the hook attaches only to stack jobs of that
host for that project, and hook.container names a service or a container of it).
check_binding is that one rule; the job routes apply it on every save, the hook routes on
every hook edit against the jobs that have it attached, and the dispatcher again at run
time after the locks. At run time resolve picks the hook's container among the job's
resolved targets, and refuses the run before anything is stopped or paused when it is
missing, ambiguous, not running or paused.

The command is an argv list passed to Docker as-is: no shell, no templating, no string
formatting, so ["echo", "$(id)"] prints the literal text (a str would be shlex-split by
docker-py, so it is always a list). Privileged, Tty, stdin and Env are hardcoded off;
only the user and the working directory are configurable. Drydock never logs argv and
never puts it in an error message.

Output: run logs are visible to every role that can see runs, so hook output is not
logged by default. It is read, counted and discarded, and only when the hook fails the
last STDERR_TAIL bytes of its standard error are logged. A superadmin may set log_output
on a hook; then up to MAX_OUTPUT bytes of both streams are logged and the rest counted.
Every occurrence of the RunLog's secrets is found and replaced before the output is cut to
fit log lines, and the last (longest secret - 1) characters wait for the next data, so a
secret never straddles two lines; when the stream breaks off (a timeout, a cancel) those
last characters are dropped, since they may be the start of a secret.

Docker cannot kill a process started with exec: when a hook times out drydock stops
waiting for it, and the command may still be running in the container, so long commands
should be wrapped in `timeout`. Docker-py reads hijacked exec sockets with no timeout, so
the runner reads the socket itself (non-blocking, select with a deadline, cancel checked
every POLL). The socket proxy closes a connection that is silent for 10 minutes; when the
stream ends the runner polls exec_inspect until the exec has ended or the deadline.

Everything here blocks; it runs on the dispatcher's executor.
"""

import codecs
import contextlib
import json
import re
import select
import socket
import ssl
import struct
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import docker.errors
import requests

from drydock.archive.writer import Cancelled
from drydock.jobs import runlog

DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 3600
MAX_OUTPUT = 64 * 1024  # bytes of output logged per hook when log_output is set
STDERR_TAIL = 4096  # bytes of stderr kept, and logged only on failure, when it is not
POST_HOOK_BUDGET = 3600  # seconds for all post-hooks of one run together
CANCEL_WAIT = 2.0  # seconds a post-hook is awaited once the run is cancelled
MAX_ARGS = 64
MAX_ARG_LEN = 4096
MAX_ARGV_BYTES = 16384
MAX_HOOKS_PER_PHASE = 10
MAX_DETAIL = 500  # characters of a Docker error message kept

PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}", re.ASCII)  # copy of stacks.PROJECT_RE
NAME_RE = re.compile(r"[^\x00-\x1f\x7f]{1,64}")
CONTAINER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
USER_RE = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,31})?", re.ASCII
)
WORKDIR_RE = re.compile(r"/[^\x00-\x1f\x7f]{0,1023}")
ID_PREFIX_RE = re.compile(r"[0-9a-f]{12,64}")

POLL = 1.0  # select slice and cancel check
INSPECT_POLL = 0.5
READ_CHUNK = 65536
FRAME = struct.Struct(">BxxxL")
STREAMS = {1: "stdout", 2: "stderr"}
STDOUT, STDERR = 1, 2

ARGV_SHAPE = (
    'Enter the command as a JSON array of strings, for example ["pg_dump", "-U", "postgres"].'
)
TIMEOUT_ERROR = f"The timeout must be 1 to {MAX_TIMEOUT} seconds."
WANT_MORE = (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError)
DOCKER_ERRORS = (docker.errors.DockerException, requests.RequestException)


class HookError(Exception):
    """A hook cannot be saved, attached or run. The message is safe to show: it never
    holds argv or hook output."""


@dataclass(frozen=True)
class Hook:
    """A hook as a run uses it. Two from_row results compare equal only when nothing that
    affects where or what runs differs (the dispatcher's check for edits while a run
    waited for its locks)."""

    id: int
    name: str
    container: str
    argv: tuple[str, ...] = field(repr=False)
    user: str = ""
    workdir: str = ""
    timeout_s: int = DEFAULT_TIMEOUT
    host_id: int | None = None
    project: str | None = None
    log_output: bool = False

    @classmethod
    def from_row(cls, row: Any) -> Hook:
        """Reads a hooks table row (models.Hook). A stored argv that is not a valid list of
        strings, for example one edited outside drydock, is refused."""
        try:
            argv = json.loads(row.argv_json)
        except TypeError, ValueError, RecursionError:  # RecursionError: deeply nested
            argv = None
        if not isinstance(argv, list) or check_argv(argv):
            raise HookError(f"Hook {row.name} is not valid.")
        return cls(
            id=row.id,
            name=row.name,
            container=row.container,
            argv=tuple(argv),
            user=row.user or "",
            workdir=row.workdir or "",
            timeout_s=int(row.timeout_s),
            host_id=row.host_id,
            project=row.project or None,
            log_output=bool(row.log_output),
        )


# VALIDATION


@dataclass(frozen=True)
class HookFields:
    """A validated hook form."""

    name: str
    container: str
    argv: tuple[str, ...] = field(repr=False)
    user: str
    workdir: str
    timeout_s: int
    project: str | None
    log_output: bool


def check_argv(argv: list[Any]) -> list[str]:
    """The problems of an argv list; empty when it can be stored and run."""
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return [ARGV_SHAPE]
    errors = []
    if not argv or not argv[0]:
        errors.append("The command needs a program name.")
    if len(argv) > MAX_ARGS:
        errors.append(f"The command can have at most {MAX_ARGS} arguments.")
    if any(len(item) > MAX_ARG_LEN for item in argv):
        errors.append(f"Each argument can be at most {MAX_ARG_LEN} characters long.")
    try:
        size = sum(len(item.encode()) for item in argv)
    except UnicodeEncodeError:  # a lone surrogate from a JSON escape such as "\ud800"
        size = 0
        errors.append("Arguments must be valid Unicode text.")
    if size > MAX_ARGV_BYTES:
        errors.append(f"The command can be at most {MAX_ARGV_BYTES} bytes long.")
    if any("\x00" in item for item in argv):
        errors.append("Arguments cannot hold NUL characters.")
    return errors


def parse_argv(text: str) -> tuple[list[str] | None, list[str]]:
    """Parses the command as typed in the hook form: a JSON array of strings. Nothing in
    the strings is interpreted ("$(id)", "${X}", "{{x}}" and spaces are literal)."""
    # JSON escapes take at most six characters per character, so anything longer cannot
    # pass the byte limit; refuse it before parsing.
    if len(text) > 6 * MAX_ARGV_BYTES + 2 * MAX_ARGS + 2:
        return None, [f"The command can be at most {MAX_ARGV_BYTES} bytes long."]
    try:
        argv = json.loads(text)
    except ValueError, RecursionError:  # RecursionError: deeply nested arrays
        return None, [ARGV_SHAPE]
    errors = check_argv(argv)
    return (None, errors) if errors else (argv, [])


def validate_form(
    name: str,
    container: str,
    argv: str,
    user: str,
    workdir: str,
    timeout_s: str,
    project: str = "",
    log_output: str = "",
) -> tuple[HookFields | None, list[str]]:
    """Validates the hook form (the host is checked by the route against the hosts
    table). Returns the fields only when there are no errors."""
    name, container, user = name.strip(), container.strip(), user.strip()
    workdir, project = workdir.strip(), project.strip()
    errors = []
    if not NAME_RE.fullmatch(name):
        errors.append("Name must be 1 to 64 characters.")
    if not CONTAINER_RE.fullmatch(container):
        errors.append(
            "Enter the container, or for a project hook the Compose service, the hook runs in."
        )
    if project and not PROJECT_RE.fullmatch(project):
        errors.append(
            "Enter the Compose project name: 1 to 63 lowercase letters, digits, '_' or '-',"
            " as docker compose ls shows it, or leave it empty for a container hook."
        )
    parsed, argv_errors = parse_argv(argv)
    errors += argv_errors
    if user and not USER_RE.fullmatch(user):
        errors.append(
            "Enter a user as name, uid, name:group or uid:gid, or leave it empty for the"
            " container's user."
        )
    if workdir and (
        not WORKDIR_RE.fullmatch(workdir) or "/../" in workdir or workdir.endswith("/..")
    ):
        errors.append("The working directory must be an absolute path inside the container.")
    timeout = DEFAULT_TIMEOUT
    if value := timeout_s.strip():
        digits = value.isascii() and value.isdigit() and len(value) <= 4
        timeout = int(value) if digits else 0
        if not 1 <= timeout <= MAX_TIMEOUT:
            errors.append(TIMEOUT_ERROR)
    if errors or parsed is None:
        return None, errors
    fields = HookFields(
        name=name,
        container=container,
        argv=tuple(parsed),
        user=user,
        workdir=workdir,
        timeout_s=timeout,
        project=project or None,
        log_output=log_output in ("1", "on"),
    )
    return fields, []


def argv_json(argv: Sequence[str]) -> str:
    """argv as the hooks table stores it."""
    return json.dumps(list(argv), ensure_ascii=False, separators=(",", ":"))


def summary(fields_or_row: Any, host_id: int | None = None) -> dict[str, Any]:
    """A hook's settings for audit details (no key matches audit.redact's patterns)."""
    obj = fields_or_row
    argv = getattr(obj, "argv", None)
    if argv is None:
        try:
            argv = json.loads(obj.argv_json)
        except TypeError, ValueError, RecursionError:
            argv = None
    return {
        "name": obj.name,
        "host_id": host_id if host_id is not None else getattr(obj, "host_id", None),
        "project": obj.project or None,
        "container": obj.container,
        "argv": list(argv) if isinstance(argv, list | tuple) else None,
        "user": obj.user or "",
        "workdir": obj.workdir or "",
        "timeout_s": obj.timeout_s,
        "log_output": bool(obj.log_output),
    }


# BINDING


def check_binding(hook: Any, *, host_id: int, target_type: str, target: str) -> None:
    """Refuses a hook that is not bound to this job's host and target (see the module
    docstring). hook is anything with name, host_id, project and container. Pure."""
    name, container = hook.name, hook.container
    project = hook.project or None
    if hook.host_id != host_id:
        raise HookError(f"Hook {name} is bound to another host, so this job cannot run it.")
    if target_type == "container":
        if project is not None:
            raise HookError(
                f"Hook {name} is for Compose project {project}; attach it to that project's"
                " stack job."
            )
        if container != target:
            raise HookError(f"Hook {name} runs in {container}, which this job does not back up.")
    elif target_type == "stack":
        if project is None:
            raise HookError(
                f"Hook {name} is for container {container}; attach it to that container's job."
            )
        if project != target:
            raise HookError(
                f"Hook {name} is for Compose project {project}, which this job does not back up."
            )
    else:
        raise HookError("This job's target type is not known.")


# RESOLUTION


class HookTarget(Protocol):
    id: str
    name: str
    service: str | None
    running: bool
    paused: bool


def _matches(hook: Hook, targets: Sequence[HookTarget]) -> list[HookTarget]:
    ref = hook.container
    if hook.project is None:
        prefix = ID_PREFIX_RE.fullmatch(ref) is not None
        return [t for t in targets if ref in (t.name, t.id) or (prefix and t.id.startswith(ref))]
    named = [t for t in targets if t.name == ref]
    if named:
        return named
    serving = [t for t in targets if t.service == ref]
    if len(serving) > 1:
        raise HookError(
            f"Hook {hook.name} names service {ref}, which has {len(serving)} containers."
            " Name one container instead."
        )
    return serving


def resolve(hooks: Sequence[Hook], targets: Sequence[HookTarget]) -> list[tuple[Hook, str, str]]:
    """The container each hook runs in, as (hook, container ID, container name), in hook
    order. Refuses a hook whose container is not exactly one running, unpaused target of
    the job."""
    resolved = []
    for hook in hooks:
        found = _matches(hook, targets)
        if not found:
            raise HookError(
                f"Hook {hook.name} runs in {hook.container}, which this job does not back up."
            )
        if len(found) > 1:
            raise HookError(
                f"Hook {hook.name} runs in {hook.container}, which matches {len(found)}"
                " containers of this job. Name one container instead."
            )
        target = found[0]
        if target.paused:
            raise HookError(f"Container {target.name} is paused, so hook {hook.name} cannot run.")
        if not target.running:
            raise HookError(
                f"Container {target.name} is not running, so hook {hook.name} cannot run."
            )
        resolved.append((hook, target.id, target.name))
    return resolved


# OUTPUT


class Demux:
    """Splits Docker's multiplexed exec stream (8-byte headers: stream, size) into
    (stream, bytes) pieces across arbitrary chunk boundaries. Frame data is passed on as
    it arrives, never buffered to its declared size."""

    def __init__(self) -> None:
        self._header = b""
        self._stream = STDOUT
        self._left = 0

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        pieces = []
        pos = 0
        while pos < len(data):
            if self._left:
                chunk = data[pos : pos + self._left]
                pos += len(chunk)
                self._left -= len(chunk)
                pieces.append((self._stream, chunk))
                continue
            need = FRAME.size - len(self._header)
            self._header += data[pos : pos + need]
            pos += need
            if len(self._header) < FRAME.size:
                break
            stream, size = FRAME.unpack(self._header)
            self._header = b""
            if stream not in (0, STDOUT, STDERR):
                raise HookError("Docker sent output drydock cannot read.")
            self._stream = stream or STDOUT  # stream 0 (stdin) counts as stdout
            self._left = size
        return pieces


def _same(text: str) -> str:
    return text


def _no_secrets() -> list[str]:
    return []


def _hold(secrets: Sequence[str]) -> int:
    return max(map(len, secrets), default=1) - 1


def _cover(text: str, mask: bytearray, secrets: Sequence[str], start: int) -> None:
    """Sets mask to 1 under every occurrence of a secret in text that ends after start,
    overlapping ones included (text[:start] was searched before)."""
    for secret in secrets:
        covered = 0
        pos = text.find(secret, max(0, start - len(secret) + 1))
        while pos != -1:
            end = pos + len(secret)
            low = max(pos, covered)
            mask[low:end] = b"\x01" * (end - low)
            covered = end
            pos = text.find(secret, pos + 1)


def _uncovered(text: str, mask: bytearray, end: int, masking: bool) -> tuple[str, bool]:
    """text[:end] with each run of covered characters replaced by one REDACTED marker (no
    marker for a run that continues the previous text's last one, when masking is set).
    Returns the text and whether its last character was covered."""
    pieces = []
    pos = 0
    while pos < end:
        covered = mask[pos]
        stop = mask.find(0 if covered else 1, pos, end)
        stop = end if stop == -1 else stop
        if not covered:
            pieces.append(text[pos:stop])
        elif not masking:
            pieces.append(runlog.REDACTED)
        masking = bool(covered)
        pos = stop
    return "".join(pieces), masking


@dataclass
class _Stream:
    """One output stream of a hook with log_output: the characters not decided yet (raw,
    searched for secrets up to scanned, then the fresh ones), and the decided text of the
    current line that is not logged yet."""

    decoder: codecs.IncrementalDecoder
    raw: str = ""
    mask: bytearray = field(default_factory=bytearray)  # 1 under a secret, per raw character
    scanned: int = 0
    known: tuple[str, ...] = ()  # the secrets raw[:scanned] was searched for
    fresh: list[str] = field(default_factory=list)
    size: int = 0  # len(raw) plus the length of the fresh text
    line: str = ""
    masking: bool = False  # the last decided character was under a secret


class OutputLog:
    """Writes a hook's output to the run log as the module docstring describes: counted
    only (plus the stderr tail on failure) by default, or up to limit bytes with
    log_output.

    Before anything is cut into log lines, every occurrence of the log's secrets (the
    RunLog's secrets()) is found and each run of them becomes one REDACTED marker. The
    last hold() characters wait for the next data, since they may be the start of a
    secret; when the stream breaks off they are dropped. A secret added while the hook
    runs covers only what is not logged yet."""

    def __init__(
        self,
        log: Callable[[str], None],
        hook_name: str,
        *,
        log_output: bool,
        limit: int = MAX_OUTPUT,
    ) -> None:
        self._log = log
        self.hook_name = hook_name
        self.log_output = log_output
        self.limit = limit
        self._redact: Callable[[str], str] = getattr(log, "redact", None) or _same
        self._secrets: Callable[[], list[str]] = getattr(log, "secrets", None) or _no_secrets
        self.stdout_bytes = 0
        self.stderr_bytes = 0
        self.logged = 0  # UTF-8 bytes of hook output written to the log
        self.dropped = 0  # bytes of output not logged (the limit, or a broken-off end)
        self.cut = False
        self.tail = bytearray()
        self.tail_cut = False
        self._streams = {
            s: _Stream(codecs.getincrementaldecoder("utf-8")(errors="replace")) for s in STREAMS
        }
        self._closed = False

    def hold(self) -> int:
        """Characters that wait for the next data: the longest secret's length minus one."""
        return _hold(self._secrets())

    def _prefix(self, stream: int) -> str:
        return f"[{self.hook_name}] " if stream == STDOUT else f"[{self.hook_name} stderr] "

    def feed(self, stream: int, data: bytes) -> None:
        if stream == STDERR:
            self.stderr_bytes += len(data)
        else:
            self.stdout_bytes += len(data)
        if not self.log_output:
            if stream == STDERR:
                self.tail += data
                if len(self.tail) > STDERR_TAIL:
                    del self.tail[: len(self.tail) - STDERR_TAIL]
                    self.tail_cut = True
            return
        if self.cut:
            self.dropped += len(data)
            return
        part = self._streams[stream]
        text = part.decoder.decode(data)
        part.fresh.append(text)
        part.size += len(text)
        self.emit(stream)

    def emit(self, stream: int, final: bool = False, *, complete: bool = True) -> None:
        """Logs what is decided: all but the last hold() characters, or everything when
        final. A final emit with complete False (the stream broke off) drops those last
        characters instead of logging them."""
        part = self._streams[stream]
        secrets = self._secrets()
        hold = _hold(secrets)
        if not final and part.size <= 2 * hold:
            return  # wait for more data, so each character is searched about once
        raw = part.raw + "".join(part.fresh)
        part.fresh.clear()
        mask = part.mask
        mask.extend(bytes(len(raw) - len(mask)))
        if tuple(secrets) != part.known:  # a secret was added: search everything again
            part.known, part.scanned = tuple(secrets), 0
        _cover(raw, mask, secrets, part.scanned)
        done = len(raw) if final and complete else max(0, len(raw) - hold)
        text, part.masking = _uncovered(raw, mask, done, part.masking)
        part.raw = raw[done:]
        del mask[:done]
        if final:
            self.dropped += len(part.raw.encode())
            part.raw = ""
            mask.clear()
        part.size = part.scanned = len(part.raw)
        *lines, partial = (part.line + text).split("\n")
        for line in lines:
            self._write(stream, line, newline=True)
        if final:
            if partial:
                self._write(stream, partial, newline=False)
            partial = ""
        else:
            piece = self._piece(stream)
            whole = len(partial) // piece * piece
            if whole:
                self._write(stream, partial[:whole], newline=False)
            partial = partial[whole:]
        part.line = partial
        if self.cut:
            self.dropped += len(part.line.encode()) + len(part.raw.encode())
            part.line, part.raw, part.size, part.scanned = "", "", 0, 0
            mask.clear()

    def _piece(self, stream: int) -> int:
        # RunLog truncates a line to MAX_LINE after its own redaction, which lengthens a
        # prefix holding a secret; a piece never reaches that, so no character is lost.
        return runlog.MAX_LINE - len(self._redact(self._prefix(stream))) - 1

    def _write(self, stream: int, text: str, *, newline: bool, limited: bool = True) -> None:
        prefix, piece = self._prefix(stream), self._piece(stream)
        chunks = [text[i : i + piece] for i in range(0, len(text), piece)] or [""]
        for index, chunk in enumerate(chunks):
            data = chunk.encode()
            size = len(data) + (1 if newline and index == len(chunks) - 1 else 0)
            if not limited:
                self._log(prefix + chunk)
                continue
            if self.cut:
                self.dropped += size
                continue
            room = self.limit - self.logged
            if size > room:
                fit = data[:room].decode(errors="ignore")
                if fit:
                    self._log(prefix + fit)
                fitted = len(fit.encode())
                self.logged += fitted
                self.dropped += size - fitted
                self._log(f"Output of hook {self.hook_name} was cut after {self.limit} bytes.")
                self.cut = True
                continue
            self._log(prefix + chunk)
            self.logged += size

    def close(self, failed: bool, complete: bool = True) -> None:
        """complete is False when the stream broke off (a timeout, a cancel, a read error),
        so its last characters may be the start of a secret that never arrived."""
        if self._closed:
            return
        self._closed = True
        if self.log_output:
            for stream, part in self._streams.items():
                if self.cut:
                    break
                text = part.decoder.decode(b"", final=True)
                part.fresh.append(text)
                part.size += len(text)
                self.emit(stream, final=True, complete=complete)
            if self.dropped:
                self._log(
                    f"{self.dropped} more bytes of output of hook {self.hook_name} were not logged."
                )
            return
        self._log(
            f"Hook {self.hook_name} wrote {self.stdout_bytes} bytes to standard output and"
            f" {self.stderr_bytes} bytes to standard error; hook output is not logged."
        )
        if failed and self.tail:
            self._log_tail(complete)

    def _log_tail(self, complete: bool) -> None:
        data = bytes(self.tail)
        if self.tail_cut:
            data = data.lstrip(bytes(range(0x80, 0xC0)))  # start at a character boundary
        text = data.decode(errors="replace")
        secrets = self._secrets()
        hold = _hold(secrets)
        mask = bytearray(len(text))
        _cover(text, mask, secrets, 0)
        # Drop the cut first line and at least hold() characters, so no part of a secret
        # cut at the front is shown, and the last hold() when the stream broke off.
        start = max(text.find("\n") + 1, hold) if self.tail_cut else 0
        end = len(text) if complete else len(text) - hold
        if start >= end:
            return
        self._log(
            f"The last {len(text[start:end].encode())} bytes of standard error of hook"
            f" {self.hook_name}:"
        )
        shown, _ = _uncovered(text[start:end], mask[start:end], end - start, False)
        *lines, last = shown.split("\n")
        for line in lines:
            self._write(STDERR, line, newline=True, limited=False)
        if last:
            self._write(STDERR, last, newline=False, limited=False)


# EXEC


def _detail(exc: Exception) -> str:
    text = exc.explanation if isinstance(exc, docker.errors.APIError) else None
    return str(text or exc)[:MAX_DETAIL]


def open_stream(api: Any, exec_id: str) -> tuple[socket.socket, bytes, Any]:
    """Starts an exec and returns its hijacked socket (non-blocking), the bytes http.client
    already buffered past the response headers, and the response to close afterwards.
    Docker's errors and socket errors (OSError) propagate, with the socket closed."""
    sock_io = api.exec_start(exec_id, tty=False, socket=True)
    raw = getattr(sock_io, "_sock", sock_io)
    try:
        raw.setblocking(False)
        response = getattr(sock_io, "_response", None)
        reader = response.raw._fp.fp
        # The reader that parsed the headers may already hold the first frames; take
        # exactly those, without blocking, so no output is lost and no header misaligned.
        try:
            pending = reader.peek(READ_CHUNK)
        except WANT_MORE:  # nothing buffered, and the next TLS record is not complete
            pending = b""
        pending = reader.read(len(pending)) if pending else b""
    except AttributeError:
        _close(getattr(sock_io, "_response", None), raw)
        raise HookError("This Docker client cannot stream hook output.") from None
    except OSError:
        _close(getattr(sock_io, "_response", None), raw)
        raise
    return raw, pending, response


def _close(response: Any, raw: Any) -> None:
    for item in (response, raw):
        if item is not None:
            with contextlib.suppress(OSError, AttributeError):
                item.close()


def _stop_if_cancelled(cancel: threading.Event, on_cancel: str) -> None:
    if on_cancel == "raise" and cancel.is_set():
        raise Cancelled("The run was cancelled.")


@dataclass
class _Limit:
    """When a hook stops being awaited. cancel with on_cancel "wait" shortens it once."""

    limit: float
    budget_limited: bool
    cancelled_wait: bool = False

    def remaining(self, cancel: threading.Event, on_cancel: str) -> float:
        if cancel.is_set():
            _stop_if_cancelled(cancel, on_cancel)
            if not self.cancelled_wait:
                self.cancelled_wait = True
                self.limit = min(self.limit, time.monotonic() + CANCEL_WAIT)
        return self.limit - time.monotonic()


def _receive(raw: Any, tls: bool) -> bytes | None:
    """The next bytes of the stream: b"" at its end, None when nothing is ready yet. Other
    socket errors propagate."""
    try:
        data = raw.recv(READ_CHUNK)
    except WANT_MORE:  # an SSL record is not complete yet; OSError subclasses, so first
        return None
    # Bytes ssl already decrypted are invisible to select.
    while tls and data and (count := raw.pending()):
        try:
            data += raw.recv(count)
        except OSError:
            break
    return data


def _pump(
    raw: Any,
    pending: bytes,
    out: OutputLog,
    timer: _Limit,
    cancel: threading.Event,
    on_cancel: str,
) -> tuple[bool, bool]:
    """Reads the stream into out. Returns (ended, complete): ended is False when the limit
    was reached; complete is True only at a normal end of stream. A socket error ends the
    stream too (the exec's result is then read from exec_inspect), but incomplete."""
    demux = Demux()
    for stream, chunk in demux.feed(pending):
        out.feed(stream, chunk)
    tls = isinstance(raw, ssl.SSLSocket)
    while True:
        remaining = timer.remaining(cancel, on_cancel)
        if remaining <= 0:
            return False, False
        try:
            readable = select.select([raw], [], [], min(POLL, remaining))[0]
            if not readable and not (tls and raw.pending()):
                continue
            data = _receive(raw, tls)
        except OSError, ValueError:  # ValueError: select on a closed socket
            return True, False
        if data is None:
            continue
        if not data:
            return True, True
        for stream, chunk in demux.feed(data):
            out.feed(stream, chunk)


def _outcome(
    api: Any,
    exec_id: str,
    hook: Hook,
    ended: bool,
    timer: _Limit,
    cancel: threading.Event,
    on_cancel: str,
) -> HookError | None:
    """After the stream: waits for the exec to end (the proxy may have closed a silent
    stream early) and returns the error to raise, if any."""
    while ended:
        try:
            info = api.exec_inspect(exec_id)
        except DOCKER_ERRORS as exc:
            return HookError(
                f"Docker could not report the result of hook {hook.name}: {_detail(exc)}"
            )
        if not info.get("Running"):
            code = info.get("ExitCode")
            if code == 0:
                return None
            if code is None:
                return HookError(f"Hook {hook.name} failed with no exit code.")
            return HookError(f"Hook {hook.name} failed with exit code {code}.")
        remaining = timer.remaining(cancel, on_cancel)
        if remaining <= 0:
            break
        if cancel.is_set():  # on_cancel "wait": cancel.wait would return at once
            time.sleep(min(INSPECT_POLL, remaining))
        else:
            cancel.wait(min(INSPECT_POLL, remaining))
    if timer.cancelled_wait:
        return HookError(
            f"Stopped waiting for hook {hook.name} because the run was cancelled. Docker may"
            " still be running it."
        )
    if timer.budget_limited:
        return HookError(
            f"Hook {hook.name} did not finish in the time left for post-hooks. Docker may"
            " still be running it."
        )
    return HookError(
        f"Hook {hook.name} timed out after {hook.timeout_s} seconds. Docker cannot stop a"
        " command started with exec, so it may still be running in the container; wrap long"
        " commands in timeout."
    )


def run_hook(
    api: Any,
    container_id: str,
    hook: Hook,
    *,
    container_name: str,
    phase: str,
    cancel: threading.Event,
    log: Callable[[str], None],
    on_cancel: str = "raise",
    deadline: float | None = None,
) -> None:
    """Runs one hook and waits for it, at most hook.timeout_s and never past deadline (a
    time.monotonic() value). Raises HookError when it fails or is not awaited to its end,
    and Cancelled when cancel is set with on_cancel "raise" (a run cancelled already never
    starts the hook). With on_cancel "wait" a cancel only shortens the wait to
    CANCEL_WAIT."""
    if on_cancel not in ("raise", "wait"):
        raise ValueError(f"on_cancel must be 'raise' or 'wait', not {on_cancel!r}")
    _stop_if_cancelled(cancel, on_cancel)
    log(f"Running {phase}-hook {hook.name} in container {container_name}.")
    try:
        exec_id = api.exec_create(
            container_id,
            list(hook.argv),  # always a list: docker-py shlex-splits a str
            stdout=True,
            stderr=True,
            stdin=False,
            tty=False,
            privileged=False,
            user=hook.user,
            environment=None,
            workdir=hook.workdir or None,
        )["Id"]
    except DOCKER_ERRORS as exc:
        raise HookError(f"Docker could not start hook {hook.name}: {_detail(exc)}") from None
    own = time.monotonic() + hook.timeout_s
    budget_limited = deadline is not None and deadline < own
    timer = _Limit(
        limit=min(own, deadline) if deadline is not None else own, budget_limited=budget_limited
    )
    _stop_if_cancelled(cancel, on_cancel)  # created, but not started yet
    try:
        raw, pending, response = open_stream(api, exec_id)
    except DOCKER_ERRORS as exc:
        raise HookError(f"Docker could not start hook {hook.name}: {_detail(exc)}") from None
    except OSError:
        raise HookError(
            f"Docker could not stream the output of hook {hook.name}; it may still be running."
        ) from None
    out = OutputLog(log, hook.name, log_output=hook.log_output)
    complete = False
    try:
        try:
            ended, complete = _pump(raw, pending, out, timer, cancel, on_cancel)
        finally:
            _close(response, raw)
        error = _outcome(api, exec_id, hook, ended, timer, cancel, on_cancel)
    except HookError:
        out.close(failed=True, complete=complete)
        raise
    except Cancelled:
        out.close(failed=False, complete=complete)
        raise
    out.close(failed=error is not None, complete=complete)
    if error is not None:
        raise error
    log(f"Hook {hook.name} finished.")


def run_all(
    api: Any,
    pairs: Sequence[tuple[Hook, str, str]],
    *,
    phase: str,
    cancel: threading.Event,
    log: Callable[[str], None],
    keep_going: bool = False,
    on_cancel: str = "raise",
    budget: float | None = None,
) -> None:
    """Runs hooks in order; pairs are resolve()'s (hook, container ID, container name).

    keep_going False (pre-hooks): the first HookError or Cancelled propagates. keep_going
    True (post-hooks, undo semantics): every hook is attempted, also after an unexpected
    error, then the first error is raised. With a budget (seconds for all of them) or once
    cancelled with on_cancel "wait", a hook that cannot be awaited is still started and
    awaited CANCEL_WAIT."""
    deadline = time.monotonic() + budget if budget is not None else None
    first: Exception | None = None
    for hook, container_id, container_name in pairs:
        hook_deadline = deadline
        spent = deadline is not None and time.monotonic() >= deadline
        if spent or (on_cancel == "wait" and cancel.is_set()):
            log(f"Starting {phase}-hook {hook.name} without waiting for it to finish.")
            hook_deadline = time.monotonic() + CANCEL_WAIT
        try:
            run_hook(
                api,
                container_id,
                hook,
                container_name=container_name,
                phase=phase,
                cancel=cancel,
                log=log,
                on_cancel=on_cancel,
                deadline=hook_deadline,
            )
        except HookError as exc:
            if not keep_going:
                raise
            log(str(exc))
            first = first or exc
        except Cancelled:
            raise
        except Exception as exc:
            if not keep_going:
                raise
            log(f"Hook {hook.name} failed because of an unexpected error in drydock.")
            first = first or exc
    if first is not None:
        raise first
