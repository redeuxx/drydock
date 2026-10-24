"""Hooks without Docker: validation, binding, resolution, output handling and the exec
runner against fake clients."""

import io
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import docker.errors
import pytest

from drydock.archive.writer import Cancelled
from drydock.jobs import hooks, runlog
from drydock.jobs.hooks import FRAME, Hook, HookError
from drydock.jobs.runlog import RunLog

SECRET = "hunter2-very-long-secret"
PIECE = runlog.MAX_LINE - len("[h] ") - 1
SHAPE = "Enter the command as a JSON array of strings"


def frame(stream: int, data: bytes) -> bytes:
    return FRAME.pack(stream, len(data)) + data


def make_hook(**fields) -> Hook:
    base = {"id": 1, "name": "h", "container": "db", "argv": ("true",), "host_id": 1}
    return Hook(**(base | fields))


def lines(path: Path) -> list[str]:
    """The log's lines without their timestamps."""
    if not path.exists():
        return []
    return [line[20:] for line in path.read_text(encoding="utf-8").splitlines()]


def hook_text(path: Path, prefix: str = "[h] ") -> str:
    return "".join(line[len(prefix) :] for line in lines(path) if line.startswith(prefix))


@pytest.fixture
def run_log(tmp_path: Path) -> RunLog:
    return RunLog(tmp_path / "logs" / "1.log")


# FAKE DOCKER CLIENT


class FakeResponse:
    def __init__(self, reader: io.BufferedReader) -> None:
        self.raw = SimpleNamespace(_fp=SimpleNamespace(fp=reader))
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.raw._fp.fp.close()


class FakeSocketIO:
    """What docker-py's exec_start(socket=True) returns for unix and tcp base URLs."""

    def __init__(self, sock, reader: io.BufferedReader | None = None) -> None:
        self._sock = sock
        self._response = FakeResponse(reader or io.BufferedReader(io.BytesIO(b"")))


class FakeApi:
    """exec_start hands out one end of a socketpair; send() writes to the other end."""

    def __init__(self, inspects=None, *, data: bytes = b"", close: bool = True) -> None:
        self.creates: list[tuple[str, object, dict]] = []
        self.sockets: list[socket.socket] = []
        self.inspects = list(inspects or [{"Running": False, "ExitCode": 0}])
        self.data = data
        self.close = close
        self.peers: list[socket.socket] = []

    def exec_create(self, container, cmd, **kwargs):
        self.creates.append((container, cmd, kwargs))
        return {"Id": f"e{len(self.creates)}"}

    def exec_start(self, exec_id, tty, socket):
        assert (tty, socket) == (False, True)
        ours, theirs = _socketpair()
        self.sockets.append(ours)
        self.peers.append(theirs)
        if self.data:
            theirs.sendall(self.data)
        if self.close:
            theirs.close()
        return FakeSocketIO(ours)

    def exec_inspect(self, exec_id):
        return self.inspects.pop(0) if len(self.inspects) > 1 else self.inspects[0]


def _socketpair():
    # exec_start's parameter named socket hides the module there.
    return socket.socketpair()


NEVER_ENDS = {"Running": True, "ExitCode": None}


# VALIDATION


def test_parse_argv_accepts_literals_and_rejects_bad_shapes() -> None:
    argv, errors = hooks.parse_argv('["echo","$(id)", "${X}", "{{x}}", "a b"]')
    assert (argv, errors) == (["echo", "$(id)", "${X}", "{{x}}", "a b"], [])
    # "[" * 90000 is deeper than the JSON decoder's stack: RecursionError, not a 500.
    for text in ('"echo"', "[1]", '{"a": 1}', "not json", '["a", null]', "[" * 90000):
        argv, errors = hooks.parse_argv(text)
        assert argv is None
        assert errors and errors[0].startswith(SHAPE), text
    for text in ("[]", '[""]'):
        assert hooks.parse_argv(text) == (None, ["The command needs a program name."])
    cases = {
        json.dumps(["a"] * 65): "at most 64 arguments",
        json.dumps(["a", "b" * 4097]): "at most 4096 characters",
        json.dumps(["a"] + ["b" * 4000] * 5): "at most 16384 bytes",
        json.dumps(["a", "b\x00c"]): "Arguments cannot hold NUL characters.",
        '["a", "\\ud800"]': "Arguments must be valid Unicode text.",
        "[" + " " * 200000 + "]": "at most 16384 bytes",
    }
    for text, expected in cases.items():
        argv, errors = hooks.parse_argv(text)
        assert argv is None
        assert any(expected in error for error in errors), (expected, errors)
        assert all(error.endswith(".") for error in errors)
    assert hooks.check_argv(["echo", "x" * 4096]) == []
    assert hooks.check_argv("echo hi") == [hooks.ARGV_SHAPE]  # never a string


def form(**overrides: str):
    base = {
        "name": "dump",
        "container": "db",
        "argv": '["pg_dump", "-f", "/backup/db.sql"]',
        "user": "",
        "workdir": "",
        "timeout_s": "",
    }
    return hooks.validate_form(**(base | overrides))


def test_validate_form_limits() -> None:
    fields, errors = form(name="  dump  ", container=" db ", project=" app ", log_output="on")
    assert errors == []
    assert fields == hooks.HookFields(
        name="dump",
        container="db",
        argv=("pg_dump", "-f", "/backup/db.sql"),
        user="",
        workdir="",
        timeout_s=300,
        project="app",
        log_output=True,
    )
    assert form()[0].project is None
    assert form()[0].log_output is False
    assert form(log_output="1")[0].log_output is True
    assert form(log_output="yes")[0].log_output is False
    for name in ("", " ", "a" * 65, "a\nb"):
        assert form(name=name) == (None, ["Name must be 1 to 64 characters."]), name
    for container in ("", "-db", "a b", "a/b", "x" * 129):
        fields, errors = form(container=container)
        assert fields is None and "Compose service" in errors[0], container
    for project in ("App", "-app", "a" * 64, "a.b"):
        fields, errors = form(project=project)
        assert fields is None and "Compose project name" in errors[0], project
    assert form(project="a")[0].project == "a"
    for user in ("root", "999", "www-data:www-data", "0:0"):
        assert form(user=user)[0].user == user
    for user in ("a b", ":x", "a:", "-a"):
        fields, errors = form(user=user)
        assert fields is None and errors[0].startswith("Enter a user"), user
    assert form(workdir="/srv")[0].workdir == "/srv"
    for workdir in ("srv", "/a/../b", "/a/..", "/x\ny", "/x\x00y"):
        fields, errors = form(workdir=workdir)
        assert fields is None, workdir
        assert errors == ["The working directory must be an absolute path inside the container."]
    for value, expected in (("", 300), ("1", 1), ("3600", 3600), (" 60 ", 60)):
        assert form(timeout_s=value)[0].timeout_s == expected
    for value in ("0", "3601", "-5", "1e3", "99999999", "٣"):
        assert form(timeout_s=value) == (None, ["The timeout must be 1 to 3600 seconds."])
    fields, errors = form(name="", argv="[]", timeout_s="0")
    assert fields is None and len(errors) == 3


def test_hook_from_row_refuses_non_list_argv() -> None:
    row = SimpleNamespace(
        id=4,
        name="dump",
        container="db",
        argv_json='["pg_dump","-U","postgres"]',
        user="",
        workdir="",
        timeout_s=60,
        host_id=2,
        project="",
        log_output=0,
    )
    hook = Hook.from_row(row)
    assert hook == Hook(4, "dump", "db", ("pg_dump", "-U", "postgres"), "", "", 60, 2, None)
    assert "pg_dump" not in repr(hook)
    assert Hook.from_row(SimpleNamespace(**(vars(row) | {"project": "app"}))).project == "app"
    assert Hook.from_row(row) != Hook.from_row(SimpleNamespace(**(vars(row) | {"user": "x"})))
    for stored in ('"echo hi"', "[1]", "[]", "nope", None, '["a\\u0000"]', "[" * 90000):
        bad = SimpleNamespace(**(vars(row) | {"argv_json": stored}))
        with pytest.raises(HookError, match=r"^Hook dump is not valid\.$"):
            Hook.from_row(bad)
    assert hooks.argv_json(("a", "é b")) == '["a","é b"]'
    assert hooks.summary(row) == {
        "name": "dump",
        "host_id": 2,
        "project": None,
        "container": "db",
        "argv": ["pg_dump", "-U", "postgres"],
        "user": "",
        "workdir": "",
        "timeout_s": 60,
        "log_output": False,
    }
    fields = form(project="app")[0]
    assert hooks.summary(fields, host_id=3)["host_id"] == 3
    assert hooks.summary(fields, host_id=3)["argv"] == ["pg_dump", "-f", "/backup/db.sql"]
    assert hooks.summary(fields)["host_id"] is None
    nested = SimpleNamespace(**(vars(row) | {"argv_json": "[" * 90000}))
    assert hooks.summary(nested)["argv"] is None


# BINDING AND RESOLUTION


def test_check_binding() -> None:
    secret_argv = ("sh", "-c", "echo s3cr3t-argument")
    box = make_hook(name="box", container="web", argv=secret_argv, host_id=1)
    project = make_hook(name="proj", container="db", argv=secret_argv, project="app")
    hooks.check_binding(box, host_id=1, target_type="container", target="web")
    hooks.check_binding(project, host_id=1, target_type="stack", target="app")
    # A hook row reads project "" as no project.
    row = SimpleNamespace(name="row", host_id=1, project="", container="web")
    hooks.check_binding(row, host_id=1, target_type="container", target="web")
    cases = [
        (box, 2, "container", "web", "bound to another host"),
        (box, 1, "container", "api", "runs in web, which this job does not back up"),
        (project, 1, "container", "db", "attach it to that project's stack job"),
        (project, 1, "stack", "other", "for Compose project app, which this job does not"),
        (box, 1, "stack", "web", "attach it to that container's job"),
        (project, 2, "stack", "app", "bound to another host"),
        (box, 1, "volume", "web", "target type is not known"),
    ]
    for hook, host_id, target_type, target, expected in cases:
        with pytest.raises(HookError) as caught:
            hooks.check_binding(hook, host_id=host_id, target_type=target_type, target=target)
        message = str(caught.value)
        assert expected in message
        assert not any(item in message for item in secret_argv)


@dataclass(frozen=True)
class T:
    id: str
    name: str
    service: str | None = None
    running: bool = True
    paused: bool = False


ID_A = "a" * 12 + "0" * 52
ID_B = "a" * 11 + "b" + "1" * 52


def test_resolve_refuses_containers_outside_the_targets() -> None:
    web = T(ID_A, "app-web-1", "web")
    db = T(ID_B, "app-db-1", "db")
    targets = [web, db]
    by_name = make_hook(name="n", container="app-db-1")
    by_id = make_hook(name="i", container=ID_A)
    by_prefix = make_hook(name="p", container=ID_A[:12])
    got = hooks.resolve([by_name, by_id, by_prefix], targets)
    assert got == [
        (by_name, ID_B, "app-db-1"),
        (by_id, ID_A, "app-web-1"),
        (by_prefix, ID_A, "app-web-1"),
    ]
    # 11 characters are not an ID prefix (and match both IDs).
    with pytest.raises(HookError, match="does not back up"):
        hooks.resolve([make_hook(name="short", container=ID_A[:11])], targets)
    # A container hook never matches by service.
    with pytest.raises(HookError, match=r"^Hook s runs in web, which this job does not back up\.$"):
        hooks.resolve([make_hook(name="s", container="web")], targets)
    # Project hooks: by container name, else by service.
    proj_name = make_hook(name="pn", container="app-web-1", project="app")
    proj_service = make_hook(name="ps", container="db", project="app")
    got = hooks.resolve([proj_service, proj_name], targets)
    assert got == [(proj_service, ID_B, "app-db-1"), (proj_name, ID_A, "app-web-1")]
    scaled = [web, T("c" * 64, "app-web-2", "web")]
    with pytest.raises(HookError, match="names service web, which has 2 containers"):
        hooks.resolve([make_hook(name="w", container="web", project="app")], scaled)
    with pytest.raises(HookError, match="which this job does not back up"):
        hooks.resolve([make_hook(name="m", container="cache", project="app")], targets)
    stopped = [T(ID_A, "app-web-1", "web", running=False)]
    with pytest.raises(HookError, match=r"^Container app-web-1 is not running, so hook"):
        hooks.resolve([make_hook(container="app-web-1")], stopped)
    paused = [T(ID_A, "app-web-1", "web", running=True, paused=True)]
    with pytest.raises(HookError, match=r"^Container app-web-1 is paused, so hook h cannot run"):
        hooks.resolve([make_hook(container="web", project="app")], paused)
    assert hooks.resolve([], targets) == []


# OUTPUT


def merged(pieces: list[tuple[int, bytes]]) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    for stream, data in pieces:
        if out and out[-1][0] == stream:
            out[-1] = (stream, out[-1][1] + data)
        else:
            out.append((stream, data))
    return out


def test_demux_handles_split_headers_and_frames() -> None:
    data = frame(1, b"hello\n") + frame(2, b"oops\n") + frame(0, b"x") + frame(1, b"")
    whole = hooks.Demux().feed(data)
    demux = hooks.Demux()
    single = [piece for byte in data for piece in demux.feed(bytes([byte]))]
    expected = [(1, b"hello\n"), (2, b"oops\n"), (1, b"x")]
    assert merged(whole) == merged(single) == expected
    # Data is passed on as it arrives, not buffered to the declared size.
    assert hooks.Demux().feed(FRAME.pack(1, 1_000_000) + b"abc") == [(1, b"abc")]
    with pytest.raises(HookError, match="cannot read"):
        hooks.Demux().feed(frame(7, b"x"))


def test_output_log_caps_and_reports_what_it_dropped(run_log: RunLog) -> None:
    out = hooks.OutputLog(run_log, "h", log_output=True)
    line = b"0123456789" * 9 + b"abcdefghi\n"  # 100 bytes
    total = 2048 * len(line)  # 200 KiB
    for _ in range(2048):
        out.feed(1, line)
    out.close(failed=False)
    logged = [x for x in lines(run_log.path) if x.startswith("[h] ")]
    assert sum(len(x) - 4 + 1 for x in logged) <= hooks.MAX_OUTPUT + 1
    notes = [x for x in lines(run_log.path) if not x.startswith("[h] ")]
    assert notes[0] == f"Output of hook h was cut after {hooks.MAX_OUTPUT} bytes."
    assert len(notes) == 2
    dropped = total - hooks.MAX_OUTPUT
    assert notes[1] == f"{dropped} more bytes of output of hook h were not logged."
    assert out.stdout_bytes == total

    # A long line without a newline is logged in pieces that RunLog never truncates.
    run_log.path.unlink()
    out = hooks.OutputLog(run_log, "h", log_output=True)
    text = "".join(chr(ord("a") + i % 26) for i in range(10000))
    for start in range(0, len(text), 333):
        out.feed(1, text[start : start + 333].encode())
    out.feed(2, b"bad \xff\xfe utf8\nsecond")
    out.close(failed=False)
    pieces = [x for x in lines(run_log.path) if x.startswith("[h] ")]
    assert len(pieces) == 3
    assert all(len(x) < runlog.MAX_LINE for x in pieces)
    assert "".join(x[4:] for x in pieces) == text
    errors = [x for x in lines(run_log.path) if x.startswith("[h stderr] ")]
    assert errors == ["[h stderr] bad �� utf8", "[h stderr] second"]

    # A hook name holding a secret grows the prefix when RunLog redacts it; the pieces
    # still fit, so RunLog's truncation never cuts one.
    log = RunLog(run_log.path.parent / "named.log")
    log.add_secrets(["dump"])
    out = hooks.OutputLog(log, "dump", log_output=True)
    for start in range(0, len(text), 333):
        out.feed(1, text[start : start + 333].encode())
    out.close(failed=False)
    prefix = "[[redacted]] "
    assert all(len(x) <= runlog.MAX_LINE for x in lines(log.path))
    assert hook_text(log.path, prefix) == text


def leaked(text: str, secret: str = SECRET, size: int = 6) -> list[str]:
    return [
        secret[i : i + size] for i in range(len(secret) - size + 1) if secret[i : i + size] in text
    ]


def test_secret_across_a_cut_is_redacted(tmp_path: Path) -> None:
    data = ("a" * 3990 + SECRET + "b" * 5000).encode()
    for size in (1, 7, 4096):
        log = RunLog(tmp_path / f"{size}.log")
        log.add_secrets([SECRET, "short", "very"])
        out = hooks.OutputLog(log, "h", log_output=True)
        for start in range(0, len(data), size):
            out.feed(1, data[start : start + size])
        out.close(failed=False)
        content = log.path.read_text(encoding="utf-8")
        assert not leaked(content), size
        assert "[redacted]" in hook_text(log.path)  # a piece may end inside the marker
        text = hook_text(log.path).replace("[redacted]", "")
        assert text.count("a") == 3990 and text.count("b") == 5000, size
        assert all(len(x) < runlog.MAX_LINE for x in lines(log.path))

    # NUL-separated output (cat /proc/1/environ) is one long partial line.
    log = RunLog(tmp_path / "environ.log")
    log.add_secrets([SECRET])
    out = hooks.OutputLog(log, "h", log_output=True)
    environ = (f"A=1\x00TOKEN={SECRET}\x00" * 400).encode()
    for start in range(0, len(environ), 13):
        out.feed(1, environ[start : start + 13])
    out.close(failed=False)
    content = log.path.read_text(encoding="utf-8")
    assert not leaked(content)
    assert hook_text(log.path).count("TOKEN=[redacted]?") == 400

    # A short secret inside a longer one is not replaced before the long one completes.
    url = "postgres://app:pw-1234@db:5432/app"
    log = RunLog(tmp_path / "nested.log")
    log.add_secrets([url, "pw-1234"])
    out = hooks.OutputLog(log, "h", log_output=True)
    for char in f"x {url} y\n".encode():
        out.feed(1, bytes([char]))
    out.close(failed=False)
    assert hook_text(log.path) == "x [redacted] y"


def test_dense_secrets_keep_the_buffer_and_the_work_bounded(tmp_path: Path) -> None:
    # Every split point falls inside an occurrence of "abcd" (hold() is 4): the buffers
    # stay small (one marker stands for the whole run) and the work is linear.
    log = RunLog(tmp_path / "dense.log")
    log.add_secrets(["abcd", "zzzzz"])
    out = hooks.OutputLog(log, "h", log_output=True)
    started = time.monotonic()
    out.feed(1, b"ab")
    for _ in range(40):
        out.feed(1, b"cdab" * 1024)
        part = out._streams[1]
        assert len(part.raw) <= out.hold() and part.line == "[redacted]"
    for _ in range(10000):
        out.feed(1, b"cdab")
    out.feed(1, b"cd ok\n")
    out.close(failed=False)
    assert time.monotonic() - started < 2.0
    assert hook_text(log.path) == "[redacted] ok"
    # Overlapping occurrences are all covered: no fragment of one shows.
    log = RunLog(tmp_path / "overlap.log")
    log.add_secrets(["aaaa"])
    out = hooks.OutputLog(log, "h", log_output=True)
    out.feed(1, b"x" + b"a" * 10 + b"y\n")
    out.close(failed=False)
    assert hook_text(log.path) == "x[redacted]y"


def test_a_stream_that_breaks_off_leaks_no_secret_start(run_log: RunLog) -> None:
    run_log.add_secrets([SECRET])
    out = hooks.OutputLog(run_log, "h", log_output=True)
    out.feed(1, b"pw=" + SECRET[:-3].encode())
    out.close(failed=True, complete=False)
    content = run_log.path.read_text(encoding="utf-8")
    assert not leaked(content, size=4)
    assert lines(run_log.path) == ["[h] p", "23 more bytes of output of hook h were not logged."]

    # The stderr tail logged on failure is trimmed the same way.
    run_log.path.unlink()
    out = hooks.OutputLog(run_log, "h", log_output=False)
    out.feed(2, b"error: token " + SECRET[:-1].encode())
    out.close(failed=True, complete=False)
    content = run_log.path.read_text(encoding="utf-8")
    assert not leaked(content, size=4)
    assert "[h stderr] error: tok" in content

    # A hook that times out in the middle of writing a secret.
    run_log.path.unlink()
    api = FakeApi([NEVER_ENDS], data=frame(1, f"x={SECRET[:-2]}".encode()), close=False)
    with pytest.raises(HookError, match="timed out"):
        hooks.run_hook(
            api,
            "c",
            make_hook(timeout_s=1, log_output=True),
            container_name="db",
            phase="pre",
            cancel=threading.Event(),
            log=run_log,
        )
    content = run_log.path.read_text(encoding="utf-8")
    assert not leaked(content, size=4)
    assert "more bytes of output of hook h were not logged." in content
    api.peers[0].close()


def test_output_is_not_logged_by_default(run_log: RunLog) -> None:
    run_log.add_secrets([SECRET])
    out = hooks.OutputLog(run_log, "h", log_output=False)
    out.feed(1, b"o" * 10240)
    out.feed(2, b"e" * 10240)
    out.close(failed=False)
    count = (
        "Hook h wrote 10240 bytes to standard output and 10240 bytes to standard error;"
        " hook output is not logged."
    )
    assert lines(run_log.path) == [count]

    run_log.path.unlink()
    out = hooks.OutputLog(run_log, "h", log_output=False)
    out.feed(1, b"o" * 10240)
    stderr = b"".join(f"line {i:05d} {'e' * 40}\n".encode() for i in range(200))
    out.feed(2, stderr)
    out.close(failed=True)
    logged = lines(run_log.path)
    assert logged[0].startswith(f"Hook h wrote 10240 bytes to standard output and {len(stderr)}")
    shown = [x[len("[h stderr] ") :] for x in logged[2:]]
    assert all(x.startswith("[h stderr] ") for x in logged[2:])
    body = "\n".join(shown) + "\n"
    assert logged[1] == f"The last {len(body.encode())} bytes of standard error of hook h:"
    assert len(body.encode()) <= hooks.STDERR_TAIL
    assert stderr.decode().endswith(body)
    assert all(len(x) == len("line 00000 ") + 40 for x in shown)  # the cut first line dropped
    assert shown[-1] == f"line 00199 {'e' * 40}"

    # A secret cut at the tail's front leaks no part of itself, with or without newlines.
    for tail_rest in (b"x" * (hooks.STDERR_TAIL - 10), b"\n" + b"x" * (hooks.STDERR_TAIL - 11)):
        run_log.path.unlink()
        out = hooks.OutputLog(run_log, "h", log_output=False)
        out.feed(2, b"z" * 100 + SECRET.encode() + tail_rest)
        assert out.tail.startswith(SECRET[-10:].encode())
        out.close(failed=True)
        content = run_log.path.read_text(encoding="utf-8")
        assert not leaked(content, size=4), tail_rest[:2]
        assert "xxxx" in content


def test_secrets(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "1.log")
    assert log.secrets() == []
    log.add_secrets(["abc", "abcd", "abcdefgh", "x" * 3])
    assert log.secrets() == ["abcdefgh", "abcd"]  # longest first, short values ignored
    log.add_secrets(["y" * 30])
    assert log.secrets()[0] == "y" * 30
    assert log.redact("abcdefgh abcd yy") == "[redacted] [redacted] yy"
    # A plain callable has no secrets: nothing is held back.
    assert hooks.OutputLog(print, "h", log_output=True).hold() == 0
    assert hooks.OutputLog(log, "h", log_output=True).hold() == 29


# EXEC


def test_open_stream_takes_bytes_already_buffered() -> None:
    ours, theirs = socket.socketpair()
    reader = ours.makefile("rb")
    try:
        first, second = frame(1, b"buffered"), frame(2, b"later")
        theirs.sendall(b"HTTP/1.1 101 UPGRADED\r\n\r\n" + first)
        assert reader.readline() == b"HTTP/1.1 101 UPGRADED\r\n"  # what http.client read
        assert reader.readline() == b"\r\n"
        theirs.sendall(second)
        time.sleep(0.05)
        sock_io = FakeSocketIO(ours, reader)
        calls = []

        class Api:
            def exec_start(self, exec_id, **kwargs):
                calls.append((exec_id, kwargs))
                return sock_io

        raw, pending, response = hooks.open_stream(Api(), "e1")
        assert calls == [("e1", {"tty": False, "socket": True})]
        assert raw is ours and response is sock_io._response
        assert pending == first
        assert raw.getblocking() is False
        assert raw.recv(100) == second
        # Nothing buffered: an empty pending, without blocking.
        assert hooks.open_stream(Api(), "e2")[1] == b""
        with pytest.raises(HookError, match="cannot stream hook output"):
            hooks.open_stream(SimpleNamespace(exec_start=lambda *a, **k: object()), "e3")
    finally:
        reader.close()
        ours.close()
        theirs.close()


def test_run_hook_exit_code_and_create_arguments(run_log: RunLog) -> None:
    argv = ("sh", "-c", "secret-arg-text")
    hook = make_hook(argv=argv, user="www-data:www-data", workdir="/srv")
    api = FakeApi([{"Running": False, "ExitCode": 3}], data=frame(1, b"out\n"))
    cancel = threading.Event()
    with pytest.raises(HookError, match=r"^Hook h failed with exit code 3\.$") as caught:
        hooks.run_hook(
            api, "cid", hook, container_name="db", phase="pre", cancel=cancel, log=run_log
        )
    container, cmd, kwargs = api.creates[0]
    assert container == "cid"
    assert type(cmd) is list and cmd == list(argv)
    assert kwargs == {
        "stdout": True,
        "stderr": True,
        "stdin": False,
        "tty": False,
        "privileged": False,
        "user": "www-data:www-data",
        "environment": None,
        "workdir": "/srv",
    }
    assert api.sockets[0].fileno() == -1
    content = run_log.path.read_text(encoding="utf-8")
    assert "Running pre-hook h in container db." in content
    assert not any(item in content or item in str(caught.value) for item in argv[1:])
    assert "secret-arg-text" not in content

    api = FakeApi(data=frame(1, b"out\n"))
    hooks.run_hook(
        api, "cid", make_hook(), container_name="db", phase="post", cancel=cancel, log=run_log
    )
    assert api.creates[0][2]["workdir"] is None and api.creates[0][2]["user"] == ""
    assert lines(run_log.path)[-1] == "Hook h finished."
    with pytest.raises(ValueError):
        hooks.run_hook(
            api,
            "c",
            make_hook(),
            container_name="db",
            phase="pre",
            cancel=cancel,
            log=run_log,
            on_cancel="x",
        )

    class Refusing(FakeApi):
        def exec_create(self, container, cmd, **kwargs):
            raise docker.errors.APIError("409", explanation="Container cid is paused")

    with pytest.raises(
        HookError, match=r"^Docker could not start hook h: Container cid is paused$"
    ):
        hooks.run_hook(
            Refusing(),
            "c",
            make_hook(),
            container_name="db",
            phase="pre",
            cancel=cancel,
            log=run_log,
        )


def test_run_hook_times_out_and_cancels(run_log: RunLog) -> None:
    api = FakeApi([NEVER_ENDS], close=False)
    started = time.monotonic()
    with pytest.raises(HookError, match="timed out after 1 seconds") as caught:
        hooks.run_hook(
            api,
            "c",
            make_hook(timeout_s=1),
            container_name="db",
            phase="pre",
            cancel=threading.Event(),
            log=run_log,
        )
    assert time.monotonic() - started < 1.5
    assert "wrap long commands in timeout" in str(caught.value)
    assert api.sockets[0].fileno() == -1

    # Cancelled before the hook: it is not even created, so nothing runs in the container.
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(Cancelled):
        hooks.run_hook(
            api, "c", make_hook(), container_name="db", phase="pre", cancel=cancel, log=run_log
        )
    assert len(api.creates) == 1 and len(api.sockets) == 1
    assert lines(run_log.path).count("Running pre-hook h in container db.") == 1

    # Cancelled after exec_create: the exec is never started.
    class CancelOnCreate(FakeApi):
        def exec_create(self, container, cmd, **kwargs):
            cancel.set()
            return super().exec_create(container, cmd, **kwargs)

    cancel = threading.Event()
    late = CancelOnCreate()
    with pytest.raises(Cancelled):
        hooks.run_hook(
            late, "c", make_hook(), container_name="db", phase="pre", cancel=cancel, log=run_log
        )
    assert len(late.creates) == 1 and late.sockets == []

    # A cancel while the hook runs is noticed within POLL.
    cancel = threading.Event()
    threading.Timer(0.3, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(Cancelled):
        hooks.run_hook(
            api, "c", make_hook(), container_name="db", phase="pre", cancel=cancel, log=run_log
        )
    assert time.monotonic() - started < 0.3 + hooks.POLL + 0.3
    for peer in api.peers:
        peer.close()


def test_run_hook_polls_inspect_after_an_early_eof(run_log: RunLog, monkeypatch) -> None:
    monkeypatch.setattr(hooks, "INSPECT_POLL", 0.05)
    running = {"Running": True, "ExitCode": None}
    api = FakeApi([running, running, {"Running": False, "ExitCode": 0}])
    hooks.run_hook(
        api,
        "c",
        make_hook(),
        container_name="db",
        phase="pre",
        cancel=threading.Event(),
        log=run_log,
    )
    assert api.inspects == [{"Running": False, "ExitCode": 0}]
    assert lines(run_log.path)[-1] == "Hook h finished."

    # Still running at the timeout: a timeout, after polling.
    api = FakeApi([NEVER_ENDS])
    started = time.monotonic()
    with pytest.raises(HookError, match="timed out"):
        hooks.run_hook(
            api,
            "c",
            make_hook(timeout_s=1),
            container_name="db",
            phase="pre",
            cancel=threading.Event(),
            log=run_log,
        )
    assert 0.9 < time.monotonic() - started < 1.5


class FakeTLS:
    """Stands in for ssl.SSLSocket: the first recv needs another record, the second
    returns a frame header and leaves the body decrypted (only pending() shows it)."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.decrypted = b""
        self.recvs = 0
        self.closed = False

    def setblocking(self, flag: bool) -> None:
        assert flag is False

    def recv(self, size: int) -> bytes:
        self.recvs += 1
        if self.recvs == 1:
            raise ssl.SSLWantReadError("want read")
        if self.recvs == 2:
            self.decrypted = self.body
            return FRAME.pack(1, len(self.body))
        if self.decrypted:
            data, self.decrypted = self.decrypted[:size], self.decrypted[size:]
            return data
        return b""

    def pending(self) -> int:
        return len(self.decrypted)

    def close(self) -> None:
        self.closed = True


def test_ssl_want_read_is_retried_and_pending_is_drained(run_log: RunLog, monkeypatch) -> None:
    tls = FakeTLS(b"all of it\n")
    monkeypatch.setattr(hooks.ssl, "SSLSocket", FakeTLS)
    monkeypatch.setattr(hooks.select, "select", lambda r, w, x, timeout: (r, [], []))

    class Api(FakeApi):
        def exec_start(self, exec_id, tty, socket):
            return FakeSocketIO(tls)

    api = Api([{"Running": False, "ExitCode": 0}])
    hook = make_hook(log_output=True)
    hooks.run_hook(
        api, "c", hook, container_name="db", phase="pre", cancel=threading.Event(), log=run_log
    )
    assert tls.recvs == 4  # want-read, header, the pending body, end of stream
    assert tls.closed
    assert "[h] all of it" in lines(run_log.path)
    assert lines(run_log.path)[-1] == "Hook h finished."


def test_run_all_post_semantics(run_log: RunLog, monkeypatch) -> None:
    monkeypatch.setattr(hooks, "CANCEL_WAIT", 0.5)
    one, two = make_hook(id=1, name="one"), make_hook(id=2, name="two")
    pairs = [(one, "c1", "db"), (two, "c2", "db")]

    class Mixed(FakeApi):
        def exec_inspect(self, exec_id):
            return {"Running": False, "ExitCode": 1 if exec_id == "e1" else 0}

    # keep_going: hook one fails, hook two still runs, the first error is raised.
    api = Mixed()
    with pytest.raises(HookError, match=r"^Hook one failed with exit code 1"):
        hooks.run_all(
            api, pairs, phase="post", cancel=threading.Event(), log=run_log, keep_going=True
        )
    assert [c[0] for c in api.creates] == ["c1", "c2"]
    assert "Hook two finished." in lines(run_log.path)
    # Without keep_going the first error stops the rest.
    api = Mixed()
    with pytest.raises(HookError, match=r"^Hook one failed"):
        hooks.run_all(api, pairs, phase="pre", cancel=threading.Event(), log=run_log)
    assert len(api.creates) == 1

    # Cancelled before the post-hooks: each is still started, awaited about CANCEL_WAIT.
    cancel = threading.Event()
    cancel.set()
    api = FakeApi([NEVER_ENDS], close=False)
    started = time.monotonic()
    with pytest.raises(HookError, match=r"^Stopped waiting for hook one because the run was"):
        hooks.run_all(
            api, pairs, phase="post", cancel=cancel, log=run_log, keep_going=True, on_cancel="wait"
        )
    assert len(api.creates) == 2
    assert time.monotonic() - started < 2 * 0.5 + 0.6
    assert "Starting post-hook two without waiting for it to finish." in lines(run_log.path)
    # Pre-hooks of a cancelled run are not started at all.
    with pytest.raises(Cancelled):
        hooks.run_all(api, pairs, phase="pre", cancel=cancel, log=run_log)
    assert len(api.creates) == 2

    # The budget runs out in hook one; hook two is still started.
    api = FakeApi([NEVER_ENDS], close=False)
    started = time.monotonic()
    with pytest.raises(HookError, match="did not finish in the time left for post-hooks"):
        hooks.run_all(
            api,
            pairs,
            phase="post",
            cancel=threading.Event(),
            log=run_log,
            keep_going=True,
            on_cancel="wait",
            budget=1,
        )
    assert len(api.creates) == 2
    assert time.monotonic() - started < 1 + 0.5 + 0.6
    logged = lines(run_log.path)
    assert "Hook one did not finish in the time left for post-hooks." in " ".join(logged)
    assert "Starting post-hook two without waiting for it to finish." in logged


class Resetting:
    """A response reader whose connection the proxy reset."""

    def peek(self, size: int) -> bytes:
        raise ConnectionResetError("reset by peer")

    def close(self) -> None:
        pass


def test_stream_errors_fail_one_hook_and_the_rest_still_run(run_log: RunLog, monkeypatch) -> None:
    one, two = make_hook(id=1, name="one"), make_hook(id=2, name="two")
    pairs = [(one, "c1", "db"), (two, "c2", "db")]

    class Reset(FakeApi):
        def exec_start(self, exec_id, tty, socket):
            if exec_id != "e1":
                return super().exec_start(exec_id, tty, socket)
            ours, theirs = _socketpair()
            self.sockets.append(ours)
            self.peers.append(theirs)
            return SimpleNamespace(_sock=ours, _response=FakeResponse(Resetting()))

    api = Reset()
    with pytest.raises(HookError, match=r"^Docker could not stream the output of hook one"):
        hooks.run_all(
            api, pairs, phase="post", cancel=threading.Event(), log=run_log, keep_going=True
        )
    assert [c[0] for c in api.creates] == ["c1", "c2"]
    assert api.sockets[0].fileno() == -1
    assert "Hook two finished." in lines(run_log.path)
    for peer in api.peers:
        peer.close()

    # A select error ends the stream like a read error; the result comes from exec_inspect.
    def broken(*args):
        raise OSError("bad file descriptor")

    monkeypatch.setattr(hooks.select, "select", broken)
    api = FakeApi(close=False)
    hooks.run_hook(
        api, "c", one, container_name="db", phase="pre", cancel=threading.Event(), log=run_log
    )
    assert lines(run_log.path)[-1] == "Hook one finished."
    monkeypatch.undo()
    api.peers[0].close()

    # Any other error in one post-hook still lets the next one run, then propagates.
    class Broken(FakeApi):
        def exec_inspect(self, exec_id):
            if exec_id == "e1":
                raise KeyError("Running")
            return super().exec_inspect(exec_id)

    api = Broken()
    with pytest.raises(KeyError):
        hooks.run_all(
            api, pairs, phase="post", cancel=threading.Event(), log=run_log, keep_going=True
        )
    assert len(api.creates) == 2
    logged = lines(run_log.path)
    assert "Hook one failed because of an unexpected error in drydock." in logged
    assert logged[-1] == "Hook two finished."
