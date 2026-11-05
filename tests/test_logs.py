"""Container logs without a daemon: parsing Docker's answer, the cursor, the caps, and the
logs page and its lines route (the daemon side: test_status_docker.py)."""

import re
from typing import Any

import docker.errors
import pytest

from drydock.hosts import logs
from drydock.hosts.logs import Cursor, Line
from drydock.routes import logs as log_routes
from tests.conftest import Browser, add_user
from tests.test_status import MARKUP, a_host_with_containers, add_host

pytestmark = pytest.mark.anyio

T0 = "2026-11-04T18:00:00.000000001Z"
T0_NS = 1_793_815_200_000_000_001
T1 = "2026-11-04T18:00:01.5Z"
T1_NS = 1_793_815_201_500_000_000


def frame(kind: int, payload: bytes) -> bytes:
    return bytes([kind, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


def stamped(stamp: str, text: str) -> bytes:
    return f"{stamp} {text}\n".encode()


# PARSING


def test_frames_name_their_stream_and_a_tty_is_plain_stdout() -> None:
    data = frame(1, stamped(T0, "out")) + frame(2, stamped(T1, "err"))
    batch = logs.parse(data, tty=False, complete=True, cursor=Cursor())
    assert batch.lines == [Line(T0_NS, "stdout", "out"), Line(T1_NS, "stderr", "err")]
    assert batch.cursor == Cursor(T1_NS, 1) and not batch.cut

    tty = stamped(T0, "one") + stamped(T1, "two\r")
    lines = logs.parse(tty, tty=True, complete=True, cursor=Cursor()).lines
    assert lines == [Line(T0_NS, "stdout", "one"), Line(T1_NS, "stdout", "two")]


def test_a_cut_answer_leaves_out_its_last_incomplete_line() -> None:
    whole = frame(1, stamped(T0, "first"))
    cut = logs.parse(whole + frame(1, stamped(T1, "second"))[:12], False, False, Cursor())
    assert [line.text for line in cut.lines] == ["first"] and cut.cut
    assert cut.cursor == Cursor(T0_NS, 1), "the next poll reads the rest"
    tty = logs.parse(stamped(T0, "first") + b"2026-11-04T18:00", True, False, Cursor())
    assert [line.text for line in tty.lines] == ["first"]
    # One frame longer than the whole answer is all there is: shown as far as it goes.
    alone = logs.parse(frame(1, stamped(T0, "x" * 100))[:40], False, False, Cursor())
    assert alone.lines[0].text == "x" * (40 - 8 - len(T0) - 1)


def test_timestamps_and_lines_without_one() -> None:
    plain = logs.line_of("stdout", b"2026-11-04T18:00:00Z no fraction", 0)
    assert plain.ns == T0_NS - 1 and plain.text == "no fraction"
    assert plain.when is not None and plain.when.year == 2026
    assert logs.line_of("stdout", b"continued", 42) == Line(42, "stdout", "continued")
    assert logs.line_of("stdout", b"2026-11-04 not docker's", 7).ns == 7


def test_long_lines_are_cut_with_a_marker() -> None:
    line = logs.line_of("stdout", f"{T0} ".encode() + b"a" * (logs.MAX_LINE + 10), 0)
    assert line.text == "a" * logs.MAX_LINE + logs.CUT


def test_escape_sequences_and_control_characters_are_removed() -> None:
    raw = (
        b"\x1b[31mred\x1b[0m \x1b]0;title\x07tab\there\x1b(B bell\x07 nul\x00 cr\rend "
        + "c1\u009bx".encode()
    )
    assert logs.clean(raw) == "red tab\there bell nul crend c1x"
    assert logs.clean("ok ‮KO‬ ⁧x⁩".encode()) == "ok KO x"
    assert logs.clean(b"\xff\xfebroken") == "��broken"


def test_the_cursor_drops_lines_already_shown() -> None:
    a, b, c = Line(10, "stdout", "a"), Line(10, "stdout", "b"), Line(20, "stdout", "c")
    shown, cursor = logs.after([a, b], Cursor())
    assert shown == [a, b] and cursor == Cursor(10, 2)
    # Docker's since returns the lines at the cursor's time again; they are dropped.
    shown, cursor = logs.after([a, b, c], cursor)
    assert shown == [c] and cursor == Cursor(20, 1)
    # Nothing new: the cursor stays.
    assert logs.after([c], cursor) == ([], cursor)
    # A third line at the same nanosecond as two shown ones still shows.
    d = Line(20, "stderr", "d")
    assert logs.after([c, d], cursor) == ([d], Cursor(20, 2))


def test_the_cursor_takes_the_newest_time_when_streams_cross() -> None:
    late = Line(15, "stderr", "late")
    shown, cursor = logs.after([Line(20, "stdout", "new"), late], Cursor(10, 1))
    assert [line.text for line in shown] == ["new", "late"]
    assert cursor == Cursor(20, 1), "never back to 15, which would show 'new' again"


def test_since_is_seconds_and_nanoseconds() -> None:
    assert Cursor(T0_NS, 3).since == "1793815200.000000001"


# READING FROM DOCKER


class FakeResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.read = 0
        self.closed = False

    def iter_content(self, chunk_size: int):
        for chunk in self.chunks:
            self.read += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


class FakeApi:
    def __init__(self, chunks: list[bytes]) -> None:
        self.response = FakeResponse(chunks)
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _url(self, path: str, *args: str) -> str:
        return path.format(*args)

    def _get(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((url, kwargs))
        return self.response

    def _raise_for_status(self, response: FakeResponse) -> None:
        pass


def test_read_asks_for_the_tail_first_then_since_the_cursor() -> None:
    api = FakeApi([frame(1, stamped(T0, "hi"))])
    batch = logs.read(api, "a" * 64, False, 100, Cursor())
    url, kwargs = api.calls[0]
    assert url == f"/containers/{'a' * 64}/logs" and kwargs["stream"] is True
    assert kwargs["params"] == {"stdout": 1, "stderr": 1, "timestamps": 1, "tail": 100}
    assert batch.lines[0].text == "hi" and api.response.closed

    api = FakeApi([])
    assert logs.read(api, "a" * 64, False, 100, batch.cursor).lines == []
    assert api.calls[0][1]["params"]["since"] == batch.cursor.since
    assert "tail" not in api.calls[0][1]["params"]


def test_read_stops_at_the_byte_cap() -> None:
    line = frame(1, stamped(T0, "z" * 1000))
    chunk = line * 100  # about 100 KiB
    api = FakeApi([chunk] * 1000)  # about 100 MiB if read whole
    batch = logs.read(api, "a" * 64, False, 5000, Cursor())
    assert batch.cut and api.response.closed
    assert api.response.read <= logs.MAX_BYTES // len(chunk) + 1
    assert len(batch.lines) == logs.MAX_BYTES // len(line)


# THE PAGE AND ITS LINES


async def test_logs_are_for_admins_only(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    lines = f"/logs/lines?host={host_id}&container={'a' * 64}"
    assert 'href="/logs"' in (await admin.get("/")).text
    await add_user(admin, "runner", "operator")
    await add_user(admin, "watcher", "viewer")
    for user in ("runner", "watcher"):
        await admin.login(user)
        assert 'href="/logs"' not in (await admin.get("/")).text
        assert (await admin.get(f"/logs?host={host_id}")).status_code == 403
        assert (await admin.get(lines)).status_code == 403


async def test_the_page_lists_the_cache_and_never_calls_docker(admin: Browser, monkeypatch) -> None:
    collector, host_id = await a_host_with_containers(admin, monkeypatch)
    page = (await admin.get(f"/logs?host={host_id}")).text
    assert MARKUP in page and "<img src=x" not in page
    assert page.index('data-name="cache"') < page.index('data-name="web"'), "by name"
    assert "Choose a container" in page and 'id="log-poller"' not in page
    assert collector._viewed_at > 0

    page = (await admin.get(f"/logs?host={host_id}&container={'a' * 64}&tail=1000")).text
    assert '<h2 id="log-title"' in page and 'title="web">web</h2>' in page
    poller = re.search(r'<span id="log-poller"[^>]*>', page)
    assert poller is not None
    assert f'hx-get="/logs/lines?host={host_id}&amp;container={"a" * 64}&amp;tail=1000"' in (
        poller.group(0)
    )
    assert 'hx-nonce="' in poller.group(0) and 'data-max-lines="1000"' in page
    for form in ("host-picker",):  # else hx-csp strips its hx-* attributes
        assert re.search(rf'id="{form}"[^>]*hx-nonce="', page), form
    # An unknown tail falls back; an ID the cache lacks still shows, by its short form.
    page = (await admin.get(f"/logs?host={host_id}&container={'f' * 64}&tail=7")).text
    assert 'data-max-lines="500"' in page and f">{'f' * 12}</h2>" in page
    assert "Choose a container" in (await admin.get("/logs?container=../x")).text


def fake_docker(monkeypatch, lines: list[Line], cut: bool = False, tty: bool = False) -> list:
    """The route's Docker side: open_host gives a client whose inspect tells the TTY, and
    logs.read answers lines after the cursor. Returns the reads' arguments."""
    reads: list = []

    class Api:
        def inspect_container(self, container: str) -> dict[str, Any]:
            return {"Config": {"Tty": tty}}

    class Handle:
        class client:
            api = Api()

        def close(self) -> None:
            pass

    def read(api, container, has_tty, tail, cursor):
        reads.append((container, has_tty, tail, cursor))
        shown, moved = logs.after(lines, cursor)
        return logs.Batch(shown, moved, cut)

    monkeypatch.setattr(log_routes, "open_host", lambda request, host, timeout: Handle())
    monkeypatch.setattr(logs, "read", read)
    return reads


async def test_lines_are_escaped_and_bring_the_next_poller(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    lines = [Line(T0_NS, "stdout", "<script>alert(1)</script>"), Line(T1_NS, "stderr", "oops")]
    reads = fake_docker(monkeypatch, lines, tty=True)
    first = await admin.get(
        f"/logs/lines?host={host_id}&container={'a' * 64}&tail=100",
        headers={"HX-Request": "true"},
    )
    assert first.status_code == 200
    text = first.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text and "<script>alert" not in text
    assert '<div data-line class="text-error">' in text and "2026-11-04 18:00:01.500" in text
    assert reads == [("a" * 64, True, 100, Cursor())], "inspected once for the TTY"
    poller = re.search(r'<span id="log-poller" hx-get="([^"]*)"[^>]*>', text)
    assert poller is not None and 'hx-trigger="every 2s"' in poller.group(0)
    next_url = poller.group(1).replace("&amp;", "&")
    assert next_url == (
        f"/logs/lines?host={host_id}&container={'a' * 64}&tail=100&after={T1_NS}&seen=1&tty=1"
    )
    # Nothing new: 204, the poller keeps its cursor.
    again = await admin.get(next_url, headers={"HX-Request": "true"})
    assert again.status_code == 204
    assert reads[-1] == ("a" * 64, True, 100, Cursor(T1_NS, 1))


async def test_the_first_request_answers_even_without_lines(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    fake_docker(monkeypatch, [])
    url = f"/logs/lines?host={host_id}&container={'a' * 64}"
    first = await admin.get(url, headers={"HX-Request": "true"})
    assert first.status_code == 200 and "after=0&amp;seen=0&amp;tty=0" in first.text


async def test_lines_refuse_bad_input_and_say_why_reads_fail(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    off = add_host(admin, name="off", enabled=False)
    good = f"container={'a' * 64}"
    for query, code in [
        (f"host={host_id}&container=../../etc", 404),
        (f"host=999999&{good}", 404),
        (f"host={host_id}&{good}&after=-1", 422),
        (f"host={host_id}&{good}&tty=2", 422),
        (f"host={host_id}&{good}&seen=x", 422),
    ]:
        assert (await admin.get(f"/logs/lines?{query}")).status_code == code, query

    disabled = await admin.get(f"/logs/lines?host={off}&{good}")
    assert disabled.status_code == 502
    assert disabled.headers["X-Drydock-Reason"] == "The host is disabled."

    class Gone:
        class client:
            class api:
                @staticmethod
                def inspect_container(container: str) -> dict[str, Any]:
                    raise docker.errors.NotFound("no such container: /secret/path")

        def close(self) -> None:
            pass

    monkeypatch.setattr(log_routes, "open_host", lambda request, host, timeout: Gone())
    gone = await admin.get(f"/logs/lines?host={host_id}&{good}")
    assert gone.status_code == 502 and gone.text == "No such container any more."
    assert "/secret/path" not in gone.headers["X-Drydock-Reason"]
