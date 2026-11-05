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
    paths = [f"/logs?host={host_id}"] + [
        f"/logs/{kind}?host={host_id}&c={'a' * 64}" for kind in ("lines", "download")
    ]
    assert 'href="/logs"' in (await admin.get("/")).text
    await add_user(admin, "runner", "operator")
    await add_user(admin, "watcher", "viewer")
    for user in ("runner", "watcher"):
        await admin.login(user)
        assert 'href="/logs"' not in (await admin.get("/")).text
        for path in paths:
            assert (await admin.get(path)).status_code == 403, path


def pollers(page: str) -> list[str]:
    return [
        url.replace("&amp;", "&")
        for url in re.findall(r'<span data-log-poller hx-get="([^"]*)"[^>]*hx-nonce="', page)
    ]


async def test_the_page_lists_the_cache_and_never_calls_docker(admin: Browser, monkeypatch) -> None:
    collector, host_id = await a_host_with_containers(admin, monkeypatch)
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    page = (await admin.get(f"/logs?host={host_id}")).text
    assert MARKUP in page and "<img src=x" not in page
    assert page.index('data-name="cache"') < page.index('data-name="web"'), "by name"
    assert "Choose a container" in page and not pollers(page)
    # The stack app (db, cache) can be shown whole, side by side.
    stack = f'href="/logs?host={host_id}&amp;c={c}&amp;c={b}&amp;mode=grouped&amp;tail=500"'
    assert stack in page and '>app <span class="opacity-60">(2)</span>' in page
    assert collector._viewed_at > 0

    page = (await admin.get(f"/logs?host={host_id}&c={a}&tail=1000")).text
    assert '<h2 id="log-title"' in page and 'title="web">web</h2>' in page
    assert pollers(page) == [f"/logs/lines?host={host_id}&tail=1000&c={a}"]
    assert 'data-max-lines="1000"' in page and 'id="log-mode"' not in page
    assert f'href="/logs/download?host={host_id}&amp;c={a}&amp;tail=1000"' in page
    for form in ("host-picker", "log-select"):  # else hx-csp strips its hx-* attributes
        assert re.search(rf'id="{form}"[^>]*hx-nonce="', page), form
    assert f'name="c" value="{a}" class="checkbox checkbox-xs" checked' in page

    # Several: merged into one log (one poller), or side by side (one each).
    page = (await admin.get(f"/logs?host={host_id}&c={a}&c={b}&c={a}")).text
    assert pollers(page) == [f"/logs/lines?host={host_id}&tail=500&c={a}&c={b}"]
    assert 'data-max-lines="1000"' in page and 'id="log-mode"' in page and ">web, db</h2>" in page
    page = (await admin.get(f"/logs?host={host_id}&c={a}&c={b}&mode=grouped")).text
    assert pollers(page) == [
        f"/logs/lines?host={host_id}&tail=500&c={a}",
        f"/logs/lines?host={host_id}&tail=500&c={b}",
    ]
    many = "&".join(f"c={i:064x}" for i in range(12))
    page = (await admin.get(f"/logs?host={host_id}&{many}")).text
    assert "At most 10 containers are shown together" in page
    ten = "&".join(f"c={i:064x}" for i in range(10))
    page = (await admin.get(f"/logs?host={host_id}&{ten}&c=junk")).text
    assert "At most 10" not in page, "an invalid value is no container left out"
    assert pollers(page)[0].count("&c=") == 10

    # An unknown tail or mode falls back; an ID the cache lacks shows by its short form.
    page = (await admin.get(f"/logs?host={host_id}&c={'f' * 64}&tail=7&mode=x")).text
    assert 'data-max-lines="500"' in page and f">{'f' * 12}</h2>" in page
    assert "Choose a container" in (await admin.get("/logs?c=../x")).text


def fake_docker(
    monkeypatch, lines: dict[str, list[Line]], cut: bool = False, tty: bool = False
) -> list:
    """The routes' Docker side: open_host gives a client whose inspect tells the TTY, and
    logs.read answers each container's lines after its cursor. Returns the reads."""
    reads: list = []

    class Api:
        def inspect_container(self, container: str) -> dict[str, Any]:
            if container not in lines:
                raise docker.errors.NotFound("no such container: /secret/path")
            return {"Config": {"Tty": tty}}

    class Handle:
        class client:
            api = Api()

        def close(self) -> None:
            pass

    def read(api, container, has_tty, tail, cursor, limit):
        reads.append((container, has_tty, tail, cursor, limit))
        shown, moved = logs.after(lines[container], cursor)
        return logs.Batch(shown, moved, cut)

    monkeypatch.setattr(log_routes, "open_host", lambda request, host, timeout: Handle())
    monkeypatch.setattr(logs, "read", read)
    return reads


async def lines_of(browser: Browser, url: str):
    response = await browser.get(url, headers={"HX-Request": "true"})
    found = pollers(response.text)
    return response, found[0] if found else None


async def test_lines_are_escaped_and_bring_the_next_poller(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    a = "a" * 64
    lines = [Line(T0_NS, "stdout", "<script>alert(1)</script>"), Line(T1_NS, "stderr", "oops")]
    reads = fake_docker(monkeypatch, {a: lines}, tty=True)
    first, next_url = await lines_of(admin, f"/logs/lines?host={host_id}&c={a}&tail=100")
    assert first.status_code == 200
    text = first.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text and "<script>alert" not in text
    assert '<div data-line class="text-error">' in text and "2026-11-04 18:00:01.500" in text
    assert ">web</span>" not in text, "one container: no names"
    assert reads == [(a, True, 100, Cursor(), logs.MAX_BYTES)], "inspected once for the TTY"
    assert 'hx-trigger="every 2s"' in text
    assert next_url == f"/logs/lines?host={host_id}&tail=100&c={a}~{T1_NS}~1~1"
    # Nothing new: 204, the poller keeps its cursor.
    again = await admin.get(next_url, headers={"HX-Request": "true"})
    assert again.status_code == 204
    assert reads[-1] == (a, True, 100, Cursor(T1_NS, 1), logs.MAX_BYTES)


async def test_merged_lines_by_time_with_a_cursor_each(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    a, b = "a" * 64, "b" * 64
    reads = fake_docker(
        monkeypatch,
        {
            a: [Line(10, "stdout", "a1"), Line(30, "stdout", "a2")],
            b: [Line(10, "stdout", "b1"), Line(20, "stderr", "b2")],
        },
    )
    first, next_url = await lines_of(admin, f"/logs/lines?host={host_id}&c={a}&c={b}")
    shown = re.findall(
        r'<span class="font-semibold ([\w-]+)">(\w+)</span> <span data-text>(\w+)<', first.text
    )
    assert shown == [
        ("text-info", "web", "a1"),
        ("text-success", "db", "b1"),  # the same time: in the order chosen
        ("text-success", "db", "b2"),
        ("text-info", "web", "a2"),
    ]
    assert {r[4] for r in reads} == {logs.MAX_BYTES // 2}, "the poll's bytes are shared"
    assert next_url == f"/logs/lines?host={host_id}&tail=500&c={a}~30~1~0&c={b}~20~1~0"
    assert (await admin.get(next_url, headers={"HX-Request": "true"})).status_code == 204


async def test_the_first_request_answers_even_without_lines(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    fake_docker(monkeypatch, {"a" * 64: []})
    first, next_url = await lines_of(admin, f"/logs/lines?host={host_id}&c={'a' * 64}")
    assert first.status_code == 200 and next_url is not None and next_url.endswith("~0~0~0")


async def test_lines_refuse_bad_input_and_say_why_reads_fail(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    off = add_host(admin, name="off", enabled=False)
    a = "a" * 64
    eleven = "&".join(f"c={i:064x}" for i in range(11))
    for query in [
        f"host={host_id}",
        f"host={host_id}&c=../../etc",
        f"host=999999&c={a}",
        f"host={host_id}&c={a}~-1~0~0",
        f"host={host_id}&c={a}~1~0~2",
        f"host={host_id}&c={a}~1~x~0",
        f"host={host_id}&c={a}~9999999999999999999~0~0",
        f"host={host_id}&{eleven}",
    ]:
        assert (await admin.get(f"/logs/lines?{query}")).status_code == 404, query

    disabled = await admin.get(f"/logs/lines?host={off}&c={a}")
    assert disabled.status_code == 502
    assert disabled.headers["X-Drydock-Reason"] == "The host is disabled."

    fake_docker(monkeypatch, {a: [Line(10, "stdout", "fine")]})
    gone = await admin.get(f"/logs/lines?host={host_id}&c={'f' * 64}")
    assert gone.status_code == 502 and gone.text == "No such container any more."
    assert "/secret/path" not in gone.headers["X-Drydock-Reason"]
    # One of several gone: the log names it and stops following it; the rest go on.
    both, next_url = await lines_of(admin, f"/logs/lines?host={host_id}&c={a}&c={'f' * 64}")
    assert both.status_code == 200 and "fine" in both.text
    assert f"{'f' * 12}: No such container any more. Reload to follow it again." in both.text
    assert next_url == f"/logs/lines?host={host_id}&tail=500&c={a}~10~1~0"
    download = await admin.get(f"/logs/download?host={host_id}&c={'f' * 64}")
    assert download.status_code == 502
    assert download.text == "Drydock could not read the logs. No such container any more."


async def test_download_is_a_text_file_of_the_merged_lines(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    a, d = "a" * 64, "d" * 64
    reads = fake_docker(
        monkeypatch,
        {a: [Line(T0_NS, "stdout", "<b>one</b>")], d: [Line(T1_NS, "stderr", "two")]},
    )
    one = await admin.get(f"/logs/download?host={host_id}&c={a}&tail=1000")
    assert one.status_code == 200 and one.headers["content-type"].startswith("text/plain")
    assert one.headers["content-disposition"] == 'attachment; filename="web-logs.txt"'
    assert one.text == "2026-11-04T18:00:00.000000+00:00 stdout <b>one</b>\n"
    assert reads[-1][2:] == (1000, Cursor(), log_routes.DOWNLOAD_BYTES)

    # Several: each line named; the file after the host. A name never shapes the header.
    both = await admin.get(f"/logs/download?host={host_id}&c={a}&c={d}")
    assert both.headers["content-disposition"] == 'attachment; filename="rigel-logs.txt"'
    assert both.text.splitlines() == [
        "2026-11-04T18:00:00.000000+00:00 web stdout <b>one</b>",
        "2026-11-04T18:00:01.500000+00:00 <img src=x onerror=alert(1)> stderr two",
    ]
    fake_docker(monkeypatch, {d: [Line(T1_NS, "stdout", "x")]}, cut=True)
    alone = await admin.get(f"/logs/download?host={host_id}&c={d}")
    assert alone.headers["content-disposition"] == (
        'attachment; filename="img-src-x-onerror-alert-1-logs.txt"'
    )
    assert alone.text.endswith("[cut: the download reached its size limit; choose fewer lines]\n")
    assert (await admin.get(f"/logs/download?host={host_id}")).status_code == 404
