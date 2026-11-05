"""Container logs for the logs page: the last lines of a container, then whatever came
after them, read in bounded pieces.

The page asks for the last TAIL lines first and then polls with a cursor: the timestamp of
the newest line it has, and how many lines with exactly that timestamp it has. Docker's
`since` returns lines at or after a time, so each poll gets those lines again and drops
them (skip). Timestamps are Docker's own, in nanoseconds.

One response reads at most MAX_BYTES of Docker's answer and keeps at most MAX_LINE bytes of
a line, so a chatty container cannot exhaust memory. A cut answer moves the cursor only as
far as the lines it holds: the next poll carries on from there.

Every line is text as the container wrote it, so it is untrusted: escape sequences and
control characters are removed here, and pages only ever autoescape it.
"""

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

KIB = 1024
MAX_BYTES = 2 * KIB * KIB  # of Docker's answers, per poll (shared by its containers)
MAX_LINE = 16 * KIB
TAILS = (100, 500, 1000, 5000)
DEFAULT_TAIL = 500
TIMEOUT = 15  # per Docker request
THREADS = 4  # log reads at once, on threads of their own (never the routes' pool)
CUT = " [cut: line longer than 16 KiB]"
STREAMS = {1: "stdout", 2: "stderr"}
HEADER = 8  # a multiplexed frame: stream, three zero bytes, payload size (big endian)

# Docker's RFC 3339 timestamp with up to nine fraction digits, then one space.
STAMP_RE = re.compile(rb"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z ")
# CSI and OSC sequences, other escapes, and control characters except tab. C1 controls
# (U+0080 to U+009F) too: some terminals read them as escapes. Bidirectional controls
# would let a line show its text in another order than it has.
CONTROL_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[ -/]*[0-~]?"
    r"|[\x00-\x08\x0a-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]"
)


@dataclass(frozen=True)
class Line:
    ns: int  # Docker's timestamp, nanoseconds since the epoch; 0 if it had none
    stream: str  # stdout or stderr
    text: str

    @property
    def when(self) -> datetime | None:
        return datetime.fromtimestamp(self.ns / 1e9, UTC) if self.ns else None


@dataclass(frozen=True)
class Cursor:
    """The newest line shown: its timestamp, and how many lines with exactly that timestamp
    were shown. ns 0: nothing shown yet."""

    ns: int = 0
    seen: int = 0

    @property
    def since(self) -> str:
        """Docker's `since` parameter: seconds and nanoseconds."""
        seconds, nanos = divmod(self.ns, 1_000_000_000)
        return f"{seconds}.{nanos:09d}"


@dataclass(frozen=True)
class Batch:
    lines: list[Line]
    cursor: Cursor
    cut: bool  # the answer was longer than MAX_BYTES: more lines follow at once


def clean(raw: bytes) -> str:
    text = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
    return CONTROL_RE.sub("", text)


def stamp_ns(found: re.Match[bytes]) -> int:
    when = datetime.strptime(found.group(1).decode(), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    fraction = (found.group(2) or b"").decode().ljust(9, "0")
    return int(when.timestamp()) * 1_000_000_000 + int(fraction)


def line_of(stream: str, raw: bytes, previous: int) -> Line:
    """One line as Docker sent it with timestamps=1. A line without a timestamp (a
    continuation) takes the one before it."""
    found = STAMP_RE.match(raw)
    ns = previous
    if found is not None:
        ns = stamp_ns(found)
        raw = raw[found.end() :]
    if len(raw) > MAX_LINE:
        return Line(ns, stream, clean(raw[:MAX_LINE]) + CUT)
    return Line(ns, stream, clean(raw))


def frames(data: bytes, tty: bool, complete: bool) -> Iterator[tuple[str, bytes]]:
    """(stream, one line) from Docker's answer. Without a TTY the answer is multiplexed
    frames, each naming its stream; with one it is plain stdout. An incomplete frame or
    line at the end is left out unless the answer is complete or it is all there is."""
    if tty:
        lines = data.split(b"\n")
        if not data.endswith(b"\n") and not complete and len(lines) > 1:
            lines.pop()  # cut mid-line: the next poll reads it whole
        yield from (("stdout", line) for line in lines if line)
        return
    at = 0
    while at + HEADER <= len(data):
        kind, size = data[at], int.from_bytes(data[at + 4 : at + HEADER], "big")
        payload = data[at + HEADER : at + HEADER + size]
        if len(payload) < size and (at > 0 or complete):
            return
        for line in payload.split(b"\n"):
            if line:
                yield STREAMS.get(kind, "stdout"), line
        at += HEADER + size


def after(lines: Iterable[Line], cursor: Cursor) -> tuple[list[Line], Cursor]:
    """The lines newer than the cursor, and the cursor after them. Those at the cursor's
    own timestamp were shown cursor.seen times already.

    The cursor moves to the newest timestamp, not the last line's: Docker copies stdout
    and stderr separately, so a line can follow a newer one by a hair. ponytail: such a
    line that arrives after the poll that read the newer one is never shown; reading
    `since` a second earlier and dropping lines by content would catch it.
    """
    kept: list[Line] = []
    skip = cursor.seen
    newest, seen = cursor.ns, cursor.seen
    for line in lines:
        if line.ns < cursor.ns:
            continue
        if line.ns == cursor.ns and skip:
            skip -= 1
            continue
        kept.append(line)
        if line.ns > newest:
            newest, seen = line.ns, 1
        elif line.ns == newest:
            seen += 1
    return kept, Cursor(newest, seen)


def parse(data: bytes, tty: bool, complete: bool, cursor: Cursor) -> Batch:
    lines: list[Line] = []
    previous = cursor.ns
    for stream, raw in frames(data, tty, complete):
        line = line_of(stream, raw, previous)
        previous = line.ns
        lines.append(line)
    kept, moved = after(lines, cursor)
    return Batch(kept, moved, cut=not complete)


def read(
    api: Any, container_id: str, tty: bool, tail: int, cursor: Cursor, limit: int = MAX_BYTES
) -> Batch:
    """Blocking. The lines after the cursor, or the last tail lines when it is empty, from
    at most limit bytes of Docker's answer.

    Uses docker-py's private _get, _url and _raise_for_status (docker==7.2.0), since its
    logs() drops which stream a line came from.
    """
    params: dict[str, Any] = {"stdout": 1, "stderr": 1, "timestamps": 1}
    if cursor.ns:
        params["since"] = cursor.since
    else:
        params["tail"] = tail
    response = api._get(
        api._url("/containers/{0}/logs", container_id),
        params=params,
        stream=True,
        timeout=TIMEOUT,
    )
    try:
        api._raise_for_status(response)
        data = bytearray()
        complete = True
        for chunk in response.iter_content(chunk_size=64 * KIB):
            data += chunk
            if len(data) >= limit:
                complete = False
                break
    finally:
        response.close()
    return parse(bytes(data[:limit]), tty, complete, cursor)
