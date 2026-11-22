"""Per-run log files at <data dir>/logs/<run_id>.log, named from the run ID only.

Every line is redacted before it reaches the disk: known secret values (the target
containers' environment values and the job passphrases) are replaced, and control
characters are escaped so a line can never forge another. The UI shows these files, so
nothing secret may be written here in the first place.
"""

import os
import re
import threading
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path

REDACTED = "[redacted]"
MIN_SECRET_LEN = 4  # shorter values (flags, ports) would blank out ordinary words
MAX_PUBLIC = 255  # longer than any container, project or image name in practice
MAX_PUBLIC_PARTS = 1024  # far more than a real run's names hold, see RunLog.add_public
PUBLIC_SPLIT_RE = re.compile(r"[-_./:]")
MAX_LINE = 4000
READ_LIMIT = 256 * 1024  # per poll
CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def cover(text: str, mask: bytearray, secrets: Sequence[str], start: int) -> None:
    """Sets mask to 1 under every occurrence of a secret in text that ends after start,
    overlapping ones included (text[:start] was searched before)."""
    # ponytail: O(len(text) * len(secret)) for a periodic secret ("aaaa...") in a long run
    # of it; extend matches by the secret's period (KMP failure function) if that matters.
    for secret in secrets:
        covered = 0
        pos = text.find(secret, max(0, start - len(secret) + 1))
        while pos != -1:
            end = pos + len(secret)
            low = max(pos, covered)
            mask[low:end] = b"\x01" * (end - low)
            covered = end
            pos = text.find(secret, pos + 1)


def uncovered(text: str, mask: bytearray, end: int, masking: bool) -> tuple[str, bool]:
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
            pieces.append(REDACTED)
        masking = bool(covered)
        pos = stop
    return "".join(pieces), masking


def log_dir(data_dir: Path) -> Path:
    return data_dir / "logs"


def log_path(data_dir: Path, run_id: int) -> Path:
    return log_dir(data_dir) / f"{int(run_id)}.log"


def env_values(env: Iterable[str] | None) -> list[str]:
    """The values of a container's Config.Env ("KEY=value" strings)."""
    return [item.split("=", 1)[1] for item in env or [] if "=" in item]


def public_names(info: dict) -> list[str]:
    """What a container inspect names that drydock shows anyway: the container's name, its
    image and its Compose project and service."""
    config = info.get("Config") or {}
    labels = config.get("Labels") or {}
    found = (
        str(info.get("Name") or "").lstrip("/"),
        config.get("Image"),
        labels.get("com.docker.compose.project"),
        labels.get("com.docker.compose.service"),
    )
    return [value for value in found if isinstance(value, str) and value]


class RunLog:
    """Appends redacted, timestamped lines. Safe to call from any thread."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._secrets: set[str] = set()
        self._public: set[str] = set()
        self._lock = threading.Lock()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def add_secrets(self, values: Iterable[str]) -> None:
        with self._lock:
            self._secrets.update(v for v in values if len(v) >= MIN_SECRET_LEN)

    def add_public(self, values: Iterable[str]) -> None:
        """Names the UI shows anyway (job, host, project, container and image names). An
        environment value that is one of them or a whole part of one (retrak in
        retrak-db-1), like POSTGRES_DB=<project>, is no secret, and masking it would garble
        every line that names the project.

        A restored archive's manifest names them, so a crafted one could list guesses at
        short secrets. Hence a secret is exempt only when it equals a name or a part
        between "-", "_", ".", "/" and ":" (never any substring), a name longer than
        MAX_PUBLIC is ignored, and only the first MAX_PUBLIC_PARTS of them count: later
        ones are masked like any secret, which costs nothing but legibility."""
        with self._lock:
            for value in values:
                if not value or len(value) > MAX_PUBLIC:
                    continue
                for part in (value, *PUBLIC_SPLIT_RE.split(value)):
                    if len(part) >= MIN_SECRET_LEN and len(self._public) < MAX_PUBLIC_PARTS:
                        self._public.add(part)

    def secrets(self) -> list[str]:
        """The registered secrets, longest first, less those that are a public name or a
        whole part of one.

        Hook output (jobs/hooks.OutputLog) searches for every one of them before it cuts
        a long output line, so a secret never straddles two lines.
        """
        with self._lock:
            kept = (s for s in self._secrets if s not in self._public)
            return sorted(kept, key=len, reverse=True)

    def redact(self, text: str) -> str:
        # Masked together, not replaced one by one: replacing "abcdXY" first would leave
        # "zwvu" of an overlapping "XYzwvu" in "abcdXYzwvu".
        mask = bytearray(len(text))
        cover(text, mask, self.secrets(), 0)
        return uncovered(text, mask, len(text), False)[0]

    def __call__(self, message: str) -> None:
        text = CONTROL_RE.sub("?", self.redact(message))[:MAX_LINE]
        stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        line = f"{stamp} {text}\n".encode(errors="replace")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        with self._lock:
            fd = os.open(self.path, flags, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)


def read_log(path: Path, offset: int, limit: int = READ_LIMIT) -> tuple[str, int]:
    """Returns the complete lines after byte offset (at most limit bytes) and the next offset.

    A line still being written is left for the next read. A missing log reads as empty.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return "", offset
    with os.fdopen(fd, "rb") as handle:
        handle.seek(max(0, offset))
        data = handle.read(limit)
    # Lines are capped far below limit, so a full read always holds a newline.
    data = data[: data.rfind(b"\n") + 1]
    return data.decode(errors="replace"), max(0, offset) + len(data)


def read_tail(path: Path, limit: int) -> tuple[str, bool]:
    """The last complete lines of a log (at most limit bytes), and whether earlier lines
    were left out. A missing log reads as empty."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return "", False
    with os.fdopen(fd, "rb") as handle:
        start = max(0, os.fstat(handle.fileno()).st_size - limit)
        handle.seek(start)
        data = handle.read(limit)
    if start:
        data = data[data.find(b"\n") + 1 :]  # drop the partial first line
    return data.decode(errors="replace"), start > 0
