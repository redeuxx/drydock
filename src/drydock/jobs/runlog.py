"""Per-run log files at <data dir>/logs/<run_id>.log, named from the run ID only.

Every line is redacted before it reaches the disk: known secret values (the target
containers' environment values and the job passphrases) are replaced, and control
characters are escaped so a line can never forge another. The UI shows these files, so
nothing secret may be written here in the first place.
"""

import os
import re
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

REDACTED = "[redacted]"
MIN_SECRET_LEN = 4  # shorter values (flags, ports) would blank out ordinary words
MAX_LINE = 4000
READ_LIMIT = 256 * 1024  # per poll
CONTROL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def log_dir(data_dir: Path) -> Path:
    return data_dir / "logs"


def log_path(data_dir: Path, run_id: int) -> Path:
    return log_dir(data_dir) / f"{int(run_id)}.log"


def env_values(env: Iterable[str] | None) -> list[str]:
    """The values of a container's Config.Env ("KEY=value" strings)."""
    return [item.split("=", 1)[1] for item in env or [] if "=" in item]


class RunLog:
    """Appends redacted, timestamped lines. Safe to call from any thread."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._secrets: set[str] = set()
        self._lock = threading.Lock()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def add_secrets(self, values: Iterable[str]) -> None:
        with self._lock:
            self._secrets.update(v for v in values if len(v) >= MIN_SECRET_LEN)

    def secrets(self) -> list[str]:
        """The registered secrets, longest first (the order redact replaces them in).

        Hook output (jobs/hooks.OutputLog) searches for every one of them before it cuts
        a long output line, so a secret never straddles two lines.
        """
        with self._lock:
            return sorted(self._secrets, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for secret in self.secrets():
            text = text.replace(secret, REDACTED)
        return text

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
