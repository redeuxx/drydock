"""Retention: which of a job's archives to delete after a successful backup.

A job keeps its archives by one policy, stored as JSON in jobs.retention:
- last: the newest keep_last archives (the default, keep_last >= 1)
- age: the archives younger than max_age_days
- gfs: the newest archive of each of the newest `daily` days, `weekly` ISO weeks,
  `monthly` months and `yearly` years that hold an archive (one archive may fill several),
  as days, weeks, months and years run in the job's time zone

select_for_deletion is pure. It only ever selects names of drydock's archive form that
carry the job's UUID, so a renamed job (its slug changes) still matches its archives and
nothing of another job, or not made by drydock, is ever selected. The newest archive of the
job always survives, whatever the policy says.
"""

import json
import uuid
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

from drydock.storage.base import StorageError, parse_name

MODES = ("last", "age", "gfs")
DEFAULT_KEEP_LAST = 7
MAX_COUNT = 1000
MAX_AGE_DAYS = 36500
GFS_FIELDS = ("daily", "weekly", "monthly", "yearly")
MODE_FIELDS = {"last": ("keep_last",), "age": ("max_age_days",), "gfs": GFS_FIELDS}
GFS_UNITS = {"daily": "day", "weekly": "week", "monthly": "month", "yearly": "year"}


class PolicyError(ValueError):
    """A retention policy is not valid. The message is safe to show."""


@dataclass(frozen=True)
class Policy:
    mode: str = "last"
    keep_last: int = DEFAULT_KEEP_LAST
    max_age_days: int = 0
    daily: int = 0
    weekly: int = 0
    monthly: int = 0
    yearly: int = 0

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise PolicyError("Choose how long to keep backups.")
        if self.mode == "last" and not 1 <= self.keep_last <= MAX_COUNT:
            raise PolicyError(f"Keep between 1 and {MAX_COUNT} backups.")
        if self.mode == "age" and not 1 <= self.max_age_days <= MAX_AGE_DAYS:
            raise PolicyError(f"Keep backups for 1 to {MAX_AGE_DAYS} days.")
        if self.mode == "gfs":
            counts = [getattr(self, f) for f in GFS_FIELDS]
            if not all(0 <= c <= MAX_COUNT for c in counts):
                raise PolicyError(
                    f"Each count of days, weeks, months or years is 0 to {MAX_COUNT}."
                )
            if not any(counts):
                raise PolicyError("Keep at least one daily, weekly, monthly or yearly backup.")

    def to_dict(self) -> dict[str, Any]:
        """Only the mode's own fields, so the stored JSON and audit diffs stay readable."""
        values = asdict(self)
        return {"mode": self.mode} | {f: values[f] for f in MODE_FIELDS[self.mode]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def describe(self) -> str:
        if self.mode == "last":
            kept = f"The newest {plural(self.keep_last, 'backup')}"
        elif self.mode == "age":
            kept = f"Backups from the last {plural(self.max_age_days, 'day')}"
        else:
            spans = [plural(getattr(self, f), u) for f, u in GFS_UNITS.items() if getattr(self, f)]
            kept = f"The newest backup of each of the last {', '.join(spans)}"
        return f"{kept}. The newest backup always stays."


def plural(count: int, unit: str) -> str:
    return f"{count} {unit}" if count == 1 else f"{count} {unit}s"


DEFAULT_JSON = Policy().to_json()


def from_dict(doc: Any) -> Policy:
    """The policy a stored or submitted document describes. Raises PolicyError."""
    if not isinstance(doc, dict) or doc.get("mode") not in MODES:
        raise PolicyError("Choose how long to keep backups.")
    numbers = {}
    for key, value in doc.items():
        if key == "mode":
            continue
        if key not in Policy.__dataclass_fields__ or type(value) is not int:
            raise PolicyError("The retention policy is not valid.")
        numbers[key] = value
    return Policy(mode=doc["mode"], **numbers)


def parse(text: str | None) -> Policy:
    try:
        doc = json.loads(text or "")
    except ValueError, RecursionError:
        raise PolicyError("The retention policy is not valid.") from None
    return from_dict(doc)


# SELECTION

BUCKETS: dict[str, Callable[[datetime], object]] = {
    "daily": lambda t: t.date(),
    "weekly": lambda t: t.isocalendar()[:2],
    "monthly": lambda t: (t.year, t.month),
    "yearly": lambda t: t.year,
}


def select_for_deletion(
    backups: Iterable[str], policy: Policy, now: datetime, job_uuid: str, tz: tzinfo = UTC
) -> list[str]:
    """The names among backups to delete, oldest first. Names not of drydock's archive form
    or of another job are never selected; the job's newest archive never is either."""
    wanted = uuid.UUID(job_uuid)
    mine: list[tuple[datetime, str]] = []
    for name in set(backups):
        try:
            parts = parse_name(name)
        except StorageError:
            continue
        if parts.job_uuid == wanted:
            mine.append((parts.created_at, name))
    mine.sort(reverse=True)  # newest first; the name breaks ties
    if not mine:
        return []
    keep = {mine[0][1]}
    if policy.mode == "last":
        keep.update(name for _, name in mine[: policy.keep_last])
    elif policy.mode == "age":
        cutoff = now - timedelta(days=policy.max_age_days)
        keep.update(name for created, name in mine if created >= cutoff)
    else:
        for field, bucket in BUCKETS.items():
            count = getattr(policy, field)
            seen: set[object] = set()
            for created, name in mine:
                if len(seen) == count:
                    break
                key = bucket(created.astimezone(tz))
                if key not in seen:
                    seen.add(key)
                    keep.add(name)
    return [name for _, name in reversed(mine) if name not in keep]
