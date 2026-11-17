"""The schedule part of the job and update policy forms: a list of rows, one crontab line each.

A row is a time on chosen days of the week, every few hours on chosen days, a day of the
month at a time, or (advanced) a typed cron expression. The server turns each row into its
line and each stored line back into a row; a line no other kind can show opens as a cron
row, so nothing stored is ever lost or rewritten unasked. The form needs no script: Add and
Remove are submit buttons that send the form back with one row more or less, and CSS shows
each row's fields for its kind (frontend/app.css).

Each row sends one value for every field (hidden ones too), so the lists line up by
position. The day checkboxes are the exception: a box is sent only when ticked, so each
one carries its row's key ("<key>:<day>").
"""

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any

from starlette.datastructures import ImmutableMultiDict

from drydock.jobs import scheduler
from drydock.jobs.scheduler import MAX_SCHEDULES, CronError

REPEATS = {
    "days": "On days of the week",
    "hours": "Every few hours",
    "monthly": "Once a month",
    "cron": "Cron expression (advanced)",
}
# Divisors of 24, so the runs fall at the same times every day.
EVERY_HOURS = (1, 2, 3, 4, 6, 8, 12)
WEEK = ((1, "Mon"), (2, "Tue"), (3, "Wed"), (4, "Thu"), (5, "Fri"), (6, "Sat"), (0, "Sun"))
ALL_DAYS = (0, 1, 2, 3, 4, 5, 6)
# 28 at most: later days are missing from some months, so the job would skip those.
MONTH_DAYS = range(1, 29)
TIME_RE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)(:00)?")
MANUAL = "Only when started by hand"
FIELDS = ("sched_repeat", "sched_time", "sched_every", "sched_minute", "sched_dom", "sched_cron")


@dataclass
class Row:
    repeat: str = "days"
    days: list[int] = dataclass_field(default_factory=lambda: list(ALL_DAYS))
    time: str = "03:00"
    every: str = "6"
    minute: str = "0"
    dom: str = "1"
    cron: str = ""

    @classmethod
    def of(cls, line: str) -> Row:
        """The row that shows a stored crontab line."""
        try:
            minute, hour, dom, month, dow = line.split()
            if not minute.isdigit() or int(minute) > 59 or month != "*":
                raise ValueError(line)
            days = sorted(scheduler.weekdays(dow)) if dow != "*" else list(ALL_DAYS)
            if hour.isdigit() and int(hour) <= 23:
                time = f"{int(hour):02d}:{int(minute):02d}"
                if dom == "*":
                    return cls("days", days, time)
                if dow == "*" and dom.isdigit() and int(dom) in MONTH_DAYS:
                    return cls("monthly", time=time, dom=str(int(dom)))
            elif dom == "*" and hour == "*":
                return cls("hours", days, every="1", minute=str(int(minute)))
            elif dom == "*" and hour.startswith("*/") and hour[2:].isdigit():
                if int(hour[2:]) in EVERY_HOURS:
                    return cls("hours", days, every=str(int(hour[2:])), minute=str(int(minute)))
        except ValueError:  # CronError too
            pass
        return cls("cron", cron=line)

    def line(self) -> str:
        """The row's crontab line. Raises CronError with a message to show."""
        if self.repeat == "cron":
            line = " ".join(self.cron.split())
            if not line:
                raise CronError("Enter a cron expression, or remove the schedule.")
            if len(line) > scheduler.CRON_MAX:
                raise CronError(scheduler.CRON_FIELDS)
            return line
        if self.repeat == "monthly":
            if not (self.dom.isdigit() and int(self.dom) in MONTH_DAYS):
                raise CronError("Choose a day of the month from 1 to 28.")
            hour, minute = self.clock()
            return f"{minute} {hour} {int(self.dom)} * *"
        if self.repeat not in ("days", "hours"):
            raise CronError("Choose how often the schedule repeats.")
        days = sorted(set(self.days))
        if not days:
            raise CronError("Tick at least one day of the week.")
        dow = "*" if len(days) == len(ALL_DAYS) else ",".join(map(str, days))
        if self.repeat == "days":
            hour, minute = self.clock()
            return f"{minute} {hour} * * {dow}"
        if not (self.every.isdigit() and int(self.every) in EVERY_HOURS):
            raise CronError("Choose every 1, 2, 3, 4, 6, 8 or 12 hours.")
        if not (self.minute.isdigit() and int(self.minute) <= 59):
            raise CronError("Enter the minute past the hour, from 0 to 59.")
        every = int(self.every)
        return f"{int(self.minute)} {'*' if every == 1 else f'*/{every}'} * * {dow}"

    def clock(self) -> tuple[int, int]:
        match = TIME_RE.fullmatch(self.time)
        if match is None:
            raise CronError("Enter a time of day, such as 03:00.")
        return int(match[1]), int(match[2])


def rows_of(cron: str | None) -> list[Row]:
    """The rows that show a stored schedule."""
    return [Row.of(line) for line in scheduler.lines(cron or "")]


def typed(cron: str) -> list[Row]:
    """The rows of cron lines from a client that sends no rows: kept as typed. One more than
    MAX_SCHEDULES at most, so a long list is refused, never rendered row by row."""
    return [Row("cron", cron=line) for line in scheduler.lines(cron)[: MAX_SCHEDULES + 1]]


def sent(params: ImmutableMultiDict[str, Any]) -> list[Row] | None:
    """The rows a form or query sent, after its Add or Remove button; None from a client
    that sends no rows (it may send a cron field instead)."""
    if params.get("schedule_rows") != "1":
        return None

    def strings(name: str) -> list[str]:
        return [v[:200] if isinstance(v, str) else "" for v in params.getlist(name)]

    keys = strings("sched_row")[: MAX_SCHEDULES + 1]
    days: dict[str, set[int]] = {}
    for value in strings("sched_day"):
        key, _, day = value.partition(":")
        if len(day) == 1 and day in "0123456":
            days.setdefault(key, set()).add(int(day))
    columns = [strings(name) for name in FIELDS]
    removed = params.get("remove_schedule")
    rows = [
        Row(repeat, sorted(days.get(key, ())), *(value.strip() for value in rest))
        for key, repeat, *rest in zip(keys, *columns, strict=False)
        if key != removed
    ]
    if params.get("add_schedule") and len(rows) < MAX_SCHEDULES:
        rows.append(Row())
    return rows


def changed(params: ImmutableMultiDict[str, Any]) -> bool:
    """Whether the form was sent by a schedule's Add or Remove button, not by Save."""
    return bool(params.get("add_schedule") or params.get("remove_schedule"))


def cron_of(rows: list[Row]) -> str:
    """The stored schedule: one line per row. Call it on rows that passed errors()."""
    return "\n".join(row.line() for row in rows)


def errors(rows: list[Row], tz: str, now: datetime) -> list[str]:
    """Each row's problem, named by its number when there are several."""
    if len(rows) > MAX_SCHEDULES:
        return [scheduler.TOO_MANY]
    found = []
    for number, row in enumerate(rows, 1):
        try:
            scheduler.checked(row.line(), tz, now)
        except CronError as exc:
            found.append(f"Schedule {number}: {exc}" if len(rows) > 1 else str(exc))
    return found


def label(cron: str | None) -> str:
    """A schedule in words for lists and pages: each line described, or shown as cron."""
    lines = scheduler.lines(cron or "")
    if not lines:
        return MANUAL
    return "; ".join(scheduler.describe_line(line) or f"cron {line}" for line in lines)
