"""Jinja2 rendering and redirects. Autoescape is always on; StrictUndefined catches typos."""

import logging
import re
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader, StrictUndefined
from starlette.responses import HTMLResponse, RedirectResponse, Response

from drydock import feed
from drydock.models import User, utcnow
from drydock.security.rbac import Role

# Only hx-csp may register; an empty value would allow any extension. Indicator CSS ships
# in app.css instead of being injected as a constructed stylesheet.
logger = logging.getLogger("drydock.templating")

HTMX_CONFIG = {"extensions": "hx-csp", "includeIndicatorCSS": False}

env = Environment(
    loader=PackageLoader("drydock", "templates"),
    autoescape=True,
    undefined=StrictUndefined,
)


def filesize(value: int | None) -> str:
    if value is None:
        return ""
    if value < 1024:
        return f"{value} bytes"
    size = value / 1024
    for unit in ("KiB", "MiB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


DISPLAY_ZONE: tzinfo = UTC  # drydock's TZ, set by create_app (set_zone)


def set_zone(name: str) -> None:
    """Pages show times in this zone (the TZ setting), with UTC beside them."""
    global DISPLAY_ZONE
    DISPLAY_ZONE = ZoneInfo(name)


def stamp(value: datetime | None, seconds: bool = True) -> str:
    """A time in drydock's zone, with UTC in parentheses unless that is the zone:
    "2026-11-01 10:30:18 CST (16:30 UTC)"."""
    if value is None:
        return ""
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    local = aware.astimezone(DISPLAY_ZONE)
    shown = local.strftime("%Y-%m-%d %H:%M:%S %Z" if seconds else "%Y-%m-%d %H:%M %Z")
    if not local.utcoffset():
        return shown
    return f"{shown} ({aware.astimezone(UTC):%H:%M} UTC)"


LOG_STAMP_RE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ", re.M)


def logtimes(text: str) -> str:
    """A run log with each line's UTC stamp (runlog.RunLog) in drydock's zone. Only the
    zone is named, not UTC as well: that would be on every line."""

    def local(found: re.Match[str]) -> str:
        when = datetime.strptime(found.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        return when.astimezone(DISPLAY_ZONE).strftime("%Y-%m-%d %H:%M:%S %Z ")

    return LOG_STAMP_RE.sub(local, text)


def clock(value: datetime | None) -> str:
    """A log line's time in drydock's zone, to the millisecond: "2026-11-01 10:30:18.042"."""
    if value is None:
        return ""
    return value.astimezone(DISPLAY_ZONE).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def ago(value: datetime | None) -> str:
    """A past time in words: "just now", "5 minutes ago", "3 days ago"."""
    if value is None:
        return ""
    seconds = int((utcnow() - value).total_seconds())
    if seconds < 60:
        return "just now"
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'' if count == 1 else 's'} ago"
    return "just now"


def duration(value: timedelta | None) -> str:
    """How long something took: "45 s", "4 min 12 s", "2 h 5 min"."""
    if value is None:
        return ""
    hours, rest = divmod(max(int(value.total_seconds()), 0), 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours} h {minutes} min"
    return f"{minutes} min {seconds} s" if minutes else f"{seconds} s"


env.globals.update(Role=Role, htmx_config=HTMX_CONFIG)
env.filters["filesize"] = filesize
env.filters["ago"] = ago
env.filters["stamp"] = stamp
env.filters["logtimes"] = logtimes
env.filters["duration"] = duration
env.filters["clock"] = clock
# A query string from a dict whose values may be lists (repeated keys); Jinja's urlencode
# writes a list as one value.
env.filters["query"] = lambda values: urlencode(values, doseq=True)
templates = Jinja2Templates(env=env)


def bell(request: Request, user_id: int) -> dict[str, Any] | None:
    """The bell in base.html. It reads through the request's own session when there is one
    (another would wait for its write lock) and writes nothing. Any failure, such as a
    session an error left in a failed transaction, only hides the bell."""
    db = getattr(request.state, "db", None)
    try:
        if db is not None:
            started = not db.in_transaction()
            try:
                user = db.get(User, user_id)
                return feed.summary(db, user) if user is not None else None
            finally:
                if started:  # its own read: never keep the write lock past the page.
                    db.commit()  # it wrote nothing; commit keeps the page's objects
        with request.app.state.sessionmaker() as own:
            user = own.get(User, user_id)
            return feed.summary(own, user) if user is not None else None
    except Exception:
        logger.debug("The bell could not be read", exc_info=True)
        return None


def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    context.setdefault("auth", None)
    context["csp_nonce"] = request.state.csp_nonce
    auth = context["auth"]
    # htmx swaps only #main, so a partial answer never shows the header's bell.
    if auth is not None and "feed" not in context and not is_htmx(request):
        context["feed"] = bell(request, auth.user.id)
    context.setdefault("feed", None)
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def see_other(request: Request, url: str) -> Response:
    """Redirects after a successful POST. url must be a server-chosen local path.

    htmx requests get HX-Redirect instead of a 303: fetch would follow a 303 silently and
    swap the next page into #main, while HX-Redirect makes the browser navigate to it.
    """
    if is_htmx(request):
        return Response(status_code=204, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)
