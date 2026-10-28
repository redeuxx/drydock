"""Notifications through Apprise: a message when a job's run ends.

A notification target is one Apprise URL, stored only encrypted (notification_targets
.url_enc) and never decrypted for display: forms and pages show its name and kind, and an
edit replaces the destination only when new values are entered. Like hooks (Decision 2),
the target library is edited by superadmins only, with recent auth; admins attach targets
to jobs. A target is sent from drydock's own container to whatever host it names, so
admins could otherwise aim one at an internal service such as the Docker socket proxy.

URLs are built here, never taken as typed, except for the "url" kind, whose scheme must
be in RAW_SCHEMES (remote chat and push services with fixed APIs). The webhook builder
passes the user's query parameters through as plain parameters, so no Apprise option
(HTTP method, headers, payload fields) can be set from it; webhooks always POST the fixed
JSON message. A URL must be exactly one Apprise service (Apprise.add splits a string on
commas and spaces before another scheme://), and each send uses the single service
instantiated from it.

Only Apprise.instantiate(), add() and notify() are used: no AppriseConfig, no plugin
paths, no attachments, no templates, no persistent store on disk, no HTTP redirects. Each
target is sent as its own task with NOTIFY_TIMEOUT, and its outcome is logged by service
name and status only, since an Apprise result's URL can hold a token; Apprise's own log
lines (recipient addresses, ntfy topics) are silenced. The message names the job, host,
run, status and the start of the run's error as stored on the run row, which is redacted
like the run log; it never carries log lines. A notification that fails is logged and
never changes the run.
"""

import concurrent.futures
import ipaddress
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import apprise
from apprise.common import PersistentStoreMode
from apprise.utils.parse import parse_urls
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from drydock.config import Settings
from drydock.crypto import Crypto, CryptoError
from drydock.models import Host, Job, JobNotification, NotificationTarget, Run, StorageTarget

log = logging.getLogger("drydock.notify")
# Apprise logs recipients, topics and partly masked URLs; drydock logs outcomes itself.
logging.getLogger("apprise").setLevel(logging.CRITICAL)

KINDS = ("webhook", "email", "ntfy", "gotify", "url")
# What the friendly forms build.
BUILT_SCHEMES = frozenset(
    {"json", "jsons", "mailto", "mailtos", "ntfy", "ntfys", "gotify", "gotifys"}
)
# The "url" kind: remote services with fixed APIs. Not json/form/xml (method, header and
# payload overrides), not mailto (local key files), not apprise:// (relays to any scheme),
# nothing local (syslog, desktop notifications).
RAW_SCHEMES = frozenset(
    {
        "discord", "slack", "msteams", "tgram", "pover", "pbul", "gchat",
        "matrix", "matrixs", "mmost", "mmosts", "rocket", "rockets", "signal", "signals",
    }
)  # fmt: skip
MAX_URL = 2048
MAX_ERROR = 500  # characters of a run's error in a message
NOTIFY_TIMEOUT = 10  # seconds per target
WORKERS = 4
SUCCESS_STATUSES = ("done",)
FAILURE_STATUSES = ("failed", "cancelled", "interrupted")
HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
TOPIC_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_.~-]{1,256}")
EMAIL_RE = re.compile(r"[^@\s,;]{1,64}@[A-Za-z0-9.-]{1,253}")
SECURITY = ("ssl", "starttls", "none")
SMTP_PORTS = {"starttls": "587", "ssl": "465", "none": "25"}
NOT_ALLOWED = (
    "This kind of URL is not allowed. Use a webhook, email, ntfy or Gotify target, or the "
    "Apprise URL of a chat service such as discord://, slack://, tgram:// or msteams://."
)
# In memory only, no plugins from anywhere on disk, and no redirects to other hosts.
ASSET = apprise.AppriseAsset(
    plugin_paths=[],
    storage_mode=PersistentStoreMode.MEMORY,
    result_log_disk_size=0,
    http_redirects=False,
)


class NotifyError(ValueError):
    """A notification destination is not valid. The message is safe to show."""


# DESTINATIONS


def netloc(parts: Any, what: str) -> str:
    """host[:port] of a split http(s) URL, the host checked. Raises NotifyError."""
    try:
        port = parts.port
    except ValueError:
        raise NotifyError(f"The {what} has an invalid port.") from None
    host = parts.hostname or ""
    if not HOST_RE.fullmatch(host):
        try:
            host = f"[{ipaddress.IPv6Address(host)}]"
        except ValueError:
            raise NotifyError(f"The {what} has an invalid host name.") from None
    return f"{host}:{port}" if port else host


def server(url: str, what: str, *, path: bool) -> tuple[bool, str]:
    """(secure, host[:port][/path]) of an http(s) server URL. Raises NotifyError."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise NotifyError(f"Enter the {what} as an http:// or https:// URL.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise NotifyError(f"The {what} must not hold a user name, a query or a fragment.")
    prefix = parts.path.rstrip("/")
    if prefix and not path:
        raise NotifyError(f"The {what} must not have a path.")
    return parts.scheme == "https", netloc(parts, what) + quote(prefix, safe="/")


def webhook_url(url: str) -> str:
    """Apprise's JSON webhook: an HTTP POST of title, message and type to url. The URL's
    own query parameters are sent as they are ("-name=value" for Apprise)."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.fragment:
        raise NotifyError("Enter the webhook as an http:// or https:// URL.")
    login = ""
    if parts.username:
        login = quote(unquote(parts.username), safe="")
        if parts.password:
            login += ":" + quote(unquote(parts.password), safe="")
        login += "@"
    params = [(f"-{k}", v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    query = f"?{urlencode(params, quote_via=quote)}" if params else ""
    scheme = "jsons" if parts.scheme == "https" else "json"
    path = quote(parts.path or "/", safe="/%")
    return check_url(f"{scheme}://{login}{netloc(parts, 'webhook')}{path}{query}", BUILT_SCHEMES)


def email_url(
    host: str, port: str, security: str, user: str, password: str, sender: str, to: str
) -> str:
    if not HOST_RE.fullmatch(host):
        raise NotifyError("Enter the SMTP server's host name.")
    if security not in SECURITY:
        raise NotifyError("Choose how to secure the SMTP connection.")
    port = port or SMTP_PORTS[security]
    if not (port.isascii() and port.isdigit() and 1 <= int(port) <= 65535):
        raise NotifyError("Enter the SMTP port, for example 587.")
    recipients = [a.strip() for a in to.split(",") if a.strip()]
    if not EMAIL_RE.fullmatch(sender) or not recipients:
        raise NotifyError("Enter the sender and at least one recipient address.")
    if not all(EMAIL_RE.fullmatch(a) for a in recipients) or len(recipients) > 20:
        raise NotifyError("Enter up to 20 recipient addresses, separated by commas.")
    query: dict[str, str] = {"from": sender, "to": ",".join(recipients)}
    if user:
        query |= {"user": user, "pass": password}
    if security != "none":
        query["mode"] = security
    scheme = "mailto" if security == "none" else "mailtos"
    url = f"{scheme}://{host}:{int(port)}?{urlencode(query, quote_via=quote)}"
    return check_url(url, BUILT_SCHEMES)


def ntfy_url(base: str, topic: str, token: str) -> str:
    secure, where = server(base or "https://ntfy.sh", "ntfy server", path=False)
    if not TOPIC_RE.fullmatch(topic):
        raise NotifyError("The ntfy topic must be 1 to 64 letters, digits, '_' or '-'.")
    if token and not TOKEN_RE.fullmatch(token):
        raise NotifyError("The ntfy access token holds characters a token never has.")
    query = f"?{urlencode({'token': token})}" if token else ""
    return check_url(f"{'ntfys' if secure else 'ntfy'}://{where}/{topic}{query}", BUILT_SCHEMES)


def gotify_url(base: str, token: str) -> str:
    secure, where = server(base, "Gotify server", path=True)
    if not TOKEN_RE.fullmatch(token):
        raise NotifyError("Enter the Gotify application token.")
    return check_url(f"{'gotifys' if secure else 'gotify'}://{where}/{token}", BUILT_SCHEMES)


def check_url(url: str, schemes: frozenset[str] = RAW_SCHEMES) -> str:
    """One Apprise service URL with a scheme in schemes. Raises NotifyError."""
    url = url.strip()
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if len(url) > MAX_URL or scheme not in schemes:
        raise NotifyError(NOT_ALLOWED)
    if re.search(r"\s", url) or len(parse_urls(url)) != 1:
        raise NotifyError("Enter a single URL, without spaces.")
    if service(url) is None:
        raise NotifyError("Apprise does not understand this URL; check it against its docs.")
    return url


def service(url: str) -> Any:
    """The one Apprise service a URL describes, or None."""
    return apprise.Apprise.instantiate(url, asset=ASSET)


# SENDING


@dataclass(frozen=True)
class Outcome:
    target: str
    ok: bool
    detail: str  # service names and statuses, never the URL


def send(name: str, url: str, title: str, body: str, *, failure: bool) -> Outcome:
    """Sends one message to one target; never raises."""
    try:
        plugin = service(url)
        notifier = apprise.Apprise(asset=ASSET)
        if plugin is None or not notifier.add(plugin):
            return Outcome(name, False, "the URL is not valid")
        result = notifier.notify(
            body=body,
            title=title,
            notify_type=apprise.NotifyType.FAILURE if failure else apprise.NotifyType.SUCCESS,
            body_format=apprise.NotifyFormat.TEXT,
            interpret_escapes=False,
            timeout=NOTIFY_TIMEOUT,
        )
        statuses = [f"{r.name}: {status_name(r.status)}" for r in result.results]
        return Outcome(name, bool(result), ", ".join(statuses) or "nothing was sent")
    except Exception as exc:
        # The type only: an exception's text could carry the URL.
        log.error("Notification target %s failed: %s", name, type(exc).__name__)
        return Outcome(name, False, f"unexpected error ({type(exc).__name__})")


def status_name(status: object) -> str:
    """An Apprise result status as a word ("success", "failure", "timeout")."""
    return str(getattr(status, "name", status)).lower()


def message(run: Run, job: Job, host: Host | None, base_url: str) -> tuple[str, str]:
    outcome = {
        "done": "succeeded",
        "cancelled": "was cancelled",
        "interrupted": "was interrupted",
    }.get(run.status, run.status)
    title = f"drydock: backup {job.name} {outcome}"
    lines = [
        f"Run #{run.id} of job {job.name} on host {host.name if host else '?'} {outcome}.",
    ]
    if run.archive_name and run.status == "done":
        lines.append(f"Archive: {run.archive_name}")
    if run.error:
        error = run.error if len(run.error) <= MAX_ERROR else run.error[:MAX_ERROR] + "..."
        lines.append(f"Error: {error}")
    lines.append(f"{base_url}/runs/{run.id}")
    return title, "\n".join(lines)


class Notifier:
    def __init__(self, settings: Settings, sessions: sessionmaker[Session], crypto: Crypto) -> None:
        self._settings = settings
        self._sessions = sessions
        self._crypto = crypto
        self._executor = ThreadPoolExecutor(WORKERS, thread_name_prefix="drydock-notify")
        self._pending: set[concurrent.futures.Future[None]] = set()
        self._lock = threading.Lock()
        self._closed = False

    def run_ended(self, run_id: int) -> None:
        """Queues the notifications for a run whose end was just committed. Thread-safe."""
        self._submit(self._notify_run, run_id)

    def _submit(self, fn: Any, *args: Any) -> None:
        with self._lock:
            if self._closed:
                return
            future = self._executor.submit(fn, *args)
            self._pending.add(future)
        future.add_done_callback(self._done)

    def _done(self, future: concurrent.futures.Future[None]) -> None:
        with self._lock:
            self._pending.discard(future)

    def close(self) -> None:
        """Gives queued notifications NOTIFY_TIMEOUT to go out, then drops the rest."""
        with self._lock:
            self._closed = True
            pending = set(self._pending)
        concurrent.futures.wait(pending, timeout=NOTIFY_TIMEOUT)
        with self._lock:  # the loads that finished meanwhile queued their sends
            pending = set(self._pending)
        concurrent.futures.wait(pending, timeout=NOTIFY_TIMEOUT)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def test(self, name: str, url_enc: str) -> Outcome:
        """Sends a test message to one target (blocking). Takes the stored values, so the
        caller can end its transaction first."""
        try:
            url = self._crypto.decrypt(url_enc)
        except CryptoError:
            return Outcome(name, False, "the URL cannot be decrypted with the secret keys")
        body = f"A test message from drydock at {self._settings.base_url}."
        return send(name, url, "drydock: test", body, failure=False)

    def _notify_run(self, run_id: int) -> None:
        """Loads what to send, then sends each target as its own task, so a slow target
        never holds up another."""
        try:
            for target, url, title, body, failure in self._load(run_id):
                with self._lock:  # close() may have run while this loaded
                    closing = self._closed
                if closing:
                    self._send_one(run_id, target, url, title, body, failure)
                else:
                    self._submit(self._send_one, run_id, target, url, title, body, failure)
        except Exception:
            log.exception("Run %d: notifications failed", run_id)

    def storage_reconnect(self, storage_id: int) -> None:
        """Tells the failure targets of the jobs using a Google Drive target that Google
        refused drydock's access (storage.gdrive_oauth.mark_reconnect). Thread-safe."""
        self._submit(self._notify_reconnect, storage_id)

    def _notify_reconnect(self, storage_id: int) -> None:
        try:
            with self._sessions() as db:
                storage = db.get(StorageTarget, storage_id)
                if storage is None:
                    return
                rows: list[Any] = list(
                    db.scalars(
                        select(NotificationTarget)
                        .join(JobNotification, JobNotification.target_id == NotificationTarget.id)
                        .join(Job, Job.id == JobNotification.job_id)
                        .where(
                            Job.storage_target_id == storage_id,
                            JobNotification.on_failure,
                            NotificationTarget.enabled,
                        )
                        .distinct()
                        .order_by(NotificationTarget.name)
                    )
                )
                name = storage.name
            title = f"drydock: storage {name} needs reconnecting"
            body = (
                f"Google refused drydock's access to the Google Drive storage {name}, so "
                "backups to it fail. Connect it again on its storage page.\n"
                f"{self._settings.base_url}/storage/{storage_id}"
            )
            for target in rows:
                try:
                    url = self._crypto.decrypt(target.url_enc)
                except CryptoError:
                    log.warning("Notification %s cannot be decrypted", target.name)
                    continue
                with self._lock:  # close() may have run while this loaded
                    closing = self._closed
                args = (storage_id, target.name, url, title, body)
                if closing:
                    self._send_reconnect(*args)
                else:
                    self._submit(self._send_reconnect, *args)
        except Exception:
            log.exception("Storage %d: the reconnect notification failed", storage_id)

    def _send_reconnect(
        self, storage_id: int, target: str, url: str, title: str, body: str
    ) -> None:
        outcome = send(target, url, title, body, failure=True)
        level = logging.INFO if outcome.ok else logging.WARNING
        log.log(level, "Storage %d: notification %s: %s", storage_id, target, outcome.detail)

    def _send_one(
        self, run_id: int, target: str, url: str, title: str, body: str, failure: bool
    ) -> None:
        outcome = send(target, url, title, body, failure=failure)
        level = logging.INFO if outcome.ok else logging.WARNING
        log.log(level, "Run %d: notification %s: %s", run_id, target, outcome.detail)

    def _load(self, run_id: int) -> list[tuple[str, str, str, str, bool]]:
        """(target name, url, title, body, failure) for each target to tell about the run."""
        with self._sessions() as db:
            run = db.get(Run, run_id)
            if run is None or run.kind != "backup" or run.job_id is None:
                return []
            failure = run.status in FAILURE_STATUSES
            if not failure and run.status not in SUCCESS_STATUSES:
                return []
            job = db.get(Job, run.job_id)
            if job is None:
                return []
            flag = JobNotification.on_failure if failure else JobNotification.on_success
            rows: list[Any] = list(
                db.scalars(
                    select(NotificationTarget)
                    .join(JobNotification, JobNotification.target_id == NotificationTarget.id)
                    .where(JobNotification.job_id == job.id, flag, NotificationTarget.enabled)
                    .order_by(NotificationTarget.name)
                )
            )
            title, body = message(run, job, db.get(Host, job.host_id), self._settings.base_url)
        sends = []
        for target in rows:
            try:
                url = self._crypto.decrypt(target.url_enc)
            except CryptoError:
                log.warning("Run %d: notification %s cannot be decrypted", run_id, target.name)
                continue
            sends.append((target.name, url, title, body, failure))
        return sends
