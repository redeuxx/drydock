"""Notifications: destination URLs and the scheme allowlists, the /notifications routes
(superadmin only; URLs encrypted at rest, never shown or echoed back), attaching targets
to jobs, and the messages runs send to a local HTTP sink."""

import json
import logging
import socket
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import anyio
import pytest
from apprise.utils.parse import parse_urls

from drydock import notify
from drydock.config import Settings
from drydock.db import make_engine
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.jobs.dispatcher import Dispatcher, DispatchError
from drydock.jobs.runlog import RunLog
from drydock.notify import Notifier, NotifyError, check_url
from tests.conftest import PASSWORD, Browser, add_user, running
from tests.docker_support import wait_until
from tests.test_jobs import add_host, add_job, add_storage, fake_docker, start_run  # noqa: F401
from tests.test_restore_schema import alembic_to
from tests.test_routes import FakeDocker
from tests.test_stacks_schema import add_job as add_job_row
from tests.test_stacks_schema import add_parents, table_sql, version

pytestmark = pytest.mark.anyio

SENTINEL = "SENTINEL-7f3c9a1e5b"


@pytest.fixture
def sink() -> Iterator[SimpleNamespace]:
    """A local HTTP server that records every request: (method, path, body, headers)."""
    received: list[tuple[str, str, bytes, dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def handle_any(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            received.append((self.command, self.path, body, dict(self.headers)))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        do_POST = do_PUT = do_DELETE = do_GET = handle_any

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield SimpleNamespace(url=f"http://127.0.0.1:{port}", port=port, received=received)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def silent() -> Iterator[int]:
    """A port that accepts connections and never answers."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()


# DESTINATIONS


def test_friendly_forms_build_apprise_urls() -> None:
    # The webhook's own query is passed through as plain parameters, never as options.
    assert notify.webhook_url("https://hooks.example.com/a/b?x=1&method=DELETE") == (
        "jsons://hooks.example.com/a/b?-x=1&-method=DELETE"
    )
    assert notify.webhook_url("http://u:p%40ss@10.0.0.5:8080/hook") == (
        "json://u:p%40ss@10.0.0.5:8080/hook"
    )
    email = notify.email_url(
        "smtp.example.com", "587", "starttls", "me", "p@ss w&rd", "me@x.org", "a@x.org, b@y.org"
    )
    assert email.startswith("mailtos://smtp.example.com:587?") and "mode=starttls" in email
    assert "p%40ss%20w%26rd" in email  # the password survives as one value
    # No port: the usual one for the security chosen.
    assert notify.email_url("mx", "", "ssl", "", "", "me@x.org", "you@x.org").startswith(
        "mailtos://mx:465?"
    )
    assert notify.email_url("mx", "", "none", "", "", "me@x.org", "you@x.org").startswith(
        "mailto://mx:25?"
    )
    assert notify.ntfy_url("", "backups", "tk_abc") == "ntfys://ntfy.sh/backups?token=tk_abc"
    assert notify.ntfy_url("http://10.0.0.5:8080", "b", "") == "ntfy://10.0.0.5:8080/b"
    assert notify.gotify_url("https://g.example.com/sub/", "Tok3n") == (
        "gotifys://g.example.com/sub/Tok3n"
    )


def test_smtp_settings_reach_apprise_as_entered() -> None:
    url = notify.email_url(
        "smtp.example.com", "465", "ssl", "me@example.com", "p@ss,w", "me@example.com", "a@x.org"
    )
    email = notify.service(url)
    assert (email.smtp_host, email.port, email.secure_mode) == ("smtp.example.com", 465, "ssl")
    assert (email.user, email.password) == ("me@example.com", "p@ss,w")
    assert email.from_addr[1] == "me@example.com" and email.targets == [(False, "a@x.org")]


@pytest.mark.parametrize(
    "build",
    [
        lambda: notify.webhook_url("ftp://example.com/x"),
        lambda: notify.webhook_url("example.com/x"),
        lambda: notify.webhook_url("http://bad_host/x"),
        lambda: notify.email_url("smtp.example.com", "0", "ssl", "", "", "a@b.c", "d@e.f"),
        lambda: notify.email_url("bad host", "25", "ssl", "", "", "a@b.c", "d@e.f"),
        lambda: notify.email_url("mx", "25", "tls13", "", "", "a@b.c", "d@e.f"),
        lambda: notify.email_url("mx", "25", "ssl", "", "", "not an address", "d@e.f"),
        lambda: notify.email_url("mx", "25", "ssl", "", "", "a@b.c", ""),
        lambda: notify.ntfy_url("", "no spaces", ""),
        lambda: notify.ntfy_url("https://user:pw@ntfy.sh", "t", ""),
        lambda: notify.ntfy_url("https://ntfy.sh?x=1", "t", ""),
        lambda: notify.ntfy_url("https://ntfy.example.com/sub", "t", ""),  # a path: topics
        lambda: notify.gotify_url("https://g.example.com", "bad/token"),
        lambda: notify.gotify_url("javascript:alert(1)", "t"),
    ],
)
def test_invalid_friendly_forms_are_refused(build) -> None:
    with pytest.raises(NotifyError):
        build()


@pytest.mark.parametrize(
    "url",
    [
        "syslog://",
        "SYSLOG://",
        "windows://",
        "dbus://",
        "file:///etc/passwd",
        "http://example.com/x",
        "nonsense://x",
        "no scheme at all",
        # Kinds with a form of their own, or with method, header or payload overrides.
        "json://example.com/x?method=DELETE",
        "form://example.com/x",
        "xml://example.com/x",
        "mailto://user:pw@example.com",
        "apprises://apprise.example.com/key",
        "ntfy://ntfy.sh/topic",
        # More than one service in one URL: Apprise would split these.
        "discord://1234/abcd,syslog://",
        "discord://1234/abcd syslog://",
        "discord://1234/abcd\tsyslog://",
        "discord://1234/abcd\nsyslog://",
        "discord://" + "a" * 2050,
        "",
    ],
)
def test_disallowed_urls_are_refused(url: str) -> None:
    with pytest.raises(NotifyError):
        check_url(url)


def test_allowed_raw_urls_pass() -> None:
    for url in ("discord://1234/abcd", "slack://T1/B1/C1", "DISCORD://1234/abcd"):
        assert check_url(url) == url


def test_a_webhook_is_one_service_whatever_its_path_holds() -> None:
    url = notify.webhook_url("http://example.com/x,syslog://y z")
    assert len(parse_urls(url)) == 1
    assert type(notify.service(url)).__name__ == "NotifyJSON"


# ROUTES


def form(**fields: str) -> dict[str, str]:
    return {"name": "ops", "kind": "webhook", "enabled": "1"} | fields


async def new_target(browser: Browser, **fields: str) -> int:
    response = await browser.post("/notifications", form(**fields))
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


async def test_urls_are_encrypted_and_never_shown(
    admin: Browser, sink: SimpleNamespace, caplog
) -> None:
    caplog.set_level(logging.INFO)  # drydock's level; urllib3 logs request paths at DEBUG
    hook = f"{sink.url}/hook/{SENTINEL}?key={SENTINEL}"
    target_id = await new_target(admin, webhook_url=hook)
    stored = admin.sql("SELECT url_enc FROM notification_targets")[0][0]
    assert SENTINEL not in stored
    assert admin.app.state.crypto.decrypt(stored) == (
        f"json://127.0.0.1:{sink.port}/hook/{SENTINEL}?-key={SENTINEL}"
    )

    # Saving without destination values keeps the stored one.
    response = await admin.post(f"/notifications/{target_id}", form(name="ops-2"))
    assert response.status_code == 303, response.text
    assert admin.sql("SELECT url_enc FROM notification_targets")[0][0] == stored
    # A new kind needs a new destination.
    response = await admin.post(f"/notifications/{target_id}", form(name="ops-2", kind="ntfy"))
    assert response.status_code == 422 and "Enter the new destination" in response.text

    # The test button sends through the stored URL, as a POST with the query passed on.
    response = await admin.post(f"/notifications/{target_id}/test")
    assert response.status_code == 200 and "Sent (JSON: success)" in response.text
    method, path, body, _ = sink.received[-1]
    assert (method, path) == ("POST", f"/hook/{SENTINEL}?key={SENTINEL}")
    assert json.loads(body)["title"] == "drydock: test"

    # A target nobody listens at: its URL is not logged either.
    unused = admin.app.state.crypto.encrypt(f"json://127.0.0.1:9/{SENTINEL}")
    admin.sql("UPDATE notification_targets SET url_enc = ?", (unused,))
    response = await admin.post(f"/notifications/{target_id}/test")
    assert response.status_code == 200 and "Test failed: JSON: failure" in response.text

    assert (await admin.post(f"/notifications/{target_id}/delete")).status_code == 303
    for path in ("/notifications", "/audit"):
        page = await admin.get(path)
        assert page.status_code == 200 and SENTINEL not in page.text, path
    assert all(SENTINEL not in d for (d,) in admin.sql("SELECT details FROM audit_events"))
    assert SENTINEL not in caplog.text


SECRETS = {
    "webhook": {"webhook_url": f"ftp://{SENTINEL}.example.com/x"},
    "email": {
        "smtp_host": "smtp.example.com",
        "smtp_user": SENTINEL,
        "smtp_password": SENTINEL,
        "smtp_from": "not an address",
        "smtp_to": "a@x.org",
    },
    "ntfy": {"ntfy_server": f"https://u:{SENTINEL}@ntfy.sh", "ntfy_topic": "t"},
    "gotify": {"gotify_server": f"https://g.example.com?k={SENTINEL}", "gotify_token": SENTINEL},
    "url": {"raw_url": f"syslog://{SENTINEL}"},
}


@pytest.mark.parametrize("kind", SECRETS)
async def test_refused_destinations_are_never_echoed(admin: Browser, kind: str) -> None:
    target_id = await new_target(admin, name="kept", kind="ntfy", ntfy_topic="kept")
    fields = {"kind": kind} | SECRETS[kind]
    for path in ("/notifications", f"/notifications/{target_id}"):
        response = await admin.post(path, form(name=f"bad-{kind}", **fields))
        assert response.status_code == 422, (path, response.text)
        assert SENTINEL not in response.text, path


async def test_a_partial_destination_is_refused_not_ignored(admin: Browser) -> None:
    target_id = await new_target(
        admin,
        kind="email",
        smtp_host="smtp.example.com",
        smtp_security="starttls",
        smtp_from="me@example.com",
        smtp_to="you@example.com",
    )
    stored = admin.sql("SELECT url_enc FROM notification_targets")[0][0]
    # Only a new password: the rest of the destination is required again.
    response = await admin.post(
        f"/notifications/{target_id}",
        form(kind="email", smtp_security="starttls", smtp_password="new"),
    )
    assert response.status_code == 422
    assert admin.sql("SELECT url_enc FROM notification_targets")[0][0] == stored


async def test_friendly_kinds_through_the_form(admin: Browser) -> None:
    for fields in (
        {
            "kind": "email",
            "smtp_host": "smtp.example.com",
            "smtp_security": "ssl",
            "smtp_port": "465",
            "smtp_user": "me",
            "smtp_password": SENTINEL,
            "smtp_from": "me@example.com",
            "smtp_to": "you@example.com",
        },
        {"kind": "ntfy", "ntfy_topic": "backups", "ntfy_token": SENTINEL},
        {"kind": "gotify", "gotify_server": "https://g.example.com", "gotify_token": SENTINEL},
        {"kind": "url", "raw_url": f"discord://1234/{SENTINEL}"},
    ):
        await new_target(admin, name=fields["kind"], **fields)
    rows = admin.sql("SELECT kind, url_enc FROM notification_targets ORDER BY id")
    assert [kind for kind, _ in rows] == ["email", "ntfy", "gotify", "url"]
    for _, stored in rows:
        assert SENTINEL not in stored and SENTINEL in admin.app.state.crypto.decrypt(stored)


async def test_targets_are_edited_by_superadmins_with_recent_auth(admin: Browser) -> None:
    target_id = await new_target(admin, kind="ntfy", ntfy_topic="t")
    await add_user(admin, "plain-admin", "admin")
    await admin.login("plain-admin")
    assert (await admin.get("/notifications")).status_code == 200  # admins see the list
    page = await admin.get(f"/notifications/{target_id}")
    assert page.status_code == 200 and "Send a test message" not in page.text
    for path, data in (
        ("/notifications", form(name="x", kind="ntfy", ntfy_topic="t")),
        (f"/notifications/{target_id}", form(name="x", kind="ntfy")),
        (f"/notifications/{target_id}/test", {}),
        (f"/notifications/{target_id}/delete", {}),
    ):
        assert (await admin.post(path, data)).status_code == 403, path
    assert (await admin.get("/notifications/new")).status_code == 403
    await admin.login("admin")
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    response = await admin.post(f"/notifications/{target_id}/delete")
    assert response.status_code == 403 and "Re-enter your password" in response.text
    assert (await admin.post("/reauth", {"password": PASSWORD, "next": "/"})).status_code == 303
    assert (await admin.post(f"/notifications/{target_id}/delete")).status_code == 303


async def test_the_test_send_holds_no_database_lock(admin: Browser, monkeypatch) -> None:
    target_id = await new_target(admin, kind="ntfy", ntfy_topic="t")
    seen: list[bool] = []

    def send(self, name: str, url_enc: str) -> notify.Outcome:
        with closing(sqlite3.connect(admin.settings.data_dir / "drydock.db", timeout=0.5)) as c:
            c.execute("BEGIN IMMEDIATE")  # raises "database is locked" if the route holds it
            c.rollback()
        seen.append(True)
        return notify.Outcome(name, True, "ntfy: success")

    monkeypatch.setattr(Notifier, "test", send)
    response = await admin.post(f"/notifications/{target_id}/test")
    assert response.status_code == 200 and seen == [True]


# JOBS AND RUNS


async def attached_job(browser: Browser, url: str, **attach: str) -> tuple[int, int]:
    target_id = await new_target(browser, webhook_url=url)
    fields = {"notifications": "1"} | {k: str(target_id) for k in attach}
    return await add_job(browser, "web backup", **fields), target_id


def job_form(browser: Browser) -> dict[str, str]:
    return {
        "name": "web backup",
        "host_id": str(browser.sql("SELECT host_id FROM jobs")[0][0]),
        "target": "web",
        "storage_target_id": str(browser.sql("SELECT storage_target_id FROM jobs")[0][0]),
        "scope": "config",
        "encrypted": "1",
        "enabled": "1",
    }


async def test_attaching_targets_to_jobs(admin: Browser, sink: SimpleNamespace) -> None:
    job_id, target_id = await attached_job(admin, f"{sink.url}/x", notify_failure="1")
    page = await admin.get(f"/jobs/{job_id}")
    assert "ops (failure)" in page.text
    box = f'name="notify_failure" value="{target_id}" aria-label="Notify ops on failure" checked'
    assert box in page.text
    base = job_form(admin)
    # A client that sends no notification fields keeps them.
    assert (await admin.post(f"/jobs/{job_id}", base)).status_code == 303
    assert admin.sql("SELECT on_success, on_failure FROM job_notifications") == [(0, 1)]
    both = base | {
        "notifications": "1",
        "notify_success": str(target_id),
        "notify_failure": str(target_id),
    }
    assert (await admin.post(f"/jobs/{job_id}", both)).status_code == 303
    assert admin.sql("SELECT on_success, on_failure FROM job_notifications") == [(1, 1)]
    assert (await admin.post(f"/jobs/{job_id}", base | {"notifications": "1"})).status_code == 303
    assert admin.sql("SELECT COUNT(*) FROM job_notifications") == [(0,)]
    diff = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'job.update' ORDER BY id DESC LIMIT 1"
    )[0][0]
    assert json.loads(diff)["notifications"] == {"from": ["ops (success, failure)"], "to": []}
    for bad, message in (("999", "no longer exists"), ("x", "from the list")):
        response = await admin.post(
            f"/jobs/{job_id}", base | {"notifications": "1", "notify_failure": bad}
        )
        assert response.status_code == 422 and message in response.text, bad
    # Deleting the target, or the job, detaches it.
    assert (await admin.post(f"/jobs/{job_id}", both)).status_code == 303
    assert (await admin.post(f"/notifications/{target_id}/delete")).status_code == 303
    assert admin.sql("SELECT COUNT(*) FROM job_notifications") == [(0,)]
    other = await new_target(admin, name="other", kind="ntfy", ntfy_topic="t")
    assert (
        await admin.post(
            f"/jobs/{job_id}", base | {"notifications": "1", "notify_failure": str(other)}
        )
    ).status_code == 303
    assert (await admin.post(f"/jobs/{job_id}/delete")).status_code == 303
    assert admin.sql("SELECT COUNT(*) FROM job_notifications") == [(0,)]


def failing_backup(self, plan, handle, targets, cancel, run_log) -> None:
    run_log.add_secrets([SENTINEL])  # as _resolve does with a container's env values
    raise DispatchError(f"The capture failed near {SENTINEL}.")


def good_backup(self, plan, handle, targets, cancel, run_log) -> None:
    return None


async def test_a_failed_run_notifies_within_10_seconds(
    admin: Browser,
    sink: SimpleNamespace,
    silent: int,
    fake_docker: dict,  # noqa: F811
    monkeypatch,
) -> None:
    monkeypatch.setattr(Dispatcher, "_backup", failing_backup)
    job_id, _ = await attached_job(admin, f"{sink.url}/fail/{SENTINEL}", notify_failure="1")
    # A target that never answers, first by name, must not hold the sink up.
    slow = await new_target(admin, name="aaa slow", kind="ntfy", ntfy_topic="t")
    admin.sql(
        "UPDATE notification_targets SET url_enc = ? WHERE id = ?",
        (admin.app.state.crypto.encrypt(f"json://127.0.0.1:{silent}/slow"), slow),
    )
    admin.sql(
        "INSERT INTO job_notifications (job_id, target_id, on_success, on_failure)"
        " VALUES (?, ?, 0, 1)",
        (job_id, slow),
    )
    started = time.monotonic()
    run_id = await start_run(admin, job_id)
    await wait_until(lambda: sink.received, 10, "the notification")
    assert time.monotonic() - started < 10
    raw = sink.received[0][2]
    payload = json.loads(raw)
    assert payload["type"] == "failure"
    assert payload["title"] == "drydock: backup web backup failed"
    assert f"Run #{run_id} of job web backup" in payload["message"]
    assert "[redacted]" in payload["message"] and SENTINEL not in raw.decode()
    assert f"/runs/{run_id}" in payload["message"]
    await anyio.sleep(0.5)
    assert len(sink.received) == 1  # exactly once


async def test_success_notifies_only_when_asked_and_failures_never_fail_the_run(
    admin: Browser,
    sink: SimpleNamespace,
    fake_docker: dict,  # noqa: F811
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setattr(Dispatcher, "_backup", good_backup)
    job_id, target_id = await attached_job(admin, f"{sink.url}/ok", notify_failure="1")
    run_id = await start_run(admin, job_id)
    await admin.app.state.dispatcher.wait(run_id)
    notifier = admin.app.state.notifier
    await wait_until(lambda: not notifier._pending, 10, "the queue")  # nothing for a done run
    assert sink.received == []

    admin.sql("UPDATE job_notifications SET on_success = 1")
    run_id = await start_run(admin, job_id)
    await wait_until(lambda: sink.received, 10, "the success notification")
    assert json.loads(sink.received[0][2])["title"] == "drydock: backup web backup succeeded"
    await admin.app.state.dispatcher.wait(run_id)

    # A target nobody listens at: logged, and the run stays done.
    url = admin.app.state.crypto.encrypt("json://127.0.0.1:9/nobody")
    admin.sql("UPDATE notification_targets SET url_enc = ? WHERE id = ?", (url, target_id))
    run_id = await start_run(admin, job_id)
    await admin.app.state.dispatcher.wait(run_id)
    await wait_until(lambda: "notification ops: JSON: failure" in caplog.text, 15, "warning")
    assert admin.sql("SELECT status FROM runs WHERE id = ?", (run_id,)) == [("done",)]


async def test_cancelled_runs_notify_once_and_restores_never(
    admin: Browser,
    fake_docker: dict,  # noqa: F811
) -> None:
    calls: list[int] = []
    dispatcher = admin.app.state.dispatcher
    dispatcher._on_end = calls.append
    job_id = await add_job(admin)
    run_id = await start_run(admin, job_id)  # blocks until cancelled
    await wait_until(lambda: admin.sql("SELECT status FROM runs")[0][0] == "running", 10, "run")
    await admin.post(f"/runs/{run_id}/cancel")
    await dispatcher.wait(run_id)
    assert calls == [run_id]
    restore = admin.sql(
        "INSERT INTO runs (kind, status, stopped_containers_json, created_at)"
        " VALUES ('restore', 'running', '[]', '2026-10-20 00:00:00') RETURNING id"
    )[0][0]
    dispatcher._finish(
        restore, RunLog(admin.settings.data_dir / "logs" / f"{restore}.log"), "done", None
    )
    dispatcher._finish(run_id, RunLog(admin.settings.data_dir / "logs" / "x.log"), "done", None)
    assert calls == [run_id]  # a restore never, and an ended run not again


async def test_a_run_interrupted_by_a_restart_notifies(
    settings: Settings,
    fake_docker: dict,  # noqa: F811
    monkeypatch,
) -> None:
    async with running(settings) as browser:
        await browser.setup()
        job_id = await add_job(browser)
        run_id = browser.sql(
            "INSERT INTO runs (job_id, kind, status, stopped_containers_json, created_at)"
            " VALUES (?, 'backup', 'running', '[]', '2026-10-20 00:00:00') RETURNING id",
            (job_id,),
        )[0][0]
    calls: list[int] = []
    monkeypatch.setattr(Notifier, "run_ended", lambda self, ended: calls.append(ended))

    async def fake_connect(url: str, *args, **kwargs) -> FakeDocker:
        return FakeDocker()

    monkeypatch.setattr(docker_client, "connect", fake_connect)
    monkeypatch.setattr(helper, "reap", lambda client, instance_id: 0)
    async with running(settings):
        assert calls == [run_id]


async def test_close_sends_what_was_queued_and_nothing_after(
    admin: Browser, sink: SimpleNamespace
) -> None:
    job_id, _ = await attached_job(admin, f"{sink.url}/late", notify_failure="1")
    run_id = admin.sql(
        "INSERT INTO runs (job_id, kind, status, stopped_containers_json, created_at)"
        " VALUES (?, 'backup', 'failed', '[]', '2026-10-20 00:00:00') RETURNING id",
        (job_id,),
    )[0][0]
    notifier = Notifier(admin.settings, admin.app.state.sessionmaker, admin.app.state.crypto)
    notifier.run_ended(run_id)
    notifier.close()
    assert len(sink.received) == 1
    notifier.run_ended(run_id)
    await anyio.sleep(0.3)
    assert len(sink.received) == 1


def test_ntfy_and_gotify_reach_their_servers(sink: SimpleNamespace) -> None:
    ntfy = notify.ntfy_url(sink.url, "backups", "tk_secret")
    outcome = notify.send("ntfy", ntfy, "t", "b", failure=True)
    assert outcome.ok, outcome
    _, path, body, headers = sink.received[-1]
    assert headers.get("Authorization") == "Bearer tk_secret"
    assert "backups" in path + body.decode()
    gotify = notify.gotify_url(f"{sink.url}/sub", "AppT0ken")
    outcome = notify.send("gotify", gotify, "t", "b", failure=True)
    assert outcome.ok, outcome
    _, path, _, headers = sink.received[-1]
    assert path.startswith("/sub/message")
    assert "AppT0ken" in path or headers.get("X-Gotify-Key") == "AppT0ken"


def test_a_stored_multi_url_string_is_never_split_at_send_time(silent: int) -> None:
    """Even a URL stored before the checks existed reaches one service at most."""
    outcome = notify.send("x", f"json://127.0.0.1:{silent}/x,syslog://", "t", "b", failure=True)
    assert "Syslog" not in outcome.detail and "syslog" not in outcome.detail.lower()


# MIGRATION


def test_migration_0008_creates_and_drops_the_tables(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "0007")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            add_job_row(conn, 1)
            conn.commit()
        alembic_to(engine, "head")
        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [("0009",)]
            assert "kind IN ('webhook', 'email', 'ntfy', 'gotify', 'url')" in (
                table_sql(conn, "notification_targets") or ""
            )
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO notification_targets (name, kind, url_enc, enabled, created_at)"
                    " VALUES ('x', 'syslog', 'x', 1, '2026-10-20 00:00:00')"
                )
            index = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
                ("ix_job_notifications_target_id",),
            ).fetchall()
            assert index == [("ix_job_notifications_target_id",)]
        alembic_to(engine, "0007", down=True)
        with closing(sqlite3.connect(path)) as conn:
            assert table_sql(conn, "notification_targets") is None
            assert table_sql(conn, "job_notifications") is None
            assert conn.execute("SELECT id FROM jobs").fetchall() == [(1,)]
    finally:
        engine.dispose()
