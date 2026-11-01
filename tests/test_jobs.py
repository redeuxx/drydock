"""Storage, jobs and runs without a Docker daemon: routes, the passphrase, run logs, the
dispatcher's queueing, cancellation, shutdown and startup recovery.

The backup itself is replaced by a stand-in that waits for its cancel event; the tests
against real daemons are in test_runs_docker.py.
"""

import json
import time
import uuid
from pathlib import Path

import anyio
import pytest

from drydock.archive.writer import Cancelled
from drydock.config import Settings
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.hosts.manager import HostManager
from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs import runlog
from drydock.jobs.dispatcher import Dispatcher, DispatchError, Target
from drydock.models import Host, Run
from tests.conftest import Browser, add_user, running
from tests.docker_support import wait_until
from tests.test_routes import FakeDocker

pytestmark = pytest.mark.anyio

# RUN LOGS


def test_run_log_redacts_secrets_and_escapes_control_characters(tmp_path: Path) -> None:
    log = runlog.RunLog(tmp_path / "logs" / "7.log")
    log.add_secrets(runlog.env_values(["PASSWORD=hunter22", "FLAG=1", "EMPTY=", "NOEQUALS"]))
    log("Connecting with hunter22 now")
    log("forged\n2026-01-01 00:00:00 Run done.\x1b[31m")
    text = (tmp_path / "logs" / "7.log").read_text()
    assert "hunter22" not in text and "[redacted]" in text
    assert text.count("\n") == 2  # the forged line stayed on its own line
    assert "\x1b" not in text
    assert oct((tmp_path / "logs" / "7.log").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "logs").stat().st_mode & 0o777) == "0o700"
    # Short values (flags, ports) are not treated as secrets.
    assert log.redact("FLAG is 1") == "FLAG is 1"


def test_read_log_returns_complete_lines_only(tmp_path: Path) -> None:
    path = tmp_path / "1.log"
    assert runlog.read_log(path, 0) == ("", 0)
    path.write_bytes(b"one\ntwo\npart")
    text, offset = runlog.read_log(path, 0)
    assert (text, offset) == ("one\ntwo\n", 8)
    assert runlog.read_log(path, offset) == ("", 8)
    with path.open("ab") as handle:
        handle.write(b"ial\n")
    assert runlog.read_log(path, offset) == ("partial\n", 16)
    assert runlog.read_log(path, 10**9) == ("", 10**9)
    assert runlog.log_path(Path("/data"), 12) == Path("/data/logs/12.log")


def test_read_tail_returns_the_last_complete_lines(tmp_path: Path) -> None:
    path = tmp_path / "1.log"
    assert runlog.read_tail(path, 100) == ("", False)
    path.write_bytes(b"first line\nsecond line\nthe outcome\n")
    assert runlog.read_tail(path, 1000) == ("first line\nsecond line\nthe outcome\n", False)
    # The cut lands inside "second line": that partial line is dropped.
    assert runlog.read_tail(path, 20) == ("the outcome\n", True)


# FIXTURES


def blocking_backup(self, plan, handle, targets, cancel, run_log) -> None:
    """Stands in for the backup: runs until cancelled (or 30 s), then stops."""
    run_log("Working.")
    if cancel.wait(30):
        raise Cancelled("The run was cancelled.")


@pytest.fixture
def fake_docker(monkeypatch) -> dict:
    """Every job runs against container "web" through a fake daemon."""
    targets = {"refs": ["web"]}
    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", lambda url, timeout=60: FakeDocker())
    # Container IDs are unique across daemons, so each host gets its own.
    monkeypatch.setattr(
        Dispatcher,
        "_resolve",
        lambda self, handle, plan, refs, log: [
            Target(f"id-{plan.host.id}-{r}", r, False) for r in targets["refs"]
        ],
    )
    monkeypatch.setattr(Dispatcher, "_backup", blocking_backup)
    return targets


def add_host(browser: Browser, name: str = "local") -> int:
    with browser.app.state.sessionmaker() as db, db.begin():
        host = Host(name=name, kind="local", docker_url="tcp://127.0.0.1:9", enabled=True)
        db.add(host)
        db.flush()
        return host.id


async def add_storage(browser: Browser, name: str = "backups") -> int:
    root = str(browser.settings.local_storage_roots[0])
    response = await browser.post("/storage", {"name": name, "path": root, "enabled": "1"})
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


async def add_job(browser: Browser, name: str = "web backup", **fields: str) -> int:
    host_id = fields.pop("host_id", None) or str(add_host(browser, f"h-{uuid.uuid4().hex[:6]}"))
    storage_id = fields.pop("storage_id", None) or str(
        await add_storage(browser, f"s-{uuid.uuid4().hex[:6]}")
    )
    form = {
        "name": name,
        "host_id": host_id,
        "target": "web",
        "storage_target_id": storage_id,
        "scope": "config",
        "encrypted": "1",
        "enabled": "1",
    } | fields
    response = await browser.post("/jobs", form)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def run_status(browser: Browser, run_id: int) -> str:
    return browser.sql("SELECT status FROM runs WHERE id = ?", (run_id,))[0][0]


async def start_run(browser: Browser, job_id: int) -> int:
    response = await browser.post(f"/jobs/{job_id}/run")
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


# STORAGE


async def test_storage_root_must_be_inside_the_allowlist(admin: Browser, tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (tmp_path / "storage" / "link").symlink_to(outside)
    for path in (str(outside), str(tmp_path / "storage" / "link"), "relative", "/nonexistent"):
        response = await admin.post("/storage", {"name": "x", "path": path, "enabled": "1"})
        assert response.status_code == 422, path
    response = await admin.post(
        "/storage", {"name": "x", "path": str(admin.settings.data_dir), "enabled": "1"}
    )
    assert response.status_code == 422
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]
    storage_id = await add_storage(admin)
    page = await admin.get(f"/storage/{storage_id}")
    assert str(admin.settings.local_storage_roots[0]) in page.text
    # The path is stored encrypted.
    stored = admin.sql("SELECT config_enc FROM storage_targets")[0][0]
    assert str(admin.settings.local_storage_roots[0]) not in stored
    tested = await admin.post(f"/storage/{storage_id}/test")
    assert tested.status_code == 200 and "The directory is writable" in tested.text
    assert [p.name for p in admin.settings.local_storage_roots[0].iterdir()] == ["link"]


async def test_storage_and_host_in_use_cannot_be_deleted(admin: Browser) -> None:
    host_id = add_host(admin)
    storage_id = await add_storage(admin)
    job_id = await add_job(admin, host_id=str(host_id), storage_id=str(storage_id))
    response = await admin.post(f"/storage/{storage_id}/delete")
    assert response.status_code == 409 and "web backup" in response.text
    response = await admin.post(f"/hosts/{host_id}/delete")
    assert response.status_code == 409 and "web backup" in response.text
    assert (await admin.post(f"/jobs/{job_id}/delete")).status_code == 303
    assert (await admin.post(f"/storage/{storage_id}/delete")).status_code == 303
    assert (await admin.post(f"/hosts/{host_id}/delete")).status_code == 303


# JOBS


async def test_job_validation(admin: Browser) -> None:
    host_id, storage_id = str(add_host(admin)), str(await add_storage(admin))
    base = {"host_id": host_id, "storage_id": storage_id}
    for bad in (
        {"target": "-rm"},
        {"target": "web; rm -rf /"},
        {"scope": "everything"},
        {"host_id": "999"},
        {"storage_target_id": "abc"},
        # Non-ASCII digits pass str.isdigit() but not int(): a 422, never a 500.
        {"host_id": "\u00b2"},
        {"storage_target_id": "\u00b2"},
        {"name": ""},
        {"name": "tab\there"},
    ):
        form = {
            "name": "job",
            "host_id": host_id,
            "target": "web",
            "storage_target_id": storage_id,
            "scope": "config",
        } | bad
        response = await admin.post("/jobs", form)
        assert response.status_code == 422, bad
    # Names are free text: archive names only ever use a slug of them.
    job_id = await add_job(admin, "../../x", **base)
    page = await admin.get(f"/jobs/{job_id}")
    assert "Job ../../x" in page.text
    response = await admin.post(
        "/jobs",
        {"name": "../../x", "host_id": host_id, "target": "web", "storage_target_id": storage_id},
    )
    assert response.status_code == 422 and "exists" in response.text
    uuid.UUID(admin.sql("SELECT uuid FROM jobs")[0][0])
    # Defaults when a client omits the Phase 4 fields: a container in stop mode, no hooks.
    assert admin.sql("SELECT target_type, consistency_mode, pre_hooks, post_hooks FROM jobs") == [
        ("container", "stop", "[]", "[]")
    ]

    # Stacks: Compose's own project rule, one character included.
    stack = {"target_type": "stack", "consistency_mode": "pause"}
    stack_id = await add_job(admin, "stack a", target="a", **stack, **base)
    for bad in ("A", "a" * 64, "-app", "app.x"):
        response = await admin.post(
            "/jobs",
            {
                "name": "stack bad",
                "host_id": host_id,
                "target": bad,
                "storage_target_id": storage_id,
                "scope": "config",
            }
            | stack,
        )
        assert response.status_code == 422 and "1 to 63" in response.text, bad
    assert admin.sql(
        "SELECT target_type, target, consistency_mode FROM jobs WHERE id = ?", (stack_id,)
    ) == [("stack", "a", "pause")]
    page = await admin.get(f"/jobs/{stack_id}")
    assert "Compose project" in page.text and "Pause: freeze the containers" in page.text

    # Modes and target types outside the lists.
    for bad, message in (
        ({"consistency_mode": "snapshot"}, "Choose a consistency mode."),
        ({"target_type": "volume"}, "Choose what to back up."),
    ):
        form = {
            "name": "job",
            "host_id": host_id,
            "target": "web",
            "storage_target_id": storage_id,
            "scope": "config",
        } | bad
        response = await admin.post("/jobs", form)
        assert response.status_code == 422 and message in response.text, bad
    live_id = await add_job(admin, "live", consistency_mode="live", **base)
    assert admin.sql("SELECT consistency_mode FROM jobs WHERE id = ?", (live_id,)) == [("live",)]

    # Hooks: unknown names are refused.
    response = await admin.post(
        "/jobs",
        {
            "name": "hooked",
            "host_id": host_id,
            "target": "web",
            "storage_target_id": storage_id,
            "pre_hooks": "nonexistent",
        },
    )
    assert response.status_code == 422 and "There is no hook named nonexistent." in response.text
    assert admin.sql("SELECT COUNT(*) FROM jobs WHERE name = 'hooked'") == [(0,)]


async def test_passphrase_reveal_needs_superadmin_and_recent_auth(admin: Browser) -> None:
    await add_user(admin, "other-admin", "admin")
    job_id = await add_job(admin)
    job_uuid = admin.sql("SELECT uuid FROM jobs WHERE id = ?", (job_id,))[0][0]
    crypto = admin.app.state.crypto
    passphrase = crypto.job_passphrase(uuid.UUID(job_uuid))
    for path in ("/jobs", f"/jobs/{job_id}", "/runs", "/backups", "/audit"):
        assert passphrase not in (await admin.get(path)).text, path

    # Superadmin, recent auth (setup just happened): revealed and audited.
    response = await admin.post(f"/jobs/{job_id}/passphrase")
    assert response.status_code == 200 and passphrase in response.text
    assert response.headers["cache-control"] == "no-store"
    events = admin.sql(
        "SELECT actor, details FROM audit_events WHERE action = 'job.passphrase_reveal'"
    )
    assert len(events) == 1 and events[0][0] == "admin"
    assert passphrase not in events[0][1]
    assert passphrase not in (await admin.get("/audit")).text

    # Without recent auth: the re-auth form, no passphrase.
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    response = await admin.post(f"/jobs/{job_id}/passphrase")
    assert response.status_code == 403 and passphrase not in response.text
    assert "Re-enter your password" in response.text

    # Admins cannot reveal it at all.
    await admin.login("other-admin")
    response = await admin.post(f"/jobs/{job_id}/passphrase")
    assert response.status_code == 403 and passphrase not in response.text
    assert admin.sql(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'job.passphrase_reveal'"
    ) == [(1,)]


# DISPATCHER


async def test_runs_queue_per_container_and_cancel(admin: Browser, fake_docker: dict) -> None:
    first_job = await add_job(admin, "first")
    second_job = await add_job(admin, "second")
    first = await start_run(admin, first_job)
    await wait_until(lambda: run_status(admin, first) == "running", 5, "first run starts")
    second = await start_run(admin, second_job)
    await anyio.sleep(0.5)
    # Different hosts: both run. The same container on one host would queue (below).
    assert run_status(admin, second) == "running"
    for run_id in (first, second):
        assert (await admin.post(f"/runs/{run_id}/cancel")).status_code == 303
        await admin.app.state.dispatcher.wait(run_id)
        assert run_status(admin, run_id) == "cancelled"
    response = await admin.post(f"/runs/{first}/cancel")
    assert response.status_code == 409


async def test_overlapping_runs_wait_and_a_queued_run_can_be_cancelled(
    admin: Browser, fake_docker: dict
) -> None:
    host_id, storage_id = str(add_host(admin)), str(await add_storage(admin))
    job_id = await add_job(admin, host_id=host_id, storage_id=storage_id)
    other_job = await add_job(admin, "same container", host_id=host_id, storage_id=storage_id)
    first = await start_run(admin, job_id)
    await wait_until(lambda: run_status(admin, first) == "running", 5, "first run starts")
    # A job has one run at a time: Run now refuses a second one.
    response = await admin.post(f"/jobs/{job_id}/run")
    assert response.status_code == 409 and "already has a run in progress" in response.text
    assert response.headers["HX-Replace-Url"] == f"/jobs/{job_id}"
    second = await start_run(admin, other_job)
    await anyio.sleep(0.5)
    assert run_status(admin, second) == "queued"
    log = runlog.log_path(admin.settings.data_dir, second).read_text()
    assert f"Waiting for run {first}" in log
    assert (await admin.post(f"/runs/{second}/cancel")).status_code == 303
    await admin.app.state.dispatcher.wait(second)
    assert run_status(admin, second) == "cancelled"
    assert run_status(admin, first) == "running"
    third = await start_run(admin, other_job)
    await anyio.sleep(0.3)
    assert run_status(admin, third) == "queued"
    await admin.post(f"/runs/{first}/cancel")
    await wait_until(lambda: run_status(admin, third) == "running", 5, "third run starts")
    await admin.post(f"/runs/{third}/cancel")
    await admin.app.state.dispatcher.wait(third)


async def test_log_polling_fragment(admin: Browser, fake_docker: dict) -> None:
    job_id = await add_job(admin)
    run_id = await start_run(admin, job_id)
    await wait_until(lambda: run_status(admin, run_id) == "running", 5, "run starts")
    page = await admin.get(f"/runs/{run_id}")
    assert 'id="log-poller"' in page.text and "Working." in page.text
    htmx = {"HX-Request": "true"}
    response = await admin.get(f"/runs/{run_id}/log?offset=0", headers=htmx)
    assert response.status_code == 200
    assert 'id="log-chunk"' in response.text and "Working." in response.text
    size = runlog.log_path(admin.settings.data_dir, run_id).stat().st_size
    assert f"/runs/{run_id}/log?offset={size}" in response.text
    # Nothing new: 204, which htmx does not swap, so the poller keeps its offset.
    response = await admin.get(f"/runs/{run_id}/log?offset={size}", headers=htmx)
    assert response.status_code == 204 and not response.content
    assert (await admin.get(f"/runs/{run_id}/log?offset=-1")).status_code == 422
    await admin.post(f"/runs/{run_id}/cancel")
    await admin.app.state.dispatcher.wait(run_id)
    response = await admin.get(f"/runs/{run_id}/log?offset={size}", headers=htmx)
    assert response.status_code == 204 and response.headers["HX-Refresh"] == "true"
    page = await admin.get(f"/runs/{run_id}")
    assert 'id="log-poller"' not in page.text and "Run cancelled" in page.text
    assert "<title>Run #" in page.text and "(cancelled)" in page.text
    # Cancelling a run that has ended shows the run page with the reason.
    response = await admin.post(f"/runs/{run_id}/cancel")
    assert response.status_code == 409
    assert "This run is not in progress." in response.text and "Run cancelled" in response.text


async def test_disabled_job_and_non_primary_process_do_not_run(
    admin: Browser, fake_docker: dict
) -> None:
    job_id = await add_job(admin, enabled="")
    response = await admin.post(f"/jobs/{job_id}/run")
    assert response.status_code == 409 and "disabled" in response.text
    app = admin.app
    secondary = Dispatcher(
        admin.settings, app.state.sessionmaker, app.state.crypto, app.state.hosts, enabled=False
    )
    with pytest.raises(DispatchError, match="lock"):
        await secondary.submit(job_id, "admin")
    await secondary.shutdown()
    assert admin.sql("SELECT COUNT(*) FROM runs") == [(0,)]


async def test_shutdown_cancels_runs(settings: Settings, fake_docker: dict) -> None:
    async with running(settings) as browser:
        await browser.setup()
        job_id = await add_job(browser)
        run_id = await start_run(browser, job_id)
        await wait_until(lambda: run_status(browser, run_id) == "running", 5, "run starts")
    assert run_status(browser, run_id) == "cancelled"
    error = browser.sql("SELECT error FROM runs WHERE id = ?", (run_id,))[0][0]
    assert error == "Drydock is shutting down."


async def test_startup_recovery(settings: Settings) -> None:
    async with running(settings) as browser:
        await browser.setup()
        job_id = await add_job(browser)
        stopped = [{"host_id": 999, "id": "c" * 64, "name": "web"}]
        with browser.app.state.sessionmaker() as db, db.begin():
            db.add(
                Run(job_id=job_id, status="running", stopped_containers_json=json.dumps(stopped))
            )
            db.add(Run(job_id=job_id, status="queued"))
            db.add(Run(job_id=job_id, status="done"))
    staging = settings.staging_dir
    staging.mkdir(exist_ok=True)
    (staging / f"member-{'a' * 32}").write_bytes(b"x")
    (staging / f"probe-{'b' * 32}.tar").write_bytes(b"x")
    # The staging directory may be a shared disk: nothing else in it is touched.
    (staging / "member-x").write_bytes(b"x")
    (staging / "dir").mkdir()
    (staging / "dir" / "f").write_bytes(b"y")
    root = settings.local_storage_roots[0]
    (root / f".partial-{'c' * 32}").write_bytes(b"z")
    (root / ".partial-0123").write_bytes(b"z")
    (root / "keep.txt").write_bytes(b"k")
    async with running(settings) as browser:
        statuses = browser.sql("SELECT id, status FROM runs ORDER BY id")
        assert [s for _, s in statuses] == ["interrupted", "interrupted", "done"]
        assert sorted(p.name for p in staging.iterdir()) == ["dir", "member-x"]
        assert sorted(p.name for p in root.iterdir()) == [".partial-0123", "keep.txt"]
        log = runlog.log_path(settings.data_dir, statuses[0][0])
        await wait_until(lambda: "could not reach" in log.read_text(), 10, "recovery log")
        assert "Interrupted" in log.read_text()


async def test_a_run_waits_for_startup_recovery_of_its_container(
    settings: Settings, fake_docker: dict, monkeypatch
) -> None:
    """Recovery holds the container's lock until it runs again, so a run started right
    after startup cannot capture it while recovery starts it mid-capture."""
    async with running(settings) as browser:
        await browser.setup()
        host_id = add_host(browser)
        job_id = await add_job(browser, host_id=str(host_id))
        stopped = [{"host_id": host_id, "id": f"id-{host_id}-web", "name": "web"}]
        with browser.app.state.sessionmaker() as db, db.begin():
            db.add(
                Run(job_id=job_id, status="running", stopped_containers_json=json.dumps(stopped))
            )
    events: list[str] = []

    def slow_restart(api, targets, run_log) -> list[str]:
        time.sleep(1.5)
        events.append("restarted")
        return []

    monkeypatch.setattr(dispatcher_module, "restart", slow_restart)
    monkeypatch.setattr(helper, "reap", lambda client, instance_id: 0)  # a fake daemon
    async with running(settings) as browser:
        await browser.login("admin")
        run_id = await start_run(browser, job_id)
        await anyio.sleep(0.5)
        assert run_status(browser, run_id) == "queued"
        log = runlog.log_path(settings.data_dir, run_id).read_text()
        assert "Waiting for startup recovery to finish" in log
        await wait_until(lambda: run_status(browser, run_id) == "running", 10, "the run")
        assert events == ["restarted"]
        await browser.post(f"/runs/{run_id}/cancel")
        await browser.app.state.dispatcher.wait(run_id)


async def test_a_run_waits_for_the_startup_reap_of_its_host(
    settings: Settings, fake_docker: dict, monkeypatch
) -> None:
    """The reaper removes every helper of this installation on the host, so a run must not
    create one before the startup reap has finished."""
    async with running(settings) as browser:
        await browser.setup()
        job_id = await add_job(browser)
    events: list[str] = []

    async def fake_connect(url: str, *args, **kwargs) -> FakeDocker:
        return FakeDocker()

    def slow_reap(client, instance_id: str) -> int:
        time.sleep(1.5)
        events.append("reaped")
        return 0

    def open_client(url: str, timeout: int = 60) -> FakeDocker:
        events.append("opened")
        return FakeDocker()

    monkeypatch.setattr(docker_client, "connect", fake_connect)
    monkeypatch.setattr(helper, "reap", slow_reap)
    monkeypatch.setattr(docker_client, "open_client", open_client)
    async with running(settings) as browser:
        await browser.login("admin")
        run_id = await start_run(browser, job_id)
        await wait_until(lambda: run_status(browser, run_id) == "running", 10, "the run")
        assert events[:2] == ["reaped", "opened"]
        await browser.post(f"/runs/{run_id}/cancel")
        await browser.app.state.dispatcher.wait(run_id)


# TARGET SUGGESTIONS


async def test_the_target_field_loads_suggestions_for_the_chosen_host(admin: Browser) -> None:
    page = (await admin.get("/jobs/new")).text
    assert 'list="target-choices"' in page
    assert 'hx-get="/jobs/target-options"' in page
    empty = await admin.get("/jobs/target-options")  # no host chosen yet
    assert empty.status_code == 200
    assert '<datalist id="target-choices">' in empty.text and "<option" not in empty.text


async def test_an_unreachable_host_still_lets_the_target_be_typed(admin: Browser) -> None:
    host_id = add_host(admin)  # tcp://127.0.0.1:9: nothing listens
    response = await admin.get(
        "/jobs/target-options", params={"host_id": host_id, "target_type": "stack"}
    )
    assert response.status_code == 200
    assert "Could not list the host" in response.text and "Type the name instead." in response.text


@pytest.mark.parametrize(
    "params",
    [{"host_id": "\u00b2"}, {"host_id": "9" * 20}, {"host_id": "1", "target_type": "stacks"}],
)
async def test_odd_target_option_requests_list_nothing(admin: Browser, params: dict) -> None:
    add_host(admin)
    response = await admin.get("/jobs/target-options", params=params)
    assert response.status_code == 200 and "<option" not in response.text


async def test_the_job_list_and_page_say_whether_a_job_is_enabled(admin: Browser) -> None:
    on = await add_job(admin, "on", schedule="1", cron_preset="0 3 * * *")
    off = await add_job(admin, "off", enabled="", schedule="1", cron_preset="manual")
    listing = (await admin.get("/jobs")).text
    assert '>enabled</span><br><span class="text-xs opacity-70">Every day at 03:00<' in listing
    assert (
        '>disabled</span><br><span class="text-xs opacity-70">Only when started by hand<' in listing
    )
    on_page = (await admin.get(f"/jobs/{on}")).text
    assert '<span class="badge badge-success">enabled</span> Runs on its schedule' in on_page
    off_page = (await admin.get(f"/jobs/{off}")).text
    assert '<span class="badge badge-error">disabled</span> No scheduled runs' in off_page
    off_edit = (await admin.get(f"/jobs/{off}/edit")).text
    assert off_edit.index('name="enabled"') < off_edit.index('name="name"'), "Enabled comes first"


# SKIPPED MOUNTS


def skips(browser: Browser, job_id: int) -> list[str]:
    return json.loads(browser.sql("SELECT skip_mounts FROM jobs WHERE id = ?", (job_id,))[0][0])


async def test_skipped_mounts_are_saved_shown_and_kept_by_older_clients(admin: Browser) -> None:
    job_id = await add_job(
        admin,
        "cached",
        skip_mounts_sent="1",
        skip_mounts=["volume:redis_data", "bind:/opt/imgcache"],
    )
    assert skips(admin, job_id) == ["bind:/opt/imgcache", "volume:redis_data"]
    page = (await admin.get(f"/jobs/{job_id}")).text
    assert "bind mount /opt/imgcache</span>, <span" in page
    edit = (await admin.get(f"/jobs/{job_id}/edit")).text
    assert 'name="skip_mounts" value="bind:/opt/imgcache" checked' in edit
    (details,) = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'job.create' ORDER BY id DESC LIMIT 1"
    )[0]
    entry = json.loads(details)
    assert entry["skip_mounts"] == ["bind:/opt/imgcache", "volume:redis_data"]

    form = {"name": "cached", "target": "web", "scope": "config", "encrypted": "1", "enabled": "1"}
    row = admin.sql("SELECT host_id, storage_target_id FROM jobs WHERE id = ?", (job_id,))[0]
    form |= {"host_id": str(row[0]), "storage_target_id": str(row[1])}
    # An older client sends no marker: the stored list stays.
    assert (await admin.post(f"/jobs/{job_id}", form)).status_code == 303
    assert skips(admin, job_id) == ["bind:/opt/imgcache", "volume:redis_data"]
    # The form always sends the marker: no ticked box means none.
    assert (
        await admin.post(f"/jobs/{job_id}", form | {"skip_mounts_sent": "1"})
    ).status_code == 303
    assert skips(admin, job_id) == []
    page = (await admin.get(f"/jobs/{job_id}")).text
    assert "none: every mount is backed up" in page


@pytest.mark.parametrize("bad", ["bind:relative", "bind:/opt/../etc", "volume:a/b", "cache"])
async def test_invalid_skipped_mounts_are_refused(admin: Browser, bad: str) -> None:
    host_id = add_host(admin)
    storage_id = await add_storage(admin)
    form = {
        "name": "bad",
        "host_id": str(host_id),
        "target": "web",
        "storage_target_id": str(storage_id),
        "scope": "config",
        "skip_mounts_sent": "1",
        "skip_mounts": bad,
    }
    response = await admin.post("/jobs", form)
    assert response.status_code == 422
    assert not admin.sql("SELECT id FROM jobs WHERE name = 'bad'")


async def test_mount_options_need_a_host_and_target(admin: Browser) -> None:
    response = await admin.get("/jobs/mount-options", params={"skip_mounts": "bind:/opt/c"})
    assert response.status_code == 200
    assert "Choose the host and the target first." in response.text
    # A ticked key stays listed, so saving never drops it silently.
    assert 'value="bind:/opt/c" checked' in response.text


@pytest.mark.parametrize(
    ("fields", "shown"),
    [
        ({"retention_mode": "last", "keep_last": "3"}, "keeps the newest 3"),
        ({"retention_mode": "age", "max_age_days": "1"}, "keeps 1 day"),
        (
            {"retention_mode": "gfs", "daily": "7", "weekly": "4", "monthly": "0", "yearly": "1"},
            "keeps 7 daily, 4 weekly, 1 yearly",
        ),
    ],
)
async def test_the_job_list_shows_the_retention(admin: Browser, fields: dict, shown: str) -> None:
    await add_job(admin, "kept", **fields)
    assert shown in (await admin.get("/jobs")).text


# DASHBOARD, BELL AND ABOUT


async def test_the_dashboard_shows_failures_recent_runs_and_hosts(admin: Browser) -> None:
    job_id = await add_job(admin, "nightly")
    admin.sql(
        "INSERT INTO runs (job_id, kind, status, stopped_containers_json, error, created_at,"
        " finished_at) VALUES (?, 'backup', 'failed', '[]', 'The host is unreachable.',"
        " datetime('now'), datetime('now'))",
        (job_id,),
    )
    page = (await admin.get("/")).text
    assert "Needs attention" in page and "The host is unreachable." in page
    assert "Recent backups" in page and "nightly" in page and "Hosts" in page


async def test_the_bell_counts_unread_runs_until_marked_read(admin: Browser) -> None:
    job_id = await add_job(admin, "belled")
    admin.sql(
        "INSERT INTO runs (job_id, kind, status, stopped_containers_json, created_at,"
        " finished_at) VALUES (?, 'backup', 'done', '[]', datetime('now', '+1 minute'),"
        " datetime('now', '+1 minute'))",
        (job_id,),
    )
    page = (await admin.get("/jobs")).text
    assert "Notifications, 1 unread" in page and "Backup of belled: done" in page
    response = await admin.post("/feed/read", {"next": "/jobs"})
    assert response.status_code == 303 and response.headers["location"] == "/jobs"
    admin.sql("UPDATE users SET feed_read_at = datetime('now', '+2 minutes')")
    page = (await admin.get("/jobs")).text
    assert "unread" not in page.split("</header>")[0]
    assert "Backup of belled: done" in (await admin.get("/feed")).text


async def test_viewers_see_backups_but_not_restores_or_alerts(admin: Browser) -> None:
    admin.sql(
        "INSERT INTO runs (kind, status, stopped_containers_json, created_at, finished_at)"
        " VALUES ('restore', 'done', '[]', datetime('now'), datetime('now'))"
    )
    admin.sql(
        "INSERT INTO audit_events (ts, action, target, outcome, details)"
        " VALUES (datetime('now'), 'host.hostkey_mismatch', 'host:3', 'failure', '{}')"
    )
    feed = (await admin.get("/feed")).text
    assert "Restore #" in feed and "Host key mismatch on host 3" in feed
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    feed = (await admin.get("/feed")).text
    assert "Restore #" not in feed and "Host key mismatch" not in feed


async def test_the_about_page_names_the_version_and_the_stack(admin: Browser) -> None:
    page = (await admin.get("/about")).text
    assert '<dd class="font-mono">0.1</dd>' in page
    assert "https://pypi.org/project/fastapi/" in page and "rclone" in page
    assert "https://github.com/rclone/rclone/releases/tag/v1.75.2" in page
