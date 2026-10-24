"""The scheduler's hourly system jobs without a Docker daemon: run-history pruning with its
log files, the staging cleanup next to active and open runs, the reaper's skipping of
helpers in use, and the maintenance job itself. test_hosts_docker.py runs the reaper
against a real daemon."""

import json
import logging
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import docker.errors
import pytest
import requests

from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs.dispatcher import Dispatcher
from drydock.jobs.runlog import log_path
from drydock.jobs.scheduler import MAINTENANCE_EVERY, MAINTENANCE_FIRST, MAINTENANCE_ID
from drydock.models import Host, utcnow
from tests.conftest import Browser, make_settings, running, sqlite_ts
from tests.test_jobs import add_job
from tests.test_routes import FakeDocker

pytestmark = pytest.mark.anyio

INSERT = (
    "INSERT INTO runs (kind, status, stopped_containers_json, paused_containers_json,"
    " restore_originals_json, created_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
)
ENTRIES = json.dumps([{"host_id": 1, "id": "abc", "name": "web"}])
CREATED = [{"name": "web", "id": "x"}]


def journal(**fields: object) -> str:
    """A journal as restore.apply writes it, with these fields set."""
    doc: dict[str, object] = {"host_id": 1, "created": CREATED, "committed": False}
    return json.dumps(doc | fields)


def add_run(
    browser: Browser,
    *,
    days: float,
    status: str = "done",
    kind: str = "backup",
    stopped: str = "[]",
    paused: str = "[]",
    doc: str = "{}",
    finished_days: float | None = None,
    finished: bool = True,
) -> int:
    """A run created days ago (finished then, or finished_days ago), with a log file."""
    created = sqlite_ts(utcnow() - timedelta(days=days))
    end = sqlite_ts(utcnow() - timedelta(days=finished_days)) if finished_days else created
    with closing(browser.db()) as conn, conn:
        run_id = conn.execute(
            INSERT, (kind, status, stopped, paused, doc, created, end if finished else None)
        ).lastrowid
    path = log_path(browser.settings.data_dir, run_id)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_text("a line\n")
    return run_id


def dispatcher(browser: Browser) -> Dispatcher:
    return browser.app.state.dispatcher


def run_ids(browser: Browser) -> set[int]:
    return {run_id for (run_id,) in browser.sql("SELECT id FROM runs")}


# RUN HISTORY


async def test_pruning_keeps_what_recovery_or_the_user_still_needs(admin: Browser) -> None:
    pruned = [
        add_run(admin, days=100),
        add_run(admin, days=91, status="failed"),
        add_run(admin, days=100, status="interrupted", finished=False),  # created_at counts
        add_run(admin, days=100, kind="restore", doc=journal(committed=True)),
        add_run(admin, days=100, kind="restore", status="failed", doc=journal(rolled_back=True)),
        # Recovery never rolls back a failed or cancelled restore again.
        add_run(admin, days=100, kind="restore", status="cancelled", doc=journal()),
    ]
    restore = {"kind": "restore", "status": "interrupted"}
    kept = {
        "recent": add_run(admin, days=89),
        "finished recently": add_run(admin, days=100, finished_days=1),
        "running": add_run(admin, days=100, status="running"),
        "awaiting": add_run(admin, days=100, kind="restore", status="awaiting_confirmation"),
        "to restart": add_run(admin, days=100, status="interrupted", stopped=ENTRIES),
        "to unpause": add_run(admin, days=100, status="interrupted", paused=ENTRIES),
        "to roll back": add_run(admin, days=100, **restore, doc=journal()),
        "to finish": add_run(admin, days=100, **restore, doc=journal(committed=True)),
        "abandoned": add_run(admin, days=100, **restore, doc=journal(abandoned=True)),
        "leftover": add_run(
            admin, days=100, kind="restore", status="failed", doc=journal(leftover=["volume x"])
        ),
        "compose": add_run(admin, days=100, doc=journal(committed=True, compose_problem="full")),
    }
    logs = log_path(admin.settings.data_dir, 1).parent
    (logs / "999999.log").write_text("no run row\n")  # left by a crash between the two
    (logs / "notes.txt").write_text("not drydock's\n")
    (logs / "0007.log").write_text("not a name drydock writes\n")
    (logs / "999998.log").mkdir()  # cannot be unlinked: logged, and the sweep goes on

    assert dispatcher(admin).prune_history(90) == len(pruned)
    assert run_ids(admin) == set(kept.values())
    assert {p.name for p in logs.iterdir()} == {f"{i}.log" for i in kept.values()} | {
        "notes.txt",
        "0007.log",
        "999998.log",
    }
    audited = admin.sql("SELECT actor, details FROM audit_events WHERE action = 'runs.prune'")
    assert [(a, json.loads(d)["runs"]) for a, d in audited] == [(None, len(pruned))]

    # Nothing left to do: no second audit record.
    assert dispatcher(admin).prune_history(90) == 0
    assert len(admin.sql("SELECT id FROM audit_events WHERE action = 'runs.prune'")) == 1


async def test_pruning_works_in_short_batches(admin: Browser, monkeypatch) -> None:
    monkeypatch.setattr(dispatcher_module, "PRUNE_BATCH", 3)
    monkeypatch.setattr(dispatcher_module, "PRUNE_MAX_BATCHES", 2)
    old = [add_run(admin, days=100) for _ in range(8)]
    kept = add_run(admin, days=100, status="interrupted", stopped=ENTRIES)
    assert dispatcher(admin).prune_history(90) == 6  # two batches of 3 per pass
    assert run_ids(admin) == {*old[6:], kept}
    assert dispatcher(admin).prune_history(90) == 2  # the next pass carries on
    assert run_ids(admin) == {kept}
    assert not log_path(admin.settings.data_dir, old[-1]).exists()


async def test_pruning_with_no_runs_and_no_logs(admin: Browser) -> None:
    assert dispatcher(admin).prune_history(1) == 0


# STAGING


async def test_staging_cleanup_keeps_what_runs_use(admin: Browser) -> None:
    staging = admin.settings.staging_dir
    staging.mkdir(parents=True, exist_ok=True)
    scratch = [staging / f"member-{'a' * 32}", staging / f"probe-{'b' * 32}.tar"]
    for path in scratch:
        path.write_bytes(b"x")
    trash = staging / f"trash-{'c' * 32}"
    trash.write_bytes(b"x")
    finished = add_run(admin, days=1, kind="restore", status="cancelled")
    awaiting = add_run(admin, days=0, kind="restore", status="awaiting_confirmation")
    gone = add_run(admin, days=0, kind="restore", status="done")
    admin.sql("DELETE FROM runs WHERE id = ?", (gone,))  # pruned: no row, an older ID
    add_run(admin, days=0)
    newer = 10**9  # a run created after the snapshot
    for run_id in (finished, awaiting, gone, newer):
        (staging / f"restore-{run_id}").mkdir()
    (staging / "other").mkdir()

    # A run is active: its scratch files stay; trash and finished restores still go.
    disp = dispatcher(admin)
    disp._active[123] = SimpleNamespace()  # type: ignore[assignment]
    try:
        await disp.clean_staging_now()
    finally:
        disp._active.pop(123)
    names = {p.name for p in staging.iterdir()}
    assert {p.name for p in scratch} <= names
    assert not {trash.name, f"restore-{finished}", f"restore-{gone}"} & names
    assert {f"restore-{awaiting}", f"restore-{newer}", "other"} <= names

    await disp.clean_staging_now()
    names = {p.name for p in staging.iterdir()}
    assert not {p.name for p in scratch} & names
    assert not [n for n in names if n.startswith("trash-")]
    assert {f"restore-{awaiting}", f"restore-{newer}", "other"} <= names


# REAPER


class Listing:
    """containers.list as the reaper reads it (sparse: Names only), and what it removes."""

    def __init__(self, names: list[str], on_list=None) -> None:
        self.found = [
            SimpleNamespace(id=f"id-{n}", attrs={"Names": [f"/{n}"] if n else []}) for n in names
        ]
        self.removed: list[str] = []
        self.missing: set[str] = set()

        def listing(**kwargs) -> list:
            if on_list is not None:
                on_list()
            return self.found

        self.containers = SimpleNamespace(list=listing)
        self.api = SimpleNamespace(remove_container=self._remove)

    def _remove(self, container: str, force: bool, v: bool) -> None:
        if container in self.missing:
            raise docker.errors.NotFound("gone")
        self.removed.append(container)


def name(char: str) -> str:
    return f"{helper.NAME_PREFIX}{char * 32}"


def test_the_reaper_skips_helpers_in_use(monkeypatch) -> None:
    monkeypatch.setattr(helper, "_live", {name("b")})
    client = Listing([name("b"), name("c"), "", name("d")])
    client.missing.add(f"id-{name('d')}")  # finished on its own meanwhile
    # Only real removals count; a helper listed without a name is left alone.
    assert helper.reap(client, "instance") == 1  # type: ignore[arg-type]
    assert client.removed == [f"id-{name('c')}"]


def test_the_reaper_reads_live_names_after_listing(monkeypatch) -> None:
    """A helper registered while the listing ran (helper() starting) is spared."""
    live: set[str] = set()
    monkeypatch.setattr(helper, "_live", live)
    client = Listing([name("e")], on_list=lambda: live.add(name("e")))
    assert helper.reap(client, "instance") == 0  # type: ignore[arg-type]
    assert client.removed == []


@pytest.mark.parametrize("fails", ["nothing", "create", "body", "remove"])
def test_helper_names_are_live_from_create_to_removal(monkeypatch, fails: str) -> None:
    monkeypatch.setattr(helper, "_live", set())
    monkeypatch.setattr(helper, "ensure_image", lambda client, image: None)
    seen: dict[str, set[str]] = {}
    created: list[str] = []

    def create(name: str, **options) -> SimpleNamespace:
        created.append(name)
        seen["create"] = set(helper._live)
        if fails == "create":
            raise RuntimeError("create failed")
        return SimpleNamespace()

    def remove_container(container: str, force: bool, v: bool) -> None:
        seen["remove"] = set(helper._live)
        if fails == "remove":
            raise requests.ConnectionError("the daemon went away")

    client = SimpleNamespace(
        containers=SimpleNamespace(create=create),
        api=SimpleNamespace(remove_container=remove_container),
    )
    try:
        with helper.helper(client, "image", "instance"):  # type: ignore[arg-type]
            if fails == "body":
                raise RuntimeError("the transfer failed")
    except RuntimeError:
        assert fails in ("create", "body")
    assert seen["create"] == seen["remove"] == set(created)  # live from create to removal
    assert helper._live == set()  # never leaked, so a failed removal is reaped later


async def test_reap_all_goes_on_past_hosts_it_cannot_reap(admin: Browser, monkeypatch) -> None:
    with admin.app.state.sessionmaker() as db, db.begin():
        db.add_all(
            [
                Host(name="off", kind="local", docker_url="tcp://off:2375", enabled=False),
                Host(name="no url", kind="local", docker_url=None, enabled=True),
                Host(name="broken", kind="local", docker_url="tcp://broken:2375", enabled=True),
                Host(name="ok", kind="local", docker_url="tcp://ok:2375", enabled=True),
                Host(name="ssh", kind="ssh", address="203.0.113.9", port=22, enabled=True),
            ]
        )
    reaped: list[str] = []

    async def connect(url: str, *args, **kwargs) -> FakeDocker:
        handle = FakeDocker()
        handle.url = url  # type: ignore[attr-defined]
        return handle

    def reap(client, instance_id: str) -> int:
        if client.url == "tcp://broken:2375":
            raise ValueError("something unexpected")
        reaped.append(client.url)
        return 0

    monkeypatch.setattr(docker_client, "connect", connect)
    monkeypatch.setattr(helper, "reap", reap)
    await admin.app.state.hosts.reap_all()
    assert reaped == ["tcp://ok:2375"]  # after the broken one, which sorts first


# THE MAINTENANCE JOB


async def test_maintenance_runs_hourly_beside_job_schedules(admin: Browser) -> None:
    sched = admin.app.state.scheduler
    job = sched._scheduler.get_job(MAINTENANCE_ID)
    assert job is not None and job.trigger.interval == MAINTENANCE_EVERY
    assert timedelta(0) < job.next_run_time - utcnow() <= MAINTENANCE_FIRST
    # A rebuild that schedules a job keeps the maintenance job (its ID is no number).
    job_id = await add_job(admin, "nightly", schedule="1", cron="0 3 * * *", timezone="UTC")
    assert sched.next_run_time(job_id) is not None
    assert sched._scheduler.get_job(MAINTENANCE_ID) is not None


@pytest.mark.parametrize("broken", ["reap", "staging", "prune"])
async def test_a_failing_step_does_not_stop_the_others(
    tmp_path: Path, monkeypatch, caplog, broken: str
) -> None:
    (tmp_path / "storage").mkdir()
    settings = make_settings(
        tmp_path / "data",
        DRYDOCK_LOCAL_STORAGE_ROOTS=str(tmp_path / "storage"),
        DRYDOCK_RUN_HISTORY_DAYS="30",
    )
    calls: list[str] = []

    def step(label: str):
        async def run() -> None:
            calls.append(label)
            if label == broken:
                raise RuntimeError(f"{label} broke")

        return run

    def prune(days: int) -> int:
        calls.append(f"prune {days}")
        if broken == "prune":
            raise RuntimeError("prune broke")
        return 0

    async with running(settings) as browser:
        monkeypatch.setattr(browser.app.state.hosts, "reap_all", step("reap"))
        monkeypatch.setattr(dispatcher(browser), "clean_staging_now", step("staging"))
        monkeypatch.setattr(dispatcher(browser), "prune_history", prune)
        caplog.set_level(logging.ERROR, logger="drydock.scheduler")
        await browser.app.state.scheduler._maintain()
    assert calls == ["reap", "staging", "prune 30"]  # the configured days reach the prune
    assert f"{broken} broke" in caplog.text
