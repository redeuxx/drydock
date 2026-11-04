"""The dispatcher's restore runs without a Docker daemon: verification before any Docker
call, confirmation, the re-check of the plan, locks shared with backups, the journal and
its rollback, expiry, discard, shutdown and startup recovery.

Archives are real (tests.restore_support.build_archive, signed with the app's keys). The
target state, apply and rollback are fakes: restore.apply has its own tests.
"""

import asyncio
import dataclasses
import json
import sys
import tarfile
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import docker
import pytest

from drydock.config import Settings
from drydock.engine import capture
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs import runlog
from drydock.jobs.dispatcher import Dispatcher, DispatchError, Target, archive_facts, name_key
from drydock.models import Run, utcnow
from drydock.restore import apply as restore_apply
from drydock.restore import plan as p
from drydock.restore import verify as rv
from tests.conftest import Browser, running, sqlite_ts
from tests.docker_support import wait_until
from tests.restore_support import (
    TarEntry,
    build_archive,
    container_inspect,
    image_tar,
    inner_tar,
    volume_inspect,
)
from tests.test_jobs import add_host, add_job, add_storage, run_status, start_run
from tests.test_routes import FakeDocker

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(sys.platform != "linux", reason="local storage needs Linux"),
]

SECRET = "sentinel-restore-env-secret"
WEB_ID = "c" * 64
NEW_ID = "d" * 64
OTHER_ID = "e" * 64
IMAGE_ID = "sha256:" + "f" * 64
DAEMON_ID = "fake-daemon-id"
SCOPE = dispatcher_module.lock_scope({"ID": DAEMON_ID}, 0)  # every host entry's daemon


# FAKES


class FakeDaemon(FakeDocker):
    """A reachable daemon whose /info names it."""

    def __init__(self) -> None:
        super().__init__()
        self.api = SimpleNamespace(info=lambda: {"ID": DAEMON_ID})


class Fakes:
    """The target state build_plan sees, and recording stand-ins for apply and rollback.
    rollback returns the journal rolled back, or with the next of results merged in."""

    def __init__(self) -> None:
        self.target: p.TargetInfo | None = None
        self.opened: list[str] = []
        self.connected: list[str] = []
        self.applied: list[p.RestorePlan] = []
        self.rolled: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []
        self.on_apply: Callable[..., None] | None = None
        self.on_rollback: Callable[[dict[str, Any]], None] | None = None

    def open_client(self, url: str, timeout: int = 60) -> FakeDaemon:
        self.opened.append(url)
        return FakeDaemon()

    def inspect_target(
        self, handle, lookup, *, host_id: int, host_name: str, helper_image: str
    ) -> p.TargetInfo:
        assert self.target is not None
        return dataclasses.replace(self.target, host_id=host_id, host_name=host_name)

    def apply(self, env, plan, staged, open_archive, *, cancel, log, journal) -> None:
        self.applied.append(plan)
        if self.on_apply is not None:
            self.on_apply(env, plan, journal, cancel)

    def rollback(self, api, doc: dict[str, Any], log) -> dict[str, Any]:
        self.rolled.append(doc)
        if self.on_rollback is not None:
            self.on_rollback(doc)
        if self.results:
            return {**doc, **self.results.pop(0)}
        # Like the real one, a complete rollback clears what an earlier try left set.
        done = {
            k: v for k, v in doc.items() if k not in ("rollback_incomplete", "rollback_unreachable")
        }
        return {**done, "rolled_back": True}


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> Fakes:
    fakes = Fakes()

    async def fake_connect(url: str, *args, **kwargs) -> FakeDocker:
        fakes.connected.append(url)
        return FakeDaemon()

    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", fakes.open_client)
    monkeypatch.setattr(docker_client, "connect", fake_connect)  # the startup reap
    monkeypatch.setattr(helper, "reap", lambda client, instance_id: 0)
    monkeypatch.setattr(restore_apply, "inspect_target", fakes.inspect_target)
    monkeypatch.setattr(restore_apply, "apply", fakes.apply)
    monkeypatch.setattr(restore_apply, "rollback", fakes.rollback)
    return fakes


# HELPERS


def web_archive(browser: Browser, host_config: dict[str, Any] | None = None) -> str:
    """Container web (ID WEB_ID) with a secret env value, volume data and a saved image."""
    container = container_inspect(
        "web",
        id=WEB_ID,
        image_id=IMAGE_ID,
        env=[f"TOKEN={SECRET}"],
        mounts=[("data", "/data")],
        host_config=host_config,
    )
    volume = inner_tar(
        [TarEntry("./", tarfile.DIRTYPE, mode=0o755), TarEntry("./index.html", data=b"hello\n")]
    )
    name, _ = build_archive(
        browser.settings.local_storage_roots[0],
        browser.app.state.crypto,
        containers=[container],
        volumes={"data": volume},
        images=[(IMAGE_ID, ["busybox:1.37"], image_tar(IMAGE_ID, ["busybox:1.37"]), None)],
    )
    return name


def target_info(host_id: int, **changes: Any) -> p.TargetInfo:
    return p.TargetInfo(
        host_id=host_id,
        host_name="local",
        api_version="1.52",
        arch="x86_64",
        images={"busybox:1.37": IMAGE_ID, IMAGE_ID: IMAGE_ID},
        **changes,
    )


def dispatcher(browser: Browser) -> Dispatcher:
    return browser.app.state.dispatcher


def staged_dir(browser: Browser, run_id: int) -> Path:
    return rv.restore_dir(browser.settings.staging_dir, run_id)


def run_row(browser: Browser, run_id: int) -> dict[str, Any]:
    row = browser.sql(
        "SELECT status, error, plan, restore_originals_json, stopped_containers_json, size "
        "FROM runs WHERE id = ?",
        (run_id,),
    )[0]
    columns = ("status", "error", "plan", "restore_originals_json", "stopped_containers_json")
    return dict(zip((*columns, "size"), row, strict=True))


def log_text(browser: Browser, run_id: int) -> str:
    path = runlog.log_path(browser.settings.data_dir, run_id)
    return path.read_text() if path.exists() else ""


async def verified(browser: Browser, storage_id: int, name: str) -> int:
    run_id = await dispatcher(browser).submit_restore(storage_id, name, "admin")
    await dispatcher(browser).wait(run_id)
    assert run_status(browser, run_id) == "awaiting_confirmation", run_row(browser, run_id)
    return run_id


def confirm_plan(browser: Browser, fakes: Fakes, run_id: int, choice: p.Choice) -> p.Choice:
    """What the plan form does: plans against the fake target and stores the choice and
    its summary. Returns the choice with every flagged field acknowledged."""
    staged = rv.load_staged(staged_dir(browser, run_id), browser.app.state.crypto)
    assert fakes.target is not None
    plan = p.build_plan(
        staged.manifest, staged.configs, fakes.target, choice, archive_facts(staged)
    )
    choice = dataclasses.replace(choice, acknowledged=frozenset(f.key for f in plan.risk))
    doc = json.loads(run_row(browser, run_id)["plan"])
    doc |= {"choice": choice.to_dict(), "summary": p.summary(plan, "local")}
    browser.sql("UPDATE runs SET plan = ? WHERE id = ?", (json.dumps(doc), run_id))
    return choice


def journal(host_id: int, run_id: int, **changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "host_id": host_id,
        "mode": "overwrite",
        "run_id": run_id,
        "originals": [
            {"id": WEB_ID, "name": "web", "old_name": "web-drydock-old", "running": True}
        ],
        "created": [],
        "networks": [],
        "volumes_created": [],
        "volumes": ["data"],
        "binds": [],
        "wipe_started": True,
        "data_started": False,
        "committed": False,
        "rolled_back": False,
        "leftover": [],
    }
    return doc | changes


async def ready_app(browser: Browser) -> tuple[int, int]:
    await browser.setup()
    return add_host(browser, "local"), await add_storage(browser)


# VERIFICATION


async def test_tampered_archive_fails_with_zero_docker_calls(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[tuple[str, str]] = []

    def spy(self, request, **kwargs):
        sent.append((request.method, request.url))
        raise AssertionError("no Docker call may happen before verification")

    monkeypatch.setattr(docker.APIClient, "send", spy)
    urls: list[int] = []

    def docker_url(self, host) -> str:
        urls.append(host.id)
        return "unix:///nonexistent"

    monkeypatch.setattr(HostManager, "docker_url", docker_url)
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    name = web_archive(admin)
    path = admin.settings.local_storage_roots[0] / name
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))

    run_id = await dispatcher(admin).submit_restore(storage_id, name, "admin")
    assert run_status(admin, run_id) == "verifying"
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"].startswith("The archive is damaged")
    assert f"Run failed: {row['error']}" in log_text(admin, run_id)
    # No client was opened or connected, and no host's Docker URL was even looked up.
    assert sent == [] and fakes.opened == [] and fakes.connected == [] and urls == []
    assert not staged_dir(admin, run_id).exists()
    with pytest.raises(DispatchError, match="not awaiting confirmation"):
        await dispatcher(admin).execute_restore(run_id, p.Choice(host_id, "overwrite"), "admin")
    assert fakes.applied == [] and sent == [] and fakes.opened == []
    assert fakes.connected == [] and urls == []


async def test_verified_restore_awaits_confirmation_with_signed_flag(
    admin: Browser, fakes: Fakes
) -> None:
    _, storage_id = add_host(admin, "local"), await add_storage(admin)
    name = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    row = run_row(admin, run_id)
    doc = json.loads(row["plan"])
    assert doc == {
        "source": {"storage_target_id": storage_id, "archive": name},
        "signed": True,
        "encrypted": False,
    }
    assert row["size"] == (admin.settings.local_storage_roots[0] / name).stat().st_size
    assert row["restore_originals_json"] == "{}" and row["stopped_containers_json"] == "[]"
    assert admin.sql("SELECT kind, job_id, archive_name FROM runs WHERE id = ?", (run_id,)) == [
        ("restore", None, name)
    ]
    dest = staged_dir(admin, run_id)
    assert dest.stat().st_mode & 0o777 == 0o700
    files = [path for path in dest.rglob("*") if path.is_file()]
    assert files
    for path in files:
        assert SECRET.encode() not in path.read_bytes(), path
    text = log_text(admin, run_id)
    assert "Verified. Choose how to restore it on the restore page." in text
    assert SECRET not in text
    staged = rv.load_staged(dest, admin.app.state.crypto)
    facts = archive_facts(staged)
    assert facts.setid_members == frozenset()
    assert IMAGE_ID in facts.loaded_ids[IMAGE_ID]
    assert fakes.opened == []


async def test_awaiting_cap_and_periodic_expiry(
    settings: Settings, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dispatcher_module, "EXPIRY_INTERVAL", 0.2)
    async with running(settings) as browser:
        _, storage_id = await ready_app(browser)
        name = web_archive(browser)
        runs = [await verified(browser, storage_id, name) for _ in range(5)]
        with pytest.raises(DispatchError, match="Too many restores are awaiting confirmation"):
            await dispatcher(browser).submit_restore(storage_id, name, "admin")
        assert browser.sql("SELECT COUNT(*) FROM runs") == [(5,)]

        stale = sqlite_ts(utcnow() - timedelta(hours=25))
        browser.sql("UPDATE runs SET created_at = ? WHERE id = ?", (stale, runs[0]))
        await wait_until(
            lambda: run_status(browser, runs[0]) == "cancelled", 10, "the periodic expiry"
        )
        await wait_until(lambda: not staged_dir(browser, runs[0]).exists(), 5, "removal")
        row = run_row(browser, runs[0])
        assert row["error"] == "Not confirmed within 24 hours."
        assert "Run cancelled: Not confirmed within 24 hours." in log_text(browser, runs[0])
        assert all(staged_dir(browser, run_id).is_dir() for run_id in runs[1:])
        assert {run_status(browser, run_id) for run_id in runs[1:]} == {"awaiting_confirmation"}


async def test_submit_expires_stale_runs_before_counting_them(admin: Browser, fakes: Fakes) -> None:
    # EXPIRY_INTERVAL keeps its hour here, so only the submit can expire the stale run.
    _, storage_id = add_host(admin, "local"), await add_storage(admin)
    name = web_archive(admin)
    runs = [await verified(admin, storage_id, name) for _ in range(5)]
    stale = sqlite_ts(utcnow() - timedelta(hours=25))
    admin.sql("UPDATE runs SET created_at = ? WHERE id = ?", (stale, runs[2]))
    sixth = await verified(admin, storage_id, name)
    row = run_row(admin, runs[2])
    assert (row["status"], row["error"]) == ("cancelled", "Not confirmed within 24 hours.")
    assert not staged_dir(admin, runs[2]).exists()
    assert "Run cancelled: Not confirmed within 24 hours." in log_text(admin, runs[2])
    assert all(staged_dir(admin, run_id).is_dir() for run_id in (*runs[:2], *runs[3:], sixth))
    with pytest.raises(DispatchError, match="Too many restores are awaiting confirmation"):
        await dispatcher(admin).submit_restore(storage_id, name, "admin")


async def test_submit_refuses_bad_names_and_unknown_storage(admin: Browser, fakes: Fakes) -> None:
    _, storage_id = add_host(admin, "local"), await add_storage(admin)
    for name in ("../x.tar.zst", "web.tar.zst", ""):
        with pytest.raises(DispatchError, match="archive name is not valid"):
            await dispatcher(admin).submit_restore(storage_id, name, "admin")
    with pytest.raises(DispatchError, match="storage does not exist"):
        await dispatcher(admin).submit_restore(storage_id + 1, web_archive(admin), "admin")
    assert admin.sql("SELECT COUNT(*) FROM runs") == [(0,)]


# EXECUTION


async def test_execute_is_single_shot(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id)
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = p.Choice(host_id, "overwrite")
    with pytest.raises(DispatchError, match="not awaiting confirmation"):
        await dispatcher(admin).execute_restore(run_id, choice, "admin")  # not planned yet
    choice = confirm_plan(admin, fakes, run_id, choice)
    results = await asyncio.gather(
        dispatcher(admin).execute_restore(run_id, choice, "admin"),
        dispatcher(admin).execute_restore(run_id, choice, "admin"),
        return_exceptions=True,
    )
    assert sum(isinstance(r, DispatchError) for r in results) == 1
    assert sum(r is None for r in results) == 1
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "done", row
    assert len(fakes.applied) == 1
    assert json.loads(row["plan"])["choice"] == choice.to_dict()
    assert "Confirmed by admin." in log_text(admin, run_id)
    assert not staged_dir(admin, run_id).exists()
    with pytest.raises(DispatchError):
        await dispatcher(admin).execute_restore(run_id, choice, "admin")
    assert len(fakes.applied) == 1


async def test_execute_refuses_a_plan_stored_after_it_was_seen(
    admin: Browser, fakes: Fakes
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id)
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    doc = json.loads(run_row(admin, run_id)["plan"])
    seen = {"choice": doc["choice"], "summary": doc["summary"]}
    # Another plan is stored between the confirm form's check and the execute.
    doc["summary"] = doc["summary"] | {"host": "elsewhere"}
    admin.sql("UPDATE runs SET plan = ? WHERE id = ?", (json.dumps(doc), run_id))
    with pytest.raises(DispatchError, match="plan changed since you viewed it"):
        await dispatcher(admin).execute_restore(run_id, choice, "admin", seen=seen)
    assert run_row(admin, run_id)["status"] == "awaiting_confirmation"
    assert fakes.applied == []
    # The plan the user saw is stored again: it runs.
    doc["summary"] = seen["summary"]
    admin.sql("UPDATE runs SET plan = ? WHERE id = ?", (json.dumps(doc), run_id))
    await dispatcher(admin).execute_restore(run_id, choice, "admin", seen=seen)
    await dispatcher(admin).wait(run_id)
    assert run_row(admin, run_id)["status"] == "done"
    assert len(fakes.applied) == 1


@pytest.mark.parametrize(
    "change",
    [
        pytest.param({"containers": {"web": container_inspect("web", id=WEB_ID)}}, id="original"),
        pytest.param({"volumes": {"data": volume_inspect("data")}}, id="volume"),
    ],
)
async def test_execute_refuses_a_changed_plan(
    admin: Browser, fakes: Fakes, change: dict[str, Any]
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id)
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    # Between the plan and the execute, the target gains an original or an existing volume.
    fakes.target = dataclasses.replace(fakes.target, **change)
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert "Plan the restore again" in row["error"]
    assert fakes.applied == [] and fakes.rolled == []
    assert not staged_dir(admin, run_id).exists()


async def test_execute_refuses_unacknowledged_flags(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id)
    name = web_archive(admin, host_config={"Privileged": True})
    run_id = await verified(admin, storage_id, name)
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    assert "web:Privileged" in choice.acknowledged
    # The routes check the acknowledgements too; the dispatcher does not rely on that.
    unacknowledged = dataclasses.replace(choice, acknowledged=frozenset())
    await dispatcher(admin).execute_restore(run_id, unacknowledged, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == "Not every flagged field was acknowledged. Plan the restore again."
    assert fakes.applied == []


async def test_backup_and_restore_never_overlap_on_a_container(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    job_id = await add_job(admin, host_id=str(host_id), storage_id=str(storage_id))
    other_job = await add_job(admin, "web again", host_id=str(host_id), storage_id=str(storage_id))
    name = web_archive(admin)
    current = {"id": WEB_ID}  # the ID the name web resolves to on the host
    events: list[str] = []
    release_apply, release_backup = threading.Event(), threading.Event()
    hold = {"apply": True, "backup": False}

    def fake_resolve(self, handle, plan, refs, run_log) -> list[Target]:
        assert list(refs) == ["web"]  # always by the job's ref, never by a held ID
        return [Target(current["id"], "web", False)]

    def fake_backup(self, plan, handle, targets, cancel, run_log) -> None:
        events.append(f"backup of {targets[0].id[:1]}")
        if hold["backup"]:
            assert release_backup.wait(30)
        events.append("backup done")

    def fake_apply(env, plan, journal, cancel) -> None:
        events.append("apply")
        if hold["apply"]:
            assert release_apply.wait(30)
        events.append("apply done")

    monkeypatch.setattr(Dispatcher, "_resolve", fake_resolve)
    monkeypatch.setattr(Dispatcher, "_backup", fake_backup)
    fakes.on_apply = fake_apply

    # The restore first. A backup started meanwhile waits for the original's ID.
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    restore = await verified(admin, storage_id, name)
    choice = confirm_plan(admin, fakes, restore, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(restore, choice, "admin")
    await wait_until(lambda: events == ["apply"], 5, "the restore applies")
    assert {WEB_ID, name_key(host_id, "container", "web")} <= set(fakes.applied[0].lock_keys)
    first = await start_run(admin, job_id)
    await asyncio.sleep(0.5)
    assert run_status(admin, first) == "queued"
    assert f"Waiting for run {restore} to finish with container {WEB_ID[:12]}." in log_text(
        admin, first
    )
    # The restore has created the new container: its ID is free, but its name is not.
    current["id"] = NEW_ID
    second = await start_run(admin, other_job)
    await asyncio.sleep(0.5)
    assert run_status(admin, second) == "queued"
    assert f"Waiting for run {restore} to finish with container web." in log_text(admin, second)
    release_apply.set()
    for run_id in (restore, first, second):
        await dispatcher(admin).wait(run_id)
        assert run_status(admin, run_id) == "done"
    assert events == ["apply", "apply done", *["backup of d", "backup done"] * 2]
    # The first backup held the original's ID, which no longer names web.
    assert "Container web was replaced while this run waited; waiting again." in log_text(
        admin, first
    )
    assert "was replaced" not in log_text(admin, second)
    restore_done = admin.sql("SELECT finished_at FROM runs WHERE id = ?", (restore,))[0][0]
    for run_id in (first, second):
        started = admin.sql("SELECT started_at FROM runs WHERE id = ?", (run_id,))[0][0]
        assert started >= restore_done

    # The reverse order: a restore confirmed during a backup waits for it.
    events.clear()
    hold.update(apply=False, backup=True)
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=NEW_ID)})
    backup = await start_run(admin, job_id)
    await wait_until(lambda: events == ["backup of d"], 5, "the backup runs")
    restore = await verified(admin, storage_id, name)
    choice = confirm_plan(admin, fakes, restore, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(restore, choice, "admin")
    await asyncio.sleep(0.5)
    assert run_status(admin, restore) == "queued"
    assert f"Waiting for run {backup} to finish" in log_text(admin, restore)
    release_backup.set()
    await dispatcher(admin).wait(backup)
    await dispatcher(admin).wait(restore)
    assert run_status(admin, restore) == "done"
    assert events == ["backup of d", "backup done", "apply", "apply done"]


async def test_backup_gives_up_on_a_container_that_keeps_changing(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    job_id = await add_job(admin, host_id=str(host_id), storage_id=str(storage_id))
    calls = {"n": 0}

    def fake_resolve(self, handle, plan, refs, run_log) -> list[Target]:
        calls["n"] += 1
        return [Target(f"{calls['n']:064x}", "web", False)]

    monkeypatch.setattr(Dispatcher, "_resolve", fake_resolve)
    run_id = await start_run(admin, job_id)
    await dispatcher(admin).wait(run_id)
    assert run_status(admin, run_id) == "failed"
    assert calls["n"] == dispatcher_module.MAX_RELOCK + 2
    assert not any(lock.locked() for lock in dispatcher(admin)._locks.values())


async def test_backup_waits_while_a_restore_has_renamed_the_container_away(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    job_id = await add_job(admin, host_id=str(host_id), storage_id=str(storage_id))
    current: dict[str, str | None] = {"id": None}  # None: no container is named web
    events: list[str] = []
    release_apply = threading.Event()

    def fake_resolve(self, handle, plan, refs, run_log) -> list[Target]:
        if current["id"] is None:
            raise capture.CaptureError(f"Container web does not exist on host {plan.host.name}.")
        return [Target(current["id"], "web", False)]

    def fake_backup(self, plan, handle, targets, cancel, run_log) -> None:
        events.append(f"backup of {targets[0].id[:1]}")

    def fake_apply(env, plan, journal, cancel) -> None:
        events.append("apply")
        assert release_apply.wait(30)
        current["id"] = NEW_ID  # the restored container now carries the name
        events.append("apply done")

    monkeypatch.setattr(Dispatcher, "_resolve", fake_resolve)
    monkeypatch.setattr(Dispatcher, "_backup", fake_backup)
    fakes.on_apply = fake_apply

    # No run holds the name: a missing container fails the backup at once.
    lone = await start_run(admin, job_id)
    await dispatcher(admin).wait(lone)
    row = run_row(admin, lone)
    assert (row["status"], row["error"]) == (
        "failed",
        "Container web does not exist on host local.",
    )
    assert "Waiting for" not in log_text(admin, lone)

    # An overwrite restore holds the name while the original is renamed away.
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    restore = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, restore, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(restore, choice, "admin")
    await wait_until(lambda: events == ["apply"], 5, "the restore applies")
    backup = await start_run(admin, job_id)
    await asyncio.sleep(0.5)
    assert run_status(admin, backup) == "queued"
    assert f"Waiting for run {restore} to finish with container web." in log_text(admin, backup)
    release_apply.set()
    for run_id in (restore, backup):
        await dispatcher(admin).wait(run_id)
        assert run_status(admin, run_id) == "done", run_row(admin, run_id)
    assert events == ["apply", "apply done", "backup of d"]
    restore_done = admin.sql("SELECT finished_at FROM runs WHERE id = ?", (restore,))[0][0]
    started = admin.sql("SELECT started_at FROM runs WHERE id = ?", (backup,))[0][0]
    assert started >= restore_done


@pytest.mark.parametrize(
    ("change", "error"),
    [
        pytest.param(
            {"containers": {"web": container_inspect("web", id=OTHER_ID)}},
            "The target changed while the restore waited. Plan it again.",
            id="replaced",
        ),
        pytest.param(
            {"volumes": {"data": volume_inspect("data")}},
            "The plan changed since it was confirmed. Plan the restore again.",
            id="volume",
        ),
    ],
)
async def test_execute_plans_again_once_it_holds_the_locks(
    admin: Browser,
    fakes: Fakes,
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, Any],
    error: str,
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    job_id = await add_job(admin, host_id=str(host_id), storage_id=str(storage_id))
    release_backup = threading.Event()

    def fake_resolve(self, handle, plan, refs, run_log) -> list[Target]:
        return [Target(WEB_ID, "web", False)]

    def fake_backup(self, plan, handle, targets, cancel, run_log) -> None:
        assert release_backup.wait(30)

    monkeypatch.setattr(Dispatcher, "_resolve", fake_resolve)
    monkeypatch.setattr(Dispatcher, "_backup", fake_backup)
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    restore = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, restore, p.Choice(host_id, "overwrite"))
    backup = await start_run(admin, job_id)
    await wait_until(lambda: run_status(admin, backup) == "running", 5, "the backup runs")
    await dispatcher(admin).execute_restore(restore, choice, "admin")
    await wait_until(
        lambda: f"Waiting for run {backup} to finish" in log_text(admin, restore),
        5,
        "the restore waits",
    )
    # The first plan matched. While the restore waits, the backup's side changes the target.
    fakes.target = dataclasses.replace(fakes.target, **change)
    release_backup.set()
    await dispatcher(admin).wait(backup)
    await dispatcher(admin).wait(restore)
    row = run_row(admin, restore)
    assert (row["status"], row["error"]) == ("failed", error)
    assert fakes.applied == [] and fakes.rolled == []
    assert not any(lock.locked() for lock in dispatcher(admin)._locks.values())


async def test_failed_overwrite_rolls_back_under_the_lock(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    held: list[tuple[str | None, str | None]] = []

    def failing_apply(env, plan, journal_doc, cancel) -> None:
        assert (env.run_id, env.helper_image) == (run_id, admin.settings.helper_image)
        assert run_status(admin, run_id) == "running"
        journal_doc(journal(host_id, run_id))
        raise restore_apply.ApplyError(f"Copying the data failed: {SECRET}")

    def check_locks(doc: dict[str, Any]) -> None:
        owners = dispatcher(admin)._owners
        held.append((owners.get(WEB_ID), owners.get(name_key(SCOPE, "container", "web"))))

    fakes.on_apply, fakes.on_rollback = failing_apply, check_locks
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == "Copying the data failed: [redacted]"
    # The journal names the scope of the locks, so startup recovery takes the same.
    assert fakes.rolled == [journal(host_id, run_id) | {"lock_scope": SCOPE}]
    assert held == [(f"run {run_id}", f"run {run_id}")]
    assert json.loads(row["restore_originals_json"])["rolled_back"] is True
    assert row["stopped_containers_json"] == "[]"
    assert not staged_dir(admin, run_id).exists()
    assert not dispatcher(admin)._locks[WEB_ID].locked()
    assert SECRET not in log_text(admin, run_id)


async def test_a_rollback_that_raises_is_abandoned(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))

    def failing_apply(env, plan, journal_doc, cancel) -> None:
        journal_doc(journal(host_id, run_id))
        raise restore_apply.ApplyError("Copying the data failed.")

    def broken_rollback(doc: dict[str, Any]) -> None:
        raise RuntimeError("bug")

    fakes.on_apply, fakes.on_rollback = failing_apply, broken_rollback
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", "Copying the data failed.")
    doc = json.loads(row["restore_originals_json"])
    assert doc == journal(host_id, run_id) | {"lock_scope": SCOPE, "abandoned": True}
    assert dispatcher_module.ROLLBACK_RAISED in log_text(admin, run_id)
    # The locks are released now, so no later start may replay this journal.
    assert not dispatcher_module.needs_rollback(doc)


async def test_a_rollback_that_cannot_reach_the_host_is_tried_again_under_the_lock(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dispatcher_module, "ROLLBACK_RETRY", 0.05)
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))
    owners: list[str | None] = []

    def failing_apply(env, plan, journal_doc, cancel) -> None:
        journal_doc(journal(host_id, run_id))
        raise restore_apply.ApplyError("The SSH connection dropped.")

    def check_locks(doc: dict[str, Any]) -> None:
        owners.append(dispatcher(admin)._owners.get(name_key(SCOPE, "container", "web")))

    fakes.on_apply, fakes.on_rollback = failing_apply, check_locks
    fakes.results = [
        {"rolled_back": False, "rollback_incomplete": True, "rollback_unreachable": True}
    ]
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", "The SSH connection dropped.")
    assert len(fakes.rolled) == 2 and fakes.rolled[1]["rollback_unreachable"] is True
    assert owners == [f"run {run_id}"] * 2  # held until the rollback was done
    assert len(fakes.opened) == 2  # the run's client, then a new one for the second try
    doc = json.loads(row["restore_originals_json"])
    assert doc["rolled_back"] is True and "abandoned" not in doc
    assert log_text(admin, run_id).count(dispatcher_module.ROLLBACK_UNREACHABLE) == 1
    assert not dispatcher(admin)._locks[WEB_ID].locked()


async def test_a_rollback_that_cannot_undo_something_is_abandoned(
    admin: Browser, fakes: Fakes
) -> None:
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    run_id = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, run_id, p.Choice(host_id, "overwrite"))

    def failing_apply(env, plan, journal_doc, cancel) -> None:
        journal_doc(journal(host_id, run_id))
        raise restore_apply.ApplyError("Copying the data failed.")

    fakes.on_apply = failing_apply
    refused = {
        "rolled_back": False,
        "rollback_incomplete": True,
        "not_renamed": ["web-drydock-old"],
    }
    fakes.results = [refused]
    await dispatcher(admin).execute_restore(run_id, choice, "admin")
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed" and len(fakes.rolled) == 1
    doc = json.loads(row["restore_originals_json"])
    assert doc["abandoned"] is True and doc["not_renamed"] == ["web-drydock-old"]
    assert dispatcher_module.ROLLBACK_INCOMPLETE in log_text(admin, run_id)
    assert not dispatcher_module.needs_rollback(doc)


async def test_host_entries_for_the_same_daemon_share_name_locks(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A backup through a second entry for the restore's daemon (an SSH tunnel next to the
    socket proxy, say) waits for the name, though the restore runs through the other."""
    host_id, storage_id = add_host(admin, "local"), await add_storage(admin)
    other_entry = add_host(admin, "via-ssh")
    job_id = await add_job(admin, host_id=str(other_entry), storage_id=str(storage_id))
    current: dict[str, str | None] = {"id": None}  # None: no container is named web
    events: list[str] = []
    release_apply = threading.Event()

    def fake_resolve(self, handle, plan, refs, run_log) -> list[Target]:
        if current["id"] is None:
            raise capture.CaptureError(f"Container web does not exist on host {plan.host.name}.")
        return [Target(current["id"], "web", False)]

    def fake_backup(self, plan, handle, targets, cancel, run_log) -> None:
        events.append(f"backup of {targets[0].id[:1]}")

    def fake_apply(env, plan, journal, cancel) -> None:
        events.append("apply")
        assert release_apply.wait(30)
        current["id"] = NEW_ID
        events.append("apply done")

    monkeypatch.setattr(Dispatcher, "_resolve", fake_resolve)
    monkeypatch.setattr(Dispatcher, "_backup", fake_backup)
    fakes.on_apply = fake_apply
    fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
    restore = await verified(admin, storage_id, web_archive(admin))
    choice = confirm_plan(admin, fakes, restore, p.Choice(host_id, "overwrite"))
    await dispatcher(admin).execute_restore(restore, choice, "admin")
    await wait_until(lambda: events == ["apply"], 5, "the restore applies")
    backup = await start_run(admin, job_id)
    await asyncio.sleep(0.5)
    assert run_status(admin, backup) == "queued"
    assert f"Waiting for run {restore} to finish with container web." in log_text(admin, backup)
    release_apply.set()
    for run_id in (restore, backup):
        await dispatcher(admin).wait(run_id)
        assert run_status(admin, run_id) == "done", run_row(admin, run_id)
    assert events == ["apply", "apply done", "backup of d"]


async def test_discard(admin: Browser, fakes: Fakes) -> None:
    _, storage_id = add_host(admin, "local"), await add_storage(admin)
    run_id = await verified(admin, storage_id, web_archive(admin))
    assert staged_dir(admin, run_id).is_dir()
    assert await dispatcher(admin).discard_restore(run_id) is True
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("cancelled", "Discarded.")
    assert "Run cancelled: Discarded." in log_text(admin, run_id)
    assert not staged_dir(admin, run_id).exists()
    assert await dispatcher(admin).discard_restore(run_id) is False
    assert await dispatcher(admin).discard_restore(run_id + 100) is False


# SHUTDOWN AND RECOVERY


async def test_startup_recovery_rolls_back_interrupted_restores(
    settings: Settings, fakes: Fakes, tmp_path: Path
) -> None:
    async with running(settings) as browser:
        host_id, _ = await ready_app(browser)
        with browser.app.state.sessionmaker() as db, db.begin():
            runs = [Run(kind="restore", status="running") for _ in range(3)]
            runs += [Run(kind="restore", status=s) for s in ("awaiting_confirmation", "verifying")]
            db.add_all(runs)
            db.flush()
            ids = [run.id for run in runs]
            runs[0].restore_originals_json = json.dumps(journal(host_id, ids[0]))
            committed = journal(
                host_id,
                ids[1],
                originals=[
                    {"id": OTHER_ID, "name": "api", "old_name": "api-drydock-old", "running": True}
                ],
                created=[{"name": "api", "id": NEW_ID, "failed": False}],
                committed=True,
            )
            runs[1].restore_originals_json = json.dumps(committed)
            incomplete = journal(host_id, ids[2])
            del incomplete["host_id"]
            runs[2].restore_originals_json = json.dumps(incomplete)
    staging = settings.staging_dir
    for run_id in ids:
        (staging / f"restore-{run_id}").mkdir(parents=True)
        (staging / f"restore-{run_id}" / "verified.json").write_bytes(b"x")
    (staging / "restore-x").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep").write_bytes(b"k")
    (staging / "restore-9").symlink_to(elsewhere)

    ready = threading.Event()
    owners: list[dict[str, str]] = []

    def record_locks(doc: dict[str, Any]) -> None:
        assert ready.wait(10)
        owners.append(dict(dispatcher(browser)._owners))

    fakes.on_rollback = record_locks
    async with running(settings) as browser:
        ready.set()
        await wait_until(lambda: len(fakes.rolled) == 2, 10, "the rollbacks")
        statuses = browser.sql("SELECT id, status FROM runs ORDER BY id")
        assert statuses == [(run_id, "interrupted") for run_id in ids]
        assert sorted(doc["run_id"] for doc in fakes.rolled) == ids[:2]
        recovery = "startup recovery"
        assert len(owners) == 2
        for seen in owners:
            assert seen[WEB_ID] == seen[name_key(host_id, "container", "web")] == recovery
            assert seen[OTHER_ID] == seen[NEW_ID] == recovery
            assert seen[name_key(host_id, "container", "api")] == recovery
            assert seen[name_key(host_id, "volume", "data")] == recovery
        await wait_until(
            lambda: all(
                json.loads(run_row(browser, i)["restore_originals_json"]).get("rolled_back")
                for i in ids[:2]
            ),
            5,
            "the journals",
        )
        assert json.loads(run_row(browser, ids[2])["restore_originals_json"]) == incomplete
        assert browser.sql("SELECT DISTINCT stopped_containers_json FROM runs") == [("[]",)]
        assert sorted(p.name for p in staging.iterdir()) == ["restore-9", "restore-x"]
        assert (elsewhere / "keep").read_bytes() == b"k"
        assert "The restore journal is incomplete; nothing to roll back." in log_text(
            browser, ids[2]
        )
        assert "Rolling back the interrupted restore." in log_text(browser, ids[0])
        await wait_until(
            lambda: not dispatcher(browser)._locks[WEB_ID].locked(), 5, "the locks released"
        )


async def test_shutdown_leaves_a_journaled_restore_for_recovery(
    settings: Settings, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dispatcher_module, "SHUTDOWN_WAIT", 1)
    release = threading.Event()
    journaled = threading.Event()

    def stuck_apply(env, plan, journal_doc, cancel) -> None:
        journal_doc(journal(plan.host_id, env.run_id))
        journaled.set()
        assert release.wait(30)  # a worker that ignores cancel
        raise restore_apply.ApplyError("Too late.")

    fakes.on_apply = stuck_apply
    async with running(settings) as browser:
        host_id, storage_id = await ready_app(browser)
        fakes.target = target_info(host_id, containers={"web": container_inspect("web", id=WEB_ID)})
        run_id = await verified(browser, storage_id, web_archive(browser))
        choice = confirm_plan(browser, fakes, run_id, p.Choice(host_id, "overwrite"))
        await dispatcher(browser).execute_restore(run_id, choice, "admin")
        await wait_until(journaled.is_set, 5, "the journal")
        old = dispatcher(browser)
    assert run_status(browser, run_id) == "running"
    assert "startup recovery will roll it back" in log_text(browser, run_id)
    release.set()
    await old.wait(run_id)
    # The abandoned task leaves the run alone: no rollback racing the next startup.
    assert run_status(browser, run_id) == "running" and fakes.rolled == []

    async with running(settings) as browser:
        await wait_until(lambda: len(fakes.rolled) == 1, 10, "the rollback")
        assert run_status(browser, run_id) == "interrupted"
        assert fakes.rolled[0]["run_id"] == run_id
        assert fakes.rolled[0]["host_id"] == host_id


async def test_startup_rollback_keeps_its_locks_while_the_host_is_down(
    settings: Settings, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dispatcher_module, "RECOVERY_WAIT", 0.2)
    monkeypatch.setattr(dispatcher_module, "RECOVERY_RETRY", 0.05)
    monkeypatch.setattr(dispatcher_module, "ROLLBACK_RETRY", 0.1)
    up = threading.Event()
    attempts = {"n": 0}

    def docker_url(self, host) -> str:
        attempts["n"] += 1
        if not up.is_set():
            raise HostUnavailable("The SSH connection is not up.")
        return "unix:///nonexistent"

    async with running(settings) as browser:
        host_id, _ = await ready_app(browser)
        with browser.app.state.sessionmaker() as db, db.begin():
            run = Run(kind="restore", status="running")
            db.add(run)
            db.flush()
            run_id = run.id
            run.restore_originals_json = json.dumps(journal(host_id, run_id))
    monkeypatch.setattr(HostManager, "docker_url", docker_url)
    async with running(settings) as browser:
        unreachable = "Recovery could not reach the host to roll back the restore"
        await wait_until(lambda: unreachable in log_text(browser, run_id), 5, "the first round")
        await wait_until(lambda: attempts["n"] > 20, 10, "more rounds")
        # Held all along: no backup or restore can change what the journal describes.
        owners = dispatcher(browser)._owners
        for key in (
            WEB_ID,
            name_key(host_id, "container", "web"),
            name_key(host_id, "volume", "data"),
        ):
            assert owners.get(key) == "startup recovery", key
        assert fakes.rolled == [] and log_text(browser, run_id).count(unreachable) == 1
        up.set()
        await wait_until(lambda: len(fakes.rolled) == 1, 10, "the rollback")
        await wait_until(
            lambda: not dispatcher(browser)._locks[WEB_ID].locked(), 5, "the locks released"
        )
        assert json.loads(run_row(browser, run_id)["restore_originals_json"])["rolled_back"]


async def test_startup_rollback_gives_up_on_a_deleted_host_and_skips_stale_journals(
    settings: Settings, fakes: Fakes
) -> None:
    async with running(settings) as browser:
        host_id, _ = await ready_app(browser)
        statuses = ("running", "interrupted", "failed", "cancelled")
        with browser.app.state.sessionmaker() as db, db.begin():
            runs = [Run(kind="restore", status=status) for status in statuses]
            db.add_all(runs)
            db.flush()
            ids = [run.id for run in runs]
            # A restore on a host entry deleted since.
            runs[0].restore_originals_json = json.dumps(journal(host_id + 100, ids[0]))
            # An earlier start was stopped before its rollback: it held the locks until then.
            runs[1].restore_originals_json = json.dumps(journal(host_id, ids[1]))
            # Rollbacks that did not finish while the run ended: their locks were released.
            for run in runs[2:]:
                run.restore_originals_json = json.dumps(journal(host_id, run.id))
    gone = "The host no longer exists, so drydock cannot roll back the restore."
    async with running(settings) as browser:
        await wait_until(lambda: len(fakes.rolled) == 1, 10, "the rollback")
        await wait_until(
            lambda: json.loads(run_row(browser, ids[0])["restore_originals_json"]).get("abandoned"),
            5,
            "the abandoned journal",
        )
        assert fakes.rolled[0]["run_id"] == ids[1]
        assert gone in log_text(browser, ids[0])
        # Stored, not only called: a shutdown before the store leaves it for the next start.
        await wait_until(
            lambda: json.loads(run_row(browser, ids[1])["restore_originals_json"]).get(
                "rolled_back"
            ),
            5,
            "the stored rollback",
        )
    async with running(settings) as browser:
        await asyncio.sleep(0.5)
        assert len(fakes.rolled) == 1
        assert log_text(browser, ids[0]).count(gone) == 1
        assert not any(lock.locked() for lock in dispatcher(browser)._locks.values())
        for run_id in ids[2:]:
            doc = json.loads(run_row(browser, run_id)["restore_originals_json"])
            assert doc == journal(host_id, run_id)


# HELPERS


def test_lock_keys_and_names() -> None:
    assert dispatcher_module.lock_subject(WEB_ID) == f"container {WEB_ID[:12]}"
    assert dispatcher_module.lock_subject(name_key(3, "volume", "a:b")) == "volume a:b"
    assert dispatcher_module.backup_keys(3, [Target(WEB_ID, "web", True)]) == [
        WEB_ID,
        "name:3:container:web",
    ]
    assert dispatcher_module.json_object("[1]") == {} and dispatcher_module.json_object("{") == {}
    # Name keys are scoped by the daemon, and a plan's (by host entry) are moved into it.
    scope = dispatcher_module.lock_scope({"ID": "ABCD:EFGH"}, 3)
    assert scope == dispatcher_module.lock_scope({"ID": "ABCD:EFGH"}, 4) != SCOPE
    assert scope.startswith("d") and ":" not in scope
    assert dispatcher_module.lock_scope({}, 3) == dispatcher_module.lock_scope(None, 3) == "3"
    assert dispatcher_module.scoped(["name:3:volume:a", WEB_ID, "name:31:volume:b"], 3, scope) == [
        WEB_ID,
        "name:31:volume:b",
        f"name:{scope}:volume:a",
    ]
    assert dispatcher_module.journal_keys(3, journal(3, 1, lock_scope=scope)) == {
        WEB_ID,
        name_key(scope, "container", "web"),
        name_key(scope, "volume", "data"),
    }
    assert dispatcher_module.journal_keys(3, journal(3, 1, lock_scope="x:y")) == {
        WEB_ID,
        "name:3:container:web",
        "name:3:volume:data",
    }
    doc = journal(3, 1, created=[{"name": "web", "id": None, "failed": True}])
    assert dispatcher_module.journal_keys(3, doc) == {
        WEB_ID,
        "name:3:container:web",
        "name:3:volume:data",
    }
    # A crash after the networks and volumes, before any container: still locked by name.
    doc = journal(
        3,
        1,
        originals=[],
        volumes=[],
        networks=[{"name": "web2-net", "id": None}, {"id": "x"}],
        volumes_created=["web2-data", 7],
    )
    assert dispatcher_module.journal_keys(3, doc) == {
        "name:3:network:web2-net",
        "name:3:volume:web2-data",
    }
    assert dispatcher_module.needs_rollback(doc)
    assert not dispatcher_module.needs_rollback(doc | {"rolled_back": True})
    assert not dispatcher_module.needs_rollback(doc | {"abandoned": True})
    assert not dispatcher_module.needs_rollback(journal(3, 1, originals=[]))


def test_journal_keys_include_the_projects() -> None:
    """A restore that touched Compose projects (a stack, or an overwrite of one member)
    holds their keys, so a stack backup of one waits for its rollback too."""
    doc = journal(3, 1, projects=["app", "web", "", 7])
    assert dispatcher_module.journal_keys(3, doc) == {
        WEB_ID,
        "name:3:container:web",
        "name:3:volume:data",
        "name:3:project:app",
        "name:3:project:web",
    }
    scope = dispatcher_module.lock_scope({"ID": "ABCD:EFGH"}, 3)
    assert name_key(scope, "project", "app") in dispatcher_module.journal_keys(
        3, journal(3, 1, projects=["app"], lock_scope=scope)
    )
    assert "name:3:project:app" not in dispatcher_module.journal_keys(
        3, journal(3, 1, projects="app")
    )
