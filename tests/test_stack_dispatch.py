"""The dispatcher's stack jobs, consistency modes and hooks without a Docker daemon: order
of stops, pauses and starts, the lists on the run row, hooks around the data read, the
re-check of hooks after the locks, retention once the archive is stored, stack discovery
under the locks, startup recovery and the shutdown fallback.

The daemon is a recording fake; the capture and (mostly) the hook runner are stand-ins:
engine.capture and jobs.hooks have their own tests, and test_stacks_docker.py runs all of
this against real daemons.
"""

import copy
import errno
import hashlib
import json
import sys
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import anyio
import docker.errors
import pytest
import requests

from drydock.archive.writer import ArchiveResult, Cancelled
from drydock.config import Settings
from drydock.engine import capture, stacks
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.hosts.inventory import PROJECT_LABEL, SERVICE_LABEL
from drydock.hosts.manager import HostManager
from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs import hooks
from drydock.jobs.dispatcher import Dispatcher, Target, name_key
from drydock.jobs.runlog import RunLog
from drydock.models import Hook as HookRow
from drydock.models import Run
from drydock.storage.base import archive_name
from tests.conftest import Browser, running
from tests.docker_support import wait_until
from tests.test_hooks import NEVER_ENDS, FakeApi
from tests.test_jobs import add_host, add_job, add_storage, run_status, start_run
from tests.test_restore_dispatch import log_text
from tests.test_routes import FakeDocker

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(sys.platform != "linux", reason="local storage needs Linux"),
]

REAL_RUN_HOOK = hooks.run_hook
REAL_RUN_ALL = hooks.run_all
REAL_WAIT_HEALTHY = stacks.wait_healthy
REAL_RESTART = dispatcher_module.restart
APP_DEPENDS = "db:service_healthy:false,redis:service_started:false"
STATE_CALLS = ("stop", "start", "pause", "unpause")


def cid(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def box(
    name: str,
    *,
    service: str | None = None,
    project: str = "app",
    depends: str | None = "",
    health: str | None = None,
    running: bool = True,
    paused: bool = False,
    autoremove: bool = False,
    network_mode: str | None = None,
) -> dict[str, Any]:
    """An inspect document. depends None: no depends_on label at all (Compose v1)."""
    labels = {PROJECT_LABEL: project, SERVICE_LABEL: service or name.removesuffix("-drydock-old")}
    if depends is not None:
        labels[stacks.DEPENDS_ON_LABEL] = depends
    config: dict[str, Any] = {"Labels": labels, "Env": []}
    state: dict[str, Any] = {"Running": running, "Paused": paused}
    if health is not None:
        config["Healthcheck"] = {"Test": ["CMD", "true"]}
        state["Health"] = {"Status": health}
    host: dict[str, Any] = {"AutoRemove": autoremove}
    if network_mode is not None:
        host["NetworkMode"] = network_mode
    return {
        "Id": cid(name),
        "Name": f"/{name}",
        "Config": config,
        "State": state,
        "HostConfig": host,
    }


def standard() -> list[dict[str, Any]]:
    """app depends on db (healthy, with a healthcheck) and redis: forward db, redis, app."""
    return [box("app", depends=APP_DEPENDS), box("db", health="healthy"), box("redis")]


def api_error(status: int) -> docker.errors.APIError:
    response = SimpleNamespace(status_code=status, url="http+docker://x", reason="Error")
    return docker.errors.APIError("error", response=response)


# FAKES


class Daemon(FakeApi):
    """A recording daemon: containers, their state calls, and (from FakeApi) execs. Also
    the stand-ins for capture.capture and hooks.run_hook."""

    def __init__(self) -> None:
        super().__init__()
        self.boxes: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.errors: dict[tuple[str, str], Exception] = {}
        self.on_call: Callable[[str, str], None] | None = None
        self.after_discover: Callable[[int], None] | None = None
        self.discovered = 0
        self.captured: list[tuple[list[str], threading.Event]] = []
        self.fail_before: str | None = None
        self.fail_after: str | None = None
        self.during: Callable[[threading.Event], None] | None = None
        self.hook_errors: dict[str, str] = {}
        self.down = False  # ping fails: the connection to the host is gone

    def add(self, *infos: dict[str, Any]) -> None:
        for info in infos:
            self.boxes[info["Id"]] = info

    def remove(self, name: str) -> None:
        del self.boxes[cid(name)]

    def state_calls(self) -> list[tuple[str, str]]:
        return [call for call in self.calls if call[0] in STATE_CALLS]

    # DOCKER API

    def info(self) -> dict[str, Any]:
        return {}  # no daemon ID: name keys are scoped by the host entry

    def ping(self) -> bool:
        if self.down:
            raise requests.exceptions.ConnectionError("The tunnel is down.")
        return True

    def find(self, ref: str) -> dict[str, Any]:
        for info in self.boxes.values():
            if ref in (info["Id"], info["Name"].lstrip("/")):
                return info
        raise docker.errors.NotFound(f"No such container: {ref}")

    def containers(self, all: bool = False, filters: dict | None = None) -> list[dict]:
        label = (filters or {}).get("label")
        if label is None:  # docker ps: the running and paused ones
            return [
                {"Id": info["Id"], "Names": [info["Name"]]}
                for info in self.boxes.values()
                if all or info["State"]["Running"]
            ]
        key, _, value = label.partition("=")
        found = [
            {"Id": info["Id"], "Names": [info["Name"]], "Labels": info["Config"]["Labels"]}
            for info in self.boxes.values()
            if info["Config"]["Labels"].get(key) == value
        ]
        self.discovered += 1
        if self.after_discover is not None:
            self.after_discover(self.discovered)
        return found

    def inspect_container(self, ref: str) -> dict[str, Any]:
        return copy.deepcopy(self.find(ref))

    def _act(self, op: str, ref: str, **state: bool) -> None:
        info = self.find(ref)
        name = info["Name"].lstrip("/")
        self.calls.append((op, name))
        if self.on_call is not None:
            self.on_call(op, name)
        if (op, name) in self.errors:
            raise self.errors[(op, name)]
        info["State"].update(state)

    def stop(self, ref: str, timeout: int | None = None) -> None:
        self._act("stop", ref, Running=False)

    def start(self, ref: str) -> None:
        self._act("start", ref, Running=True)

    def pause(self, ref: str) -> None:
        self._act("pause", ref, Paused=True)

    def unpause(self, ref: str) -> None:
        self._act("unpause", ref, Paused=False)

    def exec_create(self, container, cmd, **kwargs):
        self.calls.append(("exec", container))
        return super().exec_create(container, cmd, **kwargs)

    # STAND-INS

    def capture(self, env, job, containers, out_path, *, cancel, log, **kwargs):
        """Like capture.capture: before_data before the data; on_abort when it fails after."""
        self.captured.append((list(containers), cancel))
        if self.fail_before is not None:
            raise capture.CaptureError(self.fail_before)
        kwargs["before_data"]()
        if cancel.is_set():
            raise Cancelled("The run was cancelled.")
        try:
            if self.during is not None:
                self.during(cancel)
            if self.fail_after is not None:
                raise capture.CaptureError(self.fail_after)
        except BaseException:
            kwargs["on_abort"]()
            raise
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"archive")
        digest = hashlib.sha256(b"archive").hexdigest()
        return None, ArchiveResult(out_path, 7, digest, False, ())

    def run_hook(self, api, container_id, hook, *, container_name, phase, cancel, log, **_):
        self.calls.append(("hook", hook.name))
        if hook.name in self.hook_errors:
            raise hooks.HookError(self.hook_errors[hook.name])


class Handle(FakeDocker):
    def __init__(self, daemon: Daemon) -> None:
        super().__init__()
        self.api = daemon


@pytest.fixture
def daemon(monkeypatch: pytest.MonkeyPatch) -> Daemon:
    daemon = Daemon()

    async def fake_connect(url: str, *args, **kwargs) -> Handle:
        return Handle(daemon)

    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", lambda url, timeout=60: Handle(daemon))
    monkeypatch.setattr(docker_client, "connect", fake_connect)  # the startup reap
    monkeypatch.setattr(helper, "reap", lambda client, instance_id: 0)
    monkeypatch.setattr(dispatcher_module, "own_container", lambda api: None)
    monkeypatch.setattr(capture, "capture", daemon.capture)
    monkeypatch.setattr(hooks, "run_hook", daemon.run_hook)
    return daemon


@pytest.fixture
def waits(monkeypatch: pytest.MonkeyPatch, daemon: Daemon) -> list[tuple[list[str], int]]:
    """Every wait_healthy call: its IDs and how many calls the daemon had seen by then."""
    seen: list[tuple[list[str], int]] = []

    def spy(api, ids, deadline, cancel, log) -> bool:
        seen.append((list(ids), len(daemon.calls)))
        return REAL_WAIT_HEALTHY(api, ids, deadline, cancel, log)

    monkeypatch.setattr(stacks, "wait_healthy", spy)
    return seen


# HELPERS


def dispatcher(browser: Browser) -> Dispatcher:
    return browser.app.state.dispatcher


def entry(host_id: int, name: str, wait_for: list[str] | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {"host_id": host_id, "id": cid(name), "name": name}
    if wait_for:
        doc["wait_for"] = wait_for
    return doc


def run_row(browser: Browser, run_id: int) -> dict[str, Any]:
    status, error, stopped, paused = browser.sql(
        "SELECT status, error, stopped_containers_json, paused_containers_json FROM runs "
        "WHERE id = ?",
        (run_id,),
    )[0]
    return {
        "status": status,
        "error": error,
        "stopped": json.loads(stopped),
        "paused": json.loads(paused),
    }


def latest_lists(browser: Browser) -> tuple[list[dict], list[dict]]:
    stopped, paused = browser.sql(
        "SELECT stopped_containers_json, paused_containers_json FROM runs ORDER BY id DESC LIMIT 1"
    )[0]
    return json.loads(stopped), json.loads(paused)


def set_job(browser: Browser, job_id: int, **columns: Any) -> None:
    for column, value in columns.items():
        assert column in ("target_type", "target", "consistency_mode", "pre_hooks", "post_hooks")
        browser.sql(f"UPDATE jobs SET {column} = ? WHERE id = ?", (value, job_id))  # noqa: S608


async def stack_job(
    browser: Browser,
    *,
    mode: str = "stop",
    host_id: int | None = None,
    target_type: str = "stack",
    target: str = "app",
) -> tuple[int, int]:
    """A job for Compose project app (or a container job), and its host entry."""
    host_id = host_id or add_host(browser, f"h-{uuid.uuid4().hex[:6]}")
    storage_id = await add_storage(browser, f"s-{uuid.uuid4().hex[:6]}")
    job_id = await add_job(
        browser, f"job-{uuid.uuid4().hex[:6]}", host_id=str(host_id), storage_id=str(storage_id)
    )
    set_job(browser, job_id, target_type=target_type, target=target, consistency_mode=mode)
    return job_id, host_id


def add_hook(
    browser: Browser,
    name: str,
    host_id: int,
    container: str,
    *,
    project: str | None = "app",
    argv: tuple[str, ...] = ("true",),
) -> int:
    with browser.app.state.sessionmaker() as db, db.begin():
        row = HookRow(
            name=name,
            host_id=host_id,
            project=project,
            container=container,
            argv_json=json.dumps(list(argv)),
        )
        db.add(row)
        db.flush()
        return row.id


def attach(browser: Browser, job_id: int, pre: list[int], post: list[int]) -> None:
    set_job(browser, job_id, pre_hooks=json.dumps(pre), post_hooks=json.dumps(post))


async def run(browser: Browser, job_id: int) -> int:
    run_id = await start_run(browser, job_id)
    await dispatcher(browser).wait(run_id)
    return run_id


def backups(browser: Browser) -> int:
    return browser.sql("SELECT COUNT(*) FROM backups")[0][0]


# MODES AND ORDER


async def test_stop_mode_stops_in_reverse_and_starts_forward(
    admin: Browser, daemon: Daemon, waits: list
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    seen: list[list[dict]] = []
    daemon.on_call = lambda op, name: seen.append(latest_lists(admin)[0]) if not seen else None
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.state_calls() == [
        ("stop", "app"),
        ("stop", "redis"),
        ("stop", "db"),
        ("start", "db"),
        ("start", "redis"),
        ("start", "app"),
    ]
    # db's health was checked after it started and before app, which depends on it.
    assert waits == [([cid("db")], 5)]
    # Written before the first stop, in forward order, with what each waits for.
    assert seen == [
        [entry(host_id, "db"), entry(host_id, "redis"), entry(host_id, "app", [cid("db")])]
    ]
    assert run_row(admin, run_id)["stopped"] == [] and run_row(admin, run_id)["paused"] == []
    assert daemon.captured[0][0] == [cid("db"), cid("redis"), cid("app")]
    text = log_text(admin, run_id)
    assert "Backup of Compose project app on host" in text and "consistency mode stop" in text
    assert "record no dependency order" not in text
    assert backups(admin) == 1


async def test_pause_list_is_written_before_the_first_pause(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin, mode="pause")
    seen: list[list[dict]] = []
    daemon.on_call = lambda op, name: seen.append(latest_lists(admin)[1]) if not seen else None
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert [[e["name"] for e in names] for names in seen] == [["db", "redis", "app"]]
    assert seen[0][0] == entry(host_id, "db")
    assert daemon.state_calls() == [
        ("pause", "app"),
        ("pause", "redis"),
        ("pause", "db"),
        ("unpause", "db"),
        ("unpause", "redis"),
        ("unpause", "app"),
    ]
    assert run_row(admin, run_id)["paused"] == [] and run_row(admin, run_id)["stopped"] == []
    text = log_text(admin, run_id)
    assert "Pausing container app." in text and "Unpaused container app." in text


async def test_live_mode_makes_no_state_calls(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, _ = await stack_job(admin, mode="live")
    seen: list[tuple] = []
    daemon.on_call = lambda op, name: seen.append(latest_lists(admin))
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "done", log_text(admin, run_id)
    assert daemon.calls == [] and seen == []
    assert row["stopped"] == [] and row["paused"] == []
    assert "crash-consistent at best" in log_text(admin, run_id)
    assert backups(admin) == 1


@pytest.mark.parametrize("mode", ["stop", "pause"])
async def test_already_paused_and_stopped_containers_stay_so(
    admin: Browser, daemon: Daemon, mode: str
) -> None:
    daemon.add(
        box("app", depends=APP_DEPENDS),
        box("db", health="healthy", paused=True),
        box("redis", running=False),
    )
    job_id, _ = await stack_job(admin, mode=mode)
    seen: list[tuple] = []
    daemon.on_call = lambda op, name: seen.append(latest_lists(admin)) if not seen else None
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    undo = "start" if mode == "stop" else "unpause"
    assert daemon.state_calls() == [(mode, "app"), (undo, "app")]
    listed = seen[0][0] if mode == "stop" else seen[0][1]
    assert [e["name"] for e in listed] == ["app"]
    text = log_text(admin, run_id)
    assert "Container db is paused; it stays paused." in text
    assert "Container redis is not running; it stays stopped." in text


async def test_own_deployment_is_refused_in_every_mode(
    admin: Browser, daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    own = {"Id": "f" * 64, "Config": {"Labels": {PROJECT_LABEL: "app"}}}
    monkeypatch.setattr(dispatcher_module, "own_container", lambda api: own)
    daemon.add(*standard())
    job_id, _ = await stack_job(admin)
    messages = {
        "stop": "Stopping it would cut drydock off from Docker, so stop mode refuses it.",
        "pause": "Pausing it would cut drydock off from Docker, so pause mode refuses it.",
        "live": "which drydock does not back up while it runs",
    }
    for mode, message in messages.items():
        set_job(admin, job_id, consistency_mode=mode)
        run_id = await run(admin, job_id)
        row = run_row(admin, run_id)
        assert row["status"] == "failed" and message in row["error"], (mode, row)
        assert "belongs to drydock's own deployment" in row["error"]
    assert daemon.calls == [] and daemon.captured == []
    # Not running: live mode backs it up (stop mode would as well, with nothing to stop).
    for info in daemon.boxes.values():
        info["State"]["Running"] = False
    set_job(admin, job_id, consistency_mode="live")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.calls == []


async def test_autoremove_is_refused_only_in_stop_mode(admin: Browser, daemon: Daemon) -> None:
    daemon.add(box("web", project="solo", autoremove=True))
    job_id, _ = await stack_job(admin, target_type="container", target="web")
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed" and "(--rm), so stop mode cannot back it up" in row["error"]
    assert daemon.calls == []
    set_job(admin, job_id, consistency_mode="pause")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.state_calls() == [("pause", "web"), ("unpause", "web")]
    assert "Backup of web on host" in log_text(admin, run_id)
    set_job(admin, job_id, consistency_mode="live")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done"
    assert len(daemon.state_calls()) == 2


async def test_stop_mode_refuses_a_container_whose_namespace_provider_is_not_running(
    admin: Browser, daemon: Daemon
) -> None:
    # qbittorrent runs in gluetun's network namespace (network_mode: service:gluetun), and
    # gluetun has exited: Docker would refuse to start qbittorrent again (409).
    daemon.add(
        box("gluetun", running=False),
        box("qbittorrent", network_mode=f"container:{cid('gluetun')}"),
    )
    job_id, host_id = await stack_job(admin)
    attach(admin, job_id, [add_hook(admin, "pre", host_id, "qbittorrent")], [])
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == (
        "Container qbittorrent shares the namespaces of container gluetun, which is not "
        "running, so drydock could not start qbittorrent again after stopping it. Start "
        "gluetun first, or use pause mode."
    )
    # Refused before anything changed: no pre-hook, no stop.
    assert daemon.calls == [] and daemon.captured == [] and row["stopped"] == []
    # A provider that no longer exists, named by its ID.
    daemon.remove("gluetun")
    run_id = await run(admin, job_id)
    assert f"of container {cid('gluetun')[:12]}, which" in run_row(admin, run_id)["error"]
    assert daemon.calls == []
    # Pause mode keeps the namespace, so it backs the container up.
    attach(admin, job_id, [], [])
    set_job(admin, job_id, consistency_mode="pause")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.state_calls() == [("pause", "qbittorrent"), ("unpause", "qbittorrent")]
    # A running provider that the run stops too starts first.
    daemon.calls.clear()
    daemon.add(box("gluetun"))
    set_job(admin, job_id, consistency_mode="stop")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.state_calls() == [
        ("stop", "qbittorrent"),
        ("stop", "gluetun"),
        ("start", "gluetun"),
        ("start", "qbittorrent"),
    ]


async def test_stop_mode_refuses_to_cut_off_a_container_it_leaves_running(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(
        box("vpn", project="net"),
        box("downloader", project="media", network_mode="container:vpn"),
    )
    job_id, _ = await stack_job(admin, target_type="container", target="vpn")
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == (
        "Container downloader shares the namespaces of vpn but this run does not stop it, so "
        "stopping vpn would cut downloader off until it is restarted. Back them up in one "
        "stack job, or use pause mode."
    )
    assert daemon.calls == [] and daemon.captured == []
    # A stopped one joins the new namespace when it starts: nothing to refuse.
    daemon.boxes[cid("downloader")]["State"]["Running"] = False
    # One that shares the IPC namespace by ID, and is paused: it is cut off too.
    worker = box("worker", project="other", paused=True)
    worker["HostConfig"]["IpcMode"] = f"container:{cid('vpn')}"
    daemon.add(worker)
    run_id = await run(admin, job_id)
    assert "Container worker shares the namespaces of vpn" in run_row(admin, run_id)["error"]
    assert daemon.calls == []
    set_job(admin, job_id, consistency_mode="pause")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    daemon.remove("worker")
    set_job(admin, job_id, consistency_mode="stop")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.state_calls() == [
        ("pause", "vpn"),
        ("unpause", "vpn"),
        ("stop", "vpn"),
        ("start", "vpn"),
    ]


async def test_label_less_stack_logs_name_order(admin: Browser, daemon: Daemon) -> None:
    daemon.add(box("b", depends=None), box("a", depends=None))

    def grow(count: int) -> None:
        if count == 1:  # a relock: the stack is discovered three times
            daemon.add(box("c", depends=None))

    daemon.after_discover = grow
    job_id, _ = await stack_job(admin, mode="live")
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done"
    assert daemon.discovered == 3
    # Once, however often the stack was discovered.
    assert (
        log_text(admin, run_id).count(
            "The containers of Compose project app record no dependency order; they stop and "
            "start in name order."
        )
        == 1
    )
    assert daemon.captured[0][0] == [cid("a"), cid("b"), cid("c")]


async def test_empty_project_fails_the_run(admin: Browser, daemon: Daemon) -> None:
    daemon.add(box("other", project="elsewhere"), box("app-run", project="app"))
    daemon.boxes[cid("app-run")]["Config"]["Labels"][stacks.ONEOFF_LABEL] = "True"
    job_id, _ = await stack_job(admin)
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"].startswith("Compose project app has no containers on host h-")
    assert daemon.calls == [] and daemon.captured == []


# HOOKS


async def test_failing_pre_hook_stops_nothing(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    on = add_hook(admin, "maint-on", host_id, "app")
    off = add_hook(admin, "maint-off", host_id, "app")
    attach(admin, job_id, [on], [off])
    daemon.hook_errors["maint-on"] = "Hook maint-on failed with exit code 1."
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", "Hook maint-on failed with exit code 1.")
    # The post-hook still undoes whatever the pre-hook did; nothing was stopped or started.
    assert daemon.calls == [("hook", "maint-on"), ("hook", "maint-off")]
    assert row["stopped"] == [] and backups(admin) == 0
    assert "Hooks: 1 before, 1 after." in log_text(admin, run_id)


async def test_second_pre_hook_failing_still_runs_post_hooks(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    ids = {name: add_hook(admin, name, host_id, "db") for name in "ABCD"}
    attach(admin, job_id, [ids["A"], ids["B"]], [ids["C"], ids["D"]])
    daemon.hook_errors |= {"B": "Hook B failed with exit code 2.", "C": "Hook C timed out."}
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", "Hook B failed with exit code 2.")
    assert daemon.calls == [("hook", "A"), ("hook", "B"), ("hook", "C"), ("hook", "D")]
    assert "Hook C timed out." in log_text(admin, run_id)


async def test_post_hooks_do_not_run_when_before_data_was_never_reached(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    attach(
        admin,
        job_id,
        [add_hook(admin, "pre", host_id, "db")],
        [add_hook(admin, "post", host_id, "db")],
    )
    daemon.fail_before = "Container db could not be inspected."
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", "Container db could not be inspected.")
    assert daemon.calls == []


async def test_post_hooks_run_after_restart_even_after_a_failed_capture(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    attach(admin, job_id, [], [add_hook(admin, "after", host_id, "app")])
    daemon.fail_after = "Reading the data failed."
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", "Reading the data failed.")
    assert daemon.calls == [
        ("stop", "app"),
        ("stop", "redis"),
        ("stop", "db"),
        ("start", "db"),
        ("start", "redis"),
        ("start", "app"),
        ("hook", "after"),
    ]
    assert backups(admin) == 0 and row["stopped"] == []


async def test_post_hook_timeout_after_restart_fails_the_run(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    attach(admin, job_id, [], [add_hook(admin, "after", host_id, "app")])
    timed_out = "Hook after timed out after 1 seconds. Docker may still be running it."
    daemon.hook_errors["after"] = timed_out
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == f"The backup was stored, but a post-hook failed: {timed_out}"
    assert daemon.calls[-1] == ("hook", "after")
    assert [op for op, _ in daemon.calls[:-1]] == ["stop"] * 3 + ["start"] * 3
    assert backups(admin) == 1
    assert admin.sql("SELECT archive_name FROM runs WHERE id = ?", (run_id,))[0][0]


async def test_cancel_during_post_hooks_starts_the_rest_without_waiting(
    admin: Browser, daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin, mode="live")
    first, second = (
        add_hook(admin, "first", host_id, "db"),
        add_hook(admin, "second", host_id, "redis"),
    )
    attach(admin, job_id, [], [first, second])

    # The arguments: the run's cancel, undo semantics, the budget.
    seen: list[dict[str, Any]] = []

    def spy(api, pairs, **kwargs) -> None:
        seen.append(kwargs)
        REAL_RUN_ALL(api, pairs, **kwargs)

    monkeypatch.setattr(hooks, "run_all", spy)
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done"
    cancel = daemon.captured[0][1]
    assert [kw["phase"] for kw in seen] == ["pre", "post"]
    assert seen[0].get("keep_going", False) is False and seen[0].get("on_cancel") is None
    post = seen[1]
    assert post["cancel"] is cancel and post["keep_going"] is True
    assert post["on_cancel"] == "wait" and post["budget"] == hooks.POST_HOOK_BUDGET

    # The real runner: the first post-hook never ends; a cancel stops waiting for it.
    monkeypatch.setattr(hooks, "run_all", REAL_RUN_ALL)
    monkeypatch.setattr(hooks, "run_hook", REAL_RUN_HOOK)
    monkeypatch.setattr(hooks, "CANCEL_WAIT", 0.3)
    daemon.inspects, daemon.close = [NEVER_ENDS], False
    try:
        run_id = await start_run(admin, job_id)
        await wait_until(lambda: len(daemon.creates) == 1, 10, "the first post-hook")
        started = time.monotonic()
        assert dispatcher(admin).cancel(run_id)
        await dispatcher(admin).wait(run_id)
        assert time.monotonic() - started < dispatcher_module.SHUTDOWN_WAIT / 4
    finally:
        for peer in daemon.peers:
            peer.close()
    assert [c for c, _, _ in daemon.creates] == [cid("db"), cid("redis")]
    assert run_status(admin, run_id) == "cancelled"
    text = log_text(admin, run_id)
    assert "Stopped waiting for hook first because the run was cancelled." in text
    assert "Starting post-hook second without waiting for it to finish." in text


async def test_post_hooks_wait_for_restarted_hook_containers(
    admin: Browser, daemon: Daemon, waits: list
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    attach(admin, job_id, [], [add_hook(admin, "check", host_id, "db")])
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.calls[6] == ("hook", "check")
    # Before app's start (its dependency), then once every start is done, before the hook.
    assert waits == [([cid("db")], 5), ([cid("db")], 6)]
    # Only unpaused, or never stopped: nothing to wait for.
    for mode in ("pause", "live"):
        waits.clear()
        daemon.calls.clear()
        set_job(admin, job_id, consistency_mode=mode)
        run_id = await run(admin, job_id)
        assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
        assert daemon.calls[-1] == ("hook", "check") and waits == []


async def test_hook_outside_the_stack_is_refused_before_anything(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    attach(
        admin,
        job_id,
        [add_hook(admin, "pre", host_id, "db")],
        [add_hook(admin, "elsewhere", host_id, "worker")],
    )
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == "Hook elsewhere runs in worker, which this job does not back up."
    assert daemon.calls == [] and daemon.captured == []


async def test_binding_is_checked_again_at_run_time(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    other_host = add_host(admin, "other")
    hook_id = add_hook(admin, "dump", host_id, "db")
    attach(admin, job_id, [hook_id], [])
    # Edited behind the routes' back after the job was saved.
    admin.sql("UPDATE hooks SET host_id = ? WHERE id = ?", (other_host, hook_id))
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == "Hook dump is bound to another host, so this job cannot run it."
    admin.sql("UPDATE hooks SET host_id = ?, project = 'other' WHERE id = ?", (host_id, hook_id))
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert (
        row["error"] == "Hook dump is for Compose project other, which this job does not back up."
    )
    # A container hook on a stack job.
    admin.sql("UPDATE hooks SET project = NULL WHERE id = ?", (hook_id,))
    run_id = await run(admin, job_id)
    assert "attach it to that container's job" in run_row(admin, run_id)["error"]
    assert daemon.calls == [] and daemon.captured == []


@pytest.mark.parametrize("change", ["argv", "container", "list"])
async def test_hook_edit_while_the_run_waits_fails_it(
    admin: Browser, daemon: Daemon, change: str
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    hook_id = add_hook(admin, "dump", host_id, "db", argv=("pg_dump", "-f", "/backup/db.sql"))
    attach(admin, job_id, [], [hook_id])
    key = name_key(str(host_id), "project", "app")
    lock = dispatcher(admin)._locks[key]
    await lock.acquire()
    dispatcher(admin)._owners[key] = "run 999"
    try:
        run_id = await start_run(admin, job_id)
        await wait_until(
            lambda: "Waiting for run 999 to finish with project app." in log_text(admin, run_id),
            5,
            "the run waits",
        )
        assert run_status(admin, run_id) == "queued"
        if change == "argv":
            argv = json.dumps(["sh", "-c", "id"])
            admin.sql("UPDATE hooks SET argv_json = ? WHERE id = ?", (argv, hook_id))
        elif change == "container":
            admin.sql("UPDATE hooks SET container = 'redis' WHERE id = ?", (hook_id,))
        else:
            set_job(admin, job_id, post_hooks="[]")
    finally:
        dispatcher(admin)._owners.pop(key, None)
        lock.release()
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == ("failed", dispatcher_module.HOOKS_CHANGED)
    assert daemon.calls == [] and daemon.captured == []


async def test_missing_hook_row_fails_the_run(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, _ = await stack_job(admin)
    set_job(admin, job_id, pre_hooks="[999]")
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert (row["status"], row["error"]) == (
        "failed",
        "Hook 999 of this job no longer exists. Edit the job again.",
    )
    for bad in ('["1"]', '{"a": 1}', "[true]", "nonsense", json.dumps(list(range(11)))):
        set_job(admin, job_id, pre_hooks=bad)
        run_id = await run(admin, job_id)
        row = run_row(admin, run_id)
        assert (row["status"], row["error"]) == ("failed", dispatcher_module.INVALID_HOOKS), bad
    assert daemon.calls == [] and daemon.captured == []


# RETENTION


def old_archives(browser: Browser, job_id: int, count: int) -> list[str]:
    """count archives of the job from 2020 in its storage directory, oldest first."""
    job_uuid = browser.sql("SELECT uuid FROM jobs WHERE id = ?", (job_id,))[0][0]
    root = browser.settings.local_storage_roots[0]
    names = [
        archive_name(job_uuid, "old", datetime(2020, 1, day, tzinfo=UTC), True)
        for day in range(1, count + 1)
    ]
    for name in names:
        (root / name).write_bytes(b"old")
    return names


def stored_names(browser: Browser) -> set[str]:
    return {p.name for p in browser.settings.local_storage_roots[0].iterdir()}


def keep_last(browser: Browser, job_id: int, count: int) -> None:
    policy = json.dumps({"keep_last": count, "mode": "last"})
    browser.sql("UPDATE jobs SET retention = ? WHERE id = ?", (policy, job_id))


async def test_retention_runs_once_the_backup_is_stored(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, _ = await stack_job(admin)
    old = old_archives(admin, job_id, 2)
    keep_last(admin, job_id, 2)
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done"
    new = admin.sql("SELECT archive_name FROM runs WHERE id = ?", (run_id,))[0][0]
    assert stored_names(admin) == {old[1], new}
    assert f"Retention: deleted {old[0]}." in log_text(admin, run_id)


async def test_retention_never_runs_without_a_stored_backup(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, _ = await stack_job(admin)
    old = old_archives(admin, job_id, 3)
    keep_last(admin, job_id, 1)
    daemon.fail_after = "The data read failed."
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "failed"
    assert stored_names(admin) == set(old)
    assert "Retention" not in log_text(admin, run_id)


async def test_retention_is_skipped_when_a_post_hook_failed(admin: Browser, daemon: Daemon) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    attach(admin, job_id, [], [add_hook(admin, "after", host_id, "app")])
    daemon.hook_errors["after"] = "Hook after exited with code 1."
    old = old_archives(admin, job_id, 3)
    keep_last(admin, job_id, 1)
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == (
        "The backup was stored, but a post-hook failed: Hook after exited with code 1."
    )
    assert len(stored_names(admin) - set(old)) == 1 and set(old) <= stored_names(admin)
    assert "Retention skipped: a post-hook failed." in log_text(admin, run_id)


async def test_a_retention_failure_fails_the_run_with_the_backup_stored(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(*standard())
    job_id, _ = await stack_job(admin)
    old = old_archives(admin, job_id, 2)
    admin.sql("UPDATE jobs SET retention = 'nonsense' WHERE id = ?", (job_id,))
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed"
    assert row["error"] == (
        "The backup was stored, but retention did not finish: The retention policy is not valid."
    )
    new = admin.sql("SELECT archive_name FROM runs WHERE id = ?", (run_id,))[0][0]
    assert stored_names(admin) == {*old, new}
    assert backups(admin) == 1
    assert row["stopped"] == []


# LOCKS


async def test_stack_discovery_waits_again_when_members_change(
    admin: Browser, daemon: Daemon
) -> None:
    daemon.add(box("a"), box("b"))
    job_id, host_id = await stack_job(admin, mode="live")
    key = name_key(str(host_id), "project", "app")

    def grow(count: int) -> None:
        if count == 1:  # after the first resolve, before the locks
            daemon.add(box("c"))

    owners: list[str | None] = []
    daemon.after_discover = grow
    daemon.during = lambda cancel: owners.append(dispatcher(admin)._owners.get(key))
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.discovered == 3
    assert daemon.captured[0][0] == [cid("a"), cid("b"), cid("c")]
    assert owners == [f"run {run_id}"]
    text = log_text(admin, run_id)
    assert "Compose project app changed while this run waited; waiting again." in text
    assert "was replaced" not in text


async def test_stack_backup_and_stack_restore_share_the_project_key() -> None:
    key = name_key("d" + "0" * 32, "project", "app")
    doc = {"lock_scope": "d" + "0" * 32, "projects": ["app", "", 7, None]}
    assert dispatcher_module.journal_keys(3, doc) == {key}
    assert dispatcher_module.journal_keys(3, {"projects": "app"}) == set()
    assert dispatcher_module.backup_keys("d" + "0" * 32, [], "app") == [key]
    assert dispatcher_module.backup_keys(3, [Target("c" * 64, "web", True)], "app") == [
        "c" * 64,
        "name:3:container:web",
        "name:3:project:app",
    ]
    assert dispatcher_module.backup_keys(3, [], None) == []
    assert dispatcher_module.lock_subject(key) == "project app"


async def test_stack_backup_waits_for_a_single_container_restore_of_a_member(
    admin: Browser, daemon: Daemon
) -> None:
    # An overwrite restore of db has renamed the original away (discovery skips it) and
    # has not created the new one yet.
    old = box("db-drydock-old", health="healthy", running=False)
    daemon.add(box("app", depends=APP_DEPENDS), box("redis"), old)
    job_id, host_id = await stack_job(admin)
    restore_keys = [
        old["Id"],
        f"name:{host_id}:container:db",
        f"name:{host_id}:container:db-drydock-old",
        f"name:{host_id}:project:app",
    ]
    restore_log = RunLog(admin.settings.data_dir / "logs" / "999.log")
    scope = dispatcher_module.lock_scope({}, host_id)
    held = await dispatcher(admin)._acquire(
        dispatcher_module.scoped(restore_keys, host_id, scope), 999, restore_log
    )
    try:
        run_id = await start_run(admin, job_id)
        await wait_until(
            lambda: "Waiting for run 999 to finish with project app." in log_text(admin, run_id),
            5,
            "the backup waits",
        )
        assert run_status(admin, run_id) == "queued" and daemon.captured == []
        # The restore commits: the new db exists, the original is gone.
        daemon.remove("db-drydock-old")
        daemon.add(box("db", health="healthy"))
    finally:
        dispatcher(admin)._release(held)
    await dispatcher(admin).wait(run_id)
    assert run_row(admin, run_id)["status"] == "done", log_text(admin, run_id)
    assert daemon.captured[0][0] == [cid("db"), cid("redis"), cid("app")]
    assert ("stop", "db") in daemon.calls and ("start", "db") in daemon.calls


# RESTART AND UNPAUSE


async def test_restart_wait_is_cancellable(daemon: Daemon, tmp_path) -> None:
    daemon.add(box("db", health="starting"), box("app"), box("web"))
    cancel = threading.Event()
    timer = threading.Timer(0.2, cancel.set)
    timer.start()
    started = time.monotonic()
    failed = dispatcher_module.restart(
        daemon,
        [
            Target(cid("app"), "app", True, wait_for=(cid("db"),)),
            Target(cid("web"), "web", True, wait_for=(cid("db"),)),
        ],
        RunLog(tmp_path / "1.log"),
        cancel=cancel,
    )
    assert time.monotonic() - started < 1.0
    assert failed == [] and daemon.calls == [("start", "app"), ("start", "web")]
    timer.cancel()


async def test_restart_waits_for_healthy_dependencies_only_when_not_cancelled(
    admin: Browser, daemon: Daemon, waits: list, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    daemon.add(*standard())
    run_log = RunLog(tmp_path / "1.log")
    target = Target(cid("app"), "app", True, wait_for=(cid("db"),))
    assert dispatcher_module.restart(daemon, [target], run_log) == []
    assert waits == [([cid("db")], 0)]
    cancel = threading.Event()
    cancel.set()
    assert dispatcher_module.restart(daemon, [target], run_log, cancel=cancel) == []
    assert len(waits) == 1 and daemon.calls == [("start", "app")] * 2

    # A run cancelled mid-capture starts everything without waiting for health.
    restarted: list[list[Target]] = []

    def spy(api, targets, run_log, cancel=None) -> list[str]:
        restarted.append(list(targets))
        return REAL_RESTART(api, targets, run_log, cancel=cancel)

    def cancelled(cancel: threading.Event) -> None:
        cancel.set()
        raise Cancelled("The run was cancelled.")

    monkeypatch.setattr(dispatcher_module, "restart", spy)
    daemon.during = cancelled
    daemon.calls.clear()
    job_id, _ = await stack_job(admin)
    run_id = await run(admin, job_id)
    assert run_row(admin, run_id)["status"] == "cancelled"
    assert [[(t.name, t.wait_for) for t in ts] for ts in restarted] == [
        [("db", ()), ("redis", ()), ("app", ())]
    ]
    assert len(waits) == 1
    assert "Cancelled. Starting the stopped containers again." in log_text(admin, run_id)


async def test_unpause_treats_gone_and_unpaused_containers_as_done(
    daemon: Daemon, tmp_path
) -> None:
    daemon.add(
        box("a", paused=True),
        box("b", paused=True),
        box("c", paused=True),
        box("d", paused=False),
        box("e", paused=True),
    )
    # Docker answers 500 "is not paused" for a container unpaused meanwhile (b); c is still
    # paused after its 500, so that one failed; e is removed meanwhile.
    daemon.on_call = lambda op, name: meanwhile(daemon, op, name, unpaused="b", removed="e")
    daemon.errors[("unpause", "b")] = api_error(500)
    daemon.errors[("unpause", "c")] = api_error(500)
    daemon.errors[("unpause", "e")] = docker.errors.NotFound("No such container: e")
    run_log = RunLog(tmp_path / "1.log")
    targets = [Target(cid(n), n, True, paused=True) for n in ("a", "b", "c", "d", "e", "gone")]
    assert dispatcher_module.unpause(daemon, targets, run_log) == ["c"]
    assert daemon.calls == [("unpause", n) for n in "abce"]
    text = run_log.path.read_text()
    assert "Unpaused container a." in text and "Container b is not paused any more." in text
    assert "Could not unpause container c: 500 Server Error" in text
    assert "Container d is not paused any more." in text
    assert "Container e no longer exists." in text
    assert "Container gone no longer exists." in text


def meanwhile(daemon: Daemon, op: str, name: str, *, unpaused: str, removed: str = "") -> None:
    """Someone else unpauses or removes the container while drydock unpauses it."""
    if (op, name) == ("unpause", unpaused):
        daemon.boxes[cid(name)]["State"]["Paused"] = False
    elif (op, name) == ("unpause", removed):
        daemon.remove(name)


class FullLog(RunLog):
    """A run log on a full disk."""

    def __call__(self, message: str) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")


async def test_a_log_that_cannot_be_written_does_not_stop_the_undo(
    daemon: Daemon, tmp_path
) -> None:
    daemon.add(box("a", paused=True), box("b", paused=True), box("c", running=False))
    daemon.add(box("d", running=False), box("db", health="starting"))
    run_log = FullLog(tmp_path / "1.log")
    targets = [Target(cid(n), n, True, paused=True) for n in "ab"]
    assert dispatcher_module.unpause(daemon, targets, run_log) == []
    starting = [Target(cid("c"), "c", True, wait_for=(cid("db"),)), Target(cid("d"), "d", True)]
    cancel = threading.Event()
    threading.Timer(0.2, cancel.set).start()  # the health wait logs too
    assert dispatcher_module.restart(daemon, starting, run_log, cancel=cancel) == []
    assert daemon.state_calls() == [
        ("unpause", "a"),
        ("unpause", "b"),
        ("start", "c"),
        ("start", "d"),
    ]


@pytest.mark.parametrize("mode", ["stop", "pause"])
async def test_an_unexpected_error_in_one_undo_pass_keeps_the_other(
    admin: Browser, daemon: Daemon, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    def broken(api, targets, run_log) -> list[str]:
        raise RuntimeError("boom")

    monkeypatch.setattr(dispatcher_module, "unpause", broken)
    daemon.add(*standard())
    job_id, _ = await stack_job(admin, mode=mode)
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    assert row["status"] == "failed" and "RuntimeError" in row["error"]
    if mode == "stop":
        # The restart pass still ran, and its list was rewritten.
        assert [op for op, _ in daemon.state_calls()] == ["stop"] * 3 + ["start"] * 3
        assert row["stopped"] == []
    else:
        # Nothing was unpaused, also when tried again: the list keeps every container,
        # given up on, and the error names them.
        assert [e["name"] for e in row["paused"]] == ["db", "redis", "app"]
        assert all(e["abandoned"] for e in row["paused"])
        assert row["error"] == (
            "Unexpected error (RuntimeError). See the drydock server log. Drydock could not "
            "unpause db, redis, app. Unpause them by hand."
        )


async def test_a_dropped_connection_is_tried_again_while_the_run_holds_its_locks(
    admin: Browser, daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SSH tunnel drops mid-stream: the capture fails, and so does every unpause. The
    run keeps its locks and tries again with a new client until the host answers."""
    monkeypatch.setattr(dispatcher_module, "ROLLBACK_RETRY", 0.05)
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin, mode="pause")
    dropped = requests.exceptions.ConnectionError("Connection aborted.")
    for name in ("db", "redis", "app"):
        daemon.errors[("unpause", name)] = dropped
    daemon.fail_after = "The connection to the host dropped."

    def drop(cancel: threading.Event) -> None:
        daemon.down = True

    daemon.during = drop
    run_id = await start_run(admin, job_id)
    await wait_until(
        lambda: "Drydock keeps trying while it runs" in log_text(admin, run_id), 10, "the retry"
    )
    assert run_status(admin, run_id) == "running"
    assert [e["name"] for e in run_row(admin, run_id)["paused"]] == ["db", "redis", "app"]
    assert dispatcher(admin)._locks[name_key(str(host_id), "project", "app")].locked()
    daemon.errors.clear()
    daemon.down = False
    await dispatcher(admin).wait(run_id)
    row = run_row(admin, run_id)
    # Nothing is left paused, so the error is the capture's own.
    assert (row["status"], row["error"]) == ("failed", "The connection to the host dropped.")
    assert row["paused"] == [] and row["stopped"] == []
    assert daemon.state_calls()[-3:] == [("unpause", n) for n in ("db", "redis", "app")]
    text = log_text(admin, run_id)
    assert "Recovery could not reach the host to unpause db: The tunnel is down." in text
    assert "Unpaused container app." in text


@pytest.mark.parametrize("outcome", ["stored", "failed", "cancelled"])
async def test_what_docker_refuses_to_start_again_is_named_in_the_error(
    admin: Browser, daemon: Daemon, outcome: str
) -> None:
    daemon.add(*standard())
    job_id, host_id = await stack_job(admin)
    daemon.errors[("start", "db")] = api_error(500)
    if outcome == "failed":
        daemon.fail_after = "Reading the data failed."
    elif outcome == "cancelled":

        def cancelled(cancel: threading.Event) -> None:
            cancel.set()
            raise Cancelled("The run was cancelled.")

        daemon.during = cancelled
    run_id = await run(admin, job_id)
    row = run_row(admin, run_id)
    left = "could not start db again. Start it by hand."
    assert (row["status"], row["error"]) == {
        "stored": ("failed", f"The backup was stored, but drydock {left}"),
        "failed": ("failed", f"Reading the data failed. Drydock {left}"),
        "cancelled": ("cancelled", f"The run was cancelled. Drydock {left}"),
    }[outcome]
    assert backups(admin) == (1 if outcome == "stored" else 0)
    # Tried once more with a new client. Docker answered, so it is left to the user, and
    # no later start tries again.
    assert daemon.state_calls().count(("start", "db")) == 2
    assert row["stopped"] == [{**entry(host_id, "db"), "abandoned": True}]


# RECOVERY AND SHUTDOWN


async def recovery_run(settings: Settings, **lists: list[dict]) -> tuple[int, int]:
    """A backup run left running by a crash, with these lists, on a new host entry."""
    async with running(settings) as browser:
        await browser.setup()
        host_id = add_host(browser)
        job_id = await add_job(browser, host_id=str(host_id))
        with browser.app.state.sessionmaker() as db, db.begin():
            run = Run(
                job_id=job_id,
                status="running",
                stopped_containers_json=json.dumps(lists.get("stopped", [])),
                paused_containers_json=json.dumps(lists.get("paused", [])),
            )
            db.add(run)
            db.flush()
            return run.id, host_id


async def test_startup_recovery_unpauses_then_restarts(
    settings: Settings, daemon: Daemon, waits: list
) -> None:
    host = 1  # the first host entry of a fresh database
    stopped = [
        entry(host, "db"),
        entry(host, "app", [cid("db")]),
        {**entry(host, "x1"), "wait_for": "x"},
        {**entry(host, "x2"), "wait_for": [1]},
        {**entry(host, "x3"), "wait_for": [cid("db")] * 300},
        "not an entry",
        {"host_id": "1", "id": cid("x4"), "name": "x4"},
    ]
    paused = [entry(host, "p1"), entry(host, "p2")]
    run_id, host_id = await recovery_run(settings, stopped=stopped, paused=paused)
    assert host_id == host
    daemon.add(
        box("p1", paused=True),
        box("p2", paused=True),
        box("db", health="healthy", running=False),
        box("app", running=False),
        *(box(name, running=False) for name in ("x1", "x2", "x3", "x4")),
    )
    daemon.errors[("unpause", "p2")] = api_error(500)  # unpaused meanwhile
    daemon.on_call = lambda op, name: meanwhile(daemon, op, name, unpaused="p2")
    async with running(settings) as browser:
        await wait_until(
            lambda: run_row(browser, run_id)["stopped"] == [] == run_row(browser, run_id)["paused"],
            10,
            "recovery",
        )
        assert daemon.state_calls() == [
            ("unpause", "p1"),
            ("unpause", "p2"),
            ("start", "db"),
            ("start", "app"),
            ("start", "x1"),
            ("start", "x2"),
            ("start", "x3"),
        ]
        # app waited for db, which had started; the malformed wait_for lists were ignored.
        assert waits == [([cid("db")], 3)]
        row = run_row(browser, run_id)
        assert row["status"] == "interrupted"
        text = log_text(browser, run_id)
        assert "Interrupted" in text and "Unpaused container p1." in text
        assert "Container p2 is not paused any more." in text
        await wait_until(
            lambda: not any(lock.locked() for lock in dispatcher(browser)._locks.values()),
            5,
            "the locks released",
        )


async def test_recovery_tracks_failures_per_run(settings: Settings, daemon: Daemon) -> None:
    run_id, host_id = await recovery_run(
        settings, stopped=[entry(1, "s1"), entry(1, "s2")], paused=[entry(1, "p1")]
    )
    daemon.add(box("s1", running=False), box("s2", running=False), box("p1", paused=True))
    daemon.errors[("start", "s1")] = api_error(500)
    daemon.errors[("unpause", "p1")] = api_error(500)
    async with running(settings) as browser:
        await wait_until(lambda: ("start", "s2") in daemon.calls, 10, "recovery")
        await wait_until(
            lambda: len(run_row(browser, run_id)["stopped"]) == 1, 5, "the stopped list"
        )
        await wait_until(
            lambda: run_row(browser, run_id)["stopped"][0].get("abandoned"), 5, "given up"
        )
        row = run_row(browser, run_id)
        # Docker answered: left to the user, and no later start tries again.
        assert row["stopped"] == [{**entry(host_id, "s1"), "abandoned": True}]
        assert row["paused"] == [{**entry(host_id, "p1"), "abandoned": True}]
        text = log_text(browser, run_id)
        assert (
            "Could not start container s1 again" in text and "Started container s2 again." in text
        )
        assert "Could not unpause container p1" in text


async def test_recovery_reports_an_unreachable_host(settings: Settings, daemon: Daemon) -> None:
    run_id, _ = await recovery_run(settings, stopped=[entry(99, "s1")], paused=[entry(99, "p1")])
    async with running(settings) as browser:
        await wait_until(
            lambda: "could not reach the host to start s1" in log_text(browser, run_id),
            10,
            "recovery",
        )
        text = log_text(browser, run_id)
        assert "Recovery could not reach the host to unpause p1: unknown host" in text
        assert run_row(browser, run_id)["status"] == "interrupted"
        # The host entry does not exist: given up on at once.
        await wait_until(
            lambda: run_row(browser, run_id)["paused"] == [{**entry(99, "p1"), "abandoned": True}],
            5,
            "given up",
        )
        assert "keeps trying" not in log_text(browser, run_id)
    assert daemon.calls == []


async def test_recovery_keeps_trying_while_the_host_is_unreachable(
    settings: Settings, daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dispatcher_module, "RECOVERY_WAIT", 0.2)
    monkeypatch.setattr(dispatcher_module, "RECOVERY_RETRY", 0.05)
    monkeypatch.setattr(dispatcher_module, "ROLLBACK_RETRY", 0.05)
    run_id, host_id = await recovery_run(
        settings, stopped=[entry(1, "s1")], paused=[entry(1, "p1")]
    )
    daemon.add(box("s1", running=False), box("p1", paused=True))
    reachable = threading.Event()

    def open_client(url: str, timeout: int = 60) -> Handle:
        if not reachable.is_set():
            raise docker_client.DockerUnavailable("Connection refused.")
        return Handle(daemon)

    monkeypatch.setattr(docker_client, "open_client", open_client)
    async with running(settings) as browser:
        await wait_until(
            lambda: "Drydock keeps trying while it runs" in log_text(browser, run_id),
            10,
            "the report",
        )
        await anyio.sleep(0.6)  # longer than RECOVERY_WAIT: still trying, still holding
        assert dispatcher(browser)._locks[cid("s1")].locked()
        assert run_row(browser, run_id)["stopped"] == [entry(host_id, "s1")]
        reachable.set()
        await wait_until(
            lambda: run_row(browser, run_id)["stopped"] == [] == run_row(browser, run_id)["paused"],
            10,
            "recovery",
        )
        await wait_until(
            lambda: not any(lock.locked() for lock in dispatcher(browser)._locks.values()),
            5,
            "the locks released",
        )
    assert daemon.state_calls() == [("unpause", "p1"), ("start", "s1")]
    text = log_text(browser, run_id)
    assert text.count("Recovery could not reach the host to start s1: Connection refused.") == 1


async def test_a_later_start_tries_again_what_an_earlier_start_did_not_finish(
    settings: Settings, daemon: Daemon
) -> None:
    """An earlier start stopped while its host was unreachable: it held the containers'
    locks until then, so the lists still describe the host. Not so for entries it gave up
    on, nor for runs that failed or were cancelled."""
    async with running(settings) as browser:
        await browser.setup()
        host_id = add_host(browser)
        job_id = await add_job(browser, host_id=str(host_id))
        lists = {
            "pending": ("interrupted", [entry(host_id, "s1")], [entry(host_id, "p1")]),
            "given up": ("interrupted", [{**entry(host_id, "s2"), "abandoned": True}], []),
            "failed": ("failed", [entry(host_id, "s3")], []),
            "cancelled": ("cancelled", [], [entry(host_id, "p3")]),
        }
        runs: dict[str, int] = {}
        with browser.app.state.sessionmaker() as db, db.begin():
            for label, (status, stopped, paused) in lists.items():
                row = Run(
                    job_id=job_id,
                    status=status,
                    stopped_containers_json=json.dumps(stopped),
                    paused_containers_json=json.dumps(paused),
                )
                db.add(row)
                db.flush()
                runs[label] = row.id
    daemon.add(box("p1", paused=True), box("p3", paused=True))
    daemon.add(*(box(name, running=False) for name in ("s1", "s2", "s3")))
    pending_run = runs["pending"]
    async with running(settings) as browser:
        await wait_until(
            lambda: (
                run_row(browser, pending_run)["stopped"]
                == []
                == run_row(browser, pending_run)["paused"]
            ),
            10,
            "recovery",
        )
        await wait_until(
            lambda: not any(lock.locked() for lock in dispatcher(browser)._locks.values()),
            5,
            "the locks released",
        )
        assert daemon.state_calls() == [("unpause", "p1"), ("start", "s1")]
        assert "trying again to unpause and start" in log_text(browser, pending_run)
        for label, (status, stopped, paused) in lists.items():
            row = run_row(browser, runs[label])
            assert row["status"] == status, label
            if label != "pending":
                assert (row["stopped"], row["paused"]) == (stopped, paused), label


async def test_shutdown_ends_the_health_wait_of_recovery(
    settings: Settings, daemon: Daemon
) -> None:
    run_id, _ = await recovery_run(settings, stopped=[entry(1, "db"), entry(1, "app", [cid("db")])])
    daemon.add(box("db", health="starting", running=False), box("app", running=False))
    async with running(settings) as browser:
        await wait_until(
            lambda: "Waiting for container db to be healthy." in log_text(browser, run_id),
            10,
            "the health wait",
        )
        stopping = time.monotonic()
    # Shutdown ended the wait (HEALTH_WAIT is 120 s), and app still started.
    await wait_until(lambda: ("start", "app") in daemon.calls, 5, "app started")
    assert time.monotonic() - stopping < 5
    assert daemon.state_calls() == [("start", "db"), ("start", "app")]


async def test_recovery_names_the_post_hooks_that_did_not_run(
    settings: Settings, daemon: Daemon
) -> None:
    async with running(settings) as browser:
        await browser.setup()
        host_id = add_host(browser)
        job_id = await add_job(browser, host_id=str(host_id))
        on = add_hook(browser, "maint-on", host_id, "web", project=None)
        off = add_hook(browser, "maint-off", host_id, "web", project=None)
        attach(browser, job_id, [on], [off])
        with browser.app.state.sessionmaker() as db, db.begin():
            runs = [Run(job_id=job_id, status=status) for status in ("running", "queued")]
            db.add_all(runs)
            db.flush()
            started, queued = (r.id for r in runs)
    async with running(settings) as browser:
        notice = "The job's post-hooks (maint-off) did not run. If its pre-hooks ran, undo"
        assert notice in log_text(browser, started)
        assert "post-hooks" not in log_text(browser, queued)
        assert run_row(browser, started)["status"] == "interrupted"


async def test_shutdown_unpauses_and_abandon_leaves_the_run_open(
    settings: Settings, daemon: Daemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dispatcher_module, "SHUTDOWN_WAIT", 1)
    daemon.add(box("a"), box("b"))
    paused, release = threading.Event(), threading.Event()

    def stuck(cancel: threading.Event) -> None:
        paused.set()
        assert release.wait(30)  # a worker that ignores cancel

    daemon.during = stuck
    try:
        async with running(settings) as browser:
            await browser.setup()
            job_id, host_id = await stack_job(browser, mode="pause")
            run_id = await start_run(browser, job_id)
            await wait_until(paused.is_set, 10, "the containers paused")
            old = dispatcher(browser)
        assert daemon.state_calls() == [
            ("pause", "b"),
            ("pause", "a"),
            ("unpause", "a"),
            ("unpause", "b"),
        ]
        row = run_row(browser, run_id)
        assert row["status"] == "running"
        assert row["paused"] == [entry(host_id, "a"), entry(host_id, "b")]
        assert "startup recovery checks its containers again" in log_text(browser, run_id)
        daemon.calls.clear()
        async with running(settings) as browser:
            await wait_until(lambda: run_row(browser, run_id)["paused"] == [], 10, "recovery")
            assert run_row(browser, run_id)["status"] == "interrupted"
            text = log_text(browser, run_id)
            assert "Container a is not paused any more." in text and "Could not" not in text
            assert daemon.state_calls() == []
    finally:
        release.set()
    await old.wait(run_id)
    assert run_status(browser, run_id) == "interrupted"
