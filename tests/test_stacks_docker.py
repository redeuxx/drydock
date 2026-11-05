"""Stacks, consistency modes and hooks against real daemons (see compose.test.yaml).

The Phase 4 exit criteria that need real containers:
- An app + postgres (healthy) + redis Compose stack on the SSH host backed up in stop mode:
  Docker events show the services stopping in reverse order and starting forward, and the
  archive holds the compose files once each, byte for byte.
- Pause mode leaves container uptime unchanged and writes the paused list before the first
  pause; containers already paused or stopped stay that way.
- Live mode never stops or pauses anything.
- A failing pre-hook stops nothing, a hook bound to another project is refused at run time,
  a timed-out post-hook leaves every container running, and hooks run in order around the
  data read with their output logged only when the hook says so.
- kill -9 and SIGTERM of a real drydock process in the middle of a pause, and kill -9 in
  the middle of a stack stop: every container is unpaused or started again (dependencies
  first).

The Compose stacks run on the sshhost dind daemon (it has the Compose CLI and a host
filesystem the tests control); the hooks are project hooks bound to the SSH host entry.
The kill and SIGTERM tests use hand-labelled stacks on the host daemon. Every project made
here is named drydock-test-stack-<hex> and removed afterwards.
"""

import hashlib
import json
import re
import signal
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import docker
import pytest

from drydock.archive import verify
from drydock.config import Settings
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.jobs import runlog
from tests.conftest import Browser, running
from tests.docker_support import (
    BUSYBOX_IMAGE,
    PROJECT_LABEL,
    REDIS_IMAGE,
    STACK_PREFIX,
    Service,
    add_hook,
    add_ssh_host,
    compose_down,
    compose_stack,
    event_times,
    helpers_left,
    host_docker,
    labelled_stack,
    needs_docker,
    needs_ssh,
    recorded_events,
    remove_stack,
    sh,
    started_ns,
    wait_until,
)
from tests.test_capture import (
    dind,  # noqa: F401 (the fixture make_stack uses)
    needs_dind,
)
from tests.test_restore_docker import archived_volume
from tests.test_runs_docker import (
    PG_IMAGE,
    App,
    db_status,
    read_archive,
    setup_app,
    staged_files,
    start_drydock,
)

pytestmark = [pytest.mark.anyio, needs_docker]

SERVICES = ("db", "redis", "app")  # in start order
DB_DIR = "/var/lib/postgresql"  # where postgres 18 keeps its volume
LIVE_WARNING = "crash-consistent at best"
# The state changes a backup makes, by container ID or name.
STATE_RE = re.compile(r"(?:/v[\d.]+)?/containers/([^/]+)/(stop|pause|unpause|kill|restart|start)")
COMPOSE = """\
services:
  db:
    image: {pg}
    environment:
      POSTGRES_PASSWORD: ${{DB_PASSWORD}}
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres", "-h", "127.0.0.1"]
      interval: 1s
      retries: 30
    volumes:
      - dbdata:/var/lib/postgresql
  redis:
    image: {redis}
  app:
    image: {busybox}
    command: ["sleep", "3600"]
    init: true
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    links:
      - redis
{extra}volumes:
  dbdata: {{}}
"""
# For the pause test: a member to pause and one to stop before the backup.
IDLE_AND_SPARE = """\
  idle:
    image: {busybox}
    command: ["sleep", "3600"]
    init: true
  spare:
    image: {busybox}
    command: ["sleep", "3600"]
    init: true
"""


# THE COMPOSE STACK ON THE SSH HOST


@dataclass
class Stack:
    """A Compose project on the sshhost daemon, its files in root, and the projects
    restores made from it (removed with it)."""

    handle: docker_client.DockerHandle  # the sshhost daemon over plain TCP
    box: Any  # the sshhost container, its host
    root: str
    project: str
    password: str
    copies: list[str] = field(default_factory=list)

    @property
    def api(self):
        return self.handle.client.api

    def name(self, service: str) -> str:
        return f"{self.project}-{service}-1"

    def inspect(self, service: str) -> dict[str, Any]:
        return self.api.inspect_container(self.name(service))

    def refs(self) -> set[str]:
        """The IDs and names of every member, as a request path names them."""
        found = self.api.containers(all=True, filters={"label": f"{PROJECT_LABEL}={self.project}"})
        return {c["Id"] for c in found} | {c["Names"][0].lstrip("/") for c in found}

    def uptimes(self, services=SERVICES) -> dict[str, tuple[str, int, int]]:
        """What a stop or restart changes: StartedAt, the PID and the restart count."""
        found = {}
        for service in services:
            info = self.inspect(service)
            found[service] = (
                info["State"]["StartedAt"],
                info["State"]["Pid"],
                info["RestartCount"],
            )
        return found

    def running(self, services=SERVICES) -> bool:
        states = [self.inspect(service)["State"] for service in services]
        return all(s["Running"] and not s["Paused"] for s in states)

    def copy_name(self) -> str:
        """A new project or container name for a restore; removed with the stack."""
        name = f"drydock-test-run-{uuid.uuid4().hex[:10]}"
        self.copies.append(name)
        return name


def stack_files(password: str, extra: str = "") -> dict[str, str]:
    images = {"pg": PG_IMAGE, "redis": REDIS_IMAGE, "busybox": BUSYBOX_IMAGE}
    extra = extra.format(**images)
    return {
        "compose.yaml": COMPOSE.format(extra=extra, **images),
        ".env": f"DB_PASSWORD={password}\n",
    }


@pytest.fixture
def make_stack(request: pytest.FixtureRequest) -> Iterator[Callable[..., Stack]]:
    """Starts the db + redis + app stack in tests.test_capture's dind scratch directory on
    sshhost; extra adds services. One stack per test (its files are root/compose.yaml and
    root/.env)."""
    handle, box, root = request.getfixturevalue("dind")
    for image in (PG_IMAGE, REDIS_IMAGE):
        helper.ensure_image(handle.client, image)  # pulls only if the daemon lacks it
    made: list[Stack] = []

    def make(extra: str = "") -> Stack:
        assert not made, "one stack per test"
        stack = Stack(handle, box, root, f"{STACK_PREFIX}{uuid.uuid4().hex[:10]}", uuid.uuid4().hex)
        made.append(stack)
        compose_stack(box, root, stack.project, stack_files(stack.password, extra))
        return stack

    try:
        yield make
    finally:
        for stack in made:
            for name in [*stack.copies, stack.project]:
                compose_down(box, root, name)


async def stack_job(
    app: App,
    stack: Stack,
    host_id: int,
    mode: str,
    *,
    pre: tuple[str, ...] = (),
    post: tuple[str, ...] = (),
) -> int:
    """A stack job for the project (scope all, unencrypted so the test can read it), with
    hooks attached by name through the job form. The pinned images are in Docker Hub, so
    they are archived by reference only, which keeps the backup small."""
    return await app.add_job(
        stack.project,
        "all",
        host_id=str(host_id),
        target_type="stack",
        consistency_mode=mode,
        encrypted="",
        images_reference_only_if_pullable="1",
        pre_hooks="\n".join(pre),
        post_hooks="\n".join(post),
    )


class Spy:
    """Records the method and path of every request docker-py sends, and calls on_send
    first."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        on_send: Callable[[str, str], None] | None = None,
    ) -> None:
        self.seen: list[tuple[str, str]] = []
        real_send = docker.APIClient.send

        def send(client, request, **kwargs):
            self.seen.append((request.method, request.path_url))
            if on_send is not None:
                on_send(request.method, request.path_url)
            return real_send(client, request, **kwargs)

        monkeypatch.setattr(docker.APIClient, "send", send)

    def state_calls(self, refs: set[str]) -> list[str]:
        """The stop, pause, unpause, kill, restart and start calls on containers in refs."""
        return [
            f"{match.group(2)} {match.group(1)}"
            for method, url in self.seen
            if method == "POST"
            and (match := STATE_RE.fullmatch(url.split("?")[0]))
            and match.group(1) in refs
        ]


async def ssh_app(browser: Browser) -> tuple[App, int]:
    """The app with local storage and the SSH host entry for sshhost."""
    app = await setup_app(browser)
    return app, await add_ssh_host(browser)


# STOP MODE ON THE SSH HOST


@needs_ssh
@needs_dind
async def test_stack_stop_mode_on_the_ssh_host_orders_stop_and_start(
    settings: Settings, make_stack
) -> None:
    stack = make_stack()
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        job_id = await stack_job(app, stack, ssh_id, "stop")
        with recorded_events(stack.box, stack.project) as events:
            run_id = await app.run(job_id)
        row = app.run_row(run_id)
        log = app.log(run_id)
        assert row["status"] == "done", log
        path = settings.local_storage_roots[0] / row["archive_name"]
        manifest = verify.verify_file(path, browser.app.state.crypto).manifest
    assert stack.password not in log  # the env value of db and the .env file
    assert stack.running(), log
    stops, starts = event_times(events, "stop"), event_times(events, "start")
    assert {s: len(t) for s, t in stops.items()} == dict.fromkeys(SERVICES, 1), events
    assert {s: len(t) for s, t in starts.items()} == dict.fromkeys(SERVICES, 1), events
    assert stops["app"][0] < min(stops["db"][0], stops["redis"][0]), events
    assert max(starts["db"][0], starts["redis"][0]) < starts["app"][0], events
    healthy = event_times(events, "health_status: healthy").get("db", [])
    assert any(starts["db"][0] < t < starts["app"][0] for t in healthy), events

    assert manifest.job.target_type == "stack" and manifest.job.project == stack.project
    assert sorted(c.name for c in manifest.containers) == sorted(map(stack.name, SERVICES))
    # Every member names the same files: each is archived once.
    paths = [f.host_path for f in manifest.compose_files]
    assert sorted(paths) == [f"{stack.root}/.env", f"{stack.root}/compose.yaml"], paths
    _, small = read_archive(path, keep=("compose/",))
    for entry in manifest.compose_files:
        host_sum = sh(stack.box, 'sha256sum "$1"', entry.host_path).split()[0]
        assert hashlib.sha256(small[entry.member]).hexdigest() == host_sum, entry


# PAUSE AND LIVE


@needs_ssh
@needs_dind
async def test_pause_mode_keeps_uptime_and_lists_before_pausing(
    settings: Settings, make_stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = make_stack(IDLE_AND_SPARE)
    idle, spare = stack.name("idle"), stack.name("spare")
    sh(stack.box, 'docker pause "$1" && docker stop "$2" >/dev/null', idle, spare)
    before = stack.uptimes()
    listed: list[str] = []
    async with running(settings) as browser:

        def on_send(method: str, url: str) -> None:
            # The first pause: what the run row lists at that moment.
            if method == "POST" and not listed and url.split("?")[0].endswith("/pause"):
                query = "SELECT paused_containers_json FROM runs ORDER BY id DESC LIMIT 1"
                listed.append(browser.sql(query)[0][0])

        Spy(monkeypatch, on_send)
        app, ssh_id = await ssh_app(browser)
        job_id = await stack_job(app, stack, ssh_id, "pause")
        with recorded_events(stack.box, stack.project) as events:
            run_id = await app.run(job_id)
        row = app.run_row(run_id)
        log = app.log(run_id)
    assert row["status"] == "done", log
    assert stack.uptimes() == before, log
    assert stack.running(), log
    changes = [e for e in events if e["Action"] in ("stop", "kill", "die", "start")]
    assert changes == [], changes
    # Listed before the first pause: exactly the running, unpaused members, forward order.
    assert len(listed) == 1, log
    assert [e["name"] for e in json.loads(listed[0])] == list(map(stack.name, SERVICES))
    assert json.loads(row["paused_containers_json"]) == []
    pauses, unpauses = event_times(events, "pause"), event_times(events, "unpause")
    assert sorted(pauses) == sorted(unpauses) == sorted(SERVICES), events
    assert pauses["app"][0] < min(pauses["db"][0], pauses["redis"][0]), events
    assert unpauses["app"][0] > max(unpauses["db"][0], unpauses["redis"][0]), events
    # Already paused or stopped: left as they were.
    assert stack.inspect("idle")["State"]["Paused"]
    assert stack.inspect("spare")["State"]["Status"] == "exited"
    assert f"Container {idle} is paused; it stays paused." in log
    assert f"Container {spare} is not running; it stays stopped." in log


@needs_ssh
@needs_dind
async def test_live_mode_never_stops_or_pauses(
    settings: Settings, make_stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = make_stack()
    before = stack.uptimes()
    spy = Spy(monkeypatch)
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        run_id = await app.run(await stack_job(app, stack, ssh_id, "live"))
        row = app.run_row(run_id)
        log = app.log(run_id)
    assert row["status"] == "done", log
    assert spy.state_calls(stack.refs()) == [], log
    assert stack.uptimes() == before, log
    assert LIVE_WARNING in log


# HOOKS


@needs_ssh
@needs_dind
async def test_failing_pre_hook_stops_nothing(
    settings: Settings, make_stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = make_stack()
    before = stack.uptimes()
    spy = Spy(monkeypatch)
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        await add_hook(
            browser,
            name="fails",
            host_id=ssh_id,
            project=stack.project,
            container="app",
            argv=["sh", "-c", "exit 3"],
        )
        run_id = await app.run(await stack_job(app, stack, ssh_id, "stop", pre=("fails",)))
        row = app.run_row(run_id)
        log = app.log(run_id)
    assert row["status"] == "failed", log
    assert "exit code 3" in row["error"], row["error"]
    assert spy.state_calls(stack.refs()) == [], log
    assert "Stopping container" not in log
    assert stack.uptimes() == before, log


@needs_ssh
@needs_dind
async def test_hook_bound_to_another_project_is_refused_at_run_time(
    settings: Settings, make_stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    stack = make_stack()
    before = stack.uptimes()
    spy = Spy(monkeypatch)
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        hook_id = await add_hook(
            browser,
            name="dump",
            host_id=ssh_id,
            project=stack.project,
            container="app",
            argv=["true"],
        )
        job_id = await stack_job(app, stack, ssh_id, "stop", pre=("dump",))
        # Past the routes, which check the binding on every save.
        browser.sql("UPDATE hooks SET project = 'other' WHERE id = ?", (hook_id,))
        run_id = await app.run(job_id)
        row = app.run_row(run_id)
        log = app.log(run_id)
    assert row["status"] == "failed", log
    assert "is for Compose project other" in row["error"], row["error"]
    assert spy.state_calls(stack.refs()) == [], log
    assert "Running pre-hook" not in log
    assert stack.uptimes() == before, log


@needs_ssh
@needs_dind
async def test_hook_timeout_leaves_every_container_running(settings: Settings, make_stack) -> None:
    stack = make_stack()
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        await add_hook(
            browser,
            name="slow",
            host_id=ssh_id,
            project=stack.project,
            container="app",
            argv=["sleep", "3600"],
            timeout_s=2,
        )
        job_id = await stack_job(app, stack, ssh_id, "stop", post=("slow",))
        started = time.monotonic()
        run_id = await app.run(job_id)
        elapsed = time.monotonic() - started
        row = app.run_row(run_id)
        log = app.log(run_id)
        catalogued = browser.sql("SELECT name FROM backups")
    assert row["status"] == "failed", log
    assert "a post-hook failed" in row["error"] and "timed out" in row["error"], row["error"]
    # Loose on purpose: the whole stop run is slow on CI; this only shows the 3600 s sleep ended.
    assert elapsed < 600, log
    assert stack.running(), log
    assert row["archive_name"] and (settings.local_storage_roots[0] / row["archive_name"]).exists()
    assert catalogued == [(row["archive_name"],)]


@needs_ssh
@needs_dind
async def test_hooks_run_in_order_around_the_data_read(settings: Settings, make_stack) -> None:
    stack = make_stack()
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        common = {"host_id": ssh_id, "project": stack.project}
        await add_hook(
            browser,
            name="marker",
            container="db",
            argv=["sh", "-c", f"date +%s > {DB_DIR}/marker"],
            **common,
        )
        await add_hook(
            browser,
            name="shown",
            container="app",
            argv=["echo", "post-ran"],
            log_output=True,
            **common,
        )
        await add_hook(
            browser, name="hidden", container="app", argv=["echo", "hidden-text"], **common
        )
        job_id = await stack_job(
            app, stack, ssh_id, "stop", pre=("marker",), post=("shown", "hidden")
        )
        run_id = await app.run(job_id)
        row = app.run_row(run_id)
        log = app.log(run_id)
        assert row["status"] == "done", log
        archived = archived_volume(settings, row["archive_name"], f"{stack.project}_dbdata")
    lines = log.splitlines()

    def index(text: str, last: bool = False) -> int:
        found = [n for n, line in enumerate(lines) if text in line]
        assert found, (text, log)
        return found[-1] if last else found[0]

    # The pre-hook ran before the first stop, and the archive holds what it wrote.
    assert index("Running pre-hook marker in container") < index("Stopping container")
    assert "marker" in archived, sorted(archived)
    # Post-hooks run after every container was started again, in order.
    assert index("Started container", last=True) < index("Running post-hook shown")
    assert index("Running post-hook shown") < index("[shown] post-ran")
    assert index("[shown] post-ran") < index("Running post-hook hidden")
    assert (
        "Hook hidden wrote 12 bytes to standard output and 0 bytes to standard error; "
        "hook output is not logged."
    ) in log
    assert "hidden-text" not in log


# A REAL DRYDOCK PROCESS, KILLED OR STOPPED MID-PAUSE OR MID-STOP

# db holds 1 GiB, so the capture runs long enough to stop drydock in the middle of it.
CHAIN = (
    Service("db", mib=1024),
    Service("cache", depends_on="db:service_started:false"),
    Service("app", depends_on="cache:service_started:false,db:service_started:false"),
)


@pytest.fixture
def host_stack() -> Iterator[tuple[docker.DockerClient, str]]:
    """The host daemon (through the socket proxy) and a project name, removed afterwards."""
    handle = host_docker()
    project = f"{STACK_PREFIX}{uuid.uuid4().hex[:10]}"
    try:
        yield handle.client, project
    finally:
        remove_stack(handle.client, project)
        handle.close()


async def prepare_stack_job(settings: Settings, project: str, mode: str) -> tuple[int, str]:
    async with running(settings) as browser:
        app = await setup_app(browser)
        job_id = await app.add_job(
            project, "data", target_type="stack", consistency_mode=mode, encrypted=""
        )
        return job_id, app.instance_id


LISTS = {
    "paused": "SELECT paused_containers_json FROM runs ORDER BY id DESC LIMIT 1",
    "stopped": "SELECT stopped_containers_json FROM runs ORDER BY id DESC LIMIT 1",
}


def last_run(settings: Settings, which: str) -> str | None:
    """The paused or stopped list of the newest run, read while another process writes."""
    try:
        with closing(sqlite3.connect(settings.data_dir / "drydock.db", timeout=5)) as conn:
            row = conn.execute(LISTS[which]).fetchone()
    except sqlite3.OperationalError:
        return None
    return row[0] if row else None


def states(client, members) -> list[dict[str, Any]]:
    return [client.api.inspect_container(c.id)["State"] for c in members]


def run_log_text(settings: Settings) -> str:
    path = runlog.log_path(settings.data_dir, 1)
    return path.read_text() if path.exists() else ""


@pytest.mark.parametrize("how", ["kill", "term"])
async def test_drydock_dies_or_stops_mid_pause(
    settings: Settings, host_stack, tmp_path: Path, how: str
) -> None:
    client, project = host_stack
    members = labelled_stack(client, project, CHAIN)
    job_id, instance_id = await prepare_stack_job(settings, project, "pause")
    output = tmp_path / "drydock.out"
    proc = start_drydock(settings, job_id, output)
    try:

        def pausing() -> bool:
            assert proc.poll() is None, output.read_text()
            return (
                last_run(settings, "paused") not in (None, "[]")
                and all(s["Paused"] for s in states(client, members))
                and any(n.startswith("member-") for n in staged_files(settings))
            )

        await wait_until(pausing, 120, "the backup to pause the stack and stage its volume")
        if how == "kill":
            proc.send_signal(signal.SIGKILL)
            proc.wait(timeout=10)
            # Nothing ran after the kill: every member is still paused.
            assert all(s["Paused"] for s in states(client, members))
            async with running(settings):

                def unpaused() -> bool:
                    return not any(s["Paused"] for s in states(client, members)) and (
                        last_run(settings, "paused") == "[]"
                    )

                await wait_until(unpaused, 60, "recovery unpausing the stack")
                assert db_status(settings) == "interrupted"
                log = run_log_text(settings)
                assert "Interrupted" in log, log
                for member in members:
                    assert f"Unpaused container {member.name}." in log, log
                assert staged_files(settings) == []
                await wait_until(lambda: not helpers_left(client, instance_id), 30, "the reaper")
        else:
            proc.send_signal(signal.SIGTERM)  # what `docker compose stop` sends to PID 1
            code = proc.wait(timeout=90)
            # uvicorn re-raises the signal once its graceful shutdown (lifespan included) ends.
            assert code in (0, -signal.SIGTERM), output.read_text()
            assert not any(s["Paused"] for s in states(client, members)), run_log_text(settings)
            assert db_status(settings) == "cancelled"
            assert last_run(settings, "paused") == "[]"
            assert staged_files(settings) == []
            assert helpers_left(client, instance_id) == []
        assert all(s["Running"] for s in states(client, members))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


async def test_drydock_killed_mid_stack_stop_restarts_every_container(
    settings: Settings, host_stack, tmp_path: Path
) -> None:
    client, project = host_stack
    members = labelled_stack(client, project, CHAIN)
    job_id, instance_id = await prepare_stack_job(settings, project, "stop")
    output = tmp_path / "drydock.out"
    proc = start_drydock(settings, job_id, output)
    try:

        def stopped() -> bool:
            assert proc.poll() is None, output.read_text()
            return not any(s["Running"] for s in states(client, members)) and any(
                n.startswith("member-") for n in staged_files(settings)
            )

        await wait_until(stopped, 120, "the backup to stop the stack and stage its volume")
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
        assert not any(s["Running"] for s in states(client, members))
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    async with running(settings):

        def restarted() -> bool:
            return all(s["Running"] for s in states(client, members)) and (
                last_run(settings, "stopped") == "[]"
            )

        await wait_until(restarted, 60, "recovery starting the stack again")
        assert db_status(settings) == "interrupted"
        log = run_log_text(settings)
        assert "Interrupted" in log, log
        for member in members:
            assert f"Started container {member.name} again." in log, log
        assert staged_files(settings) == []
        await wait_until(lambda: not helpers_left(client, instance_id), 30, "the reaper")
    # Started again dependencies first: db, then cache, then app.
    infos = [client.api.inspect_container(c.id) for c in members]
    assert [i["Name"].lstrip("/") for i in infos] == [f"{project}-{s.name}-1" for s in CHAIN]
    times = [started_ns(info) for info in infos]
    assert times == sorted(times) and len(set(times)) == len(times), times
