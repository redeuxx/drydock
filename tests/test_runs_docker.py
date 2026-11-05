"""Backup runs against the host daemon through the socket proxy (see compose.test.yaml).

The Phase 2 exit criteria that need real containers: a Postgres database backed up in
every scope, cancel latency, a full disk, a container job and a stack job on the same
container, kill -9 and SIGTERM of a real drydock process in the middle of a backup, and
memory during a 5 GiB encrypted backup. Every container and volume made here carries the
drydock.test label and is removed afterwards.
"""

import base64
import dataclasses
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from collections.abc import Iterator
from compression import zstd
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import anyio
import docker
import pytest
import requests

from drydock.archive import manifest as m
from drydock.archive import verify
from drydock.archive.writer import ArchiveResult
from drydock.config import DEFAULT_HELPER_IMAGE, Settings
from drydock.crypto import Crypto
from drydock.engine import capture
from drydock.hosts import helper
from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs import runlog
from drydock.models import Host
from drydock.storage.local import LocalStorage
from tests.conftest import Browser, make_settings, running
from tests.docker_support import (
    DOCKER_URL,
    TEST_LABEL,
    helpers_left,
    host_docker,
    needs_docker,
    wait_until,
)

pytestmark = [pytest.mark.anyio, needs_docker]

IMAGE = DEFAULT_HELPER_IMAGE
# postgres:18-alpine, pinned by its multi-arch index digest.
PG_IMAGE = "postgres@sha256:4da1a4828be12604092fa55311276f08f9224a74a62dcb4708bd7439e2a03911"
SENTINEL = "SENTINEL-7e1f0a-run-secret"
SMALL_DIR = os.environ.get("DRYDOCK_TEST_SMALL_DIR", "")
MIB = 1024 * 1024


# CONTAINERS AND VOLUMES


class Targets:
    """Creates labelled containers and volumes on the host daemon and removes them later."""

    def __init__(self, client: docker.DockerClient) -> None:
        self.client = client
        self.containers: list = []
        self.volumes: list = []

    def volume(self, mib: int = 0):
        volume = self.client.volumes.create(
            f"drydock-test-run-{uuid.uuid4().hex[:10]}", labels={TEST_LABEL: "1"}
        )
        self.volumes.append(volume)
        script = "printf 'volume data' > /v/secret.txt && chown 999:999 /v/secret.txt"
        script += " && chmod 0600 /v/secret.txt"
        if mib:
            script += f" && dd if=/dev/urandom of=/v/big bs=1M count={mib} 2>/dev/null"
        # Runs as root with Docker's default capabilities (it must chown); never a helper.
        filler = self.client.containers.create(
            IMAGE,
            ["sh", "-c", script],
            mounts=[docker.types.Mount("/v", volume.name, type="volume")],
            network_mode="none",
            labels={TEST_LABEL: "1"},
        )
        try:
            filler.start()
            assert filler.wait(timeout=600)["StatusCode"] == 0
        finally:
            filler.remove(force=True)
        return volume

    def container(self, image: str = IMAGE, command=("sleep", "3600"), volume=None, **kwargs):
        mount = kwargs.pop("mount", "/data")
        mounts = [docker.types.Mount(mount, volume.name, type="volume")] if volume else []
        kwargs.setdefault("init", command is not None)  # sleep as PID 1 would ignore SIGTERM
        container = self.client.containers.create(
            image,
            list(command) if command else None,
            name=f"drydock-test-run-{uuid.uuid4().hex[:10]}",
            mounts=mounts,
            labels={TEST_LABEL: "1"},
            **kwargs,
        )
        self.containers.append(container)
        container.start()
        return container

    def running(self, container) -> bool:
        return self.client.api.inspect_container(container.id)["State"]["Running"]

    def cleanup(self) -> None:
        for container in self.containers:
            container.remove(force=True)
        for volume in self.volumes:
            volume.remove(force=True)


@pytest.fixture
def targets() -> Iterator[Targets]:
    handle = host_docker()
    made = Targets(handle.client)
    try:
        yield made
    finally:
        made.cleanup()
        handle.close()


# APP


@dataclass
class App:
    browser: Browser
    host_id: int
    storage_id: int

    @property
    def settings(self) -> Settings:
        return self.browser.settings

    @property
    def instance_id(self) -> str:
        return self.browser.app.state.hosts.instance_id

    def status(self, run_id: int) -> str:
        return self.browser.sql("SELECT status FROM runs WHERE id = ?", (run_id,))[0][0]

    def run_row(self, run_id: int) -> dict:
        with closing(self.browser.db()) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone())

    def log(self, run_id: int) -> str:
        path = runlog.log_path(self.settings.data_dir, run_id)
        return path.read_text() if path.exists() else ""

    async def add_job(self, target: str, scope: str, name: str | None = None, **fields) -> int:
        form = {
            "name": name or f"job-{uuid.uuid4().hex[:8]}",
            "host_id": str(self.host_id),
            "target": target,
            "storage_target_id": str(self.storage_id),
            "scope": scope,
            "encrypted": "1",
            "enabled": "1",
        } | fields
        response = await self.browser.post("/jobs", form)
        assert response.status_code == 303, response.text
        return int(response.headers["location"].rsplit("/", 1)[1])

    async def start(self, job_id: int) -> int:
        response = await self.browser.post(f"/jobs/{job_id}/run")
        assert response.status_code == 303, response.text
        return int(response.headers["location"].rsplit("/", 1)[1])

    async def run(self, job_id: int) -> int:
        run_id = await self.start(job_id)
        await self.browser.app.state.dispatcher.wait(run_id)
        return run_id


async def setup_app(browser: Browser) -> App:
    response = await browser.setup()
    assert response.status_code == 303
    with browser.app.state.sessionmaker() as db, db.begin():
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        db.add(host)
        db.flush()
        host_id = host.id
    root = str(browser.settings.local_storage_roots[0])
    response = await browser.post("/storage", {"name": "local", "path": root, "enabled": "1"})
    assert response.status_code == 303, response.text
    storage_id = int(response.headers["location"].rsplit("/", 1)[1])
    return App(browser, host_id, storage_id)


def staged_files(settings: Settings) -> list[str]:
    staging = settings.staging_dir
    return sorted(p.name for p in staging.iterdir()) if staging.exists() else []


def stored_files(settings: Settings) -> list[str]:
    return sorted(p.name for p in settings.local_storage_roots[0].iterdir())


def read_archive(path: Path, keep: tuple[str, ...] = ("config/", "manifest.json")):
    """Member names in order, and the contents of the small members named by keep."""
    names, small = [], {}
    with zstd.ZstdFile(path) as plain, tarfile.open(fileobj=plain, mode="r|") as tar:
        for info in tar:
            names.append(info.name)
            if info.name.startswith(keep):
                small[info.name] = tar.extractfile(info).read()  # type: ignore[union-attr]
    return names, small


# POSTGRES IN EVERY SCOPE


def pg_ready(container) -> bool:
    code, _ = container.exec_run(["pg_isready", "-U", "postgres", "-h", "127.0.0.1"])
    return code == 0


async def test_postgres_backup_in_every_scope(settings: Settings, targets: Targets) -> None:
    helper.ensure_image(targets.client, PG_IMAGE)  # pulls only if the host lacks it
    volume = targets.volume()
    pg = targets.container(
        PG_IMAGE,
        command=None,
        volume=volume,
        mount="/var/lib/postgresql",
        environment={"POSTGRES_PASSWORD": SENTINEL},
    )
    await wait_until(lambda: pg_ready(pg), 90, "postgres to accept connections")
    code, output = pg.exec_run(
        ["psql", "-U", "postgres", "-c", "CREATE TABLE t (v text); INSERT INTO t VALUES ('kept');"]
    )
    assert code == 0, output
    pg.reload()
    image_hex = pg.attrs["Image"].removeprefix("sha256:")
    config = [
        f"config/containers/{pg.id}.json",
        f"config/images/{image_hex}.json",
        f"config/volumes/{volume.name}.json",
    ]
    data = [f"volumes/{volume.name}.tar"]
    images = [f"images/{image_hex}.tar"]
    expected = {"config": config, "data": data, "image": images, "all": config + data + images}

    async with running(settings) as browser:
        app = await setup_app(browser)
        for scope, members in expected.items():
            job_id = await app.add_job(pg.name, scope, name=f"postgres {scope}", encrypted="")
            run_id = await app.run(job_id)
            row = app.run_row(run_id)
            assert row["status"] == "done", (scope, row["error"], app.log(run_id))
            path = settings.local_storage_roots[0] / row["archive_name"]
            assert path.stat().st_size == row["size"]
            assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
            names, small = read_archive(path)
            assert names == [m.MANIFEST_NAME, *members, m.CHECKSUMS_NAME], scope
            verified = verify.verify_file(path, browser.app.state.crypto)
            assert verified.signed and verified.manifest.members == members
            if config[0] in small:
                # The env secret is in the archive (which is why encryption is the default) ...
                assert SENTINEL.encode() in small[config[0]]
            # ... but never in the run log or any page.
            assert SENTINEL not in app.log(run_id)
            for page in (f"/runs/{run_id}", f"/runs/{run_id}/log", f"/jobs/{job_id}"):
                assert SENTINEL not in (await browser.get(page)).text, page
            assert "Stopping container" in app.log(run_id)
            assert targets.running(pg)
            await wait_until(lambda: pg_ready(pg), 60, "postgres after the backup")
            assert staged_files(settings) == []
        for page in ("/runs", "/jobs", "/backups"):
            assert SENTINEL not in (await browser.get(page)).text, page
        backups = browser.sql("SELECT COUNT(*) FROM backups WHERE signed = 1 AND encrypted = 0")
        assert backups == [(4,)]
        assert helpers_left(targets.client, app.instance_id) == []
    code, output = pg.exec_run(["psql", "-U", "postgres", "-tAc", "SELECT v FROM t"])
    assert code == 0 and output.strip() == b"kept"


# CANCEL


# A latency ceiling: CI's shared runner cannot hold it (run it locally).
@pytest.mark.slow
async def test_cancel_takes_effect_within_five_seconds(
    settings: Settings, targets: Targets
) -> None:
    box = targets.container(volume=targets.volume(mib=1024))
    async with running(settings) as browser:
        app = await setup_app(browser)
        job_id = await app.add_job(box.name, "data")
        run_id = await app.start(job_id)
        await wait_until(lambda: "Saving volume" in app.log(run_id), 60, "the volume capture")
        await anyio.sleep(1)
        assert not targets.running(box)
        started = time.monotonic()
        response = await browser.post(f"/runs/{run_id}/cancel")
        assert response.status_code == 303
        await wait_until(lambda: targets.running(box), 10, "the container to run again")
        restored = time.monotonic() - started
        # The run ends once the helper is gone. Docker Desktop's daemon releases a helper
        # whose archive stream was cut off only after it has read the rest of the volume.
        await wait_until(lambda: app.status(run_id) == "cancelled", 60, "the run to end")
        ended = time.monotonic() - started
        print(
            f"\nCANCEL: container running again {restored:.2f} s after the request, "
            f"run cancelled after {ended:.2f} s"
        )
        assert restored < 5
        log = app.log(run_id)
        assert log.index("Cancelled.") < log.index("Started container")
        assert staged_files(settings) == []
        assert stored_files(settings) == []
        assert helpers_left(targets.client, app.instance_id) == []


# A latency ceiling: CI's shared runner cannot hold it (run it locally).
@pytest.mark.slow
async def test_cancel_while_a_container_stops(settings: Settings, targets: Targets) -> None:
    """A stop cannot be interrupted without killing the container early, so a cancel that
    arrives while it stops starts the container again as soon as the stop returns."""
    grace = 4
    volume = targets.volume()
    # sleep as PID 1 without an init ignores SIGTERM: the daemon waits the full grace.
    # The high-level create has no stop_timeout, so the container is made with the API.
    api = targets.client.api
    created = api.create_container(
        IMAGE,
        ["sleep", "3600"],
        name=f"drydock-test-run-{uuid.uuid4().hex[:10]}",
        labels={TEST_LABEL: "1"},
        stop_timeout=grace,
        host_config=api.create_host_config(
            mounts=[docker.types.Mount("/data", volume.name, type="volume")]
        ),
    )
    box = targets.client.containers.get(created["Id"])
    targets.containers.append(box)
    box.start()
    async with running(settings) as browser:
        app = await setup_app(browser)
        job_id = await app.add_job(box.name, "data")
        run_id = await app.start(job_id)
        await wait_until(lambda: "Stopping container" in app.log(run_id), 60, "the stop")
        started = time.monotonic()
        assert (await browser.post(f"/runs/{run_id}/cancel")).status_code == 303
        await wait_until(lambda: app.status(run_id) == "cancelled", grace + 30, "the run to end")
        await wait_until(lambda: targets.running(box), 10, "the container to run again")
        restored = time.monotonic() - started
        print(f"\nCANCEL DURING STOP: container running again after {restored:.2f} s")
        assert restored < grace + 5
        log = app.log(run_id)
        assert log.index("Cancelled.") < log.index("Started container")
        assert "Saving volume" not in log
        assert stored_files(settings) == []
        assert helpers_left(targets.client, app.instance_id) == []


async def test_a_stop_call_that_fails_still_starts_the_container(
    settings: Settings, targets: Targets, monkeypatch
) -> None:
    """The daemon may still stop a container after the stop call failed (an HTTP timeout,
    a proxy error), so drydock starts it again anyway."""
    real_stop = docker.APIClient.stop

    def stop_then_time_out(self, container, timeout=None):
        real_stop(self, container, timeout=timeout)
        raise requests.exceptions.ReadTimeout("read timed out")

    monkeypatch.setattr(docker.APIClient, "stop", stop_then_time_out)
    box = targets.container(volume=targets.volume())
    async with running(settings) as browser:
        app = await setup_app(browser)
        run_id = await app.run(await app.add_job(box.name, "data"))
        row = app.run_row(run_id)
        assert row["status"] == "failed", app.log(run_id)
        assert targets.running(box)
        assert "Started container" in app.log(run_id)
        assert json.loads(row["stopped_containers_json"]) == []
        assert stored_files(settings) == []
        assert helpers_left(targets.client, app.instance_id) == []


async def test_a_name_never_falls_back_to_an_id_prefix(
    settings: Settings, targets: Targets
) -> None:
    """Docker resolves a missing name as an ID prefix. A job for a container that is gone
    must fail, not back up whichever container's ID starts with its name."""
    box = targets.container()
    prefix = box.id[:8]  # hex, so a valid job target, and no container has this name
    async with running(settings) as browser:
        app = await setup_app(browser)
        run_id = await app.run(await app.add_job(prefix, "config"))
        row = app.run_row(run_id)
        assert row["status"] == "failed" and "does not exist" in row["error"]
        assert "Stopping container" not in app.log(run_id)
        assert targets.running(box)


# FULL DISK


@pytest.mark.skipif(not SMALL_DIR, reason="needs the small tmpfs from compose.test.yaml")
@pytest.mark.parametrize("full", ["staging", "storage"])
async def test_full_disk_fails_cleanly(tmp_path: Path, targets: Targets, full: str) -> None:
    small = Path(SMALL_DIR) / f"{full}-{uuid.uuid4().hex[:8]}"
    small.mkdir()
    try:
        if full == "staging":
            (tmp_path / "storage").mkdir()
            env = {
                "DRYDOCK_STAGING_DIR": str(small),
                "DRYDOCK_LOCAL_STORAGE_ROOTS": str(tmp_path / "storage"),
            }
        else:
            env = {"DRYDOCK_LOCAL_STORAGE_ROOTS": str(small)}
        settings = make_settings(tmp_path / "data", **env)
        # 200 MiB of random data: more than the 160 MiB tmpfs can take.
        box = targets.container(volume=targets.volume(mib=200))
        async with running(settings) as browser:
            app = await setup_app(browser)
            job_id = await app.add_job(box.name, "data", encrypted="")
            run_id = await app.run(job_id)
            row = app.run_row(run_id)
            assert row["status"] == "failed", app.log(run_id)
            assert f"the {full} directory" in row["error"]
            assert str(small) not in row["error"]  # viewers see the error; paths stay hidden
            assert targets.running(box)
            assert staged_files(settings) == []
            assert stored_files(settings) == []
            assert helpers_left(targets.client, app.instance_id) == []
            assert browser.sql("SELECT COUNT(*) FROM backups") == [(0,)]
    finally:
        shutil.rmtree(small, ignore_errors=True)


# CONTAINER AND STACK JOBS


async def test_container_and_stack_jobs_never_overlap(
    settings: Settings, targets: Targets, monkeypatch
) -> None:
    first, second = targets.container(), targets.container()
    intervals: dict[str, tuple[float, float]] = {}

    def slow_capture(env, job, containers, out_path, *, cancel, log, before_data, **_):
        before_data()
        start = time.monotonic()
        api = env.handle.client.api
        assert not any(api.inspect_container(c)["State"]["Running"] for c in containers)
        time.sleep(2)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(b"archive")
        intervals[job.name] = (start, time.monotonic())
        digest = hashlib.sha256(b"archive").hexdigest()
        return None, ArchiveResult(out_path, 7, digest, False, ())

    real_load = dispatcher_module.Dispatcher._load_plan

    def load_plan(self, run_id: int, job_id: int):
        # Phase 4 stack jobs resolve to several containers; this one covers both.
        plan = real_load(self, run_id, job_id)
        if plan.job.name != "stack":
            return plan
        return dataclasses.replace(plan, targets=(first.name, second.name))

    monkeypatch.setattr(capture, "capture", slow_capture)
    monkeypatch.setattr(dispatcher_module.Dispatcher, "_load_plan", load_plan)
    async with running(settings) as browser:
        app = await setup_app(browser)
        stack_job = await app.add_job(first.name, "config", name="stack")
        # A hostile name still writes inside the storage root.
        container_job = await app.add_job(second.name, "config", name="../../x")
        stack_run = await app.start(stack_job)
        await wait_until(lambda: app.status(stack_run) == "running", 10, "the stack run")
        container_run = await app.start(container_job)
        await anyio.sleep(1)
        assert app.status(container_run) == "queued"
        assert f"Waiting for run {stack_run}" in app.log(container_run)
        for run_id in (stack_run, container_run):
            await browser.app.state.dispatcher.wait(run_id)
            assert app.status(run_id) == "done", app.log(run_id)
        assert intervals["stack"][1] <= intervals["../../x"][0]
        name = app.run_row(container_run)["archive_name"]
        root = settings.local_storage_roots[0]
        assert name.startswith("drydock-x-") and (root / name).resolve().parent == root.resolve()
        assert targets.running(first) and targets.running(second)


# CONTAINERS RUN AGAIN BEFORE THE IMAGES


@pytest.mark.parametrize("mode", ["pause", "stop"])
async def test_containers_run_again_before_the_images_are_saved(
    settings: Settings, targets: Targets, mode: str
) -> None:
    box = targets.container(volume=targets.volume())
    async with running(settings) as browser:
        app = await setup_app(browser)
        run_id = await app.run(await app.add_job(box.name, "all", consistency_mode=mode))
        assert app.status(run_id) == "done", app.log(run_id)
        log = app.log(run_id)
    again = "Unpaused container" if mode == "pause" else "Started container"
    assert log.index(again) < log.index("Saving image") < log.index("Archive written")
    assert log.index("Saving volume") < log.index(again)
    assert targets.running(box)


# SEVERAL TARGETS, ONE AFTER ANOTHER


@pytest.mark.parametrize("mode", ["pause", "stop"])
async def test_each_target_runs_again_before_the_next_is_touched(
    settings: Settings, targets: Targets, mode: str
) -> None:
    first = targets.container(volume=targets.volume())
    second = targets.container(volume=targets.volume())
    async with running(settings) as browser:
        app = await setup_app(browser)
        job_id = await app.add_job(
            first.name,
            "data",
            consistency_mode=mode,
            extra_targets_sent="1",
            extra_target_type="container",
            extra_target=second.name,
        )
        first_run = await app.start(job_id)
        second_run = first_run + 1
        for run_id in (first_run, second_run):
            await browser.app.state.dispatcher.wait(run_id)
            assert app.status(run_id) == "done", app.log(run_id)
        one, two = app.run_row(first_run), app.run_row(second_run)
        first_log, second_log = app.log(first_run), app.log(second_run)
        job_uuid = browser.sql("SELECT uuid FROM jobs WHERE id = ?", (job_id,))[0][0]
        target_uuid = browser.sql("SELECT uuid FROM job_targets WHERE job_id = ?", (job_id,))
    again = "Unpaused container" if mode == "pause" else "Started container"
    # The first target's run ended with its container running again; only then did the
    # second start.
    assert again in first_log
    assert f"Waiting for run {first_run}" in second_log
    assert again in second_log
    assert one["finished_at"] <= two["started_at"]
    # One archive each, named for the target's own UUID.
    assert job_uuid in one["archive_name"] and target_uuid[0][0] in two["archive_name"]
    assert two["target_label"] == f"container {second.name}"
    assert targets.running(first) and targets.running(second)


async def test_copy_first_starts_the_next_target_while_the_first_uploads(
    settings: Settings, targets: Targets, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = targets.container(volume=targets.volume())
    second = targets.container(volume=targets.volume())
    held: list[str] = []
    publish = LocalStorage.publish

    def slow_publish(self, partial, name):
        # The first archive is held back until the second target's run has started.
        if not held:
            held.append(name)
            deadline = time.monotonic() + 30
            while app.status(second_run) == "queued" and time.monotonic() < deadline:
                time.sleep(0.1)
        return publish(self, partial, name)

    monkeypatch.setattr(LocalStorage, "publish", slow_publish)
    async with running(settings) as browser:
        app = await setup_app(browser)
        job_id = await app.add_job(
            first.name,
            "data",
            copy_first="1",
            copy_first_sent="1",
            extra_targets_sent="1",
            extra_target_type="container",
            extra_target=second.name,
        )
        first_run = await app.start(job_id)
        second_run = first_run + 1
        for run_id in (first_run, second_run):
            await browser.app.state.dispatcher.wait(run_id)
            assert app.status(run_id) == "done", app.log(run_id)
        one, two = app.run_row(first_run), app.run_row(second_run)
        first_log = app.log(first_run)
    assert (
        first_log.index("Copy on the host first:")
        < first_log.index("Stopping container")
        < first_log.index("Copied the data on the host in")
        < first_log.index("Started container")
        < first_log.index("Saving volume")
    )
    assert two["started_at"] < one["finished_at"]
    assert targets.running(first) and targets.running(second)
    assert helpers_left(targets.client, app.instance_id) == []


# A REAL DRYDOCK PROCESS, KILLED OR STOPPED MID-BACKUP


async def prepare_job(settings: Settings, target: str, encrypted: str = "") -> tuple[int, str]:
    async with running(settings) as browser:
        app = await setup_app(browser)
        return await app.add_job(target, "data", encrypted=encrypted), app.instance_id


def start_drydock(settings: Settings, job_id: int, output: Path) -> subprocess.Popen:
    keys = "\n".join(base64.urlsafe_b64encode(k).decode() for k in settings.secret_keys)
    env = os.environ | {
        "DRYDOCK_SECRET_KEY": keys,
        "DRYDOCK_DATA_DIR": str(settings.data_dir),
        "DRYDOCK_RUN_DIR": str(settings.run_dir),
        "DRYDOCK_STAGING_DIR": str(settings.staging_dir),
        "DRYDOCK_LOCAL_STORAGE_ROOTS": str(settings.local_storage_roots[0]),
        "DRYDOCK_BASE_URL": settings.base_url,
    }
    with output.open("wb") as log:
        return subprocess.Popen(
            [sys.executable, "-m", "tests.app_process", str(job_id)],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=Path(__file__).parent.parent,
        )


def db_status(settings: Settings) -> str | None:
    try:
        with closing(sqlite3.connect(settings.data_dir / "drydock.db", timeout=5)) as conn:
            row = conn.execute("SELECT status FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    except sqlite3.OperationalError:
        return None
    return row[0] if row else None


async def mid_backup(
    settings: Settings, targets: Targets, box, proc: subprocess.Popen, *, paused: bool = False
) -> None:
    """Waits until the process has stopped (or paused) the container and is staging the
    volume."""

    def held() -> bool:
        state = targets.client.api.inspect_container(box.id)["State"]
        return state["Paused"] if paused else not state["Running"]

    def capturing() -> bool:
        assert proc.poll() is None, "drydock exited early"
        staging = staged_files(settings)
        return (
            db_status(settings) == "running"
            and held()
            and any(n.startswith("member-") for n in staging)
        )

    await wait_until(capturing, 120, "the backup to stage the volume")


async def test_drydock_killed_mid_backup(
    settings: Settings, targets: Targets, tmp_path: Path
) -> None:
    """SIGTERM, as `docker compose stop` and `down` send it, is in the next test."""
    box = targets.container(volume=targets.volume(mib=1024))
    job_id, instance_id = await prepare_job(settings, box.name)
    proc = start_drydock(settings, job_id, tmp_path / "drydock.out")
    try:
        await mid_backup(settings, targets, box, proc)
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
        # Nothing ran after the kill: the container is still down, the helper and the
        # staged member are still there.
        assert not targets.running(box)
        assert helpers_left(targets.client, instance_id)
        assert staged_files(settings)
        async with running(settings) as browser:
            await wait_until(lambda: targets.running(box), 30, "recovery restarting it")
            status = browser.sql("SELECT status, error FROM runs")
            assert status == [("interrupted", "Drydock stopped before the run finished.")]
            assert staged_files(settings) == []
            await wait_until(
                lambda: not helpers_left(targets.client, instance_id), 30, "the reaper"
            )
            log = runlog.log_path(settings.data_dir, 1).read_text()
            assert "Interrupted" in log and "Started container" in log
        assert stored_files(settings) == []
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# DOCKER COMPOSE DOWN AND UP


def kept_state(settings: Settings) -> dict[str, list[tuple]]:
    """What a restart must leave alone. Runs and sessions change, and so does when a
    host was last reached."""
    tables = {
        "users": "*",
        "installation": "*",
        "hosts": "id, name, kind, docker_url, enabled",
        "storage_targets": "*",
        "jobs": "*",
        "backups": "*",
    }
    with closing(sqlite3.connect(settings.data_dir / "drydock.db")) as conn:
        return {
            table: conn.execute(f"SELECT {columns} FROM {table} ORDER BY 1").fetchall()  # noqa: S608
            for table, columns in tables.items()
        }


@pytest.mark.parametrize("mode", ["stop", "pause"])
async def test_compose_down_and_up_mid_backup_keeps_state(
    settings: Settings, targets: Targets, tmp_path: Path, mode: str
) -> None:
    """`docker compose down` sends SIGTERM and removes the container, and with it the
    run directory's tmpfs; `up` starts a new process on the same /data volume. All state
    is kept, no run is left running and the container drydock stopped or paused runs."""
    box = targets.container(volume=targets.volume(mib=1024))
    small = targets.container()
    async with running(settings) as browser:
        app = await setup_app(browser)
        done = await app.run(await app.add_job(small.name, "config", encrypted="1"))
        assert app.status(done) == "done", app.log(done)
        job_id = await app.add_job(box.name, "data", consistency_mode=mode)
        archive = app.run_row(done)["archive_name"]
        instance_id = app.instance_id
    before = kept_state(settings)
    proc = start_drydock(settings, job_id, tmp_path / "drydock.out")
    try:
        await mid_backup(settings, targets, box, proc, paused=mode == "pause")
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)  # what `docker compose stop` and `down` send to PID 1
        code = proc.wait(timeout=90)
        print(f"\nSIGTERM SHUTDOWN ({mode}): {time.monotonic() - started:.2f} s")
        # uvicorn re-raises the signal once its graceful shutdown (lifespan included) ends.
        assert code in (0, -signal.SIGTERM), (tmp_path / "drydock.out").read_text()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    # Down: shutdown itself started or unpaused the container and cleaned up.
    state = targets.client.api.inspect_container(box.id)["State"]
    assert state["Running"] and not state["Paused"]
    assert db_status(settings) == "cancelled"
    assert staged_files(settings) == []
    assert helpers_left(targets.client, instance_id) == []
    # The container's tmpfs is gone; up mounts an empty one.
    shutil.rmtree(settings.run_dir)
    settings.run_dir.mkdir(mode=0o700)
    async with running(settings) as browser:
        assert (await browser.login("admin")).status_code == 303
        assert kept_state(settings) == before
        statuses = dict(browser.sql("SELECT id, status FROM runs"))
        assert statuses[done] == "done"
        assert [s for s in statuses.values() if s in ("queued", "running")] == []
        assert sorted(statuses.values()) == ["cancelled", "done"]
        state = targets.client.api.inspect_container(box.id)["State"]
        assert state["Running"] and not state["Paused"]
        assert stored_files(settings) == [archive]
        for path in ("/jobs", f"/jobs/{job_id}", f"/runs/{done}", "/backups"):
            assert (await browser.get(path)).status_code == 200, path


# MEMORY DURING A 5 GIB ENCRYPTED BACKUP


def rss_bytes(pid: int | str) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def age_rss() -> int:
    total = 0
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                cmdline = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            if b"/age\0" in cmdline or b"age-plugin-batchpass" in cmdline:
                total += rss_bytes(entry.name)
    return total


@pytest.mark.slow
async def test_rss_during_a_5_gib_encrypted_backup(
    settings: Settings, targets: Targets, tmp_path: Path
) -> None:
    """Measures a fresh drydock process (uvicorn, as in the image) and its age children,
    so the result does not depend on what the test process loaded before."""
    box = targets.container(volume=targets.volume(mib=5 * 1024))
    job_id, _ = await prepare_job(settings, box.name, encrypted="1")
    peaks = {"drydock": 0, "age": 0, "both": 0}
    done = threading.Event()
    proc = start_drydock(settings, job_id, tmp_path / "drydock.out")

    def sample() -> None:
        while not done.wait(0.1):
            python, age = rss_bytes(proc.pid), age_rss()
            peaks["drydock"] = max(peaks["drydock"], python)
            peaks["age"] = max(peaks["age"], age)
            peaks["both"] = max(peaks["both"], python + age)

    sampler = threading.Thread(target=sample, daemon=True)
    started = time.monotonic()
    try:
        await wait_until(lambda: db_status(settings) == "running", 60, "the run to start")
        baseline = rss_bytes(proc.pid)
        sampler.start()

        def finished() -> bool:
            assert proc.poll() is None, (tmp_path / "drydock.out").read_text()
            return db_status(settings) not in (None, "queued", "running")

        await wait_until(finished, 900, "the 5 GiB backup")
        elapsed = time.monotonic() - started
    finally:
        done.set()
        if sampler.is_alive():
            sampler.join()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=90)
    with closing(sqlite3.connect(settings.data_dir / "drydock.db")) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM runs").fetchone())
        job_uuid = conn.execute("SELECT uuid FROM jobs").fetchone()[0]
    assert row["status"] == "done", runlog.log_path(settings.data_dir, row["id"]).read_text()
    path = settings.local_storage_roots[0] / row["archive_name"]
    print(
        f"\n5 GiB ENCRYPTED BACKUP: {elapsed:.1f} s, archive {row['size'] / MIB:.0f} MiB, "
        f"drydock RSS at start {baseline / MIB:.0f} MiB, peak drydock "
        f"{peaks['drydock'] / MIB:.0f} MiB, peak age {peaks['age'] / MIB:.0f} MiB, "
        f"peak together {peaks['both'] / MIB:.0f} MiB"
    )
    assert peaks["drydock"] > 0 and peaks["age"] > 0  # both were sampled
    assert peaks["both"] < 300 * MIB
    assert path.name.endswith(".tar.zst.age") and row["size"] > 5 * 1024 * MIB
    with path.open("rb") as handle:
        stanza = handle.read(200).split(b"\n")[1].split()
    assert stanza[:2] == [b"->", b"scrypt"] and stanza[-1] == b"14"  # work factor
    crypto = Crypto(settings.secret_keys)
    with pytest.raises(verify.VerifyError, match="no passphrase"):
        verify.verify_file(path, crypto)
    with pytest.raises(verify.VerifyError):
        verify.verify_file(path, crypto, passphrases=["wrong"])
    verified = verify.verify_file(
        path, crypto, passphrases=crypto.job_passphrases(uuid.UUID(job_uuid))
    )
    assert verified.signed and verified.encrypted
    assert verified.members[-1].size > 5 * 1024 * MIB  # the volume
    assert json.loads(verified.manifest.model_dump_json())["encryption"]["method"] == "age-scrypt"
