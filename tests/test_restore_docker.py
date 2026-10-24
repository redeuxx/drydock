"""Restores against real daemons, driven through the restore wizard (see compose.test.yaml).

The Phase 3 exit criteria that need real containers:
- Postgres (alpine uid 70, plus a 999:999 file in a second volume) restored under a new
  name on the same host: data intact, ownership preserved, and the original container,
  volumes and network unchanged.
- An overwrite restore of a running container: no conflict, the volume byte-identical to
  the archive (files added since are gone), no -drydock-old container left.
- kill -9 during an overwrite after the wipe: the original renamed back and stopped, the
  run interrupted, and the run page warns that the data may be partial.
- A volume-only archive restored into a chosen existing volume and into the volumes of a
  chosen container.
- An image-only archive loads its images and creates nothing else.
- A cross-host restore: backup on the SSH host, restore on the local host, which lacks the
  image.
- nginx with a bind mount, a network alias and a static IP survives a round trip: the
  normalized inspect diff is empty.
- Overwrite never wipes a bind mount that was not opted in.
- A backup of a container waits for a restore of the same container, even though the
  restore replaces the container ID.

Every overwrite and new-name restore uses a scope 'all' backup (container config plus
data): overwrite and new-name need the container config. The sshhost dind daemon stands
in for hosts whose filesystem the test changes (binds) and for commit (local images).
Everything made here is removed afterwards, by name and by the drydock.restore.run label.
"""

import base64
import copy
import hashlib
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import tarfile
import threading
import uuid
from collections.abc import Iterator
from compression import zstd
from contextlib import closing, suppress
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
import docker.errors
import pytest
from docker.types import IPAMConfig, IPAMPool, Mount

from drydock.archive import manifest as m
from drydock.config import Settings
from drydock.engine import stream_probe
from drydock.hosts import helper
from drydock.jobs import runlog
from drydock.jobs.dispatcher import json_object
from drydock.models import Host
from drydock.restore import apply as restore_apply
from drydock.restore import plan as restore_plan
from drydock.restore import verify as restore_verify
from drydock.restore.plan import RESTORE_LABEL
from tests.conftest import running
from tests.docker_support import (
    TEST_LABEL,
    add_ssh_host,
    helpers_left,
    host_docker,
    insert_host,
    needs_docker,
    needs_ssh,
    sh,
    wait_until,
)
from tests.test_capture import (
    PLAIN_URL,
    dind,  # noqa: F401 (the fixture remote uses)
    needs_dind,
)
from tests.test_restore_routes import DIGEST_RE, WARNING_RE, bind_number, flag_keys, reauth
from tests.test_runs_docker import (
    IMAGE,
    PG_IMAGE,
    App,
    Targets,
    db_status,
    pg_ready,
    setup_app,
    staged_files,
)

pytestmark = [pytest.mark.anyio, needs_docker]

# nginx:1.29-alpine, pinned by its multi-arch index digest.
NGINX_IMAGE = "nginx@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de"
SECRET = b"volume data"  # what Targets.volume() writes to secret.txt, 999:999 0600
HEX64_RE = re.compile(r"[0-9a-f]{64}")
CONTAINER_DROPS = (
    "Id",
    "Created",
    "State",
    "ResolvConfPath",
    "HostnamePath",
    "HostsPath",
    "LogPath",
    "RestartCount",
    "GraphDriver",
    "Storage",
)
NETWORK_SETTINGS_DROPS = ("SandboxID", "SandboxKey", "Ports")
ENDPOINT_DROPS = ("EndpointID", "NetworkID", "DNSNames")


# CONTAINERS, VOLUMES, NETWORKS AND IMAGES


class RestoreTargets(Targets):
    """Targets that also removes what restores make from them.

    Restored objects are named after the originals: an overwrite reuses the names, a
    new-name copy is '<original>-copy' and its volumes and networks '<copy>-<name>', and an
    original being replaced is '<name>-drydock-old'. Cleanup removes every container,
    volume and network whose name is one of the names made here or starts with one plus
    '-', found by name and, as a fallback, by the drydock.restore.run label. The names
    carry a random part, so objects of other tests and real restores are never touched.
    """

    def __init__(self, client: docker.DockerClient) -> None:
        super().__init__(client)
        self.networks: list = []
        self.images: list[str] = []
        self.names: set[str] = set()

    def name(self, suffix: str = "") -> str:
        name = f"drydock-test-run-{uuid.uuid4().hex[:10]}{suffix}"
        self.names.add(name)
        return name

    def ours(self, name: str) -> bool:
        name = name.lstrip("/")
        return any(name == n or name.startswith(f"{n}-") for n in self.names)

    def volume(self, mib: int = 0):
        volume = super().volume(mib)
        self.names.add(volume.name)
        return volume

    def empty_volume(self):
        volume = self.client.volumes.create(self.name(), labels={TEST_LABEL: "1"})
        self.volumes.append(volume)
        return volume

    def network(self, **kwargs: Any):
        network = self.client.networks.create(
            self.name("-net"), driver="bridge", labels={TEST_LABEL: "1"}, **kwargs
        )
        self.networks.append(network)
        return network

    def container(self, image: str = IMAGE, command=("sleep", "3600"), volume=None, **kwargs):
        container = super().container(image, command, volume, **kwargs)
        self.names.add(container.name)
        return container

    def create(
        self,
        image: str,
        command: list[str] | None,
        *,
        mounts: list[Mount] | None = None,
        network: str | None = None,
        endpoint: dict[str, Any] | None = None,
        environment: dict[str, str] | None = None,
        labelled: bool = True,
        start: bool = True,
        **host_config: Any,
    ):
        """A container made through the API, for what containers.create cannot set: an
        endpoint with aliases or a static IP. labelled=False leaves out drydock.test, which
        a restore drops (every drydock.* label), for a container compared after one."""
        api = self.client.api
        networking = None
        if network is not None:
            host_config["network_mode"] = network
            config = api.create_endpoint_config(**(endpoint or {}))
            networking = api.create_networking_config({network: config})
        created = api.create_container(
            image,
            command,
            name=self.name(),
            environment=environment,
            labels={TEST_LABEL: "1"} if labelled else None,
            host_config=api.create_host_config(mounts=mounts or [], **host_config),
            networking_config=networking,
        )
        container = self.client.containers.get(created["Id"])
        self.containers.append(container)
        if start:
            container.start()
        return container

    def commit(self, base_image: str = IMAGE) -> str:
        """A local image no registry has, tagged drydock-test-img-<hex>:1. Its own label
        makes its ID unique."""
        mark = uuid.uuid4().hex[:10]
        base = self.client.containers.create(base_image, ["true"], labels={TEST_LABEL: "1"})
        self.containers.append(base)
        repository = f"drydock-test-img-{mark}"
        labels = {TEST_LABEL: "1", "test.drydock-image": mark}
        base.commit(repository=repository, tag="1", conf={"Labels": labels})
        tag = f"{repository}:1"
        self.images.append(tag)
        return tag

    def cleanup(self) -> None:
        api = self.client.api
        restored = {"label": RESTORE_LABEL}
        volumes = {v.name for v in self.volumes} | {
            v["Name"]
            for v in api.volumes(filters=restored).get("Volumes") or []
            if self.ours(v["Name"])
        }
        containers = {c.id for c in self.containers}
        for found in [api.containers(all=True, filters=restored)] + [
            api.containers(all=True, filters={"name": name}) for name in sorted(self.names)
        ]:
            containers |= {c["Id"] for c in found if self.ours(c["Names"][0])}
        # And whatever still uses a volume made here, such as the helper of a killed drydock.
        for name in sorted(volumes):
            containers |= {c["Id"] for c in api.containers(all=True, filters={"volume": name})}
        for container_id in sorted(containers):
            with suppress(docker.errors.NotFound):
                api.remove_container(container_id, force=True, v=True)
        for name in sorted(volumes):
            with suppress(docker.errors.NotFound):
                api.remove_volume(name, force=True)
        networks = {n.id: n.name for n in self.networks}
        networks |= {n["Id"]: n["Name"] for n in api.networks(filters=restored)}
        for network_id, name in sorted(networks.items()):
            if self.ours(name):
                with suppress(docker.errors.NotFound):
                    api.remove_network(network_id)
        for tag in self.images:
            with suppress(docker.errors.NotFound):
                api.remove_image(tag, force=True)


@pytest.fixture
def targets() -> Iterator[RestoreTargets]:
    """The host daemon, through the socket proxy."""
    handle = host_docker()
    made = RestoreTargets(handle.client)
    try:
        helper.ensure_image(handle.client, IMAGE)
        yield made
    finally:
        made.cleanup()
        handle.close()


@pytest.fixture
def remote(request: pytest.FixtureRequest) -> Iterator[tuple[RestoreTargets, Any, str]]:
    """The sshhost dind daemon over plain TCP, the sshhost container (its host) and a
    scratch directory there. tests.test_capture's dind fixture removes what carries
    drydock.test, and this the rest."""
    handle, box, root = request.getfixturevalue("dind")
    made = RestoreTargets(handle.client)
    try:
        yield made, box, root
    finally:
        made.cleanup()


# INSPECT


def normalized(info: dict[str, Any], *, image_loaded: bool = False) -> dict[str, Any]:
    """A container inspect without what differs for every container made from the same
    body. image_loaded: the original's Config.Image was a digest ref and the restore loaded
    the image, so the body names the image by ID instead (docker load keeps no digests)."""
    doc = copy.deepcopy(info)
    for key in CONTAINER_DROPS:
        doc.pop(key, None)
    settings = doc.get("NetworkSettings") or {}
    for key in NETWORK_SETTINGS_DROPS:
        settings.pop(key, None)
    for endpoint in (settings.get("Networks") or {}).values():
        for key in ENDPOINT_DROPS:
            endpoint.pop(key, None)
    config = doc.get("Config") or {}
    config.pop("Hostname", None)
    (config.get("Labels") or {}).pop(RESTORE_LABEL, None)
    for mount in doc.get("Mounts") or []:
        if mount.get("Type") == "volume" and HEX64_RE.fullmatch(mount.get("Name") or ""):
            mount.pop("Name", None)  # an anonymous volume
            mount.pop("Source", None)  # its path holds the name
    if image_loaded:
        config.pop("Image", None)
        doc.pop("Image", None)
    return doc


def normalized_network(info: dict[str, Any]) -> dict[str, Any]:
    """A network inspect without its ID and creation time. Its Containers map is keyed by
    container ID, so it is keyed by container name instead, without the endpoint IDs."""
    doc = copy.deepcopy(info)
    doc.pop("Id", None)
    doc.pop("Created", None)
    doc["Containers"] = {
        entry.get("Name"): {k: v for k, v in entry.items() if k != "EndpointID"}
        for entry in (doc.get("Containers") or {}).values()
    }
    return doc


def differences(before: Any, after: Any, path: str = "") -> list[str]:
    """Where two inspect documents differ, for assertion messages."""
    if isinstance(before, dict) and isinstance(after, dict):
        found = []
        for key in sorted(set(before) | set(after)):
            found += differences(before.get(key), after.get(key), f"{path}.{key}")
        return found
    return [] if before == after else [f"{path}: {before!r} != {after!r}"]


# WIZARD


async def verify(app: App, archive: str) -> int:
    """Starts a restore from the storage listing and waits for pass 1."""
    response = await app.browser.post(
        "/restore/from-storage", {"storage_id": str(app.storage_id), "name": archive}
    )
    assert response.status_code == 303, response.text
    run_id = int(response.headers["location"].split("/")[3])
    await app.browser.app.state.dispatcher.wait(run_id)
    assert app.status(run_id) == "awaiting_confirmation", app.log(run_id)
    return run_id


def staged_manifest(app: App, run_id: int) -> m.Manifest:
    settings = app.settings
    path = restore_verify.restore_dir(settings.staging_dir, run_id)
    return restore_verify.load_staged(path, app.browser.app.state.crypto).manifest


def summary_of(app: App, run_id: int) -> dict[str, Any]:
    plan = app.browser.sql("SELECT plan FROM runs WHERE id = ?", (run_id,))[0][0]
    return json.loads(plan)["summary"]


async def plan(app: App, run_id: int, mode: str, host_id: int, **fields: str) -> dict[str, Any]:
    form = {"host_id": str(host_id), "mode": mode} | fields
    response = await app.browser.post(f"/restore/runs/{run_id}/plan", form)
    assert response.status_code == 303, (response.status_code, alerts(response.text))
    return summary_of(app, run_id)


async def execute(app: App, run_id: int, confirm_name: str = "") -> None:
    """Confirms the plan the page shows, as a superadmin who just entered the password:
    the typed name (overwrite) and an acknowledgement of every flagged field."""
    browser = app.browser
    page = await browser.get(f"/restore/runs/{run_id}/plan")
    match = DIGEST_RE.search(page.text)
    assert match, alerts(page.text)
    await reauth(browser)
    form: dict[str, Any] = {"plan_digest": match.group(1), "ack": flag_keys(browser, run_id)}
    if confirm_name:
        form["confirm_name"] = confirm_name
    response = await browser.post(f"/restore/runs/{run_id}/execute", form)
    assert response.status_code == 303, (response.status_code, alerts(response.text))


async def restore(app: App, archive: str, mode: str, *, host_id: int = 0, **fields: str) -> int:
    """The whole wizard: verify, plan, confirm, and wait for the run to finish."""
    run_id = await verify(app, archive)
    summary = await plan(app, run_id, mode, host_id or app.host_id, **fields)
    names = summary["containers"]
    await execute(app, run_id, names[0] if mode == "overwrite" else "")
    await app.browser.app.state.dispatcher.wait(run_id)
    assert app.status(run_id) == "done", app.log(run_id)
    return run_id


def alerts(html: str) -> list[str]:
    return re.findall(r'role="alert"[^>]*>(.*?)</div>', html, re.DOTALL)


async def backup(app: App, target: str, scope: str, **fields: str) -> str:
    """Runs a backup job and returns its archive name."""
    run_id = await app.run(await app.add_job(target, scope, **fields))
    row = app.run_row(run_id)
    assert row["status"] == "done", app.log(run_id)
    return row["archive_name"]


def add_dind_host(app: App) -> int:
    """The sshhost dind daemon as a local host, reached over its plain TCP endpoint."""
    return insert_host(
        app.browser, Host(name="dind", kind="local", docker_url=PLAIN_URL, enabled=True)
    )


def finished(app: App, clients: list, *run_ids: int) -> None:
    """How every test ends: no helper on any daemon and no staged restore data."""
    logs = "\n".join(app.log(run_id) for run_id in run_ids)
    for client in clients:
        assert helpers_left(client, app.instance_id) == [], logs
    assert not [n for n in staged_files(app.settings) if n.startswith("restore-")], logs


# FILES


def stat(container, path: str) -> str:
    code, output = container.exec_run(["stat", "-c", "%u:%g %a", path])
    assert code == 0, output
    return output.decode().strip()


def read(container, path: str) -> bytes:
    code, output = container.exec_run(["cat", path])
    assert code == 0, output
    return output


def exists(box, path: str) -> bool:
    code, _ = box.exec_run(["test", "-e", path])
    return code == 0


def archived_volume(settings: Settings, archive: str, volume: str) -> dict[str, Any]:
    """stream_probe.describe of a volume member of an unencrypted archive."""
    member = f"volumes/{volume}.tar"
    path = settings.local_storage_roots[0] / archive
    with zstd.ZstdFile(path) as plain, tarfile.open(fileobj=plain, mode="r|") as tar:
        for info in tar:
            if info.name == member:
                data = tar.extractfile(info)
                assert data is not None
                return stream_probe.describe(data)
    raise AssertionError(f"{member} is not in {archive}")


# POSTGRES UNDER A NEW NAME


async def test_postgres_new_name_restore_on_the_same_host(
    settings: Settings, targets: RestoreTargets
) -> None:
    api = targets.client.api
    helper.ensure_image(targets.client, PG_IMAGE)  # pulls only if the host lacks it
    data, extra = targets.volume(), targets.volume()
    network = targets.network()
    pg = targets.create(
        PG_IMAGE,
        None,
        mounts=[
            Mount("/var/lib/postgresql", data.name, type="volume"),
            Mount("/extra", extra.name, type="volume"),
        ],
        network=network.name,
        endpoint={"aliases": ["pg"]},
        environment={"POSTGRES_PASSWORD": uuid.uuid4().hex},
    )
    await wait_until(lambda: pg_ready(pg), 90, "postgres to accept connections")
    code, output = pg.exec_run(
        ["psql", "-U", "postgres", "-c", "CREATE TABLE t (v text); INSERT INTO t VALUES ('kept');"]
    )
    assert code == 0, output
    async with running(settings) as browser:
        app = await setup_app(browser)
        # Scope 'all' (container config plus data), encrypted: new-name needs the config.
        archive = await backup(app, pg.name, "all")
        await wait_until(lambda: pg_ready(pg), 60, "postgres after the backup")
        original = normalized(api.inspect_container(pg.id))
        volumes = {v.name: api.inspect_volume(v.name) for v in (data, extra)}
        original_network = normalized_network(api.inspect_network(network.id))

        copy_name = f"{pg.name}-copy"
        run_id = await verify(app, archive)
        summary = await plan(app, run_id, "new-name", app.host_id, new_name=copy_name)
        assert [i["action"] for i in summary["images"]] == ["present"], summary
        assert {d["label"] for d in summary["data"]} == {
            f"volume {restore_plan.derived(copy_name, v.name)}" for v in (data, extra)
        }, summary  # volumes renamed, and no bind data
        await execute(app, run_id)
        await browser.app.state.dispatcher.wait(run_id)
        assert app.status(run_id) == "done", app.log(run_id)

        copy = targets.client.containers.get(copy_name)
        assert copy.attrs["State"]["Running"], app.log(run_id)
        await wait_until(lambda: pg_ready(copy), 90, "the copy to accept connections")
        code, output = copy.exec_run(["psql", "-U", "postgres", "-tAc", "SELECT v FROM t"])
        assert code == 0 and output.strip() == b"kept", output
        pgdata = ["sh", "-c", 'stat -c %u:%g "$PGDATA"']
        owners = [c.exec_run(pgdata).output.decode().strip() for c in (pg, copy)]
        # Numerically equal, owned by the alpine image's postgres user (uid 70).
        assert owners[0] == owners[1] and owners[0].startswith("70:"), owners
        assert stat(copy, "/extra/secret.txt") == "999:999 600"
        assert read(copy, "/extra/secret.txt") == SECRET
        copy_network = restore_plan.derived(copy_name, network.name)
        endpoints = copy.attrs["NetworkSettings"]["Networks"]
        assert list(endpoints) == [copy_network], endpoints
        assert "pg" in (endpoints[copy_network].get("Aliases") or [])

        # The original keeps running with its data intact: normalized() drops State, and
        # volume inspect carries no content.
        assert api.inspect_container(pg.id)["State"]["Running"], app.log(run_id)
        await wait_until(lambda: pg_ready(pg), 60, "the original after the restore")
        code, output = pg.exec_run(["psql", "-U", "postgres", "-tAc", "SELECT v FROM t"])
        assert code == 0 and output.strip() == b"kept", output
        assert stat(pg, "/extra/secret.txt") == "999:999 600"
        assert read(pg, "/extra/secret.txt") == SECRET
        after = normalized(api.inspect_container(pg.id))
        assert after == original, differences(original, after)
        for name, before in volumes.items():
            assert api.inspect_volume(name) == before, name
        network_after = normalized_network(api.inspect_network(network.id))
        assert network_after == original_network, differences(original_network, network_after)
        finished(app, [targets.client], run_id)


# OVERWRITE OF A RUNNING CONTAINER


async def test_overwrite_restore_of_a_running_container(
    settings: Settings, targets: RestoreTargets
) -> None:
    volume = targets.volume()
    box = targets.container(volume=volume)
    async with running(settings) as browser:
        app = await setup_app(browser)
        # Scope 'all' (container config plus data): overwrite needs the config. Unencrypted,
        # so the test can read the volume member.
        archive = await backup(app, box.name, "all", encrypted="")
        sh(
            box,
            'mkdir /data/extra && printf more > /data/extra/new && printf x >> "$1"',
            "/data/secret.txt",
        )
        run_id = await restore(app, archive, "overwrite")
        restored = targets.client.containers.get(box.name)
        assert restored.id != box.id
        assert restored.attrs["State"]["Running"], app.log(run_id)
        assert old_containers(targets) == [], app.log(run_id)
        expected = archived_volume(settings, archive, volume.name)
        actual = stream_probe.describe_volume(targets.client, IMAGE, app.instance_id, volume.name)
        assert "extra" not in actual, app.log(run_id)
        assert set(actual) == set(expected), app.log(run_id)
        assert actual == expected, differences(expected, actual)
        assert read(restored, "/data/secret.txt") == SECRET
        finished(app, [targets.client], run_id)


def old_containers(targets: RestoreTargets) -> list[str]:
    """The '-drydock-old' containers of this test's names."""
    found = targets.client.api.containers(all=True, filters={"name": restore_plan.OLD_SUFFIX})
    return [n for c in found if targets.ours(n := c["Names"][0].lstrip("/"))]


# KILL -9 AFTER THE WIPE


def start_drydock(settings: Settings, args: list[str], output: Path) -> subprocess.Popen:
    """tests.test_runs_docker.start_drydock, with any tests.app_process arguments."""
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
            [sys.executable, "-m", "tests.app_process", *args],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=Path(__file__).parent.parent,
        )


def last_restore(settings: Settings) -> tuple[int, dict[str, Any]] | None:
    """The newest restore run and its journal, read while another process writes."""
    try:
        with closing(sqlite3.connect(settings.data_dir / "drydock.db", timeout=5)) as conn:
            row = conn.execute(
                "SELECT id, restore_originals_json FROM runs WHERE kind = 'restore'"
                " ORDER BY id DESC LIMIT 1"
            ).fetchone()
    except sqlite3.OperationalError:
        return None
    return (row[0], json_object(row[1])) if row else None


def run_log_text(settings: Settings, run_id: int) -> str:
    path = runlog.log_path(settings.data_dir, run_id)
    return path.read_text() if path.exists() else ""


async def test_kill_9_during_an_overwrite_restore_after_the_wipe(
    settings: Settings, targets: RestoreTargets, tmp_path: Path
) -> None:
    volume = targets.volume(mib=512)
    box = targets.container(volume=volume)
    async with running(settings) as browser:
        app = await setup_app(browser)
        # Scope 'all' (container config plus data): overwrite needs the config.
        archive = await backup(app, box.name, "all", encrypted="")
        host_id, storage_id, instance_id = app.host_id, app.storage_id, app.instance_id
    # The restore runs in a drydock process of its own, which this test kills.
    choice = restore_plan.Choice(host_id=host_id, mode="overwrite")
    output = tmp_path / "drydock.out"
    summary_path = tmp_path / "summary.json"
    args = ["restore", str(storage_id), archive, json.dumps(choice.to_dict()), str(summary_path)]
    proc = start_drydock(settings, args, output)
    try:

        def writing() -> bool:
            assert proc.poll() is None, output.read_text()
            found = last_restore(settings)
            return (
                found is not None
                and found[1].get("wipe_started") is True
                and "Restoring the data of volume" in run_log_text(settings, found[0])
            )

        await wait_until(writing, 300, "the restore to write the volume data")
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    found = last_restore(settings)
    assert found is not None
    run_id = found[0]
    summary = json.loads(summary_path.read_text())
    assert summary["mode"] == "overwrite" and summary["originals"] == [box.name], summary
    printed = [json.loads(line) for line in output.read_text().splitlines() if line[:1] == "{"]
    assert printed == [{"run_id": run_id}], output.read_text()
    assert not targets.running(box)  # nothing ran after the kill

    def log() -> str:
        return run_log_text(settings, run_id)

    def rolled_back() -> bool:
        journal = last_restore(settings)
        return journal is not None and journal[1].get("rolled_back") is True

    async with running(settings) as browser:
        await wait_until(rolled_back, 180, "startup recovery to roll the restore back")
        info = targets.client.api.inspect_container(box.id)
        assert info["Name"] == f"/{box.name}", log()
        assert not info["State"]["Running"], log()
        assert old_containers(targets) == [], log()
        assert db_status(settings) == "interrupted", log()
        assert (await browser.login("admin")).status_code == 303
        page = (await browser.get(f"/runs/{run_id}")).text
        # The warning alert itself: the run log on the same page has the first two too.
        warning = WARNING_RE.search(page)
        assert warning is not None, log()
        for text in ("may be partial", volume.name, "renamed back"):
            assert text in warning.group(1), (text, warning.group(1))
        await wait_until(
            lambda: not helpers_left(targets.client, instance_id), 60, "the startup reap"
        )
        assert not [n for n in staged_files(settings) if n.startswith("restore-")], log()


# VOLUME-ONLY ARCHIVES


async def test_volume_only_archive_into_an_existing_volume_and_into_a_containers_volumes(
    settings: Settings, targets: RestoreTargets
) -> None:
    client = targets.client
    box = targets.container(volume=targets.volume())
    chosen = targets.empty_volume()
    inner = targets.empty_volume()
    # Stopped (never started), with a volume at the archived container's destination.
    holder = targets.create(
        IMAGE, ["true"], mounts=[Mount("/data", inner.name, type="volume")], start=False
    )
    async with running(settings) as browser:
        app = await setup_app(browser)
        archive = await backup(app, box.name, "data")

        # Into a chosen existing volume (the archive's first and only volume).
        first = await restore(app, archive, "data-only", volmap_0=chosen.name)
        restored = stream_probe.describe_volume(client, IMAGE, app.instance_id, chosen.name)
        secret = restored.get("secret.txt")
        assert secret is not None, app.log(first)
        assert (secret.uid, secret.gid, secret.mode) == (999, 999, 0o600)
        assert secret.sha256 == hashlib.sha256(SECRET).hexdigest()

        # Into the volumes of a chosen container, by mount destination.
        second = await restore(app, archive, "data-only", data_container=holder.name)
        restored = stream_probe.describe_volume(client, IMAGE, app.instance_id, inner.name)
        secret = restored.get("secret.txt")
        assert secret is not None, app.log(second)
        assert (secret.uid, secret.gid) == (999, 999)
        assert secret.sha256 == hashlib.sha256(SECRET).hexdigest()
        assert targets.running(box)  # data-only never touches the archived container
        finished(app, [client], first, second)


# IMAGE-ONLY ARCHIVES


def made(targets: RestoreTargets) -> set[str]:
    """The containers, volumes and networks a restore could have made here: labelled
    drydock.restore.run or named after this test's objects. Not the whole daemon, which
    other tests share."""
    client = targets.client
    found = [(c.name, c.labels) for c in client.containers.list(all=True)]
    found += [(v.name, v.attrs.get("Labels")) for v in client.volumes.list()]
    found += [(n.name, n.attrs.get("Labels")) for n in client.networks.list()]
    return {name for name, labels in found if RESTORE_LABEL in (labels or {}) or targets.ours(name)}


@needs_dind
async def test_image_only_archive_loads_images_and_creates_nothing_else(
    settings: Settings, remote: tuple[RestoreTargets, Any, str], monkeypatch
) -> None:
    targets, _box, _root = remote
    client = targets.client
    tag = targets.commit()
    source = targets.container(image=tag)
    seen: list[tuple[str, str]] = []
    recording = threading.Event()
    real_send = docker.APIClient.send

    def spy(self, request, **kwargs):
        if recording.is_set():
            seen.append((request.method, request.path_url))
        return real_send(self, request, **kwargs)

    async with running(settings) as browser:
        app = await setup_app(browser)
        dind_id = add_dind_host(app)
        # Scope 'image': the images only.
        archive = await backup(app, source.name, "image", host_id=str(dind_id))
        source.remove(force=True)
        client.images.remove(tag, force=True)
        with pytest.raises(docker.errors.ImageNotFound):
            client.images.get(tag)
        before = made(targets)
        run_id = await verify(app, archive)
        summary = await plan(app, run_id, "image-only", dind_id)
        assert [i["action"] for i in summary["images"]] == ["load"], summary
        monkeypatch.setattr(docker.APIClient, "send", spy)
        recording.set()
        await execute(app, run_id)
        await browser.app.state.dispatcher.wait(run_id)
        recording.clear()
        assert app.status(run_id) == "done", app.log(run_id)
        posts = [path for method, path in seen if method == "POST"]
        assert any(re.match(r"(/v[\d.]+)?/images/load", p) for p in posts), seen
        creates = r"(/v[\d.]+)?/(containers|volumes|networks)/create"
        assert not [p for p in posts if re.match(creates, p)], seen
        assert tag in client.images.get(tag).tags
        assert made(targets) == before, app.log(run_id)
        finished(app, [client], run_id)


# ACROSS HOSTS


@needs_ssh
@needs_dind
async def test_restore_across_hosts(
    settings: Settings, targets: RestoreTargets, remote: tuple[RestoreTargets, Any, str]
) -> None:
    """Backup on the SSH host (A, the sshhost daemon), restore on the local host (B), which
    lacks the image."""
    host_a, _box, _root = remote
    tag = host_a.commit()
    volume = host_a.volume()  # secret.txt, 999:999 0600
    source = host_a.container(image=tag, volume=volume)
    # B gets the same names, and the loaded image.
    targets.names |= host_a.names
    targets.images.append(tag)
    with pytest.raises(docker.errors.ImageNotFound):
        targets.client.images.get(tag)
    async with running(settings) as browser:
        app = await setup_app(browser)
        ssh_id = await add_ssh_host(browser)
        # Scope 'all' (container config plus data and the image).
        archive = await backup(app, source.name, "all", host_id=str(ssh_id))
        # Overwrite on a host without the original creates every original name.
        run_id = await verify(app, archive)
        summary = await plan(app, run_id, "overwrite", app.host_id)
        assert summary["originals"] == [] and summary["containers"] == [source.name], summary
        assert [i["action"] for i in summary["images"]] == ["load"], summary
        await execute(app, run_id, source.name)
        await browser.app.state.dispatcher.wait(run_id)
        assert app.status(run_id) == "done", app.log(run_id)
        assert tag in targets.client.images.get(tag).tags
        restored = targets.client.containers.get(source.name)
        assert restored.attrs["State"]["Running"], app.log(run_id)
        assert read(restored, "/data/secret.txt") == SECRET
        assert stat(restored, "/data/secret.txt") == "999:999 600"
        finished(app, [targets.client, host_a.client], run_id)


# NGINX ROUND TRIP


@needs_dind
async def test_nginx_with_bind_and_static_ip_round_trip(
    settings: Settings, remote: tuple[RestoreTargets, Any, str]
) -> None:
    targets, box, root = remote
    client, api = targets.client, targets.client.api
    helper.ensure_image(client, NGINX_IMAGE)
    html = f"{root}/html"
    sh(box, 'mkdir "$1" && printf "<h1>drydock %s</h1>\\n" "$2" > "$1/index.html"', html, root)
    subnet = f"10.213.{secrets.randbelow(200) + 20}"
    network = targets.network(
        ipam=IPAMConfig(pool_configs=[IPAMPool(subnet=f"{subnet}.0/24", gateway=f"{subnet}.1")])
    )
    # No drydock.test label: a restore drops drydock.* labels, and the inspects must match.
    web = targets.create(
        NGINX_IMAGE,
        None,
        mounts=[Mount("/usr/share/nginx/html", html, type="bind")],
        network=network.name,
        # A MAC address Docker generates changes on every start of the same container, so
        # the endpoint gets a fixed one, which the restore must keep like the static IP.
        endpoint={
            "aliases": ["web"],
            "ipv4_address": f"{subnet}.10",
            "mac_address": "02:" + ":".join(f"{b:02x}" for b in secrets.token_bytes(5)),
        },
        labelled=False,
    )
    page = sh(box, 'sha256sum "$1/index.html"', html)
    async with running(settings) as browser:
        app = await setup_app(browser)
        dind_id = add_dind_host(app)
        # Scope 'all' (container config plus data).
        archive = await backup(app, web.name, "all", host_id=str(dind_id))
        original = normalized(api.inspect_container(web.id))
        original_network = normalized_network(api.inspect_network(network.id))
        run_id = await verify(app, archive)
        n = bind_number(staged_manifest(app, run_id), html)
        await plan(app, run_id, "overwrite", dind_id, **{f"wipe_{n}": "1"})
        await execute(app, run_id, web.name)
        await browser.app.state.dispatcher.wait(run_id)
        assert app.status(run_id) == "done", app.log(run_id)
        restored = api.inspect_container(web.name)
        assert restored["Id"] != web.id and restored["State"]["Running"], app.log(run_id)
        after = normalized(restored)
        assert after == original, differences(original, after)
        network_after = normalized_network(api.inspect_network(network.id))
        assert network_after == original_network, differences(original_network, network_after)
        assert sh(box, 'sha256sum "$1/index.html"', html) == page
        finished(app, [client], run_id)


# BINDS THAT WERE NOT OPTED IN


@needs_dind
async def test_overwrite_never_wipes_a_bind_that_was_not_opted_in(
    settings: Settings, remote: tuple[RestoreTargets, Any, str]
) -> None:
    targets, box, root = remote
    wiped, kept = f"{root}/wiped", f"{root}/kept"
    sh(box, 'mkdir "$1" "$2" && printf a > "$1/data.txt" && printf b > "$2/data.txt"', wiped, kept)
    container = targets.create(
        IMAGE,
        ["sleep", "3600"],
        mounts=[Mount("/wiped", wiped, type="bind"), Mount("/kept", kept, type="bind")],
        init=True,
    )
    async with running(settings) as browser:
        app = await setup_app(browser)
        dind_id = add_dind_host(app)
        # Scope 'all' (container config plus data).
        archive = await backup(app, container.name, "all", host_id=str(dind_id))
        sh(box, 'printf s > "$1/sentinel" && printf s > "$2/sentinel"', wiped, kept)
        run_id = await verify(app, archive)
        n = bind_number(staged_manifest(app, run_id), wiped)
        summary = await plan(app, run_id, "overwrite", dind_id, **{f"wipe_{n}": "1"})
        assert summary["wipes"] == [f"bind mount {wiped}"], summary
        await execute(app, run_id, container.name)
        await browser.app.state.dispatcher.wait(run_id)
        assert app.status(run_id) == "done", app.log(run_id)
        assert not exists(box, f"{wiped}/sentinel"), app.log(run_id)
        assert exists(box, f"{kept}/sentinel"), app.log(run_id)
        for directory in (wiped, kept):
            assert exists(box, f"{directory}/data.txt"), app.log(run_id)
        finished(app, [targets.client], run_id)


# A BACKUP WAITS FOR A RESTORE


async def test_backup_waits_for_a_restore_on_the_same_container(
    settings: Settings, targets: RestoreTargets, monkeypatch
) -> None:
    box = targets.container(volume=targets.volume(mib=256))
    # Holds the restore before it stops the original, so the backup resolves the original
    # (by name, as its job does) and waits for its locks; released once it waits.
    gate = threading.Event()
    real_stop = restore_apply.Applier.stop_originals

    def gated_stop(self) -> None:
        gate.wait(120)
        real_stop(self)

    monkeypatch.setattr(restore_apply.Applier, "stop_originals", gated_stop)
    async with running(settings) as browser:
        app = await setup_app(browser)
        dispatcher = browser.app.state.dispatcher
        # Scope 'all' (container config plus data): overwrite needs the config.
        job_id = await app.add_job(box.name, "all", encrypted="")
        first = await app.run(job_id)
        assert app.status(first) == "done", app.log(first)
        restore_id = await verify(app, app.run_row(first)["archive_name"])
        await plan(app, restore_id, "overwrite", app.host_id)
        try:
            await execute(app, restore_id, box.name)
            await wait_until(lambda: app.status(restore_id) == "running", 60, "the restore")
            backup_id = await app.start(job_id)
            await wait_until(
                lambda: "Waiting for run" in app.log(backup_id), 60, "the backup to wait"
            )
        finally:
            gate.set()
        await dispatcher.wait(restore_id)
        await dispatcher.wait(backup_id)
        assert app.status(restore_id) == "done", app.log(restore_id)
        backup_log = app.log(backup_id)
        assert app.status(backup_id) == "done", backup_log
        assert f"Waiting for run {restore_id}" in backup_log
        assert "was replaced" in backup_log
        restore_row, backup_row = app.run_row(restore_id), app.run_row(backup_id)
        restore_end = datetime.fromisoformat(restore_row["finished_at"])
        assert datetime.fromisoformat(backup_row["started_at"]) > restore_end, backup_log
        assert targets.running(targets.client.containers.get(box.name))
        finished(app, [targets.client], restore_id, first, backup_id)
