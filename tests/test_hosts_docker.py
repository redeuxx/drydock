"""Integration tests against the host daemon (through the socket proxy) and the sshhost."""

import json
import stat
import threading
import uuid
from pathlib import Path

import anyio
import asyncssh
import docker
import docker.errors
import docker.models.containers
import pytest
import requests
from markupsafe import escape

from drydock.config import DEFAULT_HELPER_IMAGE, Settings
from drydock.hosts import client as docker_client
from drydock.hosts import helper, inventory, ssh
from drydock.hosts.manager import HostUnavailable
from drydock.models import Host
from tests.conftest import Browser, running
from tests.docker_support import (
    DOCKER_URL,
    KEY_MARKERS,
    SSH_HOST,
    TEST_INSTANCE,
    TEST_LABEL,
    TEST_PROJECT,
    add_ssh_host,
    archive_and_exec_roundtrip,
    authorize,
    connect_host,
    find_key_material,
    get_host,
    host_docker,
    insert_host,
    needs_docker,
    needs_ssh,
    sh,
    sshhost,
    wait_until,
)

pytestmark = pytest.mark.anyio

IMAGE = DEFAULT_HELPER_IMAGE


# SOCKET PROXY


@needs_docker
def test_proxy_negotiates_a_supported_api_version() -> None:
    with host_docker() as handle:
        server_max = docker_client.read_version(DOCKER_URL)["ApiVersion"]
        expected = min(docker_client.api_tuple(server_max), docker_client.api_tuple("1.56"))
        assert docker_client.api_tuple(handle.api_version) == expected
        assert handle.client.api.api_version == handle.api_version
        assert handle.client.ping()


@needs_docker
@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/events"),
        ("GET", "/system/df"),
        ("POST", "/build"),
        ("POST", "/auth"),
        ("POST", "/commit"),
        ("GET", "/swarm"),
        ("GET", "/services"),
        ("GET", "/secrets"),
        ("GET", "/plugins"),
        ("POST", "/session"),
        ("GET", "/containers/x/logs"),
        ("GET", "/containers/x/export"),
        ("GET", "/containers/x/top"),
        ("GET", "/containers/x/changes"),
        ("GET", "/libpod/_ping"),
        ("GET", "/libpod/version"),
    ],
)
def test_proxy_denies_disabled_endpoints(method: str, path: str) -> None:
    base = DOCKER_URL.replace("tcp://", "http://")
    for prefix in ("", "/v1.44"):
        response = requests.request(method, f"{base}{prefix}{path}", timeout=10)
        assert response.status_code == 403, (prefix + path, response.status_code)


@needs_docker
@pytest.mark.parametrize("path", ["/_ping", "/version", "/info", "/containers/json"])
def test_proxy_allows_enabled_endpoints(path: str) -> None:
    base = DOCKER_URL.replace("tcp://", "http://")
    assert requests.get(f"{base}/v1.44{path}", timeout=10).status_code == 200


@needs_docker
def test_proxy_allows_the_read_only_registry_lookup() -> None:
    """DISTRIBUTION=1 (PLAN.md decision 9): the daemon confirms a digest with its registry."""
    base = DOCKER_URL.replace("tcp://", "http://")
    repository, digest = IMAGE.split("@")
    ref = f"{repository.rsplit(':', 1)[0]}@{digest}"
    response = requests.get(f"{base}/v1.44/distribution/{ref}/json", timeout=30)
    assert response.status_code == 200, response.text
    assert response.json()["Descriptor"]["digest"] == digest


# HELPERS


@needs_docker
def test_helper_is_hardened_and_removed() -> None:
    with host_docker() as handle:
        with helper.helper(handle.client, IMAGE, TEST_INSTANCE, ["sleep", "60"], start=True) as box:
            info = handle.client.api.inspect_container(box.id)
            image = handle.client.api.inspect_image(info["Image"])
        host_config = info["HostConfig"]
        assert host_config["NetworkMode"] == "none"
        assert host_config["ReadonlyRootfs"] is True
        assert host_config["CapDrop"] == ["ALL"]
        assert not host_config.get("CapAdd")
        assert host_config["Privileged"] is False
        assert "no-new-privileges:true" in host_config["SecurityOpt"]
        assert host_config["PidsLimit"] == helper.PIDS_LIMIT
        labels = info["Config"]["Labels"]
        assert labels[helper.HELPER_LABEL] == "1"
        assert labels[helper.INSTANCE_LABEL] == TEST_INSTANCE
        digest = IMAGE.split("@", 1)[1]
        assert any(d.endswith("@" + digest) for d in image["RepoDigests"])
        with pytest.raises(docker.errors.NotFound):
            handle.client.containers.get(box.id)


@needs_docker
def test_helper_is_removed_when_the_body_fails() -> None:
    with host_docker() as handle:
        with (
            pytest.raises(RuntimeError),
            helper.helper(handle.client, IMAGE, TEST_INSTANCE) as box,
        ):
            raise RuntimeError("transfer failed")
        with pytest.raises(docker.errors.NotFound):
            handle.client.containers.get(box.id)


@needs_docker
def test_helper_is_removed_when_create_fails_after_the_daemon_made_it(monkeypatch) -> None:
    """docker-py inspects a container right after creating it; that call can fail too."""
    instance = f"t{uuid.uuid4().hex}"

    def connection_lost(self, container_id: str):
        raise requests.ConnectionError("the tunnel dropped")

    with host_docker() as handle:
        helper.ensure_image(handle.client, IMAGE)
        monkeypatch.setattr(docker.models.containers.ContainerCollection, "get", connection_lost)
        with pytest.raises(requests.ConnectionError), helper.helper(handle.client, IMAGE, instance):
            pytest.fail("the helper should not have been handed out")
        label = f"{helper.INSTANCE_LABEL}={instance}"
        assert handle.client.api.containers(all=True, filters={"label": label}) == []


@needs_docker
def test_put_archive_and_exec_stream_through_the_proxy() -> None:
    with host_docker() as handle:
        archive_and_exec_roundtrip(handle, TEST_INSTANCE)


@needs_docker
def test_inventory_groups_containers_by_compose_project() -> None:
    with host_docker() as handle, helper.helper(handle.client, IMAGE, TEST_INSTANCE) as box:
        # Another installation's helper, or any container with the label, stays visible.
        options = helper.helper_options(IMAGE, "anotherdrydock")
        options["labels"][TEST_LABEL] = "1"
        foreign = handle.client.containers.create(**options)
        labelled = handle.client.containers.create(
            IMAGE, labels={helper.HELPER_LABEL: "yes", TEST_LABEL: "1"}, network_mode="none"
        )
        try:
            groups = inventory.list_inventory(handle.client, TEST_INSTANCE)
        finally:
            for container in (foreign, labelled):
                helper.remove(handle.client, container.id)
    projects = [g.project for g in groups]
    assert projects == sorted(projects, key=lambda p: (p is None, p or ""))
    test_group = next(g for g in groups if g.project == TEST_PROJECT)
    remote = next(c for c in test_group.containers if c.service == "sshhost")
    assert remote.state == "running"
    assert remote.image == f"{TEST_PROJECT}-sshhost"
    data = next(m for m in remote.mounts if m.destination == "/var/lib/docker")
    assert data.type == "volume"
    assert data.name.endswith("dind-data")
    assert any(n.endswith("_default") for n in remote.networks)
    all_ids = {c.id for g in groups for c in g.containers}
    assert box.id not in all_ids, "this installation's helpers are not part of the inventory"
    assert {foreign.id, labelled.id} <= all_ids


@needs_docker
async def test_startup_reaper_removes_only_this_installations_helpers(settings: Settings) -> None:
    handle = await docker_client.run_blocking(host_docker)
    containers = handle.client.containers
    await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
    async with running(settings) as browser:
        instance = browser.app.state.hosts.instance_id
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        host_id = await docker_client.run_blocking(insert_host, browser, host)
    orphan = await docker_client.run_blocking(
        containers.create, **helper.helper_options(IMAGE, instance)
    )
    foreign = await docker_client.run_blocking(
        containers.create, **helper.helper_options(IMAGE, "anotherdrydock")
    )
    bystander = await docker_client.run_blocking(
        containers.create, IMAGE, labels={TEST_LABEL: "1"}, network_mode="none"
    )
    try:
        async with running(settings) as browser:
            assert browser.app.state.hosts.instance_id == instance

            def orphan_gone() -> bool:
                try:
                    containers.get(orphan.id)
                except docker.errors.NotFound:
                    return True
                return False

            await wait_until(orphan_gone, 30, "the reaper")
            await wait_until(lambda: get_host(browser, host_id).api_version is not None, 10, "seen")
            assert containers.get(foreign.id).id == foreign.id, "another drydock's helper"
            assert containers.get(bystander.id).id == bystander.id
            assert get_host(browser, host_id).last_seen is not None
    finally:
        for container in (orphan, foreign, bystander):
            helper.remove(handle.client, container.id)
        handle.close()


@needs_docker
async def test_the_scheduled_reaper_spares_helpers_in_use(settings: Settings) -> None:
    handle = await docker_client.run_blocking(host_docker)
    containers = handle.client.containers
    await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
    orphans: list[docker.models.containers.Container] = []
    started, release = threading.Event(), threading.Event()
    held: dict[str, str] = {}
    try:
        async with running(settings) as browser:
            instance = browser.app.state.hosts.instance_id
            host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
            await docker_client.run_blocking(insert_host, browser, host)
            options = helper.helper_options(IMAGE, instance)
            # Named like a helper, but no run uses it.
            name = f"{helper.NAME_PREFIX}{uuid.uuid4().hex}"
            orphans.append(
                await docker_client.run_blocking(lambda: containers.create(name=name, **options))
            )

            def a_run() -> None:  # a transfer in progress, through helper.helper()
                with helper.helper(handle.client, IMAGE, instance) as box:
                    held["id"] = box.id
                    started.set()
                    release.wait(60)

            thread = threading.Thread(target=a_run)
            thread.start()
            assert await anyio.to_thread.run_sync(started.wait, 30)
            await browser.app.state.scheduler._maintain()
            with pytest.raises(docker.errors.NotFound):
                containers.get(orphans[0].id)
            assert containers.get(held["id"]).id == held["id"]
            release.set()
            await anyio.to_thread.run_sync(thread.join, 30)
            with pytest.raises(docker.errors.NotFound):
                containers.get(held["id"])  # removed by the run itself
            assert helper._live == set()
    finally:
        release.set()
        for container in orphans:
            helper.remove(handle.client, container.id)
        handle.close()


# SSH


def host_state(browser: Browser, host_id: int) -> str:
    return browser.app.state.hosts.status(get_host(browser, host_id)).state


@needs_ssh
async def test_ssh_forward_carries_put_archive_and_exec_stream(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    await wait_until(lambda: host_state(admin, host_id) == "connected", 30, "the tunnel")

    socket_path = admin.app.state.hosts.socket_path(host_id)
    assert stat.S_IMODE(socket_path.parent.stat().st_mode) == 0o700
    assert stat.S_ISSOCK(socket_path.stat().st_mode)
    assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600

    handle = await connect_host(admin, host_id)
    try:
        assert handle.engine_version.startswith("29.")
        assert docker_client.api_tuple(handle.api_version) <= (1, 56)
        instance = admin.app.state.hosts.instance_id
        await docker_client.run_blocking(archive_and_exec_roundtrip, handle, instance)
    finally:
        await docker_client.run_blocking(handle.close)
    await wait_until(lambda: get_host(admin, host_id).api_version is not None, 10, "seen")


@needs_ssh
async def test_authorized_key_options_refuse_commands(admin: Browser) -> None:
    """The suggested authorized_keys options leave the forward working but run nothing."""
    host_id = await add_ssh_host(admin)
    await wait_until(lambda: host_state(admin, host_id) == "connected", 30, "the tunnel")
    hosts = admin.app.state.hosts
    target = await docker_client.run_blocking(hosts._target, get_host(admin, host_id))
    async with asyncssh.connect(SSH_HOST, 22, options=ssh.client_options(target)) as conn:
        result = await conn.run("id; echo ran", check=False)
    assert result.exit_status != 0
    assert "ran" not in str(result.stdout) and "uid=" not in str(result.stdout)


@needs_ssh
async def test_no_key_material_on_disk_after_connecting(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    await wait_until(lambda: host_state(admin, host_id) == "connected", 30, "the tunnel")
    handle = await connect_host(admin, host_id)
    await docker_client.run_blocking(handle.client.ping)
    await docker_client.run_blocking(handle.close)

    roots = [Path("/data"), Path("/tmp"), Path("/run"), admin.settings.data_dir]  # noqa: S108
    assert find_key_material([r for r in roots if r.exists()]) == []
    stored = admin.sql("SELECT ssh_key_enc FROM hosts WHERE id = ?", (host_id,))[0][0]
    assert stored.startswith("gAAAAA"), "the key is stored only as a Fernet token"


@needs_ssh
# The sshhost has only an ed25519 host key. A pinned ECDSA key makes asyncssh offer only
# ECDSA, so key exchange fails instead of reporting a mismatch; that must alarm too.
@pytest.mark.parametrize("algorithm", ["ssh-ed25519", "ecdsa-sha2-nistp256"])
async def test_host_key_mismatch_refuses_the_connection(
    admin: Browser, monkeypatch, algorithm: str
) -> None:
    docker_calls = []
    real_send = docker.APIClient.send

    def spy(self, request, **kwargs):
        # Unix socket requests (the SSH forward); the test's own proxy calls are tcp.
        if request.url.startswith("http+docker://"):
            docker_calls.append(request.url)
        return real_send(self, request, **kwargs)

    monkeypatch.setattr(docker.APIClient, "send", spy)
    impostor = ssh.known_host_line(SSH_HOST, 22, asyncssh.generate_private_key(algorithm))
    _, real_fingerprint = await ssh.scan_host_key(SSH_HOST, 22)

    host_id = await add_ssh_host(admin, known_host_line=impostor)
    await wait_until(lambda: host_state(admin, host_id) == "hostkey_mismatch", 30, "mismatch")

    def audit_rows() -> list[tuple]:
        return admin.sql(
            "SELECT actor, target, outcome, details FROM audit_events "
            "WHERE action = 'host.hostkey_mismatch'"
        )

    await wait_until(lambda: bool(audit_rows()), 30, "the audit row")
    actor, target, outcome, details = audit_rows()[0]
    assert (actor, target, outcome) == (None, f"host:{host_id}", "failure")
    assert json.loads(details)["presented_fingerprint"] == real_fingerprint

    host = get_host(admin, host_id)
    status = admin.app.state.hosts.status(host)
    assert "does not match the trusted key" in status.error
    page = await admin.get(f"/hosts/{host_id}")
    assert "Host key mismatch: drydock refused to connect." in page.text
    assert "does not match the trusted key" in page.text
    listing = await admin.get("/hosts")
    assert "host key mismatch" in listing.text
    assert not admin.app.state.hosts.socket_path(host_id).exists()
    with pytest.raises(HostUnavailable, match="does not match"):
        admin.app.state.hosts.docker_url(host)
    assert docker_calls == []
    assert host.api_version is None and host.last_seen is None


@needs_ssh
async def test_reconnects_after_sshd_restart(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    await wait_until(lambda: host_state(admin, host_id) == "connected", 30, "the tunnel")
    proxy = await docker_client.run_blocking(host_docker)
    remote = await docker_client.run_blocking(sshhost, proxy)
    try:
        # Kills the listener and every session process (sshd-session, sshd-auth).
        await docker_client.run_blocking(sh, remote, "pkill sshd; true")
        await wait_until(lambda: host_state(admin, host_id) == "disconnected", 30, "disconnect")
        assert not admin.app.state.hosts.socket_path(host_id).exists()
        with pytest.raises(HostUnavailable):
            admin.app.state.hosts.docker_url(get_host(admin, host_id))
        # Let the backoff grow past its first steps before sshd comes back.
        await anyio.sleep(8)
    finally:
        await docker_client.run_blocking(sh, remote, "pgrep -x sshd || /usr/sbin/sshd")
        await docker_client.run_blocking(proxy.close)
    elapsed = await wait_until(lambda: host_state(admin, host_id) == "connected", 60, "reconnect")
    assert elapsed < 60
    handle = await connect_host(admin, host_id)
    try:
        assert await docker_client.run_blocking(handle.client.ping)
    finally:
        await docker_client.run_blocking(handle.close)


@needs_ssh
async def test_startup_reconnects_and_reaps_ssh_hosts(settings: Settings) -> None:
    async with running(settings) as browser:
        assert (await browser.setup()).status_code == 303
        host_id = await add_ssh_host(browser)
        await wait_until(lambda: host_state(browser, host_id) == "connected", 30, "the tunnel")
        handle = await connect_host(browser, host_id)
        remote = handle.client
        await docker_client.run_blocking(helper.ensure_image, remote, IMAGE)
        options = helper.helper_options(IMAGE, browser.app.state.hosts.instance_id)
        orphan = await docker_client.run_blocking(remote.containers.create, **options)
        await docker_client.run_blocking(handle.close)

    async with running(settings) as browser:
        await wait_until(lambda: host_state(browser, host_id) == "connected", 30, "the tunnel")
        handle = await connect_host(browser, host_id)
        try:
            # Blocking calls must leave the event loop free: it also runs the SSH forward.
            # sparse: list() would inspect each match, which 404s if the reaper wins the race.
            for _ in range(150):
                found = await docker_client.run_blocking(
                    handle.client.containers.list, all=True, filters={"id": orphan.id}, sparse=True
                )
                if not found:
                    break
                await anyio.sleep(0.2)
            assert not found, "the startup reaper did not remove the orphaned helper"
        finally:
            await docker_client.run_blocking(handle.close)
    assert not (settings.run_dir / "hosts" / f"{host_id}.sock").exists()


# THROUGH THE UI


def host_id_from(response) -> int:
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


@needs_docker
async def test_local_host_through_the_ui(admin: Browser) -> None:
    form = {"kind": "local", "name": "local", "docker_url": DOCKER_URL, "enabled": "1"}
    host_id = host_id_from(await admin.post("/hosts", form))

    test = await admin.post(f"/hosts/{host_id}/test")
    assert test.status_code == 200
    expected = docker_client.negotiate(docker_client.read_version(DOCKER_URL))
    assert f"{expected} (negotiated)" in test.text
    assert "Docker " in test.text and "linux/" in test.text
    assert get_host(admin, host_id).api_version == expected

    inventory = await admin.get(f"/hosts/{host_id}/containers")
    assert inventory.status_code == 200
    assert f"Compose project <code>{TEST_PROJECT}</code>" in inventory.text
    assert "service sshhost" in inventory.text
    assert f"{TEST_PROJECT}-sshhost" in inventory.text


@needs_ssh
async def test_ssh_host_through_the_ui(admin: Browser) -> None:
    form = {
        "kind": "ssh",
        "name": "remote",
        "address": SSH_HOST,
        "port": "22",
        "username": "drydock",
        "remote_socket_path": "/var/run/docker.sock",
        "key_source": "generate",
        "enabled": "1",
    }
    host_id = host_id_from(await admin.post("/hosts", form))
    public_key = get_host(admin, host_id).ssh_public_key
    page = await admin.get(f"/hosts/{host_id}")
    assert str(escape(f"{ssh.AUTHORIZED_KEY_OPTIONS} {public_key}")) in page.text
    await docker_client.run_blocking(authorize, public_key)

    _, fingerprint = await ssh.scan_host_key(SSH_HOST, 22)
    scan = await admin.post(f"/hosts/{host_id}/scan-hostkey")
    assert scan.status_code == 200 and fingerprint in scan.text
    trust = await admin.post(f"/hosts/{host_id}/trust-hostkey", {"fingerprint": fingerprint})
    assert trust.status_code == 303
    await wait_until(lambda: host_state(admin, host_id) == "connected", 30, "the tunnel")

    test = await admin.post(f"/hosts/{host_id}/test")
    assert "Docker 29." in test.text and "(negotiated)" in test.text

    handle = await connect_host(admin, host_id)
    remote = handle.client
    await docker_client.run_blocking(helper.ensure_image, remote, IMAGE)
    labels = {"com.docker.compose.project": "demo", "com.docker.compose.service": "web"}
    container = await docker_client.run_blocking(
        remote.containers.create, IMAGE, name="demo-web-1", labels=labels
    )
    try:
        inventory = await admin.get(f"/hosts/{host_id}/containers")
        assert "Compose project <code>demo</code>" in inventory.text
        assert "demo-web-1" in inventory.text and "service web" in inventory.text
    finally:
        await docker_client.run_blocking(helper.remove, remote, container.id)
        await docker_client.run_blocking(handle.close)

    page = await admin.get(f"/hosts/{host_id}")
    assert fingerprint in page.text
    for marker in KEY_MARKERS:
        assert marker.decode() not in page.text
    assert "gAAAAA" not in page.text
    roots = [Path("/data"), Path("/tmp"), Path("/run"), admin.settings.data_dir]  # noqa: S108
    assert find_key_material([r for r in roots if r.exists()]) == []


# JOB FORM SUGGESTIONS


@needs_docker
async def test_the_job_form_suggests_the_hosts_containers_and_projects(admin: Browser) -> None:
    with admin.app.state.sessionmaker() as db, db.begin():
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        db.add(host)
        db.flush()
        host_id = host.id
    project = f"drydock-test-pick-{uuid.uuid4().hex[:8]}"
    with host_docker() as handle:
        box = handle.client.containers.create(
            IMAGE,
            ["sleep", "60"],
            name=f"{project}-web-1",
            labels={TEST_LABEL: "1", "com.docker.compose.project": project},
        )
        try:
            containers = await admin.get(
                "/jobs/target-options", params={"host_id": host_id, "target_type": "container"}
            )
            stacks = await admin.get(
                "/jobs/target-options", params={"host_id": host_id, "target_type": "stack"}
            )
        finally:
            box.remove(force=True)
    assert f'<option value="{project}-web-1">' in containers.text
    assert f'<option value="{project}">' in stacks.text
    assert f'<option value="{project}-web-1">' not in stacks.text


@needs_docker
async def test_the_job_form_lists_the_targets_mounts_to_skip(admin: Browser) -> None:
    with admin.app.state.sessionmaker() as db, db.begin():
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        db.add(host)
        db.flush()
        host_id = host.id
    project = f"drydock-test-mounts-{uuid.uuid4().hex[:8]}"
    with host_docker() as handle:
        volume = handle.client.volumes.create(f"{project}_data", labels={TEST_LABEL: "1"})
        box = handle.client.containers.create(
            IMAGE,
            ["sleep", "60"],
            name=f"{project}-db-1",
            labels={TEST_LABEL: "1", "com.docker.compose.project": project},
            mounts=[docker.types.Mount("/data", volume.name, type="volume")],
        )
        try:
            listed = await admin.get(
                "/jobs/mount-options",
                params={
                    "host_id": host_id,
                    "target_type": "stack",
                    "target": project,
                    "skip_mounts": ["bind:/gone/elsewhere"],
                },
            )
        finally:
            box.remove(force=True)
            volume.remove(force=True)
    assert f'value="volume:{volume.name}">' in listed.text  # offered, not ticked
    assert f"{project}-db-1:/data" in listed.text
    assert 'value="bind:/gone/elsewhere" checked' in listed.text
    assert "not a mount of this target now" in listed.text
