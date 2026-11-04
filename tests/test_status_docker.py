"""The container status collector against real daemons: the host daemon through the socket
proxy, and the sshhost through its SSH tunnel."""

import asyncio
import contextlib

import docker.errors
import pytest

from drydock.config import DEFAULT_HELPER_IMAGE, Settings
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.hosts.status import HostSnapshot, StatusCollector
from drydock.models import Host
from tests.conftest import Browser, running
from tests.docker_support import (
    DOCKER_URL,
    TEST_LABEL,
    add_ssh_host,
    connect_host,
    get_host,
    host_docker,
    insert_host,
    needs_docker,
    needs_ssh,
    wait_until,
)

pytestmark = pytest.mark.anyio

IMAGE = DEFAULT_HELPER_IMAGE
BUSY = ["sh", "-c", "while :; do :; done"]  # keeps one core busy, so CPU shows


async def poll(collector: StatusCollector, host_id: int) -> HostSnapshot:
    collector.touch()
    await asyncio.gather(*await collector.poll())
    snapshot = collector.snapshot(host_id)
    assert snapshot is not None
    assert snapshot.error is None, snapshot.error
    return snapshot


def row(snapshot: HostSnapshot, container_id: str):
    return next(c for c in snapshot.containers if c.id == container_id)


def remove(client, *containers) -> None:
    for container in containers:
        with contextlib.suppress(docker.errors.NotFound):
            container.remove(force=True)


@needs_docker
async def test_status_of_the_local_host_through_the_proxy(settings: Settings) -> None:
    handle = await docker_client.run_blocking(host_docker)
    containers = handle.client.containers
    await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
    busy = await docker_client.run_blocking(
        containers.run, IMAGE, BUSY, detach=True, labels={TEST_LABEL: "1"}, network_mode="none"
    )
    # Exits at once and is restarted by Docker: its restart count goes up.
    flaky = await docker_client.run_blocking(
        containers.run,
        IMAGE,
        ["sh", "-c", "exit 1"],
        detach=True,
        labels={TEST_LABEL: "1"},
        network_mode="none",
        restart_policy={"Name": "on-failure", "MaximumRetryCount": 2},
    )
    try:
        async with running(settings) as browser:
            instance = browser.app.state.hosts.instance_id
            orphan = await docker_client.run_blocking(
                containers.create, **helper.helper_options(IMAGE, instance)
            )
            try:
                host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
                host_id = await docker_client.run_blocking(insert_host, browser, host)
                collector: StatusCollector = browser.app.state.status

                first = await poll(collector, host_id)
                assert first.engine and first.ncpu and first.mem_total
                found = row(first, busy.id)
                assert found.state == "running" and found.status.startswith("Up")
                assert found.mem_bytes and found.mem_limit
                assert found.cpu_percent is None, "one sample so far"
                assert all(c.id != orphan.id for c in first.containers), "helpers left out"
                assert first.states["running"] >= 1

                await asyncio.sleep(1)
                second = await poll(collector, host_id)
                assert row(second, busy.id).cpu_percent > 10, "a busy loop uses a core"
                assert second.cpu_percent is not None and second.cpu_percent > 0

                def restarted() -> bool:
                    return flaky.client.api.inspect_container(flaky.id)["RestartCount"] > 0

                await wait_until(restarted, 30, "a restart")
                await asyncio.sleep(1)
                collector._caches[host_id].inspected.clear()  # skip the 60 s re-inspect
                third = await poll(collector, host_id)
                assert row(third, flaky.id).restarts > 0
            finally:
                await docker_client.run_blocking(helper.remove, handle.client, orphan.id)
    finally:
        await docker_client.run_blocking(remove, handle.client, busy, flaky)
        handle.close()


@needs_ssh
async def test_status_of_an_ssh_host_through_its_tunnel(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    handle = await connect_host(admin, host_id)
    try:
        await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
        sleeper = await docker_client.run_blocking(
            handle.client.containers.run,
            IMAGE,
            ["sleep", "600"],
            detach=True,
            labels={TEST_LABEL: "1"},
            network_mode="none",
        )
        try:
            collector: StatusCollector = admin.app.state.status
            snapshot = await poll(collector, host_id)
            assert row(snapshot, sleeper.id).state == "running"
            assert snapshot.engine == handle.engine_version

            # The tunnel goes down and comes back: the kept client is replaced once.
            await admin.app.state.hosts.reload(host_id)
            hosts = admin.app.state.hosts
            await wait_until(
                lambda: hosts.status(get_host(admin, host_id)).state == "connected",
                30,
                "the tunnel to come back",
            )
            again = await poll(collector, host_id)
            assert row(again, sleeper.id).state == "running"
        finally:
            await docker_client.run_blocking(remove, handle.client, sleeper)
    finally:
        handle.close()
