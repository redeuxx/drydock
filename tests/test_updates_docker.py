"""Checking for newer images against a real registry: a local registry on the host daemon
(reached by the daemon at 127.0.0.1, which Docker trusts without TLS), through the socket
proxy, as drydock does it."""

import contextlib
import functools
import secrets
import time
import uuid

import docker.errors
import pytest

from drydock.config import DEFAULT_HELPER_IMAGE
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.models import Host
from tests.conftest import Browser
from tests.docker_support import DOCKER_URL, TEST_LABEL, host_docker, insert_host, needs_docker

pytestmark = pytest.mark.anyio

REGISTRY_IMAGE = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
IMAGE = DEFAULT_HELPER_IMAGE


def push(api, repository: str, source: str) -> None:
    """Blocking. Tags source as repository:latest, pushes it (trying again while the
    registry is still starting) and pulls it back."""
    api.tag(source, repository, "latest")
    for attempt in range(10):
        failed = None
        for line in api.push(repository, tag="latest", stream=True, decode=True):
            if isinstance(line, dict) and line.get("error"):
                failed = line["error"]
        if failed is None:
            # Pulled back, as a host gets its images: RepoDigests then holds the digest
            # the registry serves (a push of one platform of an index makes a new one).
            api.pull(repository, tag="latest")
            return
        if attempt == 9:
            raise AssertionError(f"push failed: {failed}")
        time.sleep(1)


@needs_docker
async def test_a_newer_image_on_the_registry_is_found(admin: Browser) -> None:
    handle = await docker_client.run_blocking(host_docker)
    client = handle.client
    api = client.api
    made: list = []
    repository = ""
    port = 20000 + secrets.randbelow(40000)
    try:
        for image in (REGISTRY_IMAGE, IMAGE):
            await docker_client.run_blocking(helper.ensure_image, client, image)
        registry = await docker_client.run_blocking(
            functools.partial(
                client.containers.run,
                REGISTRY_IMAGE,
                detach=True,
                labels={TEST_LABEL: "1"},
                # On the daemon's own network, listening on loopback only: the daemon
                # pushes to it, and nothing outside the host can reach it.
                network_mode="host",
                environment={
                    "REGISTRY_HTTP_ADDR": f"127.0.0.1:{port}",
                    "OTEL_TRACES_EXPORTER": "none",
                },
            )
        )
        made.append(registry)
        # 127.0.0.1, not localhost: the daemon may resolve that to ::1, where nothing listens.
        repository = f"127.0.0.1:{port}/drydock-test-{uuid.uuid4().hex[:8]}"
        await docker_client.run_blocking(push, api, repository, IMAGE)
        app = await docker_client.run_blocking(
            functools.partial(
                client.containers.run,
                f"{repository}:latest",
                ["sleep", "3600"],
                detach=True,
                init=True,
                labels={TEST_LABEL: "1"},
                network_mode="none",
            )
        )
        made.append(app)
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        host_id = await docker_client.run_blocking(insert_host, admin, host)
        checker = admin.app.state.updates

        first = await checker.check_host(host)
        assert first.error is None
        assert first.verdicts[app.id].state == "current", first.verdicts[app.id]
        assert first.verdicts[registry.id].state == "skipped", "pinned by digest"

        # Another image under the same tag: the running container is now behind.
        await docker_client.run_blocking(push, api, repository, REGISTRY_IMAGE)
        checker._caches.clear()
        second = await checker.check_host(host)
        # Pushing through this daemon moved its tag too (and pulling it back made the old
        # image nameless in containerd's store): found as already pulled.
        found = second.verdicts[app.id]
        assert found.state == "update" and found.ref == f"{repository}:latest", found
        assert checker.result(host_id) is second
    finally:
        for container in made:
            with contextlib.suppress(docker.errors.NotFound):
                await docker_client.run_blocking(functools.partial(container.remove, force=True))
        if repository:
            with contextlib.suppress(docker.errors.APIError):
                await docker_client.run_blocking(api.remove_image, f"{repository}:latest")
        handle.close()


def by_name(api, name: str) -> dict:
    """Blocking. The container of that exact name now."""
    return api.inspect_container(name)


@needs_docker
async def test_an_update_replaces_a_container_or_puts_it_back(admin: Browser) -> None:
    handle = await docker_client.run_blocking(host_docker)
    client = handle.client
    api = client.api
    names: list[str] = []
    made: list = []
    repository = ""
    port = 20000 + secrets.randbelow(40000)
    try:
        for image in (REGISTRY_IMAGE, IMAGE):
            await docker_client.run_blocking(helper.ensure_image, client, image)
        registry = await docker_client.run_blocking(
            functools.partial(
                client.containers.run,
                REGISTRY_IMAGE,
                detach=True,
                labels={TEST_LABEL: "1"},
                network_mode="host",
                environment={
                    "REGISTRY_HTTP_ADDR": f"127.0.0.1:{port}",
                    "OTEL_TRACES_EXPORTER": "none",
                },
            )
        )
        made.append(registry)
        repository = f"127.0.0.1:{port}/drydock-test-{uuid.uuid4().hex[:8]}"
        await docker_client.run_blocking(push, api, repository, IMAGE)

        def start(command: list[str]):
            name = f"drydock-test-update-{uuid.uuid4().hex[:8]}"
            names.append(name)
            return client.containers.run(
                f"{repository}:latest",
                command,
                name=name,
                detach=True,
                init=True,
                labels={TEST_LABEL: "1"},
                network_mode="none",
                restart_policy={"Name": "unless-stopped"},
            )

        good = await docker_client.run_blocking(start, ["sh", "-c", "sleep 3600"])
        # Exits at once on the new image (the registry's, which has /bin/registry).
        bad = await docker_client.run_blocking(
            start, ["sh", "-c", "test -e /bin/registry && exit 3; sleep 3600"]
        )
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        host_id = await docker_client.run_blocking(insert_host, admin, host)
        await docker_client.run_blocking(push, api, repository, REGISTRY_IMAGE)
        tagged = f"{repository}:latest"
        new_image = (await docker_client.run_blocking(api.inspect_image, tagged))["Id"]
        dispatcher = admin.app.state.dispatcher

        run_id = await dispatcher.submit_update(host_id, [good.id], "tester", good.name)
        await dispatcher.wait(run_id)
        assert admin.sql("SELECT kind, status, error FROM runs WHERE id = ?", (run_id,)) == [
            ("update", "done", None)
        ]
        now = await docker_client.run_blocking(by_name, api, good.name)
        assert now["Id"] != good.id and now["Image"] == new_image
        assert now["Config"]["Image"] == f"{repository}:latest"
        assert now["Config"]["Cmd"] == ["sh", "-c", "sleep 3600"]
        assert now["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
        assert now["State"]["Running"]
        with pytest.raises(docker.errors.NotFound):
            await docker_client.run_blocking(api.inspect_container, good.id)

        run_id = await dispatcher.submit_update(host_id, [bad.id], "tester", bad.name)
        await dispatcher.wait(run_id)
        ((status, error),) = admin.sql("SELECT status, error FROM runs WHERE id = ?", (run_id,))
        assert status == "failed" and "after the update" in error, error
        back = await docker_client.run_blocking(by_name, api, bad.name)
        assert back["Id"] == bad.id and back["State"]["Running"], "the original, running"
        assert back["HostConfig"]["RestartPolicy"]["Name"] == "unless-stopped"
        listed = await docker_client.run_blocking(
            functools.partial(api.containers, all=True, filters={"name": bad.name})
        )
        assert [c["Names"][0] for c in listed] == [f"/{bad.name}"], "no new or -drydock-old left"
    finally:
        for name in names:
            with contextlib.suppress(docker.errors.NotFound):
                await docker_client.run_blocking(
                    functools.partial(api.remove_container, name, force=True)
                )
        for container in made:
            with contextlib.suppress(docker.errors.NotFound):
                await docker_client.run_blocking(functools.partial(container.remove, force=True))
        if repository:
            with contextlib.suppress(docker.errors.APIError):
                await docker_client.run_blocking(api.remove_image, f"{repository}:latest")
        handle.close()
