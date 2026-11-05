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
