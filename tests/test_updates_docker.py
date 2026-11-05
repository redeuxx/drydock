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


def start_registry(client):
    """Blocking. A registry on the daemon's own network, listening on loopback only (the
    daemon pushes to it; nothing outside the host can reach it), its debug listener on the
    next port (its default, :5001, is shared by every registry on the host, such as the
    other CI leg's). Waits until it listens; returns it and its port."""
    for attempt in range(5):
        # Below Linux's ephemeral range (32768+), where the host's own client sockets sit.
        port = 20000 + 2 * secrets.randbelow(6000)
        registry = client.containers.run(
            REGISTRY_IMAGE,
            detach=True,
            labels={TEST_LABEL: "1"},
            network_mode="host",
            environment={
                "REGISTRY_HTTP_ADDR": f"127.0.0.1:{port}",
                "REGISTRY_HTTP_DEBUG_ADDR": f"127.0.0.1:{port + 1}",
                "OTEL_TRACES_EXPORTER": "none",
            },
        )
        deadline = time.monotonic() + 60
        while b"listening on 127.0.0.1:%d" % port not in registry.logs():
            registry.reload()
            if registry.status != "running" or time.monotonic() > deadline:
                logs = registry.logs()[-2000:].decode(errors="replace")
                registry.remove(force=True)
                # Taken by something else on the shared host: try another port.
                if "address already in use" in logs and attempt < 4:
                    break
                raise AssertionError(f"the test registry did not start: {logs}")
            time.sleep(0.5)
        else:
            return registry, port
    raise AssertionError("unreachable")


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
    try:
        for image in (REGISTRY_IMAGE, IMAGE):
            await docker_client.run_blocking(helper.ensure_image, client, image)
        registry, port = await docker_client.run_blocking(start_registry, client)
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
    try:
        for image in (REGISTRY_IMAGE, IMAGE):
            await docker_client.run_blocking(helper.ensure_image, client, image)
        registry, port = await docker_client.run_blocking(start_registry, client)
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


@needs_docker
async def test_a_stack_update_is_all_or_nothing(admin: Browser) -> None:
    """db (healthcheck) and app (needs db healthy, exits on the new image) share a newer
    image; side is pinned by digest. app fails, so db is put back too; side is untouched."""
    handle = await docker_client.run_blocking(host_docker)
    client = handle.client
    api = client.api
    project = f"drydock-test-stack-{uuid.uuid4().hex[:8]}"
    made: list = []
    repository = ""
    try:
        for image in (REGISTRY_IMAGE, IMAGE):
            await docker_client.run_blocking(helper.ensure_image, client, image)
        registry, port = await docker_client.run_blocking(start_registry, client)
        made.append(registry)
        repository = f"127.0.0.1:{port}/drydock-test-{uuid.uuid4().hex[:8]}"
        await docker_client.run_blocking(push, api, repository, IMAGE)

        def member(service: str, image: str, command: list[str], **extra):
            labels = {
                TEST_LABEL: "1",
                "com.docker.compose.project": project,
                "com.docker.compose.service": service,
            } | extra.pop("labels", {})
            return client.containers.run(
                image,
                command,
                name=f"{project}-{service}-1",
                detach=True,
                init=True,
                labels=labels,
                network_mode="none",
                restart_policy={"Name": "unless-stopped"},
                **extra,
            )

        tagged = f"{repository}:latest"
        db = await docker_client.run_blocking(
            functools.partial(
                member,
                "db",
                tagged,
                ["sleep", "3600"],
                healthcheck={"test": ["CMD", "true"], "interval": 500_000_000},
            )
        )
        app = await docker_client.run_blocking(
            functools.partial(
                member,
                "app",
                tagged,
                ["sh", "-c", "test -e /bin/registry && exit 3; sleep 3600"],
                labels={"com.docker.compose.depends_on": "db:service_healthy:false"},
            )
        )
        side = await docker_client.run_blocking(
            functools.partial(member, "side", IMAGE, ["sleep", "3600"])
        )
        made += [db, app, side]
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        host_id = await docker_client.run_blocking(insert_host, admin, host)
        await docker_client.run_blocking(push, api, repository, REGISTRY_IMAGE)
        dispatcher = admin.app.state.dispatcher

        run_id = await dispatcher.submit_update(host_id, [], "tester", project, project=project)
        await dispatcher.wait(run_id)
        ((status, error),) = admin.sql("SELECT status, error FROM runs WHERE id = ?", (run_id,))
        assert status == "failed" and "app" in error, error
        log = (admin.app.state.settings.data_dir / "logs" / f"{run_id}.log").read_text()
        assert f"Updating {project}-db-1:" in log and f"Updating {project}-app-1:" in log
        assert f"{project}-side-1: pinned by digest or image ID, so not updated." in log
        assert log.index(f"Creating container {project}-db-1.") < log.index(
            f"Creating container {project}-app-1."
        ), "dependencies first"
        for original in (db, app, side):
            now = await docker_client.run_blocking(by_name, api, original.name)
            assert now["Id"] == original.id, f"{original.name} is the original again"
            assert now["State"]["Running"], original.name
        listed = await docker_client.run_blocking(
            functools.partial(
                api.containers, all=True, filters={"label": f"com.docker.compose.project={project}"}
            )
        )
        assert len(listed) == 3, "no new or -drydock-old containers left"
    finally:
        for container in made:
            with contextlib.suppress(docker.errors.NotFound):
                await docker_client.run_blocking(functools.partial(container.remove, force=True))
        if repository:
            with contextlib.suppress(docker.errors.APIError):
                await docker_client.run_blocking(api.remove_image, f"{repository}:latest")
        handle.close()
