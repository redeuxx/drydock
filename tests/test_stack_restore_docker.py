"""Stack restores against the sshhost dind daemon, driven through the restore wizard (see
compose.test.yaml).

The Phase 4 exit criteria that need real containers:
- A Compose stack backed up on the SSH host and restored under a new project name runs
  beside the original: no volume or network is shared, and service names and links
  resolve inside the copy.
- The compose files and .env written by a restore match the host files byte for byte, in
  a new 0700 directory of 0600 files owned by root; an existing directory is refused before
  anything changes, even for a stack with no bind mounts.
- A compose directory under /etc is rejected through the wizard before any Docker change.
- A single-container restore can write its compose files too, and keeps no Compose label.
- An overwrite restore of a stack stops the originals and creates the copies in dependency
  order and leaves no -drydock-old container.

Backups go through the SSH host entry; restores through a second, plain TCP host entry for
the same daemon (add_dind_host), as a restore on another host entry would. Every project
made here is drydock-test-stack-<hex> or drydock-test-run-<hex> and removed afterwards.
"""

import hashlib
import json
import re
import uuid
from typing import Any

import docker
import pytest

from drydock.config import Settings
from drydock.restore.plan import OLD_SUFFIX
from tests.conftest import running
from tests.docker_support import (
    PROJECT_LABEL,
    event_times,
    needs_docker,
    needs_ssh,
    recorded_events,
    sh,
    wait_until,
)
from tests.test_capture import (
    dind,  # noqa: F401 (the fixture make_stack uses)
    needs_dind,
)
from tests.test_restore_docker import (
    add_dind_host,
    alerts,
    archived_volume,
    execute,
    finished,
    plan,
    verify,
)
from tests.test_runs_docker import App
from tests.test_stacks_docker import (
    DB_DIR,
    SERVICES,
    Stack,
    make_stack,  # noqa: F401 (the fixture stack uses)
    ssh_app,
    stack_job,
)

pytestmark = [pytest.mark.anyio, needs_docker, needs_ssh, needs_dind]

COMPOSE_FILES = [".env", "compose.yaml"]
NAME_RE = re.compile(r"^Name:\s*\S+\s*\nAddress:\s*([0-9.]+)", re.MULTILINE)


# HELPERS


@pytest.fixture
def stack(request: pytest.FixtureRequest) -> Stack:
    """The db + redis + app stack of tests.test_stacks_docker, on sshhost."""
    return request.getfixturevalue("make_stack")()


async def backup(app: App, stack: Stack, ssh_id: int) -> str:
    """A stop mode backup of the whole stack through the SSH host entry."""
    run_id = await app.run(await stack_job(app, stack, ssh_id, "stop"))
    row = app.run_row(run_id)
    assert row["status"] == "done", app.log(run_id)
    return row["archive_name"]


async def run_restore(app: App, run_id: int, confirm_name: str = "") -> str:
    """Confirms the stored plan and waits for the run; returns its status."""
    await execute(app, run_id, confirm_name)
    await app.browser.app.state.dispatcher.wait(run_id)
    return app.status(run_id)


def volume_names(info: dict[str, Any]) -> set[str]:
    return {m["Name"] for m in info.get("Mounts") or [] if m.get("Type") == "volume"}


def endpoints(info: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return (info.get("NetworkSettings") or {}).get("Networks") or {}


def resolved(container, host: str) -> set[str]:
    """The addresses busybox nslookup finds for host inside the container."""
    code, output = container.exec_run(["nslookup", host])
    assert code == 0, output
    return set(NAME_RE.findall(output.decode()))


def host_sums(stack: Stack, directory: str) -> dict[str, str]:
    return {
        name: sh(stack.box, 'sha256sum "$1"', f"{directory}/{name}").split()[0]
        for name in COMPOSE_FILES
    }


def check_compose_dir(stack: Stack, directory: str) -> None:
    """The compose files byte for byte, alone in a 0700 directory, each 0600, all root's."""
    assert host_sums(stack, directory) == host_sums(stack, stack.root)
    listing = sh(stack.box, 'cd "$1" && find . -mindepth 1 | sort', directory).split()
    assert listing == [f"./{name}" for name in COMPOSE_FILES], listing
    assert sh(stack.box, 'stat -c "%u %a" "$1"', directory).strip() == "0 700"
    for name in COMPOSE_FILES:
        assert sh(stack.box, 'stat -c "%u %a" "$1"', f"{directory}/{name}").strip() == "0 600"


def leftovers(stack: Stack, name: str) -> list[str]:
    """Containers, volumes and networks of the sshhost daemon named after name."""
    client = stack.handle.client
    found = [c.name for c in client.containers.list(all=True)]
    found += [v.name for v in client.volumes.list()]
    found += [n.name for n in client.networks.list()]
    return [n for n in found if n == name or n.startswith((f"{name}-", f"{name}_"))]


# A NEW PROJECT BESIDE THE ORIGINAL


async def test_stack_restored_under_a_new_project_runs_beside_it(
    settings: Settings, stack: Stack
) -> None:
    new = stack.copy_name()
    api = stack.api
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        archive = await backup(app, stack, ssh_id)
        dind_id = add_dind_host(app)
        uptimes = stack.uptimes()
        run_id = await verify(app, archive)
        summary = await plan(
            app, run_id, "new-name", dind_id, new_name=new, compose_dir=f"{stack.root}/copy"
        )
        assert summary["project"] == new, summary
        assert summary["containers"] == [f"{new}-{s}-1" for s in SERVICES], summary
        assert summary["compose"] == {"dir": f"{stack.root}/copy", "files": COMPOSE_FILES}
        assert await run_restore(app, run_id) == "done", app.log(run_id)
        # The compose write is best effort after the commit, so "done" alone does not prove it.
        assert f"Wrote 2 compose files to {stack.root}/copy." in app.log(run_id), app.log(run_id)
        finished(app, [stack.handle.client], run_id)
    check_compose_dir(stack, f"{stack.root}/copy")

    # The original runs untouched.
    assert stack.running() and stack.uptimes() == uptimes
    originals = {s: stack.inspect(s) for s in SERVICES}
    copies = {s: api.inspect_container(f"{new}-{s}-1") for s in SERVICES}
    for service, info in copies.items():
        assert info["State"]["Running"], service
        assert info["Config"]["Labels"][PROJECT_LABEL] == new, service
    # Nothing shared: every volume and network of the copy is its own.
    old_volumes = set().union(*map(volume_names, originals.values()))
    new_volumes = set().union(*map(volume_names, copies.values()))
    assert new_volumes and not old_volumes & new_volumes, (old_volumes, new_volumes)
    old_networks = {n: e["NetworkID"] for i in originals.values() for n, e in endpoints(i).items()}
    new_networks = {n: e["NetworkID"] for i in copies.values() for n, e in endpoints(i).items()}
    assert list(new_networks) == [f"{new}_default"], new_networks
    assert not set(old_networks) & set(new_networks)
    assert not set(old_networks.values()) & set(new_networks.values())

    # Service names resolve to the copies inside the new network.
    network = f"{new}_default"
    app_copy = stack.handle.client.containers.get(copies["app"]["Id"])
    for service in ("db", "redis"):
        address = endpoints(copies[service])[network]["IPAddress"]
        assert address != endpoints(originals[service])[f"{stack.project}_default"]["IPAddress"]
        # Docker's embedded DNS can answer a moment after the start under load, and a short
        # exec can lose its output under load, so the lookup is only ever retried, not repeated.
        await wait_until(
            lambda s=service, a=address: resolved(app_copy, s) == {a}, 30, f"{service} in DNS"
        )
    # Compose writes links: into the endpoint; the copy's name only containers of its own.
    links = endpoints(copies["app"])[network].get("Links") or []
    assert f"{new}-redis-1:redis" in links, links
    assert all(link.split(":")[0].startswith(f"{new}-") for link in links), links
    # Compose on a user-defined network leaves HostConfig.Links empty, so the endpoint Links
    # above and the lookups are what show the copy links only its own containers.
    assert not originals["app"]["HostConfig"].get("Links"), originals["app"]["HostConfig"]


# COMPOSE FILES


async def test_compose_files_are_written_byte_for_byte(settings: Settings, stack: Stack) -> None:
    first, second = stack.copy_name(), stack.copy_name()
    directory = f"{stack.root}/restored"
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        archive = await backup(app, stack, ssh_id)
        dind_id = add_dind_host(app)
        run_id = await verify(app, archive)
        await plan(app, run_id, "new-name", dind_id, new_name=first, compose_dir=directory)
        assert await run_restore(app, run_id) == "done", app.log(run_id)
        assert f"Wrote 2 compose files to {directory}." in app.log(run_id), app.log(run_id)
        check_compose_dir(stack, directory)
        sums = host_sums(stack, directory)
        # The journal records the write, so the run page raises no compose warning.
        page = await app.browser.get(f"/runs/{run_id}")
        assert "not have been written" not in page.text, page.text
        assert "were not written" not in page.text, page.text

        # The directory exists now: a second restore into it is refused before any change.
        # The stack has no bind mounts, so only the compose directory makes apply check.
        again = await verify(app, archive)
        await plan(app, again, "new-name", dind_id, new_name=second, compose_dir=directory)
        assert await run_restore(app, again) == "failed", app.log(again)
        error = app.run_row(again)["error"]
        assert f"{directory} already exists on the host" in error, error
        assert leftovers(stack, second) == [], app.log(again)
        assert host_sums(stack, directory) == sums
        finished(app, [stack.handle.client], run_id, again)


async def test_compose_dir_under_etc_is_rejected_end_to_end(
    settings: Settings, stack: Stack, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = stack.copy_name()
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        archive = await backup(app, stack, ssh_id)
        dind_id = add_dind_host(app)
        run_id = await verify(app, archive)
        seen: list[tuple[str, str]] = []
        real_send = docker.APIClient.send

        def spy(self, request, **kwargs):
            seen.append((request.method, request.path_url))
            return real_send(self, request, **kwargs)

        monkeypatch.setattr(docker.APIClient, "send", spy)
        form = {
            "host_id": str(dind_id),
            "mode": "new-name",
            "new_name": new,
            "compose_dir": "/etc/drydock-x",
        }
        response = await browser.post(f"/restore/runs/{run_id}/plan", form)
        monkeypatch.undo()
        assert response.status_code == 422, alerts(response.text)
        assert "Drydock never writes to /etc/drydock-x." in response.text
        assert [m for m, _ in seen if m not in ("GET", "HEAD")] == [], seen
        plan_doc = browser.sql("SELECT plan FROM runs WHERE id = ?", (run_id,))[0][0]
        assert "summary" not in json.loads(plan_doc)
        assert app.status(run_id) == "awaiting_confirmation"
    assert leftovers(stack, new) == []


async def test_single_container_restore_writes_compose_files(
    settings: Settings, stack: Stack
) -> None:
    new = stack.copy_name()
    directory = f"{stack.root}/single"
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        run_id = await app.run(
            await app.add_job(
                stack.name("redis"),
                "all",
                host_id=str(ssh_id),
                encrypted="",
                images_reference_only_if_pullable="1",
            )
        )
        assert app.status(run_id) == "done", app.log(run_id)
        archive = app.run_row(run_id)["archive_name"]
        dind_id = add_dind_host(app)
        restore_id = await verify(app, archive)
        summary = await plan(
            app, restore_id, "new-name", dind_id, new_name=new, compose_dir=directory
        )
        assert "project" not in summary and summary["containers"] == [new], summary
        assert summary["compose"] == {"dir": directory, "files": COMPOSE_FILES}, summary
        assert await run_restore(app, restore_id) == "done", app.log(restore_id)
        log = app.log(restore_id)
        assert f"Wrote 2 compose files to {directory}." in log, log
        finished(app, [stack.handle.client], restore_id)
    check_compose_dir(stack, directory)
    copy = stack.api.inspect_container(new)
    assert copy["State"]["Running"]
    labels = copy["Config"]["Labels"] or {}
    assert not [k for k in labels if k.startswith("com.docker.compose.")], labels
    assert stack.inspect("redis")["Config"]["Labels"][PROJECT_LABEL] == stack.project


# OVERWRITE


async def test_overwrite_restore_of_a_stack_restores_in_order(
    settings: Settings, stack: Stack
) -> None:
    db = stack.handle.client.containers.get(stack.name("db"))
    marker = uuid.uuid4().hex
    write = 'printf "%s" "$1" > "$2/marker"'
    sh(db, write, marker, DB_DIR)
    originals = {stack.inspect(s)["Id"] for s in SERVICES}
    async with running(settings) as browser:
        app, ssh_id = await ssh_app(browser)
        archive = await backup(app, stack, ssh_id)
        # The archive holds the marker as written: a wrong one below is the restore's.
        archived = archived_volume(settings, archive, f"{stack.project}_dbdata")
        assert archived["marker"].sha256 == hashlib.sha256(marker.encode()).hexdigest(), (
            archived.get("marker")
        )
        sh(db, write, "changed since the backup", DB_DIR)
        dind_id = add_dind_host(app)
        run_id = await verify(app, archive)
        summary = await plan(app, run_id, "overwrite", dind_id)
        assert summary["project"] == stack.project, summary
        assert summary["containers"] == list(map(stack.name, SERVICES)), summary
        assert summary["originals"][0] == stack.name("app"), summary
        with recorded_events(stack.box, stack.project) as events:
            status = await run_restore(app, run_id, stack.project)
        assert status == "done", app.log(run_id)
        finished(app, [stack.handle.client], run_id)

    # The originals stop app first; the copies are created dependencies first.
    stops = event_times([e for e in events if e["Actor"]["ID"] in originals], "stop")
    assert sorted(stops) == sorted(SERVICES), events
    assert stops["app"][0] < min(stops["db"][0], stops["redis"][0]), events
    creates = event_times([e for e in events if e["Actor"]["ID"] not in originals], "create")
    assert sorted(creates) == sorted(SERVICES), events
    assert max(creates["db"][0], creates["redis"][0]) < creates["app"][0], events
    assert stack.running()
    assert not originals & {stack.inspect(s)["Id"] for s in SERVICES}
    old = stack.api.containers(all=True, filters={"name": OLD_SUFFIX})
    assert not [c["Names"] for c in old if stack.project in c["Names"][0]], old
    restored = stack.handle.client.containers.get(stack.name("db"))
    # Under load Docker sometimes drops the output of a short exec (an empty read of a
    # full file), so the read is retried; a wrong marker still fails.
    await wait_until(
        lambda: sh(restored, 'cat "$1/marker"', DB_DIR) == marker, 10, "the restored marker"
    )
