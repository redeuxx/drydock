"""The container status collector against real daemons (the host daemon through the socket
proxy, the sshhost through its SSH tunnel), and the containers page's actions."""

import asyncio
import contextlib
import functools
import html
import re

import docker.errors
import pytest

from drydock.config import DEFAULT_HELPER_IMAGE, Settings
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.hosts.status import HostSnapshot, StatusCollector
from drydock.jobs.dispatcher import lock_scope, name_key
from drydock.models import Host
from drydock.routes.containers import ACTIONS
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
    """One fresh reading of the host, whether this call or the collector's own loop (woken
    by the touch) starts it."""
    await collector.refresh(host_id, wait=60)
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
                assert found.started_at is not None and found.started_at <= first.taken_at
                assert (TEST_LABEL, "1") in found.labels
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


# THE CONTAINERS PAGE'S ACTIONS AND INSPECT


QUICK_STOP = ["sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"]


def state_of(client, container_id: str, key: str = "Status") -> str:
    """Blocking: call through run_blocking, since the test's loop serves the SSH tunnel."""
    return client.api.inspect_container(container_id)["State"][key]


@needs_ssh
async def test_container_actions_and_inspect_on_a_real_container(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    handle = await connect_host(admin, host_id)
    client = handle.client
    start = functools.partial(
        client.containers.run,
        IMAGE,
        QUICK_STOP,
        detach=True,
        labels={TEST_LABEL: "1", "app.password": "hunter2", "app.tier": "web"},
        environment={"SECRET": "hunter2"},
        network_mode="none",
    )
    try:
        await docker_client.run_blocking(helper.ensure_image, client, IMAGE)
        web = await docker_client.run_blocking(start)
        other = await docker_client.run_blocking(start)
        try:
            await poll(admin.app.state.status, host_id)

            async def do(action: str, *ids: str) -> str:
                data = {"host": str(host_id), "action": action, "id": list(ids)}
                response = await admin.post(
                    "/containers/actions", data, headers={"HX-Request": "true"}
                )
                assert response.status_code == 200, response.text
                return response.text

            for action, expect in [
                (f"pause:{web.id}", "paused"),
                (f"unpause:{web.id}", "running"),
                (f"stop:{web.id}", "exited"),
                (f"start:{web.id}", "running"),
            ]:
                text = await do(action)
                assert f"{web.name}: {ACTIONS[action.split(':')[0]]}" in text, text
                assert await docker_client.run_blocking(state_of, client, web.id) == expect
            started = functools.partial(state_of, client, web.id, "StartedAt")
            before = await docker_client.run_blocking(started)
            await do(f"restart:{web.id}")
            assert await docker_client.run_blocking(started) != before

            # Several at once, and the page shows the reading taken after them.
            text = await do("stop", web.id, other.id)
            assert f"{web.name}: stopped" in text and f"{other.name}: stopped" in text
            stopped = admin.app.state.status.snapshot(host_id)
            assert {row(stopped, web.id).state, row(stopped, other.id).state} == {"exited"}

            # A container a run holds is refused, and so is a helper.
            dispatcher = admin.app.state.dispatcher
            scope = lock_scope(await docker_client.run_blocking(client.api.info), host_id)
            for keys in ([web.id], [name_key(scope, "container", web.name)]):
                assert await dispatcher.try_hold(keys, "run 1")
                try:
                    assert "A backup or restore is using it" in await do(f"start:{web.id}")
                finally:
                    dispatcher.release_held(keys)
            assert await docker_client.run_blocking(state_of, client, web.id) == "exited"
            instance = admin.app.state.hosts.instance_id
            orphan = await docker_client.run_blocking(
                client.containers.create, **helper.helper_options(IMAGE, instance)
            )
            try:
                assert "helper containers are left to drydock" in await do(f"start:{orphan.id}")
            finally:
                await docker_client.run_blocking(helper.remove, client, orphan.id)

            audited = admin.sql(
                "SELECT action, target, outcome FROM audit_events WHERE action LIKE 'container.%'"
            )
            assert ("container.pause", f"container:{web.name}", "success") in audited
            assert ("container.start", f"container:{web.name}", "failure") in audited

            # Inspect: everything but the environment's values and secret-looking labels.
            inspected = await admin.get(f"/containers/{host_id}/{web.id}/inspect")
            assert inspected.status_code == 200 and "hunter2" not in inspected.text
            shown = html.unescape(inspected.text)
            assert "SECRET=***" in shown and '"app.password": "***"' in shown
            assert '"app.tier": "web"' in shown
            gone = await admin.get(f"/containers/{host_id}/{'f' * 64}/inspect")
            assert "No such container any more." in gone.text
        finally:
            await docker_client.run_blocking(remove, client, web, other)
    finally:
        handle.close()


# THE LOGS PAGE ON A REAL DAEMON

COUNTING = [
    "sh",
    "-c",
    'i=0; while :; do echo "line $i"; echo "err $i" >&2; i=$((i+1)); sleep 0.2; done',
]
MARKED = ["sh", "-c", 'echo "<script>x</script>"; printf "\033[31mred\033[0m\n"; exec sleep 3600']
LINE_RE = re.compile(
    r'<div data-line( class="text-error")?><span data-stamp[^>]*>[^<]*</span>'
    r"(?:<span[^>]*>[^<]*</span> )?<span data-text>([^<]*)</span></div>"
)
NEXT_RE = re.compile(r'<span data-log-poller hx-get="([^"]*)"')


async def read_log(browser: Browser, url: str) -> tuple[list[tuple[bool, str]], str | None]:
    """(stderr?, text) per line, and the next poll's URL (None: nothing new)."""
    response = await browser.get(url, headers={"HX-Request": "true"})
    if response.status_code == 204:
        return [], None
    assert response.status_code == 200, (response.status_code, response.text)
    lines = [(bool(err), html.unescape(text)) for err, text in LINE_RE.findall(response.text)]
    found = NEXT_RE.search(response.text)
    assert found is not None
    return lines, html.unescape(found.group(1))


@needs_docker
async def test_logs_through_the_proxy_without_gaps_or_repeats(admin: Browser) -> None:
    handle = await docker_client.run_blocking(host_docker)
    run = functools.partial(
        handle.client.containers.run,
        IMAGE,
        detach=True,
        init=True,
        labels={TEST_LABEL: "1"},
        network_mode="none",
    )
    try:
        await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
        counting = await docker_client.run_blocking(functools.partial(run, COUNTING))
        tty = await docker_client.run_blocking(functools.partial(run, MARKED, tty=True))
        try:
            host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
            host_id = await docker_client.run_blocking(insert_host, admin, host)
            await asyncio.sleep(1.5)

            # The tail first, then each poll brings only lines it has not had.
            lines, url = await read_log(
                admin, f"/logs/lines?host={host_id}&c={counting.id}&tail=100"
            )
            assert lines[:2] in (
                [(False, "line 0"), (True, "err 0")],
                [(True, "err 0"), (False, "line 0")],
            )
            assert url is not None and url.endswith("~0")
            out: list[int] = []
            err: list[int] = []
            for _ in range(8):
                for stderr, text in lines:
                    (err if stderr else out).append(int(text.split()[1]))
                    assert text.startswith("err" if stderr else "line"), text
                await asyncio.sleep(0.5)
                lines, next_url = await read_log(admin, url)
                url = next_url or url
            assert out == list(range(out[0], out[0] + len(out))), out
            assert err == list(range(err[0], err[0] + len(err))), err
            assert len(out) > 10

            # A TTY container: one stream, escape sequences gone, markup escaped.
            lines, url = await read_log(admin, f"/logs/lines?host={host_id}&c={tty.id}")
            assert lines == [(False, "<script>x</script>"), (False, "red")]
            assert url is not None and url.endswith("~1")

            # Both at once: merged, a cursor each.
            lines, url = await read_log(
                admin, f"/logs/lines?host={host_id}&c={tty.id}&c={counting.id}"
            )
            assert (False, "<script>x</script>") in lines and len(lines) > 2
            assert url is not None and url.count("&c=") == 2
        finally:
            await docker_client.run_blocking(remove, handle.client, counting, tty)
        gone = await admin.get(f"/logs/lines?host={host_id}&c={counting.id}")
        assert gone.status_code == 502 and gone.text == "No such container any more."
    finally:
        handle.close()


# CONTAINER EVENTS ON A REAL DAEMON


@needs_docker
async def test_container_events_through_the_proxy_are_stored(admin: Browser) -> None:
    handle = await docker_client.run_blocking(host_docker)
    containers = handle.client.containers
    try:
        await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
        host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
        host_id = await docker_client.run_blocking(insert_host, admin, host)
        collector = admin.app.state.events
        await collector.supervise()  # now, not at its next check
        await wait_until(
            lambda: collector._follows[host_id].stream is not None, 30, "the event stream"
        )
        quitter = await docker_client.run_blocking(
            functools.partial(
                containers.run,
                IMAGE,
                ["sh", "-c", "exit 3"],
                detach=True,
                labels={TEST_LABEL: "1", "app.token": "hunter2"},
                network_mode="none",
            )
        )
        sleeper = await docker_client.run_blocking(
            functools.partial(
                containers.run,
                IMAGE,
                ["sleep", "3600"],
                detach=True,
                init=True,
                labels={TEST_LABEL: "1"},
                network_mode="none",
            )
        )
        try:
            await docker_client.run_blocking(
                sleeper.exec_run, ["sh", "-c", "echo hunter2 > /dev/null"]
            )

            def actions(container_id: str) -> set[str]:
                rows = admin.sql(
                    "SELECT action FROM docker_events WHERE container_id = ?", (container_id,)
                )
                return {action for (action,) in rows}

            await wait_until(
                lambda: {"create", "start", "die"} <= actions(quitter.id), 30, "its events"
            )
            await wait_until(lambda: "start" in actions(sleeper.id), 30, "its start")
            assert not {a for a in actions(sleeper.id) if a.startswith("exec_")}, "no execs"
            (row,) = admin.sql(
                "SELECT host_id, name, image, exit_code FROM docker_events "
                "WHERE container_id = ? AND action = 'die'",
                (quitter.id,),
            )
            assert row == (host_id, quitter.name, IMAGE, 3)
            everything = admin.sql("SELECT * FROM docker_events")
            assert "hunter2" not in repr(everything), "no labels, no exec commands"
        finally:
            await docker_client.run_blocking(remove, handle.client, quitter, sleeper)
    finally:
        handle.close()


@needs_docker
async def test_a_container_that_dies_alerts_through_the_event_stream(admin: Browser) -> None:
    handle = await docker_client.run_blocking(host_docker)
    try:
        await docker_client.run_blocking(helper.ensure_image, handle.client, IMAGE)
        host = Host(
            name="local", kind="local", docker_url=DOCKER_URL, enabled=True, alerts_enabled=True
        )
        host_id = await docker_client.run_blocking(insert_host, admin, host)
        collector = admin.app.state.events
        await collector.supervise()
        await wait_until(
            lambda: collector._follows[host_id].stream is not None, 30, "the event stream"
        )
        quitter = await docker_client.run_blocking(
            functools.partial(
                handle.client.containers.run,
                IMAGE,
                ["sh", "-c", "exit 3"],
                detach=True,
                labels={TEST_LABEL: "1"},
                network_mode="none",
            )
        )
        try:

            def alerted() -> list[tuple]:
                return admin.sql(
                    "SELECT outcome, details FROM audit_events WHERE action = 'alert.died'"
                )

            await wait_until(lambda: bool(alerted()), 30, "the alert")
            ((outcome, details),) = alerted()
            assert outcome == "failure"
            assert f"local: {quitter.name} exited with code 3." in details
        finally:
            await docker_client.run_blocking(remove, handle.client, quitter)
    finally:
        handle.close()
