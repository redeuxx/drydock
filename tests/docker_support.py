"""Shared helpers for tests against real Docker daemons (see compose.test.yaml).

The host daemon is reached only through the socket proxy (DRYDOCK_TEST_DOCKER_URL). The
sshhost service is a docker:dind container running sshd, standing in for a remote host;
the tests control it through the proxy with exec.
"""

import contextlib
import hashlib
import io
import json
import os
import stat
import tarfile
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
import pytest
from docker import errors as docker_errors
from docker.types import Mount
from sqlalchemy.orm import Session

from drydock.config import DEFAULT_HELPER_IMAGE
from drydock.hosts import client as docker_client
from drydock.hosts import helper, ssh
from drydock.models import Host
from drydock.restore.plan import RESTORE_LABEL
from tests.conftest import PASSWORD, Browser

DOCKER_URL = os.environ.get("DRYDOCK_TEST_DOCKER_URL", "")
SSH_HOST = os.environ.get("DRYDOCK_TEST_SSH_HOST", "")
SSH_USER = "drydock"
# compose.test.yaml's project; CI runs it under its own name (compose.ci.yaml).
TEST_PROJECT = os.environ.get("DRYDOCK_TEST_PROJECT", "drydock-test")
TEST_LABEL = "drydock.test"
# Helpers that test code makes outside a running app carry this installation ID. One per
# test run: CI runs every Python at once on one daemon, and each run counts and reaps
# only its own helpers.
TEST_INSTANCE = f"drydocktest{uuid.uuid4().hex[:12]}"

needs_docker = pytest.mark.skipif(
    not DOCKER_URL, reason="needs the socket proxy from compose.test.yaml"
)
needs_ssh = pytest.mark.skipif(
    not (DOCKER_URL and SSH_HOST), reason="needs the sshhost service from compose.test.yaml"
)

KEY_MARKERS = (b"PRIVATE KEY-----", b"openssh-key-v1", b"b3BlbnNzaC1rZXktdjE")


# HOST DAEMON AND THE SSHHOST CONTAINER


def host_docker() -> docker_client.DockerHandle:
    return docker_client.open_client(DOCKER_URL)


def sshhost(handle: docker_client.DockerHandle):
    labels = [f"com.docker.compose.project={TEST_PROJECT}", "com.docker.compose.service=sshhost"]
    found = handle.client.containers.list(filters={"label": labels})
    assert len(found) == 1, "start the sshhost service from compose.test.yaml"
    return found[0]


def helpers_left(client, instance_id: str) -> list:
    """The helper containers of an installation that still exist on a daemon."""
    labels = [f"{k}={v}" for k, v in helper.helper_labels(instance_id).items()]
    return client.containers.list(all=True, filters={"label": labels})


def sh(container, script: str, *args: str) -> str:
    code, output = container.exec_run(["sh", "-c", script, "sh", *args])
    assert code == 0, output.decode(errors="replace")
    return output.decode()


def authorize(public_key_line: str) -> None:
    with host_docker() as handle:
        sh(
            sshhost(handle),
            # The options the host page tells admins to use.
            'printf "%s %s\\n" "$1" "$2" > /home/drydock/.ssh/authorized_keys'
            " && chown drydock:docker /home/drydock/.ssh/authorized_keys"
            " && chmod 0600 /home/drydock/.ssh/authorized_keys",
            ssh.AUTHORIZED_KEY_OPTIONS,
            public_key_line,
        )


# REGISTERED HOSTS


def insert_host(browser: Browser, host: Host) -> int:
    with browser.app.state.sessionmaker() as db, db.begin():
        db.add(host)
        db.flush()
        return host.id


def get_host(browser: Browser, host_id: int) -> Host:
    db: Session
    with browser.app.state.sessionmaker() as db:
        host = db.get(Host, host_id)
        assert host is not None
        return host


async def add_ssh_host(browser: Browser, known_host_line: str | None = None) -> int:
    """Registers sshhost with a fresh in-memory key, authorizes it there and opens the tunnel,
    waiting for it to connect (unless known_host_line pins another key, which never does)."""
    host = Host(
        name=f"remote-{uuid.uuid4().hex[:8]}",
        kind="ssh",
        address=SSH_HOST,
        port=22,
        username=SSH_USER,
        remote_socket_path="/var/run/docker.sock",
        enabled=True,
    )
    public = ssh.generate_key(host, browser.app.state.crypto)
    await docker_client.run_blocking(authorize, public)
    line, fingerprint = await ssh.scan_host_key(SSH_HOST, 22)
    host.known_host_line = known_host_line or line
    host.host_key_fingerprint = fingerprint
    host_id = await docker_client.run_blocking(insert_host, browser, host)
    hosts = browser.app.state.hosts
    await hosts.reload(host_id)
    if known_host_line is None:
        await wait_until(
            lambda: hosts.status(get_host(browser, host_id)).state == "connected",
            30,
            "the SSH tunnel",
        )
    return host_id


async def connect_host(browser: Browser, host_id: int) -> docker_client.DockerHandle:
    return await docker_client.connect(
        browser.app.state.hosts.docker_url(get_host(browser, host_id))
    )


async def wait_until(predicate: Callable[[], bool], timeout: float, what: str) -> float:
    start = time.monotonic()
    while not predicate():
        if time.monotonic() - start > timeout:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}")
        await anyio.sleep(0.2)
    return time.monotonic() - start


# TRANSFERS


def make_tar(payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("data.bin")
        info.size = len(payload)
        info.mode = 0o600
        info.uid = info.gid = 999
        tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def archive_and_exec_roundtrip(handle: docker_client.DockerHandle, instance_id: str) -> None:
    """put_archive into a volume in a helper, then read it back with exec(stream=True)."""
    client = handle.client
    payload = os.urandom(4 * 1024 * 1024)
    volume = client.volumes.create(
        f"drydock-test-{uuid.uuid4().hex[:12]}", labels={TEST_LABEL: "1"}
    )
    try:
        mounts = [Mount("/v", volume.name, type="volume")]
        command = ["sleep", "300"]
        with helper.helper(
            client, DEFAULT_HELPER_IMAGE, instance_id, command, mounts, start=True
        ) as box:
            assert box.put_archive("/v", make_tar(payload))
            # Without CAP_DAC_OVERRIDE even root in the helper cannot read another uid's file.
            code, output = box.exec_run(["cat", "/v/data.bin"])
            assert code != 0 and b"Permission denied" in output
            result = box.exec_run(["cat", "/v/data.bin"], stream=True, user="999:999")
            chunks = list(result.output)
            assert len(chunks) > 1, "expected a streamed response"
            assert hashlib.sha256(b"".join(chunks)).digest() == hashlib.sha256(payload).digest()
            code, owner = box.exec_run(["stat", "-c", "%u:%g %a", "/v/data.bin"])
            assert code == 0
            assert owner.decode().strip() == "999:999 600"
    finally:
        volume.remove(force=True)


def find_key_material(roots: list[Path]) -> list[str]:
    hits = []
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = Path(dirpath) / name
                try:
                    if not stat.S_ISREG(path.lstat().st_mode):
                        continue
                    data = path.read_bytes()
                except OSError:
                    continue
                if any(marker in data for marker in KEY_MARKERS):
                    hits.append(str(path))
    return hits


# STACKS

# redis:8-alpine, pinned by its multi-arch index digest.
REDIS_IMAGE = "redis@sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0"
BUSYBOX_IMAGE = DEFAULT_HELPER_IMAGE
PROJECT_LABEL = "com.docker.compose.project"
SERVICE_LABEL = "com.docker.compose.service"
# The projects tests make. Never TEST_PROJECT, the project of the test services themselves.
STACK_PREFIX = "drydock-test-stack-"
COPY_PREFIX = "drydock-test-run-"
COMPOSE_TIMEOUT = 300

COMPOSE_DOWN = r"""
cd "$1" 2>/dev/null || cd /
docker compose -p "$2" down -v --remove-orphans -t 1 >/dev/null 2>&1
docker ps -aq --filter "label=com.docker.compose.project=$2" | xargs -r docker rm -f -v >/dev/null
docker ps -a --filter "label=$3" --format '{{.ID}} {{.Names}}' | while read -r id name; do
  case "$name" in "$2" | "$2"-* | "$2"_*) docker rm -f -v "$id" >/dev/null ;; esac
done
docker volume ls -q | while read -r name; do
  case "$name" in "$2"-* | "$2"_*) docker volume rm -f "$name" >/dev/null ;; esac
done
docker network ls --format '{{.Name}}' | while read -r name; do
  case "$name" in "$2"-* | "$2"_*) docker network rm "$name" >/dev/null ;; esac
done
true
"""
# Recorded in the background, so a test sees every event: for --since the daemon keeps only
# the last 256, and a healthcheck every second adds three.
EVENTS_START = (
    'docker events --since "$1" --filter "label=$2" --filter type=container'
    ' --format "{{json .}}" > "$3" 2>/dev/null < /dev/null & echo $!'
)
EVENTS_STOP = 'kill "$1" 2>/dev/null; cat "$2"; rm -f "$2"'


def own_project(project: str) -> None:
    """The cleanup helpers remove whole projects: only ever one a test made."""
    assert project.startswith((STACK_PREFIX, COPY_PREFIX)), project


def compose_stack(box, root: str, project: str, files: dict[str, str]) -> None:
    """Writes files (relative path: text) below root on the sshhost filesystem and starts
    the project there with the real Compose CLI, waiting until every service runs and is
    healthy."""
    own_project(project)
    for name, text in files.items():
        sh(box, 'mkdir -p "$1" && printf "%s" "$3" > "$1/$2"', root, name, text)
    # Image pulls and health waits outlast the default client timeout.
    with docker_client.open_client(DOCKER_URL, timeout=COMPOSE_TIMEOUT + 60) as handle:
        sh(
            sshhost(handle),
            'cd "$1" && docker compose -p "$2" up -d --wait --wait-timeout "$3" 2>&1',
            root,
            project,
            str(COMPOSE_TIMEOUT),
        )


def compose_down(box, root: str, project: str) -> None:
    """Removes a project from the sshhost daemon: its containers and volumes, the restored
    copies named after it, and the volumes and networks named '<project>_...' or
    '<project>-...'."""
    own_project(project)
    sh(box, COMPOSE_DOWN, root, project, RESTORE_LABEL)


@contextlib.contextmanager
def recorded_events(box, project: str) -> Iterator[list[dict[str, Any]]]:
    """The container events of a project on the sshhost daemon while the block runs, in
    time order (filled in when it ends). Read with sshhost's own docker CLI: the socket
    proxy refuses /events."""
    path = f"/srv/drydock-test-events-{uuid.uuid4().hex[:10]}"
    pid = sh(box, EVENTS_START, f"{time.time():.6f}", f"{PROJECT_LABEL}={project}", path)
    found: list[dict[str, Any]] = []
    try:
        yield found
    finally:
        time.sleep(1)  # events already sent reach the file
        output = sh(box, EVENTS_STOP, pid.strip(), path)
        found.extend(
            sorted(
                (json.loads(line) for line in output.splitlines() if line.strip()),
                key=lambda event: event["timeNano"],
            )
        )


def event_times(events: list[dict[str, Any]], action: str) -> dict[str, list[int]]:
    """When the containers of each Compose service had the event action, by service."""
    times: dict[str, list[int]] = {}
    for event in events:
        if event.get("Action") == action:
            attributes = (event.get("Actor") or {}).get("Attributes") or {}
            times.setdefault(attributes.get(SERVICE_LABEL, ""), []).append(event["timeNano"])
    return times


@dataclass(frozen=True)
class Service:
    """A container of a hand-labelled stack. depends_on is the label value in the Compose
    v2 format ("db:service_started:false"); mib, when set, gives it a named volume at /data
    holding that many MiB of random data."""

    name: str
    depends_on: str = ""
    mib: int | None = None


def filled_volume(client, name: str, labels: dict[str, str], mib: int):
    volume = client.volumes.create(name, labels=labels)
    script = f"dd if=/dev/urandom of=/v/big bs=1M count={int(mib)} 2>/dev/null"
    # Runs as root with Docker's default capabilities; test only, never a helper.
    filler = client.containers.create(
        BUSYBOX_IMAGE,
        ["sh", "-c", script],
        mounts=[Mount("/v", volume.name, type="volume")],
        network_mode="none",
        labels={TEST_LABEL: "1"},
    )
    try:
        filler.start()
        assert filler.wait(timeout=600)["StatusCode"] == 0
    finally:
        filler.remove(force=True)
    return volume


def labelled_stack(client, project: str, specs: Sequence[Service]) -> list:
    """A stack on a daemon without the Compose CLI: running containers with the labels
    Compose v2 writes, named '<project>-<service>-1', created and started in specs order.
    remove_stack removes it."""
    assert project.startswith(STACK_PREFIX), project
    helper.ensure_image(client, BUSYBOX_IMAGE)
    made = []
    for spec in specs:
        labels = {
            TEST_LABEL: "1",
            PROJECT_LABEL: project,
            SERVICE_LABEL: spec.name,
            "com.docker.compose.container-number": "1",
            "com.docker.compose.oneoff": "False",
            "com.docker.compose.depends_on": spec.depends_on,
        }
        mounts = []
        if spec.mib is not None:
            volume_labels = {TEST_LABEL: "1", PROJECT_LABEL: project}
            volume = filled_volume(client, f"{project}_{spec.name}", volume_labels, spec.mib)
            mounts.append(Mount("/data", volume.name, type="volume"))
        container = client.containers.create(
            BUSYBOX_IMAGE,
            ["sleep", "3600"],
            name=f"{project}-{spec.name}-1",
            labels=labels,
            mounts=mounts,
            init=True,  # sleep as PID 1 would ignore SIGTERM
        )
        made.append(container)
        container.start()
    return made


def remove_stack(client, project: str) -> None:
    """Removes a labelled_stack: its containers, whatever still uses its volumes (such as
    the helper of a killed drydock) and the volumes."""
    assert project.startswith(STACK_PREFIX), project
    api = client.api
    label = {"label": f"{PROJECT_LABEL}={project}"}
    volumes = [v["Name"] for v in api.volumes(filters=label).get("Volumes") or []]
    ids = {c["Id"] for c in api.containers(all=True, filters=label)}
    for name in volumes:
        ids |= {c["Id"] for c in api.containers(all=True, filters={"volume": name})}
    for container_id in sorted(ids):
        try:
            api.remove_container(container_id, force=True, v=True)
        except docker_errors.NotFound:
            pass
        except docker_errors.APIError as exc:
            if exc.status_code != 409:  # 409: the reaper is removing it already
                raise
    for name in volumes:
        for attempt in range(40):
            try:
                api.remove_volume(name, force=True)
            except docker_errors.NotFound:
                pass
            except docker_errors.APIError as exc:
                if exc.status_code != 409 or attempt == 39:  # 409: still in use
                    raise
                time.sleep(0.5)
                continue
            break


def started_ns(info: dict[str, Any]) -> int:
    """State.StartedAt in nanoseconds. Docker trims trailing zeros of the fraction, so the
    strings themselves do not sort."""
    stamp = info["State"]["StartedAt"].removesuffix("Z")
    whole, _, fraction = stamp.partition(".")
    seconds = int(datetime.fromisoformat(whole).replace(tzinfo=UTC).timestamp())
    return seconds * 1_000_000_000 + int(fraction.ljust(9, "0")[:9])


# HOOKS


async def add_hook(
    browser: Browser,
    *,
    name: str,
    host_id: int,
    container: str,
    argv: list[str],
    project: str | None = None,
    timeout_s: int = 300,
    log_output: bool = False,
) -> int:
    """Creates a hook through POST /hooks as the superadmin, bound to host_id and to a
    container (project None) or to a Compose project, and returns its ID."""
    response = await browser.post("/reauth", {"password": PASSWORD, "next": "/"})
    assert response.status_code == 303, response.text
    form = {
        "name": name,
        "host_id": str(host_id),
        "project": project or "",
        "container": container,
        "argv": json.dumps(argv),
        "user": "",
        "workdir": "",
        "timeout_s": str(timeout_s),
    }
    if log_output:
        form["log_output"] = "1"
    response = await browser.post("/hooks", form)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])
