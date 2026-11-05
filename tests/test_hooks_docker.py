"""Hooks against the host daemon, through the socket proxy (see compose.test.yaml)."""

import json
import re
import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import docker
import pytest

from drydock.config import DEFAULT_HELPER_IMAGE
from drydock.hosts import helper
from drydock.jobs import hooks
from drydock.jobs.hooks import Hook, HookError
from drydock.jobs.runlog import RunLog, env_values
from tests.docker_support import TEST_LABEL, host_docker, needs_docker

IMAGE = DEFAULT_HELPER_IMAGE
SECRET = "hunter2-xyz"
EXEC_CREATE = re.compile(r"(/v[\d.]+)?/containers/[0-9a-f]{64}/exec")


@pytest.fixture(scope="module")
def target() -> Iterator[tuple]:
    """A running busybox container with a secret in its environment."""
    with host_docker() as handle:
        helper.ensure_image(handle.client, IMAGE)
        box = handle.client.containers.run(
            IMAGE,
            ["sleep", "3600"],
            name=f"drydock-hooktest-{uuid.uuid4().hex[:12]}",
            detach=True,
            labels={TEST_LABEL: "1"},
            environment={"SECRET_TOKEN": SECRET},
            network_mode="none",
        )
        try:
            yield handle.client.api, box
        finally:
            box.remove(force=True)


@pytest.fixture
def run_log(tmp_path: Path, target) -> RunLog:
    _api, box = target
    log = RunLog(tmp_path / "logs" / "1.log")
    log.add_secrets(env_values(box.attrs["Config"]["Env"]))
    return log


def make_hook(box, argv: list[str], **fields) -> Hook:
    return Hook(id=1, name="h", container=box.name, argv=tuple(argv), host_id=1, **fields)


def run(target, hook: Hook, log: RunLog, cancel: threading.Event | None = None) -> None:
    api, box = target
    hooks.run_hook(
        api,
        box.id,
        hook,
        container_name=box.name,
        phase="pre",
        cancel=cancel or threading.Event(),
        log=log,
    )


def lines(log: RunLog) -> list[str]:
    return [line[20:] for line in log.path.read_text(encoding="utf-8").splitlines()]


class Recording:
    """An APIClient that remembers the exec IDs it created."""

    def __init__(self, api) -> None:
        self.api = api
        self.ids: list[str] = []

    def __getattr__(self, name: str):
        return getattr(self.api, name)

    def exec_create(self, *args, **kwargs):
        result = self.api.exec_create(*args, **kwargs)
        self.ids.append(result["Id"])
        return result


@needs_docker
def test_argv_is_passed_literally_without_a_shell(target, run_log: RunLog, monkeypatch) -> None:
    _api, box = target
    bodies: list[dict] = []
    real_send = docker.APIClient.send

    def spy(self, request, **kwargs):
        if request.method == "POST" and EXEC_CREATE.fullmatch(request.path_url):
            bodies.append(json.loads(request.body))
        return real_send(self, request, **kwargs)

    monkeypatch.setattr(docker.APIClient, "send", spy)
    argv = ["echo", "$(id)", "${HOSTNAME}", "{{job.name}}", "a b"]
    run(target, make_hook(box, argv, log_output=True), run_log)
    logged = lines(run_log)
    assert "[h] $(id) ${HOSTNAME} {{job.name}} a b" in logged
    assert "uid=" not in run_log.path.read_text(encoding="utf-8")
    assert logged[-1] == "Hook h finished."
    body = bodies[0]
    assert body["Cmd"] == argv
    assert body["Privileged"] is False
    assert body["Tty"] is False
    assert body["AttachStdin"] is False
    assert "Env" not in body  # docker-py leaves out None values: no environment
    assert body["User"] == ""
    assert "WorkingDir" not in body

    argv = ["sh", "-c", "id -un && pwd"]
    run(target, make_hook(box, argv, user="nobody", workdir="/var", log_output=True), run_log)
    body = bodies[1]
    assert (body["User"], body["WorkingDir"]) == ("nobody", "/var")
    assert body["Cmd"] == argv
    logged = lines(run_log)
    assert logged[-3:] == ["[h] nobody", "[h] /var", "Hook h finished."]


@needs_docker
def test_output_is_counted_not_logged_by_default(target, run_log: RunLog) -> None:
    _api, box = target
    script = "echo $SECRET_TOKEN; head -c 20000 /dev/zero | tr '\\0' a"
    run(target, make_hook(box, ["sh", "-c", script]), run_log)
    content = run_log.path.read_text(encoding="utf-8")
    assert (
        "Hook h wrote 20012 bytes to standard output and 0 bytes to standard error;"
        " hook output is not logged."
    ) in content
    assert "aaaa" not in content
    assert "[redacted]" not in content
    assert SECRET not in content

    with pytest.raises(HookError, match=r"^Hook h failed with exit code 4\.$"):
        run(target, make_hook(box, ["sh", "-c", "echo oops-$SECRET_TOKEN >&2; exit 4"]), run_log)
    logged = lines(run_log)
    assert logged[-2:] == [
        "The last 17 bytes of standard error of hook h:",
        "[h stderr] oops-[redacted]",
    ]
    assert SECRET not in run_log.path.read_text(encoding="utf-8")


@needs_docker
def test_output_is_redacted_and_capped(target, run_log: RunLog) -> None:
    _api, box = target
    script = "echo $SECRET_TOKEN; head -c 2000000 /dev/zero | tr '\\0' a"
    started = time.monotonic()
    run(target, make_hook(box, ["sh", "-c", script], log_output=True), run_log)
    assert time.monotonic() - started < 60
    content = run_log.path.read_text(encoding="utf-8")
    assert "[h] [redacted]" in content
    assert SECRET not in content
    logged = lines(run_log)
    output = [line[len("[h] ") :] for line in logged if line.startswith("[h] ")]
    assert sum(len(line) for line in output) <= hooks.MAX_OUTPUT
    assert f"Output of hook h was cut after {hooks.MAX_OUTPUT} bytes." in logged
    dropped = 2000000 + len("[redacted]\n") - hooks.MAX_OUTPUT
    assert f"{dropped} more bytes of output of hook h were not logged." in logged
    assert logged[-1] == "Hook h finished."


@needs_docker
def test_timeout_returns_while_docker_keeps_the_exec(target, run_log: RunLog) -> None:
    api, box = target
    recording = Recording(api)
    started = time.monotonic()
    with pytest.raises(HookError, match="timed out after 2 seconds"):
        hooks.run_hook(
            recording,
            box.id,
            make_hook(box, ["sleep", "3600"], timeout_s=2),
            container_name=box.name,
            phase="post",
            cancel=threading.Event(),
            log=run_log,
        )
    # Loose on purpose: it proves the hook did not wait for sleep 3600, not Docker's speed.
    assert time.monotonic() - started < 60
    # Docker cannot kill an exec: it is still running, and so is the container.
    assert api.exec_inspect(recording.ids[0])["Running"] is True
    box.reload()
    assert box.status == "running"


@needs_docker
def test_failing_hook_reports_its_exit_code(target, run_log: RunLog) -> None:
    _api, box = target
    with pytest.raises(HookError, match=r"^Hook h failed with exit code 7\.$"):
        run(target, make_hook(box, ["sh", "-c", "exit 7"]), run_log)
    assert "Hook h wrote 0 bytes to standard output" in lines(run_log)[-1]


@needs_docker
def test_exec_into_a_paused_container_fails_cleanly(target, run_log: RunLog) -> None:
    api, box = target
    api.pause(box.id)
    try:
        started = time.monotonic()
        with pytest.raises(HookError, match=r"^Docker could not start hook h: "):
            run(target, make_hook(box, ["true"]), run_log)
        assert time.monotonic() - started < 60  # no hang, on a slow shared daemon
    finally:
        api.unpause(box.id)
    run(target, make_hook(box, ["true"]), run_log)
    assert lines(run_log)[-1] == "Hook h finished."
