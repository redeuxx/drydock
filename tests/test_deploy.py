"""Deployment files: compose hardening, Dockerfile CMD and image layout."""

import json
import re
from pathlib import Path

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CMD = [
    "uvicorn",
    "drydock.main:app",
    "--host",
    "0.0.0.0",  # noqa: S104 (inside the container; compose publishes on 127.0.0.1)
    "--port",
    "8000",
    "--workers",
    "1",
    "--proxy-headers",
    "--timeout-graceful-shutdown",
    "30",
]


def load_compose(name: str) -> dict:
    return YAML(typ="safe").load((ROOT / name).read_text())


def seconds(duration: str) -> float:
    units = {"h": 3600, "m": 60, "s": 1, "ms": 0.001}
    parts = re.findall(r"(\d+(?:\.\d+)?)(ms|h|m|s)", duration)
    assert parts and "".join(n + u for n, u in parts) == duration, duration
    return sum(float(n) * units[u] for n, u in parts)


def tmpfs_options(service: dict, path: str) -> dict[str, str]:
    for entry in service.get("tmpfs", []):
        target, _, options = entry.partition(":")
        if target == path:
            return dict(option.split("=", 1) for option in options.split(",") if option)
    pytest.fail(f"{path} is not a tmpfs")


def published_ports(service: dict) -> list[str]:
    ports = []
    for entry in service.get("ports", []):
        assert isinstance(entry, str), "use the short port syntax so the host IP is explicit"
        ports.append(entry)
    return ports


# COMPOSE


@pytest.mark.parametrize("name", ["compose.yaml", "compose.dev.yaml"])
def test_compose_binds_loopback_and_hardens_the_container(name: str) -> None:
    compose = load_compose(name)
    service = compose["services"]["drydock"]
    ports = published_ports(service)
    assert ports == ["127.0.0.1:8000:8000"]
    assert "network_mode" not in service
    assert tmpfs_options(service, "/run/drydock") == {
        "uid": "10001",
        "gid": "10001",
        "mode": "0700",
    }
    assert seconds(service["stop_grace_period"]) >= 90
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "privileged" not in service
    assert "cap_add" not in service
    assert service["secrets"] == ["drydock_secret_key"]
    assert service["environment"]["DRYDOCK_SECRET_KEY_FILE"] == "/run/secrets/drydock_secret_key"
    assert "DRYDOCK_SECRET_KEY" not in service["environment"]
    assert compose["secrets"]["drydock_secret_key"]["file"] == "./secrets/drydock_secret_key"
    data_mounts = [v for v in service["volumes"] if v.endswith(":/data")]
    assert len(data_mounts) == 1
    assert not data_mounts[0].startswith((".", "/")), "/data must be a named volume"


def test_compose_mounts_the_restore_inbox_read_only() -> None:
    service = load_compose("compose.yaml")["services"]["drydock"]
    assert "./restore-inbox:/restore-inbox:ro" in service["volumes"]
    assert service["environment"]["DRYDOCK_RESTORE_PATHS"] == "/restore-inbox"


def test_dev_compose_reloads_with_polling() -> None:
    service = load_compose("compose.dev.yaml")["services"]["drydock"]
    assert "--reload" in service["command"]
    assert service["environment"]["WATCHFILES_FORCE_POLLING"] == "true"
    assert "./src:/app/src:ro" in service["volumes"]


def test_smoke_app_matches_production_hardening() -> None:
    services = load_compose("compose.test.yaml")["services"]
    app = services["app"]
    assert "ports" not in app
    assert app["read_only"] is True
    assert app["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in app["security_opt"]
    assert services["smoke"]["network_mode"] == "service:app"
    assert services["smoke"]["pid"] == "service:app"


# DOCKERFILE


def dockerfile_instructions() -> list[tuple[str, str]]:
    text = (ROOT / "Dockerfile").read_text()
    text = re.sub(r"\\\n", " ", text)  # join continuation lines
    instructions = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            keyword, _, rest = line.partition(" ")
            instructions.append((keyword.upper(), rest.strip()))
    return instructions


def runtime_stage() -> list[tuple[str, str]]:
    instructions = dockerfile_instructions()
    starts = [i for i, (keyword, _) in enumerate(instructions) if keyword == "FROM"]
    return instructions[starts[-1] :]


def test_dockerfile_cmd_is_exec_form() -> None:
    cmds = [rest for keyword, rest in runtime_stage() if keyword == "CMD"]
    assert len(cmds) == 1
    assert cmds[0].startswith("["), "CMD must be exec form so uvicorn is PID 1"
    assert json.loads(cmds[0]) == EXPECTED_CMD
    assert not [rest for keyword, rest in runtime_stage() if keyword == "ENTRYPOINT"]


def test_dockerfile_runtime_stage() -> None:
    stage = runtime_stage()
    assert ("USER", "10001:10001") in stage
    env = " ".join(rest for keyword, rest in stage if keyword == "ENV")
    assert "TMPDIR=/data/tmp" in env
    workdir = [rest for keyword, rest in stage if keyword == "WORKDIR"]
    assert workdir == ["/app"], "uvicorn adds its working directory to sys.path"
    healthchecks = [rest for keyword, rest in stage if keyword == "HEALTHCHECK"]
    assert len(healthchecks) == 1
    assert 'CMD ["python"' in healthchecks[0]
    assert "/healthz" in healthchecks[0]
    assert not any(keyword == "COPY" and "node" in rest.lower() for keyword, rest in stage)


def test_runtime_image_carries_a_checksummed_age() -> None:
    """Archive encryption runs the age CLI from /opt/age, pinned and checked per platform."""
    text = (ROOT / "Dockerfile").read_text().partition("AS age")[2].partition("# RCLONE")[0]
    inline = load_compose("compose.test.yaml")["services"]["tests"]["build"]["dockerfile_inline"]
    inline = inline.partition("AS age")[2].partition("\n\n")[0]
    sums = re.findall(r"(amd64|arm64)\) sum=([0-9a-f]{64}) ;;", text)
    assert dict(sums) == dict(re.findall(r"(amd64|arm64)\) sum=([0-9a-f]{64}) ;;", inline))
    assert len(sums) == 2
    assert "sha256sum -c -" in text
    assert "age/age age/age-plugin-batchpass" in text
    assert ("COPY", "--from=age /opt/age /opt/age") in runtime_stage()
    versions = set(re.findall(r"releases/download/(v[0-9.]+)/age-", text + inline))
    assert versions == {"v1.3.2"}


def test_runtime_image_carries_a_checksummed_rclone() -> None:
    """Remote storage runs the rclone binary from /opt/rclone, pinned and checked per platform."""
    text = (ROOT / "Dockerfile").read_text()
    inline = load_compose("compose.test.yaml")["services"]["tests"]["build"]["dockerfile_inline"]
    pattern = r"(amd64|arm64)\) sum=([0-9a-f]{64}) ;;"
    stage = text.partition("AS rclone")[2].partition("# RUNTIME")[0]
    inline_stage = inline.partition("AS rclone")[2].partition("\n\n")[0]
    sums = re.findall(pattern, stage)
    assert len(sums) == 2
    assert dict(sums) == dict(re.findall(pattern, inline_stage))
    for text_stage in (stage, inline_stage):
        assert "set -eu;" in text_stage  # a failed check ends the RUN
        assert "sha256sum -c -" in text_stage
        assert "|| true" not in text_stage
    assert ("COPY", "--from=rclone /opt/rclone /opt/rclone") in runtime_stage()
    # Without it every rclone test in the tests image would skip.
    assert "COPY --from=rclone /opt/rclone /opt/rclone" in inline
    versions = set(re.findall(r"releases/download/(v[0-9.]+)/rclone-\1-", text + inline))
    assert versions == {"v1.75.2"}


def test_every_base_image_is_pinned_by_digest() -> None:
    sources = [rest.split()[0] for keyword, rest in dockerfile_instructions() if keyword == "FROM"]
    sources += re.findall(r"--from=(\S+)", (ROOT / "Dockerfile").read_text())
    stages = {"frontend", "build", "age", "rclone"}
    for source in sources:
        if source in stages:
            continue
        assert re.fullmatch(r"[^\s:@]+(?::[\w.-]+)?@sha256:[0-9a-f]{64}", source), source


# SOCKET PROXY

PROXY_ENABLED = {
    "CONTAINERS",
    "DISTRIBUTION",
    "IMAGES",
    "VOLUMES",
    "NETWORKS",
    "EXEC",
    "POST",
    "ALLOW_START",
    "ALLOW_STOP",
    "ALLOW_RESTARTS",
    "ALLOW_PAUSE",
    "ALLOW_UNPAUSE",
    "ALLOW_ARCHIVE",
    "INFO",
    "VERSION",
    "PING",
}
# Every other flag that linuxserver/socket-proxy 3.4.6 reads. Each must be set to 0
# explicitly: the image defaults EVENTS, LIBPOD_PING and LIBPOD_VERSION to 1.
PROXY_DISABLED = {
    "ALLOW_CHANGES",
    "ALLOW_EXPORT",
    "ALLOW_LOGS",
    "ALLOW_TOP",
    "AUTH",
    "BUILD",
    "COMMIT",
    "CONFIGS",
    "EVENTS",
    "GRPC",
    "NODES",
    "PLUGINS",
    "SECRETS",
    "SERVICES",
    "SESSION",
    "SWARM",
    "SYSTEM",
    "TASKS",
    "LIBPOD_ALLOW_PAUSE",
    "LIBPOD_ALLOW_POD_PAUSE",
    "LIBPOD_ALLOW_POD_RESTARTS",
    "LIBPOD_ALLOW_POD_START",
    "LIBPOD_ALLOW_POD_STOP",
    "LIBPOD_ALLOW_POD_UNPAUSE",
    "LIBPOD_ALLOW_RESTARTS",
    "LIBPOD_ALLOW_START",
    "LIBPOD_ALLOW_STOP",
    "LIBPOD_ALLOW_UNPAUSE",
    "LIBPOD_CONTAINERS",
    "LIBPOD_EVENTS",
    "LIBPOD_EXEC",
    "LIBPOD_GENERATE",
    "LIBPOD_IMAGES",
    "LIBPOD_INFO",
    "LIBPOD_MANIFESTS",
    "LIBPOD_NETWORKS",
    "LIBPOD_PING",
    "LIBPOD_PLAY",
    "LIBPOD_PODS",
    "LIBPOD_SECRETS",
    "LIBPOD_SYSTEM",
    "LIBPOD_VERSION",
    "LIBPOD_VOLUMES",
}
DIGEST_RE = r"[^\s:@]+(?::[\w.-]+)?@sha256:[0-9a-f]{64}"


def test_socket_proxy_enables_exactly_the_planned_endpoints() -> None:
    env = load_compose("compose.yaml")["services"]["socket-proxy"]["environment"]
    assert set(env) == PROXY_ENABLED | PROXY_DISABLED
    assert {name for name, value in env.items() if value == "1"} == PROXY_ENABLED
    assert {name for name, value in env.items() if value == "0"} == PROXY_DISABLED


def test_socket_proxy_is_hardened() -> None:
    compose = load_compose("compose.yaml")
    proxy = compose["services"]["socket-proxy"]
    assert re.fullmatch(DIGEST_RE, proxy["image"])
    assert proxy["image"].startswith("lscr.io/linuxserver/socket-proxy:")
    assert proxy["read_only"] is True
    assert proxy["tmpfs"] == ["/run"]
    assert proxy["volumes"] == ["/var/run/docker.sock:/var/run/docker.sock:ro"]
    assert proxy["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in proxy["security_opt"]
    for key in ("cap_add", "privileged", "ports", "network_mode"):
        assert key not in proxy
    assert proxy["networks"] == ["docker-proxy"]
    assert compose["networks"]["docker-proxy"]["internal"] is True


def test_drydock_reaches_docker_only_through_the_proxy() -> None:
    compose = load_compose("compose.yaml")
    services = compose["services"]
    drydock = services["drydock"]
    assert sorted(drydock["networks"]) == ["docker-proxy", "egress"]
    assert not (compose["networks"]["egress"] or {}).get("internal")
    on_proxy_network = {n for n, s in services.items() if "docker-proxy" in s.get("networks", [])}
    assert on_proxy_network == {"drydock", "socket-proxy"}
    for name, service in services.items():
        mounts_socket = any("docker.sock" in str(v) for v in service.get("volumes", []))
        assert mounts_socket == (name == "socket-proxy"), name
    assert drydock["environment"]["DRYDOCK_LOCAL_DOCKER_URL"] == "tcp://socket-proxy:2375"


def test_tests_use_the_production_proxy() -> None:
    services = load_compose("compose.test.yaml")["services"]
    proxy = services["socket-proxy"]
    assert proxy["extends"] == {"file": "compose.yaml", "service": "socket-proxy"}
    assert set(proxy) == {"extends", "restart"}
    assert not any("docker.sock" in str(v) for v in services["tests"]["volumes"])
    assert services["tests"]["environment"]["DRYDOCK_TEST_DOCKER_URL"] == (
        "tcp://socket-proxy:2375"
    )


def test_test_images_are_pinned_by_digest() -> None:
    services = load_compose("compose.test.yaml")["services"]
    for name, service in services.items():
        build = service.get("build")
        inline = build.get("dockerfile_inline", "") if isinstance(build, dict) else ""
        sources = re.findall(r"^FROM (\S+)", inline, re.MULTILINE)
        stages = re.findall(r"^FROM \S+ AS (\S+)", inline, re.MULTILINE)
        sources += [s for s in re.findall(r"--from=(\S+)", inline) if s not in stages]
        for source in sources:
            assert re.fullmatch(DIGEST_RE, source), (name, source)
