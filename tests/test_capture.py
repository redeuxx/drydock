"""Capture against real daemons: scopes, compose files, binds, images and cleanup.

The host daemon (through the socket proxy) covers volumes, tmpfs, networks and the
per-scope member lists. Compose files and bind mounts need host paths the test can
create, so those tests use the sshhost dind daemon, whose host filesystem is the sshhost
container; its plain TCP endpoint also allows commit, which makes a locally built image.
"""

import contextlib
import hashlib
import io
import json
import os
import tarfile
import threading
import uuid
from collections.abc import Iterator
from compression import zstd
from pathlib import Path

import docker
import pytest
import requests

from drydock.archive import manifest as m
from drydock.archive import verify
from drydock.archive.writer import AGE_DIR, Cancelled
from drydock.config import DEFAULT_HELPER_IMAGE
from drydock.crypto import Crypto
from drydock.engine import capture, compose_files
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from tests.docker_support import (
    TEST_INSTANCE,
    TEST_LABEL,
    helpers_left,
    host_docker,
    needs_docker,
    sh,
    sshhost,
)

PLAIN_URL = os.environ.get("DRYDOCK_TEST_SSHHOST_PLAIN_URL", "")
needs_dind = pytest.mark.skipif(not PLAIN_URL, reason="needs the sshhost service")
SENTINEL = "SENTINEL-c2d81f-env-secret"
IMAGE = DEFAULT_HELPER_IMAGE
# Runs as root with Docker's default capabilities (it must chown); test only, never a helper.
POPULATE = (
    "printf 'volume data' > /v/secret.txt && chown 999:999 /v/secret.txt"
    " && chmod 0600 /v/secret.txt && mkdir /v/empty"
)


def collect() -> tuple[list[str], capture.Log]:
    lines: list[str] = []
    return lines, lines.append


def members_of(path: Path) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(zstd.decompress(path.read_bytes()))) as tar:
        return {i.name: tar.extractfile(i).read() for i in tar.getmembers()}  # type: ignore[union-attr]


def inner(data: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {i.name: i for i in tar.getmembers()}


def inner_file(data: bytes, name: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return tar.extractfile(name).read()  # type: ignore[union-attr]


def make_env(handle, tmp_path: Path, crypto: Crypto, host_name: str) -> capture.CaptureEnv:
    return capture.CaptureEnv(
        handle=handle,
        host_name=host_name,
        helper_image=IMAGE,
        instance_id=TEST_INSTANCE,
        staging_dir=tmp_path / "staging",
        crypto=crypto,
    )


def job(scope: str, **kwargs) -> capture.CaptureJob:
    return capture.CaptureJob(uuid=str(uuid.uuid4()), name="test", scope=scope, **kwargs)  # type: ignore[arg-type]


def run(env, job_, containers, out: Path, secrets: list[str] | None = None):
    lines, log = collect()
    manifest, result = capture.capture(
        env,
        job_,
        containers,
        out,
        cancel=threading.Event(),
        log=log,
        secrets=None if secrets is None else secrets.extend,
    )
    return manifest, result, lines


# DOCKER-PY PRIVATE API


class RecordingAPI:
    """Stands in for docker.APIClient to record the image export request."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.real = docker.APIClient(base_url="tcp://127.0.0.1:1", version="1.48")

    def _url(self, path: str, *args) -> str:
        return self.real._url(path, *args)

    def _get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self

    def _raise_for_status(self, response) -> None:
        pass

    def _stream_raw_result(self, response, chunk_size, decode):
        yield b"tar"

    def close(self) -> None:
        pass


def test_docker_py_private_api_used_for_image_export() -> None:
    """capture.image_stream relies on these private members of docker==7.2.0."""
    assert docker.__version__ == "7.2.0"
    for name in ("_get", "_url", "_raise_for_status", "_stream_raw_result"):
        assert callable(getattr(docker.APIClient, name)), name
    entry = m.ImageEntry(
        id="sha256:" + "c" * 64,
        refs=["web:1", "web:latest", "busybox@sha256:" + "d" * 64],
        repo_digests=[],
        os="linux",
        architecture="arm64",
        variant="v8",
        saved=True,
    )
    for version, platform in (("1.48", True), ("1.47", False), ("1.56", True)):
        api = RecordingAPI()
        assert b"".join(capture.image_stream(api, entry, version)) == b"tar"
        url, kwargs = api.calls[0]
        assert url == "http://127.0.0.1:1/v1.48/images/get"
        assert kwargs["stream"] is True
        assert kwargs["params"]["names"] == ["web:1", "web:latest"]
        if platform:
            assert json.loads(kwargs["params"]["platform"]) == {
                "os": "linux",
                "architecture": "arm64",
                "variant": "v8",
            }
        else:
            assert "platform" not in kwargs["params"]
        api.real.close()


# REFERENCE-ONLY IMAGES (PLAN.md DECISION 9)


class RegistryAPI:
    """Answers GET /distribution/<ref>/json from a table: a digest, or an exception."""

    def __init__(self, answers: dict[str, object]) -> None:
        self.answers = answers
        self.asked: list[tuple[str, object]] = []

    def _url(self, path: str, *args: str) -> str:
        return path.format(*args)

    def _get(self, url: str, **kwargs):
        self.asked.append((url, kwargs.get("timeout")))
        return url

    def _result(self, url: str, json: bool = False):
        answer = self.answers[url.removeprefix("/distribution/").removesuffix("/json")]
        if isinstance(answer, BaseException):
            raise answer
        return {"Descriptor": {"digest": answer, "mediaType": "x", "size": 1}}


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def image_plan(digests: list[str]) -> capture.Plan:
    image_id = "sha256:" + "c" * 64
    inspect = {"RepoTags": ["web:1"], "RepoDigests": digests, "Os": "linux"}
    return capture.Plan(images={image_id: inspect}, image_refs={image_id: ["web:1"]})


@pytest.mark.parametrize(
    ("answers", "saved"),
    [
        ({f"web@{DIGEST_A}": DIGEST_A}, False),  # confirmed: reference only
        ({f"web@{DIGEST_A}": DIGEST_B}, True),  # the registry holds another digest
        ({f"web@{DIGEST_A}": docker.errors.NotFound("unknown")}, True),  # local build
        ({f"web@{DIGEST_A}": docker.errors.APIError("unauthorized")}, True),
        ({f"web@{DIGEST_A}": requests.exceptions.ReadTimeout("slow")}, True),
        ({f"web@{DIGEST_A}": KeyError("Descriptor")}, True),
    ],
)
def test_reference_only_needs_the_registry_to_confirm_the_digest(answers, saved) -> None:
    api = RegistryAPI(answers)
    lines, log = collect()
    for scope, toggle in (("all", True), ("all", False), ("image", True)):
        api.asked.clear()
        lines.clear()
        [(entry, _)] = capture.image_entries(
            api,
            image_plan([f"web@{DIGEST_A}"]),
            capture.SCOPE_PARTS[scope],
            job(scope, images_reference_only_if_pullable=toggle),
            threading.Event(),
            log,
        )
        if scope == "all" and toggle:
            assert api.asked == [(f"/distribution/web@{DIGEST_A}/json", 10)]
            assert entry.saved is saved
            assert entry.confirmed_digest == (None if saved else f"web@{DIGEST_A}")
            assert entry.data_member == (f"images/{'c' * 64}.tar" if saved else None)
            [line] = lines
            assert ("saved in full" in line) is saved
            assert ("by reference only" in line) is not saved
        else:
            # Without the toggle, and always in the image scope, nothing is looked up.
            assert api.asked == [] and lines == [] and entry.saved


def test_reference_only_tries_each_digest_and_skips_malformed_ones() -> None:
    api = RegistryAPI(
        {f"old/web@{DIGEST_A}": docker.errors.NotFound("gone"), f"web@{DIGEST_B}": DIGEST_B}
    )
    lines, log = collect()
    digests = ["web@sha256:short", f"old/web@{DIGEST_A}", f"web@{DIGEST_B}"]
    [(entry, _)] = capture.image_entries(
        api,
        image_plan(digests),
        capture.SCOPE_PARTS["all"],
        job("all", images_reference_only_if_pullable=True),
        threading.Event(),
        log,
    )
    assert not entry.saved and entry.confirmed_digest == f"web@{DIGEST_B}"
    assert [url for url, _ in api.asked] == [
        f"/distribution/old/web@{DIGEST_A}/json",
        f"/distribution/web@{DIGEST_B}/json",
    ]
    # No digest at all: saved without a lookup.
    api.asked.clear()
    [(entry, _)] = capture.image_entries(
        api,
        image_plan([]),
        capture.SCOPE_PARTS["all"],
        job("all", images_reference_only_if_pullable=True),
        threading.Event(),
        log,
    )
    assert entry.saved and api.asked == []
    assert "no registry digest" in lines[-1]


def test_docker_py_private_api_used_for_registry_lookup() -> None:
    for name in ("_get", "_url", "_result"):
        assert callable(getattr(docker.APIClient, name)), name


# LOCAL HOST: SCOPES


@pytest.fixture
def local_target() -> Iterator[tuple[docker_client.DockerHandle, dict]]:
    handle = host_docker()
    client = handle.client
    suffix = uuid.uuid4().hex[:10]
    labels = {TEST_LABEL: "1"}
    volume = client.volumes.create(f"drydock-test-cap-{suffix}", labels=labels)
    network = client.networks.create(f"drydock-test-net-{suffix}", labels=labels)
    created = []
    try:
        helper.ensure_image(client, IMAGE)
        filler = client.containers.create(
            IMAGE,
            ["sh", "-c", POPULATE],
            mounts=[docker.types.Mount("/v", volume.name, type="volume")],
            network_mode="none",
            labels=labels,
        )
        created.append(filler)
        filler.start()
        assert filler.wait(timeout=60)["StatusCode"] == 0
        container = client.containers.create(
            IMAGE,
            ["sleep", "300"],
            name=f"drydock-test-web-{suffix}",
            environment={"API_TOKEN": SENTINEL},
            mounts=[
                docker.types.Mount("/data", volume.name, type="volume"),
                docker.types.Mount("/scratch", None, type="tmpfs"),
            ],
            tmpfs={"/cache": "size=1m"},
            network=network.name,
            labels=labels,
        )
        created.append(container)
        yield handle, {"container": container, "volume": volume, "network": network}
    finally:
        for item in created:
            item.remove(force=True)
        network.remove()
        volume.remove(force=True)
        handle.close()


@needs_docker
def test_each_scope_produces_exactly_its_members(local_target, tmp_path: Path) -> None:
    handle, target = local_target
    container, volume, network = target["container"], target["volume"], target["network"]
    crypto = Crypto((os.urandom(32),))
    env = make_env(handle, tmp_path, crypto, "local")
    image_id = container.attrs["Image"]
    image_hex = image_id.removeprefix("sha256:")
    config = [
        f"config/containers/{container.id}.json",
        f"config/images/{image_hex}.json",
        f"config/networks/{network.id}.json",
        f"config/volumes/{volume.name}.json",
    ]
    data = [f"volumes/{volume.name}.tar"]
    images = [f"images/{image_hex}.tar"]
    expected = {"config": config, "data": data, "image": images, "all": config + data + images}
    for scope, members in expected.items():
        out = tmp_path / f"{scope}.tar.zst"
        manifest, result, lines = run(env, job(scope), [container.name], out)
        assert manifest.members == members, scope
        stored = members_of(out)
        assert list(stored) == [m.MANIFEST_NAME, *members, m.CHECKSUMS_NAME], scope
        verified = verify.verify_file(out, crypto)
        assert verified.signed and verified.manifest == manifest
        assert result.sha256 and result.size == out.stat().st_size
        # tmpfs mounts are recorded and logged, never captured.
        assert sorted(t.destination for t in manifest.skipped_tmpfs) == ["/cache", "/scratch"]
        assert any("tmpfs" in line for line in lines)
        assert all(SENTINEL not in line for line in lines)
        assert manifest.source.api_version == handle.api_version
        assert manifest.job.scope == scope
        assert [c.id for c in manifest.containers] == [container.id]
        assert [n.name for n in manifest.networks] == [network.name]
        assert list((tmp_path / "staging").iterdir()) == []
        if "config/containers/" in "".join(members):
            # The env secret is in the archive (encrypt archives for this reason) ...
            assert SENTINEL.encode() in stored[config[0]]
        if data[0] in stored:
            files = inner(stored[data[0]])
            secret = files["./secret.txt"]
            assert (secret.uid, secret.gid, secret.mode) == (999, 999, 0o600)
            assert inner_file(stored[data[0]], "./secret.txt") == b"volume data"
            assert files["./empty"].isdir()
        if images[0] in stored:
            saved = inner(stored[images[0]])
            assert "manifest.json" in saved or "index.json" in saved
    assert helpers_left(handle.client, TEST_INSTANCE) == []


@needs_docker
def test_a_skipped_volume_is_mounted_but_not_saved(local_target, tmp_path: Path) -> None:
    handle, target = local_target
    container, volume = target["container"], target["volume"]
    env = make_env(handle, tmp_path, Crypto((os.urandom(32),)), "local")
    skips = frozenset({f"volume:{volume.name}", "bind:/not/mounted/here"})
    out = tmp_path / "skip.tar.zst"
    manifest, _, lines = run(env, job("all", skip_mounts=skips), [container.id], out)
    (entry,) = manifest.volumes
    assert entry.name == volume.name and entry.mounts  # the container still mounts it
    assert entry.data_member is None and entry.skipped == capture.SKIPPED_BY_JOB
    assert entry.config_member is not None
    assert not [name for name in members_of(out) if name.startswith("volumes/")]
    assert f"Skipped the data of volume {volume.name}: the job skips it." in lines
    assert helpers_left(handle.client, TEST_INSTANCE) == []


@needs_docker
def test_after_data_runs_between_the_data_and_the_images(local_target, tmp_path: Path) -> None:
    handle, target = local_target
    container = target["container"]
    env = make_env(handle, tmp_path, Crypto((os.urandom(32),)), "local")
    lines, log = collect()
    capture.capture(
        env,
        job("all"),
        [container.id],
        tmp_path / "order.tar.zst",
        cancel=threading.Event(),
        log=log,
        after_data=lambda: lines.append("AFTER DATA"),
    )
    marker = lines.index("AFTER DATA")
    assert any(line.startswith("Saving volume") for line in lines[:marker])
    assert any(line.startswith("Saving image") for line in lines[marker:])
    assert not any(line.startswith("Saving image") for line in lines[:marker])


@needs_docker
def test_encrypted_capture(local_target, tmp_path: Path) -> None:
    if not (AGE_DIR / "age").is_file():
        pytest.skip("needs the age CLI")
    handle, target = local_target
    crypto = Crypto((os.urandom(32),))
    env = make_env(handle, tmp_path, crypto, "local")
    job_ = job("config", encrypted=True)
    out = tmp_path / "a.tar.zst.age"
    manifest, result, _ = run(env, job_, [target["container"].id], out)
    assert result.encrypted and manifest.encryption is not None
    assert SENTINEL.encode() not in out.read_bytes()
    with pytest.raises(verify.VerifyError):
        verify.verify_file(out, crypto)
    passphrase = crypto.job_passphrase(uuid.UUID(job_.uuid))
    assert verify.verify_file(out, crypto, passphrases=[passphrase]).signed


@needs_docker
def test_cancel_or_failure_leaves_no_helper_or_file(local_target, tmp_path: Path) -> None:
    handle, target = local_target
    env = make_env(handle, tmp_path, Crypto((os.urandom(32),)), "local")
    cancel = threading.Event()
    seen_helpers: list[int] = []

    def log(line: str) -> None:
        # Cancel once the helper exists and the volume is being read.
        if line.startswith("Saving volume"):
            seen_helpers.append(len(helpers_left(handle.client, TEST_INSTANCE)))
            cancel.set()

    out = tmp_path / "a.tar.zst"
    with pytest.raises(Cancelled):
        capture.capture(env, job("data"), [target["container"].name], out, cancel=cancel, log=log)
    assert seen_helpers == [1]
    assert not out.exists()
    assert list((tmp_path / "staging").iterdir()) == []
    assert helpers_left(handle.client, TEST_INSTANCE) == []
    with pytest.raises(capture.CaptureError, match="does not exist"):
        capture.capture(
            env,
            job("all"),
            ["drydock-test-no-such-container"],
            out,
            cancel=threading.Event(),
            log=lambda _: None,
        )
    assert not out.exists()
    assert helpers_left(handle.client, TEST_INSTANCE) == []


# SSHHOST: COMPOSE FILES, BINDS AND IMAGES


@pytest.fixture
def dind() -> Iterator[tuple[docker_client.DockerHandle, object, str]]:
    """The sshhost daemon over plain TCP, a scratch directory on its host, and cleanup."""
    host = host_docker()
    box = sshhost(host)
    root = f"/srv/drydock-test-{uuid.uuid4().hex[:10]}"
    handle = docker_client.open_client(PLAIN_URL)
    try:
        helper.ensure_image(handle.client, IMAGE)
        sh(box, 'mkdir -p "$1"', root)
        yield handle, box, root
    finally:
        for container in handle.client.containers.list(
            all=True, filters={"label": f"{TEST_LABEL}=1"}
        ):
            container.remove(force=True)
        for image in handle.client.images.list(filters={"label": f"{TEST_LABEL}=1"}):
            handle.client.images.remove(image.id, force=True)
        sh(box, 'rm -rf "$1"', root)
        handle.close()
        host.close()


COMPOSE_SETUP = r"""
set -e
cd "$1"
mkdir proj bind
printf 'services:\n  web:\n    image: busybox\n    env_file:\n' > proj/compose.yaml
printf '      - web.env\n      - path: ${MISSING}.env\n' >> proj/compose.yaml
printf '        required: false\n' >> proj/compose.yaml
printf 'DB_PASSWORD=hunter2\n\000\377 binary-safe\n' > proj/.env
printf 'export API_KEY="web-env-secret"\n' > proj/web.env
chmod 0600 proj/.env proj/compose.yaml proj/web.env
head -c 1100000 /dev/zero > proj/big.env
mkfifo proj/fifo.yaml
mkdir proj/dir.yaml
ln -s compose.yaml proj/link.yml
printf 'bind data' > bind/owned.txt
chown -R 999:999 bind
chmod 0600 bind/owned.txt
printf 'single file bind' > single.conf
"""


@needs_dind
def test_compose_files_and_binds(dind, tmp_path: Path) -> None:
    handle, box, root = dind
    sh(box, COMPOSE_SETUP, root)
    proj = f"{root}/proj"
    config_files = ",".join(
        f"{proj}/{name}"
        for name in ("compose.yaml", "fifo.yaml", "dir.yaml", "link.yml", "missing.yaml")
    )
    labels = {
        TEST_LABEL: "1",
        "com.docker.compose.project": "drydocktest",
        "com.docker.compose.service": "web",
        compose_files.CONFIG_FILES_LABEL: config_files + ",relative/compose.yaml",
        compose_files.ENVIRONMENT_FILE_LABEL: f"{proj}/big.env",
        compose_files.WORKING_DIR_LABEL: proj,
    }
    container = handle.client.containers.create(
        IMAGE,
        ["sleep", "300"],
        labels=labels,
        mounts=[
            docker.types.Mount("/srv/bind", f"{root}/bind", type="bind"),
            docker.types.Mount("/etc/single.conf", f"{root}/single.conf", type="bind"),
            # Never backed up: a pseudo-filesystem.
            docker.types.Mount("/host/proc", "/proc", type="bind", read_only=True),
        ],
    )
    crypto = Crypto((os.urandom(32),))
    env = make_env(handle, tmp_path, crypto, "sshhost")
    out = tmp_path / "config.tar.zst"
    secrets: list[str] = []
    manifest, _, lines = run(env, job("config"), [container.id], out, secrets)
    stored = members_of(out)
    compose_members = [name for name in stored if name.startswith("compose/")]
    assert compose_members == ["compose/0/compose.yaml", "compose/1/.env", "compose/2/web.env"]
    assert stored["compose/2/web.env"] == b'export API_KEY="web-env-secret"\n'
    # Env file values reach the run log's redaction set; compose.yaml's do not need to.
    assert {"hunter2", "web-env-secret"} <= set(secrets)
    host_bytes = {
        "compose/0/compose.yaml": sh(box, 'cat "$1"', f"{proj}/compose.yaml").encode(),
    }
    assert stored["compose/0/compose.yaml"] == host_bytes["compose/0/compose.yaml"]
    # .env holds bytes that are not valid UTF-8; compare hashes computed on the host.
    host_sum = sh(box, 'sha256sum "$1"', f"{proj}/.env").split()[0]
    assert hashlib.sha256(stored["compose/1/.env"]).hexdigest() == host_sum
    assert [(f.role, f.host_path) for f in manifest.compose_files] == [
        ("config_file", f"{proj}/compose.yaml"),
        ("dotenv", f"{proj}/.env"),
        ("env_file", f"{proj}/web.env"),
    ]
    skipped = {s.host_path: s.reason for s in manifest.skipped_compose_files}
    assert skipped == {
        f"{proj}/fifo.yaml": "not a regular file",
        f"{proj}/dir.yaml": "not a regular file",
        f"{proj}/link.yml": "not a regular file",
        f"{proj}/missing.yaml": "not found",
        "relative/compose.yaml": "not an absolute, normalized host path",
        f"{proj}/big.env": "larger than 1 MiB",
        "${MISSING}.env": "uses a variable",
    }
    for path in skipped:
        assert any(path in line and "Skipped compose file" in line for line in lines), path
    assert all("hunter2" not in line for line in lines)
    assert verify.verify_file(out, crypto).signed

    out = tmp_path / "data.tar.zst"
    manifest, _, lines = run(env, job("data"), [container.id], out)
    stored = members_of(out)
    binds = {b.source: b for b in manifest.binds}
    # Docker lists mounts in its own order; the /proc bind is numbered but has no member.
    assert (
        manifest.members == [b.data_member for b in manifest.binds if b.source != "/proc"]
        and len(manifest.members) == 2
    )
    assert binds["/proc"].data_member is None and binds["/proc"].skipped == "a system path"
    assert any("bind mount /proc" in line and "system path" in line for line in lines)
    assert binds[f"{root}/bind"].kind == "dir" and binds[f"{root}/single.conf"].kind == "file"
    tree = inner(stored[binds[f"{root}/bind"].data_member])  # type: ignore[index]
    owned = tree["./owned.txt"]
    assert (owned.uid, owned.mode) == (999, 0o600)
    single = stored[binds[f"{root}/single.conf"].data_member]  # type: ignore[index]
    n = binds[f"{root}/single.conf"].n
    assert inner_file(single, f"b{n}") == b"single file bind"
    assert helpers_left(handle.client, TEST_INSTANCE) == []


@needs_dind
def test_compose_labels_inherited_from_the_image_are_ignored(dind, tmp_path: Path) -> None:
    """Docker merges image labels into the container's. An image that ships Compose labels
    must not make drydock read host files of its choosing."""
    handle, box, root = dind
    sh(box, 'printf "host secret" > "$1/secret.yaml"', root)
    lure = {
        "com.docker.compose.project": "lure",
        "com.docker.compose.service": "web",
        compose_files.CONFIG_FILES_LABEL: f"{root}/secret.yaml",
        compose_files.WORKING_DIR_LABEL: root,
    }
    base = handle.client.containers.create(IMAGE, ["true"], labels={TEST_LABEL: "1"})
    tag = f"drydock-test/lure:{uuid.uuid4().hex[:8]}"
    repository, version = tag.split(":")
    base.commit(repository=repository, tag=version, conf={"Labels": {TEST_LABEL: "1", **lure}})
    container = handle.client.containers.create(tag, ["true"], labels={TEST_LABEL: "1"})
    assert container.labels[compose_files.CONFIG_FILES_LABEL] == f"{root}/secret.yaml"
    env = make_env(handle, tmp_path, Crypto((os.urandom(32),)), "sshhost")
    manifest, _, lines = run(env, job("config"), [container.id], tmp_path / "a.tar.zst")
    assert manifest.compose_files == [] and manifest.skipped_compose_files == []
    assert not [name for name in members_of(tmp_path / "a.tar.zst") if name.startswith("compose/")]
    assert manifest.containers[0].compose_project is None
    assert any("comes from its image" in line for line in lines)
    assert helpers_left(handle.client, TEST_INSTANCE) == []


@needs_dind
def test_images_are_deduplicated_and_reference_only_is_optional(dind, tmp_path: Path) -> None:
    handle, _box, _root = dind
    client = handle.client
    tag = f"drydock-test/local:{uuid.uuid4().hex[:8]}"
    base = client.containers.create(IMAGE, ["true"], labels={TEST_LABEL: "1"})
    repository, version = tag.split(":")
    local = base.commit(repository=repository, tag=version, conf={"Labels": {TEST_LABEL: "1"}})
    first = client.containers.create(tag, ["true"], labels={TEST_LABEL: "1"})
    second = client.containers.create(tag, ["true"], labels={TEST_LABEL: "1"})
    pullable = client.containers.create(IMAGE, ["true"], labels={TEST_LABEL: "1"})
    busybox = client.images.get(IMAGE)
    assert busybox.attrs.get("RepoDigests")
    crypto = Crypto((os.urandom(32),))
    env = make_env(handle, tmp_path, crypto, "sshhost")
    targets = [first.id, second.id, pullable.id]
    local_member = f"images/{local.id.removeprefix('sha256:')}.tar"
    busybox_member = f"images/{busybox.id.removeprefix('sha256:')}.tar"

    out = tmp_path / "default.tar.zst"
    manifest, _, _ = run(env, job("all"), targets, out)
    image_members = [name for name in manifest.members if name.startswith("images/")]
    assert image_members == [local_member, busybox_member]  # the shared image once
    assert all(i.saved for i in manifest.images)
    stored = members_of(out)
    saved = inner(stored[local_member])
    index = json.loads(inner_file(stored[local_member], "manifest.json"))
    assert tag in index[0]["RepoTags"]
    assert "manifest.json" in saved

    out = tmp_path / "reference.tar.zst"
    toggle = job("all", images_reference_only_if_pullable=True)
    manifest, _, lines = run(env, toggle, targets, out)
    # The committed image exists in no registry (on Docker 29 it still has a RepoDigest of
    # its own), so it is saved. The pinned busybox digest is confirmed by Docker Hub.
    assert [n for n in manifest.members if n.startswith("images/")] == [local_member]
    by_id = {i.id: i for i in manifest.images}
    assert by_id[local.id].saved and by_id[local.id].confirmed_digest is None
    assert any(tag in line and "saved in full" in line for line in lines)
    reference = by_id[busybox.id]
    assert not reference.saved and reference.data_member is None
    assert reference.repo_digests == busybox.attrs["RepoDigests"]
    assert reference.confirmed_digest in busybox.attrs["RepoDigests"]
    assert any("confirmed" in line and "by reference only" in line for line in lines)
    assert verify.verify_file(out, crypto).signed

    # The image scope ignores the toggle: its whole point is saving images.
    out = tmp_path / "image.tar.zst"
    manifest, _, _ = run(env, job("image", images_reference_only_if_pullable=True), targets, out)
    assert manifest.members == [local_member, busybox_member]
    assert helpers_left(client, TEST_INSTANCE) == []


# COMPOSE FILE LIMITS (NO DAEMON)


def test_compose_paths_in_system_locations_are_refused() -> None:
    for path in ("/etc/shadow", "/root/.ssh/id_ed25519", "/home/u/.gnupg/x", "/proc/1/environ"):
        assert compose_files.path_problem(path) == "refused location", path
    assert compose_files.path_problem("/root/stacks/app/compose.yaml") is None
    assert compose_files.system_path("/") and compose_files.system_path("/var/lib/docker/x")
    assert not compose_files.system_path("/srv/data")


def test_compose_files_are_capped(monkeypatch) -> None:
    """More than MAX_FILES references, or more than MAX_TOTAL_BYTES in all, are skipped."""
    read: list[str] = []

    class Box:
        pass

    @contextlib.contextmanager
    def fake_helper(client, image, instance_id, mounts):
        yield Box()

    def fake_read_one(box, ref):
        read.append(ref.host_path)
        return compose_files.CapturedFile(ref, b"x" * (3 * 1024 * 1024))

    monkeypatch.setattr(compose_files.helper, "helper", fake_helper)
    monkeypatch.setattr(compose_files, "read_one", fake_read_one)
    refs = [
        compose_files.ComposeRef("config_file", f"/srv/p{n}/compose.yaml")
        for n in range(compose_files.MAX_FILES + 5)
    ]
    _, log = collect()
    budget = [compose_files.MAX_FILES, compose_files.MAX_TOTAL_BYTES]
    captured, skipped = compose_files.read_files(None, IMAGE, TEST_INSTANCE, refs, log, budget)  # type: ignore[arg-type]
    assert len(read) == compose_files.MAX_FILES  # one helper per directory, capped
    assert len(captured) == 2  # 3 MiB each, 8 MiB in all
    reasons = [s.reason for s in skipped]
    assert reasons.count(f"more than {compose_files.MAX_FILES} compose files") == 5
    assert reasons.count("compose files over 8 MiB in total") == compose_files.MAX_FILES - 2


def test_env_file_entries_resolve_against_the_project_directory() -> None:
    config = b"""
services:
  web:
    env_file:
      - common.env
      - path: ../shared/secrets.env
        required: false
      - /abs/other.env
  db:
    env_file: db.env
"""
    refs, skipped = compose_files.env_file_refs(config, "web", "/srv/app")
    assert [r.host_path for r in refs] == [
        "/srv/app/common.env",
        "/srv/shared/secrets.env",
        "/abs/other.env",
    ]
    assert skipped == []
    refs, _ = compose_files.env_file_refs(config, "db", "/srv/app")
    assert [r.host_path for r in refs] == ["/srv/app/db.env"]
    assert compose_files.env_file_refs(b": not yaml: [", "web", "/srv") == ([], [])
    assert compose_files.dotenv_values(b"# c\nA=1234\nexport B='quoted'\n") == [
        "1234",
        "'quoted'",
        "quoted",
    ]


@needs_dind
def test_a_skipped_bind_records_its_owner_and_mode_but_no_data(dind, tmp_path: Path) -> None:
    handle, box, root = dind
    cache = f"{root}/cache"
    sh(
        box,
        'mkdir -p "$1/sub" && echo x > "$1/sub/f" && chown -R 101:102 "$1" && chmod 2750 "$1"',
        cache,
    )
    container = handle.client.containers.create(
        IMAGE, ["true"], labels={TEST_LABEL: "1"}, volumes=[f"{cache}:/cache"]
    )
    try:
        env = make_env(handle, tmp_path, Crypto((os.urandom(32),)), "sshhost")
        out = tmp_path / "skip.tar.zst"
        skips = frozenset({f"bind:{cache}"})
        manifest, _, lines = run(env, job("data", skip_mounts=skips), [container.id], out)
    finally:
        container.remove(force=True)
    (entry,) = manifest.binds
    assert entry.source == cache and entry.data_member is None
    assert entry.skipped == capture.SKIPPED_BY_JOB and entry.kind == "dir"
    assert (entry.uid, entry.gid, entry.mode) == (101, 102, 0o2750)
    assert not [name for name in members_of(out) if name.startswith("binds/")]
    assert f"Skipped the data of bind mount {cache}: the job skips it." in lines
    assert helpers_left(handle.client, TEST_INSTANCE) == []


@needs_dind
def test_a_missing_skipped_bind_only_loses_its_owner(dind, tmp_path: Path) -> None:
    """A skipped cache that is gone on the host never fails the backup."""
    handle, box, root = dind
    kept, gone = f"{root}/kept", f"{root}/gone"
    sh(box, 'mkdir -p "$1" "$2" && echo x > "$1/f"', kept, gone)
    container = handle.client.containers.create(
        IMAGE, ["true"], labels={TEST_LABEL: "1"}, volumes=[f"{kept}:/kept", f"{gone}:/gone"]
    )
    sh(box, 'rm -rf "$1"', gone)
    try:
        env = make_env(handle, tmp_path, Crypto((os.urandom(32),)), "sshhost")
        out = tmp_path / "gone.tar.zst"
        manifest, _, lines = run(
            env, job("data", skip_mounts=frozenset({f"bind:{gone}"})), [container.id], out
        )
    finally:
        container.remove(force=True)
    by_source = {b.source: b for b in manifest.binds}
    assert by_source[kept].data_member is not None
    assert by_source[gone].data_member is None and by_source[gone].uid is None
    assert any(f"Could not read the owner of skipped bind mount {gone}" in line for line in lines)
    assert helpers_left(handle.client, TEST_INSTANCE) == []
