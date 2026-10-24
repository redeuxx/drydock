"""Restore apply and rollback against a recording fake of docker-py's APIClient.

No daemon: FakeAPI keeps containers, volumes, networks and images in dicts, resolves
container references the way Docker does (exact name, then ID, then ID prefix) and records
every call in one list, which the journal and the fake archive reader write into too, so
the tests can check what happened before what.
"""

import base64
import contextlib
import copy
import dataclasses
import hashlib
import io
import json
import posixpath
import tarfile
import threading
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import docker
import docker.errors
import pytest
import requests

from drydock.archive.verify import VerifyError
from drydock.archive.writer import Cancelled
from drydock.config import DEFAULT_HELPER_IMAGE
from drydock.engine import stacks
from drydock.hosts import helper, inventory
from drydock.restore import apply
from drydock.restore import plan as p
from drydock.restore.verify import MemberFacts
from tests.restore_support import TarEntry, inner_tar


def hexid(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


RUN = 7
ORIG = hexid("original")
ORIG2 = hexid("original2")
NEW = hexid("new")
IMAGE_ID = "sha256:" + hexid("image")
CONFIG_DIGEST = "sha256:" + hexid("config")
FOREIGN_ID = "sha256:" + hexid("foreign")
DIGEST_REF = "nginx@sha256:" + hexid("digest")
GO_DIR = 1 << 31
GO_LINK = 1 << 27
READ_ONLY_CALLS = {
    "inspect_container",
    "inspect_volume",
    "inspect_network",
    "inspect_image",
    "containers",
    "info",
}


# FAKES


class FakeResponse:
    def __init__(
        self, status_code: int = 200, headers: dict | None = None, lines: list | None = None
    ):
        self.status_code = status_code
        self.headers = requests.structures.CaseInsensitiveDict(headers or {})
        self.lines = lines or []
        self.closed = False

    def iter_lines(self) -> Iterator[bytes]:
        for line in self.lines:
            yield json.dumps(line).encode()

    def close(self) -> None:
        self.closed = True


def stat_header(mode: int, name: str = "x", size: int = 0) -> dict[str, str]:
    document = {"name": name, "size": size, "mode": mode, "mtime": "", "linkTarget": "/ignored"}
    return {"X-Docker-Container-Path-Stat": base64.b64encode(json.dumps(document).encode())}


class FakeAPI:
    """Stands in for docker.APIClient. failures[name] is raised once by that call, and
    hooks[name] runs when it is called."""

    def __init__(self) -> None:
        self.real = docker.APIClient(base_url="tcp://127.0.0.1:1", version="1.48")
        self.calls: list[tuple[str, tuple, dict]] = []
        self.containers_by_id: dict[str, dict] = {}
        self.volumes: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}  # by Id
        self.images: dict[str, dict] = {}  # by ref or ID
        self.host: dict[str, tuple[str, str | None]] = {"/srv": ("dir", None)}
        self.box_paths: set[str] = set()  # paths that exist in the data helper
        self.box_dirs: dict[str, int] = {}  # directories in a helper: their permission bits
        self.box_sizes: dict[str, int] = {}  # sizes of the files put into a helper
        self.extract = True
        self.failures: dict[str, BaseException] = {}
        self.hooks: dict[str, Any] = {}
        self.load_lines: list = []
        self.pull_lines: list | dict[str, list] = []
        self.wait_results: list = []
        self.commands: dict[str, list[str] | None] = {}  # of each helper, by ID
        self.target_mode = 0o755  # of the data helper's TARGET
        self.chmod = True  # whether a started ROOT_SCRIPT helper sets the mode
        self.uploaded = b""
        self.serial = 0

    def record(self, call: str, /, *args: Any, **kwargs: Any) -> None:
        self.calls.append((call, args, kwargs))
        if call in self.hooks:
            self.hooks[call]()
        if call in self.failures:
            raise self.failures.pop(call)

    def names(self) -> list[str]:
        return [name for name, _, _ in self.calls]

    def called(self, name: str) -> list[tuple[tuple, dict]]:
        return [(args, kwargs) for n, args, kwargs in self.calls if n == name]

    def index(self, name: str) -> int:
        return self.names().index(name)

    # CONTAINERS

    def add(self, container_id: str, name: str, *, labels=None, running=False, **extra) -> dict:
        info = {
            "Id": container_id,
            "Name": "/" + name,
            "Config": {"Labels": labels or {}, "Env": extra.pop("env", [])},
            "State": {"Running": running, "Status": "running" if running else "exited"},
            "Mounts": extra.pop("mounts", []),
            **extra,
        }
        self.containers_by_id[container_id] = info
        return info

    def find(self, ref: str) -> dict:
        for info in self.containers_by_id.values():
            if info["Name"] == "/" + ref:
                return info
        if ref in self.containers_by_id:
            return self.containers_by_id[ref]
        matches = [i for cid, i in self.containers_by_id.items() if cid.startswith(ref)]
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise docker.errors.APIError(
                f"multiple IDs found with provided prefix: {ref}", response=FakeResponse(400)
            )
        raise docker.errors.NotFound(f"No such container: {ref}")

    def inspect_container(self, ref: str) -> dict:
        self.record("inspect_container", ref)
        return copy.deepcopy(self.find(ref))

    def containers(self, all: bool = False, filters: dict | None = None) -> list[dict]:
        self.record("containers", all=all, filters=filters)
        listing = []
        for info in self.containers_by_id.values():
            volume = (filters or {}).get("volume")
            if volume and not any(m.get("Name") == volume for m in info["Mounts"]):
                continue
            label = (filters or {}).get("label")
            if label:
                key, _, value = label.partition("=")
                if info["Config"]["Labels"].get(key) != value:
                    continue
            listing.append(
                {
                    "Id": info["Id"],
                    "Names": [info["Name"]],
                    "State": info["State"]["Status"],
                    "Labels": copy.deepcopy(info["Config"]["Labels"]),
                    "Mounts": copy.deepcopy(info["Mounts"]),
                }
            )
        return listing

    def stop(self, container: str, timeout: int) -> None:
        self.record("stop", container, timeout=timeout)
        self.find(container)["State"] = {"Running": False, "Status": "exited"}

    def update_container(self, container: str, restart_policy: dict | None = None) -> dict:
        self.record("update_container", container, restart_policy=restart_policy)
        host = self.find(container).setdefault("HostConfig", {})
        host["RestartPolicy"] = dict(restart_policy or {})
        return {"Warnings": []}

    def rename(self, container: str, name: str) -> None:
        self.record("rename", container, name)
        self.find(container)["Name"] = "/" + name

    def start(self, container: str) -> None:
        self.record("start", container)
        command = self.commands.get(container)
        if command and command[2] == apply.ROOT_SCRIPT and self.chmod:
            self.target_mode = int(command[-1], 8)

    def create_container_from_config(self, config: dict, name: str) -> dict:
        self.record("create_container_from_config", copy.deepcopy(config), name=name)
        self.serial += 1
        container_id = hexid(f"{name}-{self.serial}")
        self.add(container_id, name, labels=config.get("Labels"))
        return {"Id": container_id, "Warnings": []}

    def remove_container(self, container: str, v: bool = False, force: bool = False) -> None:
        self.record("remove_container", container, v=v, force=force)
        self.containers_by_id.pop(self.find(container)["Id"])

    def wait(self, container: str, timeout=None, condition=None) -> dict:
        self.record("wait", container, timeout=timeout, condition=condition)
        result = self.wait_results.pop(0) if self.wait_results else {"StatusCode": 0}
        if isinstance(result, BaseException):
            raise result
        command = self.commands.get(container)
        if command and command[2:3] == [apply.COMPOSE_SCRIPT] and result.get("StatusCode") == 0:
            self.extract_compose(f"{apply.TARGET}/{command[-1]}")
        return result

    def extract_compose(self, directory: str) -> None:
        """What a COMPOSE_SCRIPT helper that exits 0 leaves: the new 0700 directory, with
        the compose tar from the last put extracted into it."""
        self.box_dirs[directory] = apply.COMPOSE_DIR_MODE
        with tarfile.open(fileobj=io.BytesIO(self.uploaded)) as outer:
            inner = outer.extractfile(apply.COMPOSE_TAR).read()  # type: ignore[union-attr]
        with tarfile.open(fileobj=io.BytesIO(inner)) as tar:
            for info in tar:
                path = f"{directory}/{info.name}"
                self.box_paths.add(path)
                if info.isdir():
                    self.box_dirs.setdefault(path, info.mode)
                elif info.isfile():
                    self.box_sizes[path] = info.size

    # NETWORKS AND VOLUMES

    def create_network(self, name: str, **kwargs: Any) -> dict:
        self.record("create_network", name, **kwargs)
        network_id = hexid("network-" + name)
        self.networks[network_id] = {
            "Id": network_id,
            "Name": name,
            "Labels": kwargs.get("labels") or {},
            "Containers": {},
        }
        return {"Id": network_id, "Warning": ""}

    def inspect_network(self, ref: str) -> dict:
        self.record("inspect_network", ref)
        for info in self.networks.values():
            if info["Name"] == ref:
                return copy.deepcopy(info)
        matches = [i for nid, i in self.networks.items() if nid.startswith(ref)]
        if len(matches) == 1:
            return copy.deepcopy(matches[0])
        raise docker.errors.NotFound(f"network {ref} not found")

    def remove_network(self, network_id: str) -> None:
        self.record("remove_network", network_id)
        self.networks.pop(network_id)

    def create_volume(self, name, driver=None, driver_opts=None, labels=None) -> dict:
        self.record("create_volume", name, driver, driver_opts, labels)
        info = self.volumes.setdefault(
            name, {"Name": name, "Driver": driver, "Options": driver_opts, "Labels": labels}
        )
        return copy.deepcopy(info)

    def inspect_volume(self, name: str) -> dict:
        self.record("inspect_volume", name)
        if name not in self.volumes:
            raise docker.errors.NotFound(f"get {name}: no such volume")
        return copy.deepcopy(self.volumes[name])

    def remove_volume(self, name: str, force: bool = False) -> None:
        self.record("remove_volume", name, force=force)
        self.volumes.pop(name)

    # IMAGES

    def inspect_image(self, ref: str) -> dict:
        self.record("inspect_image", ref)
        if ref not in self.images:
            raise docker.errors.ImageNotFound(f"No such image: {ref}")
        return copy.deepcopy(self.images[ref])

    def pull(self, repository: str, stream: bool = False, decode: bool = False):
        self.record("pull", repository, stream=stream, decode=decode)
        if isinstance(self.pull_lines, dict):
            return iter(self.pull_lines.get(repository, []))
        return iter(self.pull_lines)

    def tag(self, image: str, repository: str, tag=None) -> bool:
        self.record("tag", image, repository, tag)
        self.images[f"{repository}:{tag}" if tag else repository] = {"Id": image}
        return True

    def remove_image(self, image: str, force: bool = False, noprune: bool = False) -> None:
        self.record("remove_image", image, force=force, noprune=noprune)
        if image not in self.images:
            raise docker.errors.ImageNotFound(f"No such image: {image}")
        del self.images[image]

    def info(self) -> dict:
        self.record("info")
        return {"DockerRootDir": "/var/lib/docker"}

    # RAW REQUESTS

    def _url(self, path: str, *args: str) -> str:
        return self.real._url(path, *args)

    def _raise_for_status(self, response: FakeResponse) -> None:
        if response.status_code >= 400:
            raise docker.errors.APIError(f"HTTP {response.status_code}")

    def _post(self, url: str, **kwargs: Any) -> FakeResponse:
        data = kwargs.pop("data")
        self.record("_post", url, **kwargs)
        self.uploaded = b"".join(data)
        return FakeResponse(lines=self.load_lines)

    def _put(self, url: str, **kwargs: Any) -> FakeResponse:
        data = kwargs.pop("data")
        # requests form-encodes these instead of streaming them (it fails on a list of bytes).
        assert not isinstance(data, (list, tuple, Mapping)), type(data)
        self.record("_put", url, **kwargs)
        self.uploaded = b"".join(data)
        if self.extract:
            base = kwargs["params"]["path"]
            with tarfile.open(fileobj=io.BytesIO(self.uploaded), mode="r|") as tar:
                for info in tar:
                    name = posixpath.normpath(info.name)
                    path = base if name == "." else f"{base}/{name}"
                    self.box_paths.add(path)
                    if info.isdir() and path != apply.TARGET:
                        self.box_dirs.setdefault(path, info.mode)
                    elif info.isfile():
                        self.box_sizes[path] = info.size
        return FakeResponse()

    def head(self, url: str, params: dict, timeout: float) -> FakeResponse:
        self.record("head", url, params=params, timeout=timeout)
        path = params["path"]
        if path.startswith(apply.PROBE_ROOT + "/"):
            found = self.host.get(path.removeprefix(apply.PROBE_ROOT))
            if found is None:
                return FakeResponse(404)
            kind = found[0]
            mode = {"dir": GO_DIR | 0o755, "file": 0o644, "link": GO_LINK | 0o777}[kind]
            return FakeResponse(headers=stat_header(mode))
        if path == apply.TARGET:
            return FakeResponse(headers=stat_header(GO_DIR | self.target_mode))
        if path in self.box_dirs:
            return FakeResponse(headers=stat_header(GO_DIR | self.box_dirs[path]))
        if path in self.box_paths:
            return FakeResponse(headers=stat_header(0o644, size=self.box_sizes.get(path, 0)))
        return FakeResponse(404)


class FakeReader:
    def __init__(self, calls: list, members: dict[str, bytes]) -> None:
        self.calls = calls
        self.members = members

    def advance_to(self, member: str) -> None:
        self.calls.append(("advance_to", (member,), {}))

    def data(self, member: str, rename_to: str | None = None) -> Iterator[bytes]:
        def stream() -> Iterator[bytes]:
            self.calls.append(("data", (member, rename_to), {}))
            yield self.members[member]

        return stream()

    def facts(self, member: str) -> MemberFacts:
        return MemberFacts(root_mode=0o700, root_uid=70, root_gid=70, setid=False, entries=2)

    def close(self) -> None:
        self.calls.append(("reader.close", (), {}))


class Recorder:
    """A run log: lines, and the secrets it was told to redact."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.secrets: list[str] = []

    def __call__(self, line: str) -> None:
        self.lines.append(line)

    def add_secrets(self, values) -> None:
        self.secrets += list(values)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeAPI:
    api = FakeAPI()

    @contextlib.contextmanager
    def fake_helper(client, image, instance_id, command=None, mounts=None, start=False, **kw):
        api.serial += 1
        box_id = f"box{api.serial}"
        details = {"command": command, "mounts": mounts, "start": start, **kw}
        api.commands[box_id] = command
        api.record("helper", box_id, **details)
        api.add(box_id, f"drydock-helper-{api.serial}", running=start)
        try:
            yield SimpleNamespace(id=box_id, client=SimpleNamespace(api=api))
        finally:
            api.containers_by_id.pop(box_id, None)
            api.calls.append(("helper-removed", (box_id,), {}))

    @contextlib.contextmanager
    def fake_open_archive(box, path, chunk_size):
        api.record("get_archive", path)
        target = api.host[path.removeprefix(apply.PROBE_ROOT)][1]
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo(posixpath.basename(path))
            info.type = tarfile.SYMTYPE
            info.linkname = target or ""
            tar.addfile(info)
        yield iter([buffer.getvalue()]), {}

    monkeypatch.setattr(helper, "helper", fake_helper)
    monkeypatch.setattr(helper, "open_archive", fake_open_archive)
    return api


def make_env(api: FakeAPI, api_version: str = "1.48") -> apply.ApplyEnv:
    handle = SimpleNamespace(
        client=SimpleNamespace(api=api), api_version=api_version, arch="amd64", os="linux"
    )
    return apply.ApplyEnv(handle, DEFAULT_HELPER_IMAGE, "test", RUN)  # type: ignore[arg-type]


def make_plan(**changes: Any) -> p.RestorePlan:
    fields: dict[str, Any] = {
        "mode": "overwrite",
        "host_id": 1,
        "images": (),
        "networks": (),
        "volumes": (),
        "originals": (),
        "wipes": (),
        "data": (),
        "containers": (),
        "risk": (),
        "warnings": (),
        "lock_keys": (),
        "bind_sources": (),
        "write_targets": (),
    } | changes
    return p.RestorePlan(**fields)


def image_step(action: str = "load", **changes: Any) -> p.ImageStep:
    fields: dict[str, Any] = {
        "id": IMAGE_ID,
        "label": "web:1",
        "action": action,
        "member": "images/0.tar" if action == "load" else None,
        "pull": DIGEST_REF if action == "pull" else None,
        "refs": ("web:1",),
        "os": "linux",
        "architecture": "arm64",
        "variant": "v8",
        "accepted_ids": (CONFIG_DIGEST, IMAGE_ID),
        "moves": (),
    } | changes
    return p.ImageStep(**fields)


def original(running: bool = True) -> p.Original:
    return p.Original(ORIG, "web", "web-drydock-old", running, 30)


def container_step(**changes: Any) -> p.ContainerStep:
    body = {"Image": "nginx:1.29", "Labels": {"keep": "yes"}, "HostConfig": {}}
    fields: dict[str, Any] = {"name": "web", "body": body, "start": True, "image_entry": None}
    return p.ContainerStep(**(fields | changes))


class Run:
    """One apply() call: its journal snapshots and log lines."""

    def __init__(
        self,
        api: FakeAPI,
        plan: p.RestorePlan,
        *,
        reader=None,
        cancel=None,
        opener=None,
        staged=None,
    ) -> None:
        self.api = api
        self.staged = staged
        self.journal: list[dict] = []
        self.log = Recorder()
        self.plan = plan
        self.reader = reader
        self.cancel = cancel or threading.Event()
        self.opener = opener or (lambda: contextlib.nullcontext(self.reader))

    def record(self, doc: dict) -> None:
        self.api.calls.append(("journal", (doc,), {}))
        self.journal.append(doc)

    def __call__(self, api_version: str = "1.48") -> None:
        apply.apply(
            make_env(self.api, api_version),
            self.plan,
            self.staged,
            self.opener,
            cancel=self.cancel,
            log=self.log,
            journal=self.record,
        )

    def snapshot_before(self, name: str) -> dict:
        """The last journal written before the first call of name."""
        before = self.api.calls[: self.api.index(name)]
        return [args[0] for n, args, _ in before if n == "journal"][-1]


# DOCKER-PY PRIVATE API


def test_docker_py_private_api_pins(fake: FakeAPI) -> None:
    """apply relies on these private members of docker==7.2.0 and on the session's head()."""
    assert docker.__version__ == "7.2.0"
    for name in ("_post", "_put", "_url", "_raise_for_status", "head"):
        assert callable(getattr(docker.APIClient, name)), name
    assert docker.APIClient.head is requests.Session.head

    apply.load_image(fake, io.BytesIO(b"saved" * 3), image_step(), "1.48", threading.Event())
    (url,), kwargs = fake.called("_post")[-1]
    assert url == fake.real._url("/images/load") == "http://127.0.0.1:1/v1.48/images/load"
    assert kwargs == {
        "params": {
            "quiet": "0",
            "platform": '{"os":"linux","architecture":"arm64","variant":"v8"}',
        },
        "headers": {"Content-Type": "application/x-tar"},
        "stream": True,
        "timeout": None,
    }
    assert fake.uploaded == b"saved" * 3
    apply.load_image(fake, io.BytesIO(b"saved"), image_step(), "1.47", threading.Event())
    assert fake.called("_post")[-1][1]["params"] == {"quiet": "0"}

    fake.extract = False
    apply.put_data(fake, "box", iter([b"tar"]))
    (url,), kwargs = fake.called("_put")[-1]
    assert url == fake.real._url("/containers/{0}/archive", "box")
    assert kwargs == {
        "params": {"path": apply.TARGET, "noOverwriteDirNonDir": "true"},
        "headers": {"Content-Type": "application/x-tar"},
    }

    assert apply.path_stat(fake, "box", "/host/srv") is not None
    (url,), kwargs = fake.called("head")[-1]
    assert url == fake.real._url("/containers/{0}/archive", "box")
    assert kwargs == {"params": {"path": "/host/srv"}, "timeout": apply.PROBE_TIMEOUT}
    assert apply.path_stat(fake, "box", "/host/missing") is None


# IMAGES


def test_image_load_accepts_any_recorded_id_and_rejects_others(
    fake: FakeAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apply, "open_staged_image", lambda staged, member: io.BytesIO(b"saved"))
    plan = make_plan(mode="image-only", images=(image_step(),))
    fake.load_lines = [{"stream": "Loaded image: web:1\n"}]
    # Under the classic store the ref names the config digest, not ImageEntry.id.
    fake.images["web:1"] = {"Id": CONFIG_DIGEST}
    run = Run(fake, plan)
    run()
    assert "Loading image web:1." in run.log.lines
    assert run.journal[-1]["committed"] is True

    fake.images["web:1"] = {"Id": FOREIGN_ID}
    with pytest.raises(apply.ApplyError, match="web:1 names another image"):
        Run(fake, plan)()

    fake.images["web:1"] = {"Id": CONFIG_DIGEST}
    fake.load_lines = [{"errorDetail": {"message": "unexpected EOF"}, "error": "unexpected EOF"}]
    with pytest.raises(apply.ApplyError, match="unexpected EOF"):
        Run(fake, plan)()

    # Without refs, the ID the daemon reports must be a recorded one.
    untagged = make_plan(mode="image-only", images=(image_step(refs=()),))
    fake.images[CONFIG_DIGEST] = {"Id": CONFIG_DIGEST}
    fake.load_lines = [{"stream": f"Loaded image ID: {CONFIG_DIGEST}\n"}]
    Run(fake, untagged)()
    fake.images[FOREIGN_ID] = {"Id": FOREIGN_ID}
    fake.load_lines = [{"stream": f"Loaded image ID: {FOREIGN_ID}\n"}]
    with pytest.raises(apply.ApplyError, match="did not load as recorded"):
        Run(fake, untagged)()


def test_pulls_run_before_any_load_and_a_pull_error_changes_nothing(
    fake: FakeAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apply, "open_staged_image", lambda staged, member: io.BytesIO(b"saved"))
    fake.add(ORIG, "web", running=True)
    plan = make_plan(
        # The load comes first in plan order; the pull still runs first.
        images=(image_step(), image_step("pull", id="sha256:" + hexid("pulled"), refs=("db:1",))),
        networks=(p.NetworkStep("net", "create", {"name": "net", "driver": "bridge"}, ()),),
        volumes=(p.VolumeStep("vol", "create", "local", {}, {}, None),),
        originals=(original(),),
        containers=(container_step(),),
    )
    fake.pull_lines = [{"status": "Pulling from library/db"}, {"error": "manifest unknown"}]
    run = Run(fake, plan)
    with pytest.raises(apply.ApplyError, match="Pulling image web:1 failed: manifest unknown"):
        run()
    assert fake.called("pull")[0][0] == (DIGEST_REF,)
    for name in ("_post", "create_network", "create_volume", "stop", "rename", "tag"):
        assert not fake.called(name), name
    assert run.journal and not run.journal[-1]["networks"]

    # A first pull that succeeded moves no tag when a later one fails.
    other = "cache@sha256:" + hexid("cache")
    fake.calls.clear()
    fake.images[DIGEST_REF] = {"Id": "sha256:" + hexid("pulled")}
    fake.pull_lines = {DIGEST_REF: [], other: [{"error": "manifest unknown"}]}
    two = make_plan(
        mode="image-only",
        images=(
            image_step("pull", label="db:1", refs=("db:1",)),
            image_step("pull", id="sha256:" + hexid("c"), label="cache:1", pull=other),
        ),
    )
    with pytest.raises(apply.ApplyError, match="Pulling image cache:1 failed"):
        Run(fake, two)()
    assert [args for args, _ in fake.called("pull")] == [(DIGEST_REF,), (other,)]
    assert not fake.called("tag")


def test_pull_tags_the_refs_on_the_pulled_image(fake: FakeAPI) -> None:
    fake.images[DIGEST_REF] = {"Id": FOREIGN_ID}  # another store, another ID: still accepted
    step = image_step("pull", refs=("web:1", "registry.example:5000/web"))
    plan = make_plan(
        images=(step,), containers=(container_step(image_entry=IMAGE_ID),), mode="new-name"
    )
    run = Run(fake, plan)
    run()
    assert [args for args, _ in fake.called("tag")] == [
        (FOREIGN_ID, "web", "1"),
        (FOREIGN_ID, "registry.example:5000/web", None),
    ]
    assert run.log.lines[0] == f"Pulling image web:1 ({DIGEST_REF})."
    assert fake.called("create_container_from_config")[0][0][0]["Image"] == FOREIGN_ID


def test_digest_ref_body_gets_the_resolved_image_id(
    fake: FakeAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(apply, "open_staged_image", lambda staged, member: io.BytesIO(b"saved"))
    body = {"Image": DIGEST_REF, "Labels": {"keep": "yes"}, "HostConfig": {}}
    plan = make_plan(
        mode="new-name",
        images=(image_step(refs=()),),
        containers=(container_step(body=body, image_entry=IMAGE_ID),),
    )
    fake.load_lines = [{"stream": f"Loaded image ID: {CONFIG_DIGEST}\n"}]
    fake.images[CONFIG_DIGEST] = {"Id": CONFIG_DIGEST}
    Run(fake, plan)()
    (created,), kwargs = fake.called("create_container_from_config")[0]
    assert created["Image"] == CONFIG_DIGEST
    assert created["Labels"] == {"keep": "yes", p.RESTORE_LABEL: str(RUN)}
    assert kwargs == {"name": "web"}
    assert body["Image"] == DIGEST_REF  # the plan is not changed

    # A present image is named by the target's ID of a ref that names an accepted ID.
    fake.images["web:1"] = {"Id": "sha256:" + hexid("config")}
    present = make_plan(
        mode="new-name",
        images=(image_step("present"),),
        containers=(container_step(body=body, image_entry=IMAGE_ID),),
    )
    Run(fake, present)()
    assert fake.called("create_container_from_config")[-1][0][0]["Image"] == CONFIG_DIGEST
    assert not fake.called("pull")


def test_tags_are_journaled_before_they_move_and_pointed_back_on_rollback(
    fake: FakeAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, pulled, other = ("sha256:" + hexid(seed) for seed in ("old", "pulled", "other"))
    plan = make_plan(
        mode="image-only",
        images=(
            image_step(),
            image_step("pull", id=pulled, label="db:1", refs=("db:1", "cache:1")),
        ),
    )

    # A staged tar that is gone stops the restore before any pull moves a tag.
    def gone(staged, member):
        fake.calls.append(("open_staged_image", (member,), {}))
        raise VerifyError("The archive changed since it was verified.")

    monkeypatch.setattr(apply, "open_staged_image", gone)
    with pytest.raises(VerifyError):
        Run(fake, plan)()
    assert fake.names() == ["journal", "open_staged_image"]

    def staged_image(staged, member):
        fake.calls.append(("open_staged_image", (member,), {}))
        return io.BytesIO(b"saved")

    monkeypatch.setattr(apply, "open_staged_image", staged_image)
    fake.calls.clear()
    fake.images |= {"db:1": {"Id": old}, DIGEST_REF: {"Id": pulled}}  # db:1 of another stack
    fake.load_lines = [{"errorDetail": {"message": "short read"}, "error": "short read"}]
    run = Run(fake, plan)
    with pytest.raises(apply.ApplyError, match="short read"):
        run()
    names = fake.names()
    assert names.index("open_staged_image") < names.index("pull") < names.index("tag")
    assert names.index("tag") < names.index("_post")
    assert run.snapshot_before("tag")["tags"] == [
        {"ref": "db:1", "previous": old, "image": pulled},
        {"ref": "cache:1", "previous": None, "image": pulled},
    ]
    assert run.snapshot_before("_post")["tags"][-1] == {
        "ref": "web:1",
        "previous": None,
        "image": None,
    }
    assert fake.images["db:1"] == {"Id": pulled}

    log = Recorder()
    doc = apply.rollback(fake, run.journal[-1], log)
    assert doc["rolled_back"] is True and doc["tags_left"] == []
    assert fake.called("tag")[-1] == ((old, "db", "1"), {})
    assert fake.called("remove_image") == [(("cache:1",), {"force": False, "noprune": True})]
    assert fake.images["db:1"] == {"Id": old} and "cache:1" not in fake.images
    assert log.lines == ["Removed the tag cache:1.", "Pointed db:1 back at its earlier image."]

    # A tag someone else moved since is left alone, and reported.
    fake.images["db:1"] = {"Id": other}
    doc = apply.rollback(fake, run.journal[-1], Recorder())
    assert doc["rolled_back"] is False and doc["tags_left"] == ["db:1"]
    assert fake.images["db:1"] == {"Id": other}


# JOURNAL


def config_only_overwrite() -> p.RestorePlan:
    return make_plan(originals=(original(),), containers=(container_step(),))


def test_initial_journal_is_written_without_data(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    run = Run(fake, config_only_overwrite())
    run()
    assert run.journal[0] == {
        "host_id": 1,
        "mode": "overwrite",
        "run_id": RUN,
        "originals": [],
        "tags": [],
        "created": [],
        "networks": [],
        "volumes_created": [],
        "volumes": [],
        "binds": [],
        "wipe_started": False,
        "data_started": False,
        "committed": False,
        "rolled_back": False,
        "leftover": [],
    }
    assert fake.index("journal") < fake.index("stop")
    assert fake.called("stop")[0] == ((ORIG,), {"timeout": 30})
    assert fake.called("rename")[0] == ((ORIG, "web-drydock-old"), {})
    assert not fake.called("helper")  # no host paths, no wipe, no data
    assert "Checking host paths." not in run.log.lines
    final = run.journal[-1]
    assert final["committed"] and final["leftover"] == []
    assert final["created"] == [{"name": "web", "id": fake.find("web")["Id"], "failed": False}]
    assert fake.called("remove_container") == [((ORIG,), {"v": False, "force": True})]
    assert fake.called("start") == [((fake.find("web")["Id"],), {})]
    assert run.log.lines == [
        "Stopping container web.",
        "Renaming container web to web-drydock-old.",
        "Creating container web.",
        "Starting container web.",
        "Removing the original container web-drydock-old.",
    ]


def test_originals_are_stopped_as_they_are_now_with_their_restart_policy_off(
    fake: FakeAPI,
) -> None:
    """The plan saw web stopped, and it started since. Its restart policy is journaled and
    turned off before the stop, so neither the policy nor a daemon restart starts it on
    half-written data; a rollback before any data gives the policy back."""
    always = {"Name": "always", "MaximumRetryCount": 0}
    fake.add(ORIG, "web", running=True, HostConfig={"RestartPolicy": always})
    fake.failures["create_container_from_config"] = docker.errors.APIError("injected")
    plan = make_plan(originals=(original(running=False),), containers=(container_step(),))
    run = Run(fake, plan)
    with pytest.raises(docker.errors.APIError, match="injected"):
        run()
    assert run.snapshot_before("update_container")["originals"] == [
        {
            "id": ORIG,
            "name": "web",
            "old_name": "web-drydock-old",
            "running": True,
            "stop_timeout": 30,
            "restart_policy": always,
        }
    ]
    assert fake.called("update_container") == [((ORIG,), {"restart_policy": {"Name": "no"}})]
    assert fake.called("stop") == [((ORIG,), {"timeout": 30})]
    names = fake.names()
    assert names.index("update_container") < names.index("stop") < names.index("rename")
    assert "Turning off the restart policy of container web." in run.log.lines

    fake.calls.clear()
    doc = apply.rollback(fake, run.journal[-1], Recorder())
    assert doc["rolled_back"] is True
    assert fake.called("update_container") == [((ORIG,), {"restart_policy": always})]
    assert fake.index("rename") < fake.index("update_container") < fake.index("start")


def test_rollback_after_data_stops_an_original_that_started_again(fake: FakeAPI) -> None:
    """A daemon restart started the renamed original on partial data: the rollback stops it
    and keeps its restart policy off."""
    always = {"Name": "always", "MaximumRetryCount": 0}
    fake.add(ORIG, "web-drydock-old", running=True, HostConfig={"RestartPolicy": always})
    entry = {
        "id": ORIG,
        "name": "web",
        "old_name": "web-drydock-old",
        "running": True,
        "stop_timeout": 30,
        "restart_policy": always,
    }
    log = Recorder()
    doc = apply.rollback(
        fake, rollback_doc(originals=[entry], wipe_started=True, volumes=["data"]), log
    )
    assert doc["rolled_back"] is True
    assert fake.called("rename") == [((ORIG, "web"), {})]
    assert fake.called("stop") == [((ORIG,), {"timeout": 30})]
    assert fake.find(ORIG)["State"]["Running"] is False
    assert not fake.called("start") and not fake.called("update_container")
    assert log.lines == [
        "Renamed web-drydock-old back to web.",
        "Stopped container web: it had started again.",
        "The data in volume data may be partial. The original containers were left stopped.",
        "Container web keeps its restart policy turned off while its data may be partial; set "
        "it back to always once the data is right.",
    ]


def full_plan() -> p.RestorePlan:
    return make_plan(
        networks=(p.NetworkStep("net", "create", {"name": "net", "labels": {"a": "b"}}, ()),),
        volumes=(p.VolumeStep("vol", "create", "local", {}, {"x": "y"}, None),),
        originals=(original(),),
        wipes=(p.Wipe("volume", "vol", "volume vol"),),
        containers=(container_step(),),
    )


@pytest.mark.parametrize(
    ("failing", "check"),
    [
        ("create_network", lambda doc: doc["networks"] == [{"name": "net", "id": None}]),
        ("create_volume", lambda doc: doc["volumes_created"] == ["vol"]),
        ("stop", lambda doc: doc["originals"][0]["id"] == ORIG),
        ("rename", lambda doc: doc["originals"][0]["old_name"] == "web-drydock-old"),
        ("helper", lambda doc: doc["wipe_started"] and doc["volumes"] == ["vol"]),
        (
            "create_container_from_config",
            lambda doc: doc["created"] == [{"name": "web", "id": None, "failed": False}],
        ),
        ("start", lambda doc: doc["created"][0]["id"] is not None),
    ],
)
def test_apply_journals_before_each_mutation(fake: FakeAPI, failing: str, check) -> None:
    fake.add(ORIG, "web", running=True)
    fake.failures[failing] = docker.errors.APIError("injected")
    run = Run(fake, full_plan())
    with pytest.raises(docker.errors.APIError, match="injected"):
        run()
    assert check(run.snapshot_before(failing))
    assert not run.journal[-1]["committed"]
    if failing == "create_network":
        assert fake.called("create_network")[0][1]["labels"] == {"a": "b", p.RESTORE_LABEL: "7"}
    if failing == "create_container_from_config":
        assert run.journal[-1]["created"][0]["failed"] is True


def test_full_apply_labels_everything_and_wipes_with_exactly_two_caps(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    run = Run(fake, full_plan())
    run()
    assert fake.called("create_volume")[0][0] == (
        "vol",
        "local",
        {},
        {"x": "y", "drydock.restore.run": "7"},
    )
    ((_, details),) = fake.called("helper")
    assert details["command"] == ["sh", "-c", apply.WIPE_SCRIPT, "sh", "/w0"]
    assert apply.WIPE_SCRIPT.endswith('exec find "$@" -xdev -mindepth 1 -delete')
    assert details["cap_add"] == ["DAC_OVERRIDE", "FOWNER"] and details["start"] is True
    (mount,) = details["mounts"]
    assert (mount["Target"], mount["Source"], mount["Type"], mount["ReadOnly"]) == (
        "/w0",
        "vol",
        "volume",
        False,
    )
    assert fake.called("wait")[0][1] == {"timeout": apply.WAIT_POLL, "condition": "not-running"}
    assert "Wiping volume vol." in run.log.lines
    assert run.journal[-1]["committed"] is True


def test_existing_volume_with_the_name_stops_the_restore(fake: FakeAPI) -> None:
    fake.volumes["vol"] = {"Name": "vol", "Driver": "local", "Options": {}, "Labels": {}}
    with pytest.raises(apply.ApplyError, match="Volume vol already exists"):
        Run(fake, full_plan())()
    assert not fake.called("stop")


def test_commit_marker_precedes_original_removal(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    fake.add(ORIG2, "db", running=True)
    cancel = threading.Event()
    # A cancel as the last container starts (the end of step 7) is ignored from the commit
    # on: both originals are still removed, after a failed removal too.
    fake.hooks["start"] = cancel.set
    fake.failures["remove_container"] = docker.errors.APIError("device busy")
    plan = make_plan(
        originals=(original(), p.Original(ORIG2, "db", "db-drydock-old", True, 10)),
        containers=(container_step(),),
    )
    run = Run(fake, plan, cancel=cancel)
    run()  # returns: nothing after the commit raises
    assert cancel.is_set()
    assert run.snapshot_before("remove_container")["committed"] is True
    final = run.journal[-1]
    assert final["committed"] is True and final["leftover"] == ["web-drydock-old"]
    assert any(
        line.startswith("Could not remove web-drydock-old; remove it by hand.")
        for line in run.log.lines
    )
    assert [args for args, _ in fake.called("remove_container")] == [(ORIG,), (ORIG2,)]
    assert ORIG2 not in fake.containers_by_id and ORIG in fake.containers_by_id
    assert fake.index("start") < fake.index("remove_container")


def test_cancel_stops_before_the_next_step(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    cancel = threading.Event()
    fake.hooks["rename"] = cancel.set
    run = Run(fake, full_plan(), cancel=cancel)
    with pytest.raises(Cancelled):
        run()
    assert not fake.called("helper") and not fake.called("create_container_from_config")


def test_archive_is_opened_before_any_mutation(fake: FakeAPI) -> None:
    """A missing, replaced or undecryptable archive stops the restore before anything."""
    fake.add(ORIG, "web", running=True)
    fake.host["/srv/app"] = ("dir", None)

    def gone() -> contextlib.AbstractContextManager[Any]:
        fake.calls.append(("open_archive", (), {}))
        raise apply.ApplyError("The archive changed since it was verified.")

    data = p.DataStep("volumes/0.tar", "volume", "vol", "volume vol", None)
    plan = dataclasses.replace(
        full_plan(),
        wipes=(p.Wipe("bind", "/srv/app", "bind mount /srv/app"),),
        data=(data,),
        write_targets=("/srv/app",),
    )
    run = Run(fake, plan, opener=gone)
    with pytest.raises(apply.ApplyError, match="changed since it was verified"):
        run()
    assert fake.names() == ["journal", "open_archive"]
    assert run.journal == [run.journal[0]] and run.journal[0]["wipe_started"] is False


@pytest.mark.parametrize("stage", ["wipe", "data"])
def test_a_path_that_changed_before_any_write_leaves_the_originals_running(
    fake: FakeAPI, stage: str
) -> None:
    """The resolve right before the wipe or data helper fails: nothing was deleted or
    written, so the flags stay unset and a rollback starts the running original again."""
    fake.add(ORIG, "web", running=True)
    fake.host["/srv/app"] = ("dir", None)
    if stage == "wipe":
        plan = make_plan(
            originals=(original(),),
            wipes=(p.Wipe("bind", "/srv/app", "bind mount /srv/app"),),
            containers=(container_step(),),
            write_targets=("/srv/app",),
        )
    else:
        data = p.DataStep("binds/0.tar", "bind-dir", "/srv/app", "bind mount /srv/app", None)
        plan = make_plan(
            originals=(original(),),
            data=(data,),
            containers=(container_step(),),
            write_targets=("/srv/app",),
        )
    reader = FakeReader(fake.calls, {"binds/0.tar": volume_member()})

    def swap() -> None:
        if len(fake.called("helper")) == 2:  # the probe right before the mount
            fake.host |= {"/srv/app": ("link", "/srv/elsewhere"), "/srv/elsewhere": ("dir", None)}

    fake.hooks["helper"] = swap
    run = Run(fake, plan, reader=reader)
    with pytest.raises(apply.ApplyError, match="/srv/app changed during the restore"):
        run()
    assert len(fake.called("helper")) == 2 and not fake.called("_put")
    doc = run.journal[-1]
    assert doc["wipe_started"] is False and doc["data_started"] is False
    assert doc["binds"] == []
    log = Recorder()
    apply.rollback(fake, doc, log)
    assert fake.called("start") == [((ORIG,), {})]
    assert log.lines == ["Renamed web-drydock-old back to web.", "Started container web again."]


def test_wipe_refuses_a_target_with_a_mount_inside(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    fake.wait_results = [{"StatusCode": apply.WIPE_REFUSED}]
    run = Run(fake, full_plan())
    with pytest.raises(apply.ApplyError, match="another mount inside it, so nothing was wiped"):
        run()
    assert run.snapshot_before("helper")["wipe_started"] is True
    doc = run.journal[-1]
    assert doc["wipe_started"] is False and doc["volumes"] == []
    assert not fake.called("create_container_from_config")
    # The refusal comes from the script, before find runs.
    script = apply.WIPE_SCRIPT
    assert "/proc/self/mountinfo || exit 3" in script
    assert script.index("mountinfo") < script.index("exec find")


# HOST PATHS


def test_existence_check_scope(fake: FakeAPI) -> None:
    fake.host |= {"/srv/app": ("dir", None), "/srv/app/conf": ("dir", None)}
    env = make_env(fake)
    file_bind = p.DataStep(
        "binds/1.tar", "bind-file", "/srv/app/conf/app.conf", "bind mount x", "app.conf"
    )
    volume = p.DataStep("volumes/0.tar", "volume", "vol1", "volume vol1", None)
    plan = make_plan(
        data=(file_bind, volume),
        bind_sources=("/srv/app/conf/app.conf",),
        write_targets=("/srv/app/conf",),
    )
    # The file itself may be missing (a new host); its directory must exist.
    resolved = apply.check_paths(env, plan)
    assert resolved == {
        "/srv/app/conf": "/srv/app/conf",
        "/srv/app/conf/app.conf": "/srv/app/conf/app.conf",
    }
    assert not any("vol1" in str(args) for args, _ in fake.called("head"))

    missing = p.DataStep("binds/2.tar", "bind-dir", "/srv/gone", "bind mount /srv/gone", None)
    with pytest.raises(apply.ApplyError, match="/srv/gone does not exist on the host"):
        apply.check_paths(env, make_plan(data=(missing,), write_targets=("/srv/gone",)))
    wipe = make_plan(
        wipes=(p.Wipe("bind", "/srv/gone", "bind mount /srv/gone"),),
        write_targets=("/srv/gone",),
    )
    with pytest.raises(apply.ApplyError, match="/srv/gone does not exist"):
        apply.check_paths(env, wipe)
    fake.host["/srv/file"] = ("file", None)
    not_dir = p.DataStep("binds/3.tar", "bind-dir", "/srv/file", "bind mount /srv/file", None)
    with pytest.raises(apply.ApplyError, match="/srv/file is not a directory"):
        apply.check_paths(env, make_plan(data=(not_dir,), write_targets=("/srv/file",)))
    # Every probe helper mounts the host's / read-only and is never started.
    for _, details in fake.called("helper"):
        assert details["start"] is False and details["command"] is None
        (mount,) = details["mounts"]
        assert (mount["Target"], mount["Source"], mount["ReadOnly"]) == ("/host", "/", True)


def test_file_bind_onto_a_symbolic_link_is_refused(fake: FakeAPI) -> None:
    """Writing app.conf into its directory would replace the link, and the container's bind
    would then resolve elsewhere than it was checked."""
    fake.host |= {
        "/srv/app": ("dir", None),
        "/srv/shared": ("dir", None),
        "/srv/app/nginx.conf": ("link", "/srv/shared/nginx.conf"),
        "/srv/shared/nginx.conf": ("file", None),
    }
    target = "/srv/app/nginx.conf"
    step = p.DataStep("binds/0.tar", "bind-file", target, f"bind mount {target}", "nginx.conf")
    plan = make_plan(data=(step,), bind_sources=(target,), write_targets=("/srv/app",))
    with pytest.raises(
        apply.ApplyError,
        match=r"nginx.conf is a symbolic link to /srv/shared/nginx.conf on the host",
    ):
        apply.check_paths(make_env(fake), plan)

    # A directory in the file's place would refuse the file after the originals stopped.
    fake.host["/srv/app/nginx.conf"] = ("dir", None)
    with pytest.raises(apply.ApplyError, match=r"nginx.conf is not a file on the host"):
        apply.check_paths(make_env(fake), plan)

    # Through a linked directory the name itself is no link: written there as resolved.
    fake.host |= {"/srv/link": ("link", "shared")}
    linked = p.DataStep("binds/0.tar", "bind-file", "/srv/link/nginx.conf", "b", "nginx.conf")
    resolved = apply.check_paths(
        make_env(fake),
        make_plan(
            data=(linked,), bind_sources=("/srv/link/nginx.conf",), write_targets=("/srv/link",)
        ),
    )
    assert resolved["/srv/link/nginx.conf"] == "/srv/shared/nginx.conf"


def test_symlinked_bind_source_is_refused_before_any_mutation(fake: FakeAPI) -> None:
    fake.host |= {"/srv/app": ("dir", None), "/srv/app/l": ("link", "../../etc/./")}
    fake.host["/etc"] = ("dir", None)
    body = {"Image": "nginx", "HostConfig": {"Binds": ["/srv/app/l:/conf:ro"]}}
    plan = make_plan(
        mode="new-name",
        containers=(container_step(body=body),),
        bind_sources=("/srv/app/l",),
    )
    run = Run(fake, plan)
    with pytest.raises(apply.ApplyError, match="Binding /etc is refused for every role"):
        run()
    assert fake.called("get_archive") == [(("/host/srv/app/l",), {})]
    assert not fake.called("create_container_from_config")
    assert len(run.journal) == 1


def test_bind_sources_are_resolved_again_and_mounted_as_resolved(fake: FakeAPI) -> None:
    fake.host |= {
        "/srv/real": ("dir", None),
        "/srv/link": ("link", "real"),
    }
    body = {"Image": "nginx", "HostConfig": {"Binds": ["/srv/link:/data"]}}
    plan = make_plan(
        mode="new-name", containers=(container_step(body=body),), bind_sources=("/srv/link",)
    )
    Run(fake, plan)()
    created = fake.called("create_container_from_config")[0][0][0]
    assert created["HostConfig"]["Binds"] == ["/srv/real:/data"]
    assert len(fake.called("helper")) == 2  # step 0, and again right before the create

    # A path that resolves elsewhere by the time of the create stops the restore.
    def swap() -> None:
        if len(fake.called("helper")) == 4:
            fake.host["/srv/link"] = ("link", "/etc")

    fake.hooks["helper"] = swap
    with pytest.raises(apply.ApplyError, match="/srv/link changed during the restore"):
        Run(fake, plan)()
    assert len(fake.called("create_container_from_config")) == 1


# DATA


def volume_data_plan() -> p.RestorePlan:
    step = p.DataStep("volumes/0.tar", "volume", "vol1", "volume vol1", None)
    return make_plan(mode="data-only", data=(step,))


def volume_member() -> bytes:
    return inner_tar(
        [
            TarEntry("./", tarfile.DIRTYPE, mode=0o700, uid=70, gid=70),
            TarEntry("./a.txt", data=b"hello", uid=999, gid=999, mode=0o600),
        ]
    )


def test_reader_advance_happens_before_put(fake: FakeAPI) -> None:
    fake.volumes["vol1"] = {"Name": "vol1", "Driver": "local", "Options": {}}
    reader = FakeReader(fake.calls, {"volumes/0.tar": volume_member()})
    run = Run(fake, volume_data_plan(), reader=reader)
    run()
    names = fake.names()
    assert names.index("advance_to") < names.index("helper") < names.index("_put")
    assert names.index("_put") < names.index("data")  # the request opens before bytes flow
    assert names.index("reader.close") < len(names) - 1
    assert run.snapshot_before("helper")["data_started"] is True
    assert run.snapshot_before("helper")["volumes"] == ["vol1"]
    ((box, details),) = fake.called("helper")
    # Never started for the put; started after it, with exactly ROOT_CAPS, to give the top
    # directory the archived owner and mode (FakeReader.facts), which Docker leaves alone.
    assert details["start"] is False
    assert details["cap_add"] == ["CHOWN", "FOWNER", "FSETID"]
    assert details["command"] == ["sh", "-c", apply.ROOT_SCRIPT, "sh", "70:70", "700"]
    assert fake.called("start") == [(box, {})]
    assert names.index("_put") < names.index("start") < names.index("wait")
    (mount,) = details["mounts"]
    assert (mount["Target"], mount["Source"], mount["Type"]) == ("/t", "vol1", "volume")
    assert fake.uploaded == volume_member()
    paths = [kwargs["params"]["path"] for _, kwargs in fake.called("head")]
    assert paths == ["/t/a.txt", "/t"]
    last_head = max(i for i, name in enumerate(names) if name == "head")
    assert names.index("wait") < last_head  # the mode is checked after the helper ran
    assert "Restoring the data of volume vol1." in run.log.lines


def test_top_directory_that_keeps_its_mode_stops_the_restore(fake: FakeAPI) -> None:
    fake.volumes["vol1"] = {"Name": "vol1", "Driver": "local", "Options": {}}
    fake.chmod = False
    reader = FakeReader(fake.calls, {"volumes/0.tar": volume_member()})
    with pytest.raises(apply.ApplyError, match="top directory of volume vol1 did not get"):
        Run(fake, volume_data_plan(), reader=reader)()
    fake.chmod = True
    fake.wait_results = [{"StatusCode": 1}]
    with pytest.raises(apply.ApplyError, match=r"did not get the owner .* \(exit 1\)"):
        Run(fake, volume_data_plan(), reader=reader)()


def test_root_metadata_needs_a_complete_directory_root() -> None:
    def facts(mode=0o2750, uid=999, gid=998) -> MemberFacts:
        return MemberFacts(root_mode=mode, root_uid=uid, root_gid=gid, setid=False, entries=1)

    volume = p.DataStep("volumes/0.tar", "volume", "v", "volume v", None)
    bind_dir = p.DataStep("binds/0.tar", "bind-dir", "/srv/a", "bind mount /srv/a", None)
    bind_file = p.DataStep("binds/1.tar", "bind-file", "/srv/a/f", "bind mount f", "f")
    into_volume = p.DataStep("binds/1.tar", "volume", "v", "volume v", "f")
    assert apply.root_metadata(volume, facts()) == ("999:998", "2750")
    assert apply.root_metadata(bind_dir, facts(mode=0o40700)) == ("999:998", "700")
    assert apply.root_metadata(bind_file, facts()) is None
    assert apply.root_metadata(into_volume, facts()) is None
    assert apply.root_metadata(volume, facts(uid=None)) is None
    assert apply.root_metadata(volume, facts(mode=None)) is None


def test_data_that_docker_did_not_write_stops_the_restore(fake: FakeAPI) -> None:
    fake.volumes["vol1"] = {"Name": "vol1", "Driver": "local", "Options": {}}
    fake.extract = False  # a daemon that answers 200 and extracts nothing
    reader = FakeReader(fake.calls, {"volumes/0.tar": volume_member()})
    with pytest.raises(apply.ApplyError, match="Docker did not write the data of volume vol1"):
        Run(fake, volume_data_plan(), reader=reader)()


def test_file_bind_data_is_renamed_into_its_resolved_directory(fake: FakeAPI) -> None:
    fake.host |= {"/srv/real": ("dir", None), "/srv/conf": ("link", "real")}
    member = inner_tar([TarEntry("app.conf", data=b"x=1")])  # as the guard renames it
    reader = FakeReader(fake.calls, {"binds/0.tar": member})
    step = p.DataStep("binds/0.tar", "bind-file", "/srv/conf/app.conf", "bind mount b", "app.conf")
    plan = make_plan(data=(step,), write_targets=("/srv/conf",))
    run = Run(fake, plan, reader=reader)
    run()
    assert ("data", ("binds/0.tar", "app.conf"), {}) in fake.calls
    data_helper = fake.called("helper")[-1][1]
    (mount,) = data_helper["mounts"]
    assert (mount["Source"], mount["Type"]) == ("/srv/real", "bind")
    # Not through a host mount below the directory (a bind of /etc at conf, say).
    assert mount["BindOptions"] == {"NonRecursive": True}
    assert run.journal[-1]["binds"] == ["/srv/conf/app.conf"]
    assert [kwargs["params"]["path"] for _, kwargs in fake.called("head")][-1] == "/t/app.conf"


# WIPE WAIT


def test_wipe_wait_survives_read_timeouts(fake: FakeAPI) -> None:
    fake.add("box", "drydock-helper-x", running=True)
    fake.wait_results = [
        requests.exceptions.ReadTimeout(),
        requests.exceptions.ConnectionError(),
        {"StatusCode": 0},
    ]
    assert apply.wait_for_exit(fake, "box", threading.Event()) == 0
    assert len(fake.called("wait")) == 3
    assert all(kw == {"timeout": 60, "condition": "not-running"} for _, kw in fake.called("wait"))

    fake.wait_results = [requests.exceptions.ReadTimeout()]
    fake.find("box")["State"] = {"Running": False, "Status": "exited", "ExitCode": 3}
    assert apply.wait_for_exit(fake, "box", threading.Event()) == 3

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(Cancelled):
        apply.wait_for_exit(fake, "box", cancel)


def test_failed_wipe_raises(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    fake.wait_results = [{"StatusCode": 1}]
    with pytest.raises(apply.ApplyError, match=r"The wipe failed \(exit 1\)"):
        Run(fake, full_plan())()
    assert not fake.called("create_container_from_config")


# ROLLBACK


def rollback_doc(**changes: Any) -> dict[str, Any]:
    return {
        "host_id": 1,
        "mode": "overwrite",
        "run_id": RUN,
        "originals": [{"id": ORIG, "name": "web", "old_name": "web-drydock-old", "running": True}],
        "created": [],
        "networks": [],
        "volumes_created": [],
        "volumes": [],
        "binds": [],
        "wipe_started": False,
        "data_started": False,
        "committed": False,
        "rolled_back": False,
        "leftover": [],
    } | changes


def test_rollback_removes_only_created_containers_and_renames_back(fake: FakeAPI) -> None:
    ours = {p.RESTORE_LABEL: str(RUN)}
    # The original even carries this run's label: it is still never removed.
    fake.add(ORIG, "web-drydock-old", labels=ours)
    fake.add(NEW, "web", labels=ours)
    unrelated = "cafe" + hexid("unrelated")[4:]
    fake.add(unrelated, "unrelated", labels=ours)  # 'cafe' resolves to it by ID prefix
    fake.add(hexid("web2"), "web2", labels=ours)  # held the name; our create got a 409
    fake.add(hexid("lbl"), "lbl")  # took the name, without this run's label
    for name, labels in (("v1", ours), ("v2", ours), ("v3", {})):
        fake.volumes[name] = {"Name": name, "Driver": "local", "Labels": labels}
    fake.add(hexid("user"), "user", mounts=[{"Type": "volume", "Name": "v2"}])
    fake.networks["n1" + "0" * 62] = {"Id": "n1" + "0" * 62, "Name": "n1", "Labels": ours}
    fake.networks["n2" + "0" * 62] = {
        "Id": "n2" + "0" * 62,
        "Name": "n2",
        "Labels": ours,
        "Containers": {hexid("user"): {}},
    }
    doc = rollback_doc(
        created=[
            {"name": "web", "id": NEW, "failed": False},
            {"name": "cafe", "id": None, "failed": False},
            {"name": "web2", "id": None, "failed": True},
            {"name": "lbl", "id": None, "failed": False},
            {"name": "sneaky", "id": ORIG, "failed": False},
        ],
        networks=[{"name": "n1", "id": "n1" + "0" * 62}, {"name": "n2", "id": "n2" + "0" * 62}],
        volumes_created=["v1", "v2", "v3"],
        volumes=["v1"],
        binds=["/srv/app"],
        wipe_started=True,
    )
    log = Recorder()
    result = apply.rollback(fake, doc, log)
    # What a container still uses stays, so the rollback is not complete.
    assert result["rolled_back"] is False and doc["rolled_back"] is False
    assert result["rollback_incomplete"] is True and "rollback_unreachable" not in result
    assert result["leftover"] == ["network n2", "volume v2"]
    assert result["not_renamed"] == [] and result["tags_left"] == []
    assert fake.called("remove_container") == [((NEW,), {"v": False, "force": True})]
    assert unrelated in fake.containers_by_id and ORIG in fake.containers_by_id
    assert not any(args == ("web2",) for args, _ in fake.called("inspect_container"))
    assert fake.called("rename") == [((ORIG, "web"), {})]
    assert fake.find(ORIG)["Name"] == "/web"
    assert not fake.called("start")  # wipe_started: the originals stay stopped
    assert fake.called("remove_network") == [(("n1" + "0" * 62,), {})]
    assert fake.called("remove_volume") == [(("v1",), {"force": False})]
    assert log.lines == [
        "Removed container web.",
        "Renamed web-drydock-old back to web.",
        "Removed network n1.",
        "Kept network n2: a container uses it.",
        "Removed volume v1.",
        "Kept volume v2: a container uses it.",
        "The data in volume v1, bind mount /srv/app may be partial. The original containers "
        "were left stopped.",
    ]

    # Before any data was touched, the running originals start again, secrets known first.
    fake2 = FakeAPI()
    fake2.add(ORIG, "web-drydock-old", env=["PASSWORD=s3cret-value"])
    log = Recorder()
    apply.rollback(fake2, rollback_doc(), log)
    assert fake2.called("rename") == [((ORIG, "web"), {})]
    assert fake2.called("start") == [((ORIG,), {})]
    assert "s3cret-value" in log.secrets
    assert log.lines[-1] == "Started container web again."

    # It never raises, whatever Docker does.
    fake3 = FakeAPI()
    fake3.add(ORIG, "web-drydock-old")
    fake3.failures["rename"] = docker.errors.APIError("conflict")
    fake3.failures["inspect_network"] = requests.exceptions.ConnectionError("gone")
    log = Recorder()
    result = apply.rollback(fake3, rollback_doc(networks=[{"name": "n", "id": None}]), log)
    assert result["rolled_back"] is False and result["rollback_unreachable"] is True
    assert result["not_renamed"] == ["web-drydock-old"] and result["leftover"] == ["network n"]
    assert any(
        line.startswith("Could not rename web-drydock-old back to web") for line in log.lines
    )
    assert any(line.startswith("Could not inspect network n") for line in log.lines)
    assert apply.rollback(fake3, {"garbage": 1}, log)["rolled_back"] is True
    assert apply.rollback(fake3, rollback_doc(created="nonsense"), log)["rolled_back"] is True


def test_rollback_starts_an_original_only_when_it_got_its_name_back(fake: FakeAPI) -> None:
    """The restored container could not be removed and still holds the name: starting the
    original as web-drydock-old would run two containers on the same data."""
    ours = {p.RESTORE_LABEL: str(RUN)}
    fake.add(ORIG, "web-drydock-old")
    fake.add(NEW, "web", labels=ours, running=True)
    fake.failures["remove_container"] = docker.errors.APIError("daemon busy")
    fake.failures["rename"] = docker.errors.APIError("409 Conflict: name in use")
    log = Recorder()
    doc = apply.rollback(fake, rollback_doc(created=[{"name": "web", "id": NEW}]), log)
    assert doc["rolled_back"] is False and doc["rollback_incomplete"] is True
    assert "rollback_unreachable" not in doc  # Docker refused: trying again will not help
    assert doc["leftover"] == ["container web"] and doc["not_renamed"] == ["web-drydock-old"]
    assert not fake.called("start")
    assert log.lines[-1] == (
        "Left container web-drydock-old stopped: it did not get its name web back."
    )


class Unreachable:
    """An APIClient whose every call finds the SSH tunnel or the socket proxy down."""

    def __getattr__(self, name: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            raise requests.exceptions.ConnectionError("Connection refused")

        return call


def test_rollback_is_complete_only_when_everything_was_undone(fake: FakeAPI) -> None:
    ours = {p.RESTORE_LABEL: str(RUN)}
    fake.add(ORIG, "web-drydock-old")
    fake.add(NEW, "web", labels=ours)
    fake.volumes["v1"] = {"Name": "v1", "Driver": "local", "Labels": ours}
    doc = rollback_doc(
        created=[{"name": "web", "id": NEW, "failed": False}], volumes_created=["v1"]
    )

    # Docker cannot be reached: nothing is undone, and the caller is told to try again.
    log = Recorder()
    first = apply.rollback(Unreachable(), doc, log)
    assert first["rolled_back"] is False
    assert first["rollback_incomplete"] is True and first["rollback_unreachable"] is True
    assert first["leftover"] == ["container web", "volume v1"]
    assert first["not_renamed"] == ["web-drydock-old"]
    assert "Left container web-drydock-old stopped: it did not get its name web back." in log.lines

    # Run again on its own result once the host is back: done, and the flags are cleared.
    second = apply.rollback(fake, first, Recorder())
    assert second["rolled_back"] is True
    assert "rollback_incomplete" not in second and "rollback_unreachable" not in second
    assert second["leftover"] == [] and second["not_renamed"] == []
    assert NEW not in fake.containers_by_id and "v1" not in fake.volumes
    assert fake.find(ORIG)["Name"] == "/web" and fake.called("start") == [((ORIG,), {})]

    # An original removed by hand meanwhile did not get its name back either.
    log = Recorder()
    result = apply.rollback(FakeAPI(), rollback_doc(), log)
    assert result["rolled_back"] is False and result["not_renamed"] == ["web-drydock-old"]
    assert "rollback_unreachable" not in result
    assert "Container web-drydock-old no longer exists, so it cannot get web back." in log.lines


def test_only_connection_and_gateway_errors_count_as_unreachable() -> None:
    def api_error(status: int) -> docker.errors.APIError:
        response = requests.Response()
        response.status_code = status
        return docker.errors.APIError("proxy", response=response)

    assert apply.unreachable(requests.exceptions.ConnectionError())
    assert apply.unreachable(requests.exceptions.ReadTimeout())
    assert apply.unreachable(api_error(503)) and apply.unreachable(api_error(502))
    assert not apply.unreachable(api_error(409)) and not apply.unreachable(api_error(500))
    assert not apply.unreachable(docker.errors.NotFound("gone"))
    assert not apply.unreachable(docker.errors.DockerException("odd"))


def test_rollback_without_a_run_id_removes_nothing(fake: FakeAPI) -> None:
    fake.add(NEW, "web", labels={p.RESTORE_LABEL: "None"})
    doc = rollback_doc(run_id=None, originals=[], created=[{"name": "web", "id": NEW}])
    apply.rollback(fake, doc, Recorder())
    assert not fake.called("remove_container")


def test_committed_rollback_only_removes_old_originals(fake: FakeAPI) -> None:
    ours = {p.RESTORE_LABEL: str(RUN)}
    fake.add(ORIG, "web-drydock-old")
    fake.add(ORIG2, "db")  # renamed back by hand: no longer an -drydock-old container
    fake.add(NEW, "web", labels=ours)
    doc = rollback_doc(
        committed=True,
        originals=[
            {"id": ORIG, "name": "web", "old_name": "web-drydock-old", "running": True},
            {"id": ORIG2, "name": "db", "old_name": "db-drydock-old", "running": True},
        ],
        created=[{"name": "web", "id": NEW, "failed": False}],
        volumes_created=["v1"],
        leftover=["web-drydock-old"],
    )
    result = apply.rollback(fake, doc, Recorder())
    assert fake.called("remove_container") == [((ORIG,), {"v": False, "force": True})]
    assert NEW in fake.containers_by_id and ORIG2 in fake.containers_by_id
    assert not fake.called("rename") and not fake.called("start")
    assert not fake.called("inspect_volume")
    assert result["leftover"] == [] and result["rolled_back"] is True

    fake.add(ORIG, "web-drydock-old")
    fake.failures["remove_container"] = docker.errors.APIError("busy")
    result = apply.rollback(fake, doc, Recorder())
    assert result["leftover"] == ["web-drydock-old"]
    assert result["rolled_back"] is False and "rollback_unreachable" not in result
    fake.failures["remove_container"] = requests.exceptions.ConnectionError("tunnel closed")
    result = apply.rollback(fake, doc, Recorder())
    assert result["leftover"] == ["web-drydock-old"] and result["rollback_unreachable"] is True


# TARGET STATE


def test_inspect_target_ignores_id_prefix_matches_and_collects_own_objects(
    fake: FakeAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    own_id, web_id, user_id = hexid("drydock"), hexid("web"), hexid("user")
    unrelated = "cafe" + hexid("unrelated")[4:]
    fake.add(
        web_id,
        "web",
        running=True,
        mounts=[{"Type": "volume", "Name": "webdata", "Driver": "local", "Destination": "/d"}],
    )
    fake.add(unrelated, "unrelated")
    fake.add(
        own_id,
        "drydock",
        running=True,
        Image="sha256:" + hexid("own-image"),
        NetworkSettings={
            "Networks": {
                "drydock_default": {"NetworkID": hexid("own-net")},
                "bridge": {"NetworkID": hexid("bridge")},
            }
        },
        mounts=[
            {"Type": "bind", "Source": "/srv/drydock/key", "Destination": "/run/key"},
            {"Type": "volume", "Name": "drydock_data", "Driver": "local", "Destination": "/data"},
        ],
    )
    fake.find("drydock")["Config"]["Image"] = "drydock:local"
    fake.add(
        user_id,
        "user",
        running=True,
        mounts=[
            {"Type": "bind", "Source": "/srv/shared", "Destination": "/s"},
            {"Type": "volume", "Name": "hostvol", "Driver": "local", "Destination": "/h"},
            {"Type": "volume", "Name": "../evil", "Driver": "local", "Destination": "/e"},
        ],
    )
    fake.volumes |= {
        "data": {"Name": "data", "Driver": "local", "Options": {}},
        "webdata": {"Name": "webdata", "Driver": "local", "Options": None},
        "hostvol": {
            "Name": "hostvol",
            "Driver": "local",
            "Options": {"device": "/srv/hostdir", "o": "bind", "type": "none"},
        },
        "drydock_data": {
            "Name": "drydock_data",
            "Driver": "local",
            "Mountpoint": "/var/lib/docker/volumes/drydock_data/_data",
        },
    }
    fake.networks[hexid("net")] = {"Id": hexid("net"), "Name": "net"}
    fake.networks["abc" + hexid("x")[3:]] = {"Id": "abc" + hexid("x")[3:], "Name": "other"}
    fake.images["nginx:1"] = {"Id": IMAGE_ID}
    fake.images["sha256:" + hexid("own-image")] = {
        "Id": "sha256:" + hexid("own-image"),
        "RepoTags": ["drydock:local", "ghcr.io/example/drydock:1.2"],
    }
    monkeypatch.setattr(inventory, "own_ids", lambda api: frozenset({own_id}))
    lookup = p.Lookup(
        containers=frozenset({"web", "cafe"}),
        volumes=frozenset({"data", "absent"}),
        networks=frozenset({"net", "abc"}),
        images=frozenset({"nginx:1", "missing:1"}),
    )
    target = apply.inspect_target(
        make_env(fake).handle,
        lookup,
        host_id=3,
        host_name="box",
        helper_image=DEFAULT_HELPER_IMAGE,
    )
    assert (target.host_id, target.host_name, target.api_version) == (3, "box", "1.48")
    assert target.arch == "amd64"
    assert set(target.containers) == {"web"}
    assert set(target.volumes) == {"data", "webdata"}
    assert set(target.networks) == {"net"}
    assert target.images == {"nginx:1": IMAGE_ID}
    assert target.volume_users["webdata"] == (p.ContainerUse(web_id, "web", "running"),)
    assert "../evil" not in target.volume_users
    assert set(target.bind_users) == {
        p.BindUse(user_id, "user", "running", "/srv/shared"),
        p.BindUse(user_id, "user", "running", "/srv/hostdir"),
        p.BindUse(own_id, "drydock", "running", "/srv/drydock/key"),
    }
    assert target.own == frozenset({own_id})
    assert target.own_networks == {"drydock_default", hexid("own-net")}
    assert target.own_volumes == {"drydock_data"}
    assert target.own_paths == {
        "/srv/drydock/key",
        "/var/lib/docker/volumes/drydock_data/_data",
        "/var/lib/docker",
    }
    assert {p.repository(r) for r in target.protected_repos} == {
        "drydock",
        "ghcr.io/example/drydock",
        "busybox",
    }
    assert set(fake.names()) <= READ_ONLY_CALLS


def test_inspect_target_reads_an_ambiguous_id_prefix_as_no_such_name(fake: FakeAPI) -> None:
    """Docker tries a name before an ID prefix, so a name that is the prefix of several IDs
    (400) names no container. Any other error still stops the plan."""
    fake.add("a1" + hexid("one")[2:], "one")
    fake.add("a2" + hexid("two")[2:], "two")
    fake.add(hexid("web"), "web")
    lookup = p.Lookup(frozenset({"a", "web"}), frozenset(), frozenset(), frozenset())
    target = apply.inspect_target(
        make_env(fake).handle, lookup, host_id=1, host_name="box", helper_image="busybox"
    )
    assert set(target.containers) == {"web"}
    fake.failures["inspect_container"] = docker.errors.APIError(
        "server error", response=FakeResponse(500)
    )
    with pytest.raises(docker.errors.APIError):
        apply.inspect_target(
            make_env(fake).handle, lookup, host_id=1, host_name="box", helper_image="busybox"
        )


def test_inspect_target_lists_the_members_of_each_project(fake: FakeAPI) -> None:
    project = {"com.docker.compose.project": "app"}
    fake.add(hexid("web"), "app-web-1", labels=project)
    fake.add(hexid("db"), "app-db-1", labels=project)
    fake.add(hexid("old"), "app-db-1-drydock-old", labels=project)
    fake.add(hexid("box"), "drydock-helper-9", labels=project | {helper.HELPER_LABEL: "1"})
    fake.add(hexid("other"), "other-web-1", labels={"com.docker.compose.project": "other"})
    lookup = p.Lookup(
        frozenset(), frozenset(), frozenset(), frozenset(), frozenset({"app", "empty"})
    )
    target = apply.inspect_target(
        make_env(fake).handle, lookup, host_id=1, host_name="box", helper_image="busybox"
    )
    assert target.projects == {"app": ("app-db-1", "app-web-1"), "empty": ()}
    filters = [kw["filters"] for _, kw in fake.called("containers")]
    assert [f for f in filters if f and "label" in f] == [
        {"label": "com.docker.compose.project=app"},
        {"label": "com.docker.compose.project=empty"},
    ]
    assert set(fake.names()) <= READ_ONLY_CALLS


# STACKS

MUTATING_CALLS = {
    "stop",
    "rename",
    "update_container",
    "start",
    "create_container_from_config",
    "remove_container",
    "create_network",
    "create_volume",
    "_put",
    "tag",
    "pull",
    "_post",
}


def mutations(api: FakeAPI) -> list[str]:
    """The calls that change the target, and every helper that is not a never-started,
    read-only probe."""
    changed = [name for name in api.names() if name in MUTATING_CALLS]
    for _, details in api.called("helper"):
        if details["start"] or any(not mount["ReadOnly"] for mount in details["mounts"]):
            changed.append("helper")
    return changed


def stack_step(name: str, *, wait_healthy: tuple[str, ...] = ()) -> p.ContainerStep:
    body = {"Image": "nginx:1.29", "Labels": {}, "HostConfig": {}}
    return p.ContainerStep(name, body, True, None, wait_healthy)


def test_dependents_wait_for_healthy_dependencies(
    fake: FakeAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[tuple[list[str], threading.Event | None]] = []
    outcome = {"healthy": True, "cancel": False}

    def wait_healthy(api, ids, deadline, cancel, log) -> bool:
        api.calls.append(("wait_healthy", (list(ids),), {}))
        waits.append((list(ids), cancel))
        assert deadline > 0
        if outcome["cancel"]:
            cancel.set()
        return outcome["healthy"]

    monkeypatch.setattr(stacks, "wait_healthy", wait_healthy)
    plan = make_plan(
        mode="new-name",
        containers=(
            stack_step("copy-db-1"),
            stack_step("copy-web-1", wait_healthy=("copy-db-1",)),
        ),
    )
    run = Run(fake, plan)
    run()
    db_id, web_id = fake.find("copy-db-1")["Id"], fake.find("copy-web-1")["Id"]
    assert [(n, a) for n, a, _ in fake.calls if n in ("start", "wait_healthy")] == [
        ("start", (db_id,)),
        ("wait_healthy", ([db_id],)),
        ("start", (web_id,)),
    ]
    assert waits[0][1] is run.cancel
    names = [kwargs["name"] for _, kwargs in fake.called("create_container_from_config")]
    assert names == ["copy-db-1", "copy-web-1"]

    # Not healthy in time: it starts anyway.
    fake2 = FakeAPI()
    outcome["healthy"] = False
    Run(fake2, plan)()
    assert len(fake2.called("start")) == 2

    # A cancel during the wait stops the restore before the dependent starts.
    fake3 = FakeAPI()
    outcome["cancel"] = True
    run = Run(fake3, plan)
    with pytest.raises(Cancelled):
        run()
    assert len(fake3.called("start")) == 1
    assert run.journal[-1]["committed"] is False


def test_rollback_starts_originals_in_forward_order(fake: FakeAPI) -> None:
    """The journal lists the originals in stop order (dependents first)."""
    fake.add(ORIG, "web-drydock-old")
    fake.add(ORIG2, "db-drydock-old")
    stopped = [
        {"id": ORIG, "name": "web", "old_name": "web-drydock-old", "running": True},
        {"id": ORIG2, "name": "db", "old_name": "db-drydock-old", "running": True},
    ]
    log = Recorder()
    doc = apply.rollback(fake, rollback_doc(originals=stopped), log)
    assert doc["rolled_back"] is True
    assert [args for args, _ in fake.called("start")] == [(ORIG2,), (ORIG,)]
    assert log.lines[-2:] == ["Started container db again.", "Started container web again."]


def test_journal_records_projects(fake: FakeAPI) -> None:
    fake.add(ORIG, "web", running=True)
    run = Run(fake, dataclasses.replace(config_only_overwrite(), projects=("app", "shop")))
    run()
    assert all(doc["projects"] == ["app", "shop"] for doc in run.journal)
    run = Run(FakeAPI(), make_plan(mode="new-name", containers=(container_step(),)))
    run()
    assert all("projects" not in doc for doc in run.journal)


# COMPOSE FILES

COMPOSE_BYTES = {
    "compose/0/compose.yaml": b"services: {}\n",
    "compose/1/app.env": b"TOKEN=s3cret\n",
}
CREATED_AT = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


def compose_write(directory: str = "/srv/new") -> p.ComposeWrite:
    return p.ComposeWrite(
        directory,
        (
            p.ComposeOut("compose/0/compose.yaml", "compose.yaml", 13),
            p.ComposeOut("compose/1/app.env", "env/app.env", 13),
        ),
    )


def compose_staged(compose: dict[str, bytes] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        manifest=SimpleNamespace(created_at=CREATED_AT),
        compose=COMPOSE_BYTES if compose is None else compose,
    )


def stack_overwrite(**changes: Any) -> p.RestorePlan:
    """An overwrite of web and db with named volumes only, no bind mounts: the usual stack."""
    fields: dict[str, Any] = {
        "volumes": (p.VolumeStep("app_data", "reuse", "local", {}, {}, None),),
        "originals": (original(), p.Original(ORIG2, "db", "db-drydock-old", True, 10)),
        "containers": (container_step(name="db"), container_step()),
        "projects": ("app",),
        "compose": compose_write(),
    }
    return make_plan(**(fields | changes))


def stack_originals(api: FakeAPI) -> None:
    api.add(ORIG, "web", running=True)
    api.add(ORIG2, "db", running=True)


def compose_call(api: FakeAPI) -> tuple[int, str, dict[str, Any]]:
    """The position, box ID and details of the one compose directory helper."""
    ((at, box_id, details),) = [
        (i, args[0], kwargs)
        for i, (name, args, kwargs) in enumerate(api.calls)
        if name == "helper" and apply.COMPOSE_SCRIPT in (kwargs["command"] or [])
    ]
    return at, box_id, details


def test_compose_files_are_written_after_commit_and_verified(fake: FakeAPI) -> None:
    stack_originals(fake)
    run = Run(fake, stack_overwrite(), staged=compose_staged())
    run()

    made, box_id, details = compose_call(fake)
    assert details["command"] == ["sh", "-c", apply.COMPOSE_SCRIPT, "sh", "new"]
    assert details["cap_add"] == ["DAC_OVERRIDE"] == apply.MKDIR_CAPS
    assert details["start"] is False  # only after the put
    parent, source = details["mounts"]
    assert (parent["Target"], parent["Source"], parent["Type"], parent["ReadOnly"]) == (
        "/t",
        "/srv",
        "bind",
        False,
    )
    assert parent["BindOptions"] == {"NonRecursive": True}
    # Anonymous: removed with the helper, and nobody else can reach it.
    assert (source["Target"], source["Source"], source["Type"]) == ("/src", None, "volume")

    # After the commit marker and after both originals were removed.
    names = fake.names()
    removed = [i for i, n in enumerate(names) if n == "remove_container"]
    assert len(removed) == 2 and max(removed) < made
    before = [args[0] for n, args, _ in fake.calls[:made] if n == "journal"]
    assert before[-1]["committed"] is True

    # The only put goes into the helper's own volume, before the helper starts.
    (((url,), kwargs),) = [c for c in fake.called("_put") if box_id in c[0][0]]
    assert url == fake.real._url("/containers/{0}/archive", box_id)
    assert kwargs["params"] == {"path": "/src", "noOverwriteDirNonDir": "true"}
    put = names.index("_put", made)
    assert names.index("start", made) > put
    with tarfile.open(fileobj=io.BytesIO(fake.uploaded)) as outer:
        (wrapper,) = outer.getmembers()
        assert (wrapper.name, wrapper.type, wrapper.mode, wrapper.uid) == (
            "compose.tar",
            tarfile.REGTYPE,
            0o600,
            0,
        )
        inner = outer.extractfile(wrapper).read()  # type: ignore[union-attr]
    with tarfile.open(fileobj=io.BytesIO(inner)) as tar:
        members = tar.getmembers()
        entries = [(i.name, i.type, i.mode, i.uid, i.gid, i.mtime) for i in members]
        data = {i.name: tar.extractfile(i).read() for i in members if i.isfile()}  # type: ignore[union-attr]
    stamp = int(CREATED_AT.timestamp())
    assert entries == [
        ("env", tarfile.DIRTYPE, 0o700, 0, 0, stamp),
        ("compose.yaml", tarfile.REGTYPE, 0o600, 0, 0, stamp),
        ("env/app.env", tarfile.REGTYPE, 0o600, 0, 0, stamp),
    ]
    assert data == {"compose.yaml": b"services: {}\n", "env/app.env": b"TOKEN=s3cret\n"}

    waited = max(i for i, n in enumerate(names) if n == "wait")
    checked = [kw["params"]["path"] for n, _, kw in fake.calls[made:] if n == "head"]
    assert checked == ["/t/new", "/t/new/compose.yaml", "/t/new/env/app.env"]
    assert "head" not in names[made:waited]
    assert run.log.lines[-2:] == [
        "Creating the directory /srv/new.",
        "Wrote 2 compose files to /srv/new.",
    ]
    final = run.journal[-1]
    assert final["committed"] is True and "compose_problem" not in final
    assert final["projects"] == ["app"]
    assert "s3cret" not in json.dumps(run.journal) and "s3cret" not in str(run.log.lines)
    assert "s3cret" not in str(details)


def test_compose_script_writes_only_through_a_checked_new_directory() -> None:
    """The name is an argument, never part of the script; mkdir has no -p; the working
    directory is checked against the parent's entry before tar runs, and tar extracts
    relative to it."""
    script = apply.COMPOSE_SCRIPT
    assert script == (
        'cd /t && mkdir -m 0700 -- "$1" || exit 2; '
        'cd -P -- "$1" && case "$(stat -c %u:%a .)" in 0:700|0:2700) ;; *) false ;; esac'
        ' && [ "$(stat -c %d:%i .)" = "$(stat -c %d:%i "/t/$1")" ]'
        ' && [ "$(stat -c %d:%i ..)" = "$(stat -c %d:%i /t)" ]'
        ' && [ -z "$(ls -A)" ] || exit 3; '
        "exec tar -x -f /src/compose.tar"
    )
    assert (apply.COMPOSE_EXISTS, apply.COMPOSE_MOVED) == (2, 3)


@pytest.mark.parametrize("single", [False, True])
def test_compose_dir_without_binds_is_checked_and_written(fake: FakeAPI, single: bool) -> None:
    stack_originals(fake)
    plan = stack_overwrite()
    if single:
        plan = dataclasses.replace(config_only_overwrite(), compose=compose_write())
    assert not plan.bind_sources and not plan.write_targets
    fake.host["/srv/new"] = ("dir", None)
    run = Run(fake, plan, staged=compose_staged())
    with pytest.raises(apply.ApplyError, match="/srv/new already exists on the host"):
        run()
    probed = [kw["params"]["path"] for _, kw in fake.called("head")]
    assert probed == ["/host/srv", "/host/srv/new"]
    assert mutations(fake) == []
    assert run.log.lines == ["Checking host paths."]

    fake.calls.clear()
    del fake.host["/srv/new"]
    run = Run(fake, plan, staged=compose_staged())
    run()
    first = min(i for i, (n, _, _) in enumerate(fake.calls) if n in MUTATING_CALLS)
    early = [kw["params"]["path"] for n, _, kw in fake.calls[:first] if n == "head"]
    assert "/host/srv/new" in early
    assert run.journal[-1]["committed"] is True
    assert "compose_problem" not in run.journal[-1]
    assert not any("was not checked before the restore" in line for line in run.log.lines)
    assert run.log.lines[-1] == "Wrote 2 compose files to /srv/new."


@pytest.mark.parametrize("kind", ["file", "dir", "link"])
def test_existing_compose_dir_stops_the_restore_before_any_mutation(
    fake: FakeAPI, kind: str
) -> None:
    """Even a dangling symbolic link in its place: mkdir would fail, so nothing starts."""
    stack_originals(fake)
    fake.host["/srv/new"] = (kind, "/srv/gone" if kind == "link" else None)
    run = Run(fake, stack_overwrite(), staged=compose_staged())
    with pytest.raises(apply.ApplyError, match="Choose a new directory: drydock never writes"):
        run()
    assert mutations(fake) == [] and len(run.journal) == 1


def test_compose_parent_must_exist_as_a_directory(fake: FakeAPI) -> None:
    stack_originals(fake)
    plan = stack_overwrite(compose=compose_write("/srv/app/new"))
    with pytest.raises(apply.ApplyError, match="/srv/app does not exist on the host"):
        Run(fake, plan, staged=compose_staged())()
    fake.host["/srv/app"] = ("file", None)
    with pytest.raises(apply.ApplyError, match="/srv/app is not a directory on the host"):
        Run(fake, plan, staged=compose_staged())()
    assert mutations(fake) == []


def test_compose_dir_resolving_into_etc_is_rejected(fake: FakeAPI) -> None:
    stack_originals(fake)
    fake.host |= {"/srv/conf": ("link", "../etc"), "/etc": ("dir", None)}
    run = Run(fake, stack_overwrite(compose=compose_write("/srv/conf/stack")))
    with pytest.raises(apply.ApplyError, match="/srv/conf leads to /etc: Binding /etc is refused"):
        run()
    assert mutations(fake) == [] and len(run.journal) == 1


def test_compose_parent_resolving_to_root_is_rejected(fake: FakeAPI) -> None:
    stack_originals(fake)
    fake.host["/srv/top"] = ("link", "/")
    run = Run(fake, stack_overwrite(compose=compose_write("/srv/top/new")))
    with pytest.raises(apply.ApplyError, match="/srv/top leads to the root directory on the host"):
        run()
    assert mutations(fake) == [] and len(run.journal) == 1
    for _, details in fake.called("helper"):
        assert all(mount["ReadOnly"] for mount in details["mounts"])


def test_compose_live_notes_are_logged(fake: FakeAPI) -> None:
    """A live container mounts a link to /srv, which the plan could not see."""
    stack_originals(fake)
    fake.host["/srv/link"] = ("link", "/srv")
    users = (p.BindUse(hexid("reader"), "reader", "running", "/srv/link"),)
    run = Run(fake, stack_overwrite(live_users=users), staged=compose_staged())
    run()
    assert run.log.lines[:2] == [
        "Checking host paths.",
        "Container reader mounts /srv on the host, so it can read the restored .env files.",
    ]
    assert run.log.lines[-1] == "Wrote 2 compose files to /srv/new."


@pytest.mark.parametrize(
    ("code", "problem"),
    [
        (
            apply.COMPOSE_EXISTS,
            "/srv/new could not be created on the host (it may have appeared during the "
            "restore); the compose files were not written",
        ),
        (
            apply.COMPOSE_MOVED,
            "/srv/new was moved or replaced while drydock created it; the compose files "
            "were not written",
        ),
        (1, "The compose files could not be extracted (exit 1)"),
    ],
)
def test_compose_helper_failure_is_a_compose_problem(
    fake: FakeAPI, code: int, problem: str
) -> None:
    """Exit 3 is the script refusing a directory renamed or replaced by a symbolic link
    between its mkdir and its cd: nothing was extracted, and nothing is checked after."""
    stack_originals(fake)
    fake.wait_results = [{"StatusCode": code}]
    run = Run(fake, stack_overwrite(), staged=compose_staged())
    run()  # returns: the restore is done
    made, _, _ = compose_call(fake)
    assert "head" not in fake.names()[made:]
    assert [kw["params"]["path"] for _, kw in fake.called("_put")] == ["/src"]
    message = (
        f"Could not write the compose files to /srv/new: {problem}. The restore itself is done."
    )
    final = run.journal[-1]
    assert final["compose_problem"] == message and run.log.lines[-1] == message
    assert final["committed"] is True and final["rolled_back"] is False
    assert len(fake.called("remove_container")) == 2  # only the originals


@pytest.mark.parametrize(
    ("setup", "problem"),
    [
        ("put", "disk full"),
        ("staged", "The archive's compose file env/app.env was not staged"),
        ("size", "The archive's compose file env/app.env does not have the size"),
        ("mode", "Docker did not create /srv/new as expected"),
        ("short", "Docker did not write compose.yaml"),
    ],
)
def test_compose_write_failure_never_fails_the_restore(
    fake: FakeAPI, setup: str, problem: str
) -> None:
    stack_originals(fake)
    staged = compose_staged()
    cancel = threading.Event()
    if setup == "put":
        fake.failures["_put"] = docker.errors.APIError("disk full")
    elif setup == "staged":
        staged = compose_staged({"compose/0/compose.yaml": b"services: {}\n"})
    elif setup == "size":
        staged = compose_staged(COMPOSE_BYTES | {"compose/1/app.env": b"TOKEN=longer\n\n"})
    elif setup == "mode":
        fake.hooks["head"] = lambda: fake.box_dirs.update({"/t/new": 0o755})
    else:
        fake.hooks["head"] = lambda: fake.box_sizes.update({"/t/new/compose.yaml": 3})
    run = Run(fake, stack_overwrite(), staged=staged, cancel=cancel)
    run()
    final = run.journal[-1]
    assert final["committed"] is True and final["rolled_back"] is False
    assert final["compose_problem"].startswith("Could not write the compose files to /srv/new: ")
    assert problem in final["compose_problem"]
    assert final["compose_problem"].endswith("The restore itself is done.")
    assert run.log.lines[-1] == final["compose_problem"]
    assert len(fake.called("remove_container")) == 2


def test_cancel_after_the_commit_still_writes_the_compose_files(fake: FakeAPI) -> None:
    """From the commit on cancel is ignored: the mkdir helper may already have made the
    directory, so its exit is awaited and the files go in."""
    stack_originals(fake)
    cancel = threading.Event()
    fake.hooks["remove_container"] = cancel.set
    run = Run(fake, stack_overwrite(), staged=compose_staged(), cancel=cancel)
    run()
    final = run.journal[-1]
    assert final["committed"] is True and "compose_problem" not in final
    assert run.log.lines[-1] == "Wrote 2 compose files to /srv/new."
    _, box_id, _ = compose_call(fake)
    assert [args for args, _ in fake.called("wait")][-1] == (box_id,)
    assert fake.called("_put")


class FullDiskLog(Recorder):
    """A run log that cannot take any more lines once the restore committed."""

    def __init__(self) -> None:
        super().__init__()
        self.full = False

    def __call__(self, line: str) -> None:
        if self.full:
            raise OSError(28, "No space left on device")
        super().__call__(line)

    def redact(self, line: str) -> str:
        return line.replace("web", "[redacted]")


def test_a_full_run_log_after_the_commit_never_fails_the_restore(
    fake: FakeAPI, caplog: pytest.LogCaptureFixture
) -> None:
    stack_originals(fake)
    fake.failures["remove_container"] = docker.errors.APIError("busy")
    run = Run(fake, stack_overwrite(), staged=compose_staged())
    run.log = FullDiskLog()

    def full_once_committed(doc: dict) -> None:
        run.journal.append(doc)
        run.log.full = run.log.full or doc["committed"]

    run.record = full_once_committed  # type: ignore[method-assign]
    run()  # returns: from the commit on nothing raises
    final = run.journal[-1]
    assert final["committed"] is True and "compose_problem" not in final
    assert len(final["leftover"]) == 1
    assert len(fake.called("remove_container")) == 2
    assert compose_call(fake) and fake.box_sizes["/t/new/env/app.env"] == 13
    lost = [r.getMessage() for r in caplog.records if r.name == "drydock.restore.apply"]
    assert any("[redacted]-drydock-old" in line and "No space left" in line for line in lost)
    assert any("Could not remove" in line for line in lost)
    assert any("Wrote 2 compose files to /srv/new." in line for line in lost)
    assert not any("web" in line for line in lost)


def test_compose_dir_mounted_through_a_link_is_refused_before_any_mutation(
    fake: FakeAPI,
) -> None:
    """The restored web binds /srv/link, a symbolic link to the compose directory's parent:
    every service would see the .env files, so nothing starts."""
    stack_originals(fake)
    fake.host |= {"/srv/link": ("link", "/srv/shared"), "/srv/shared": ("dir", None)}
    body = {"Image": "nginx:1.29", "HostConfig": {"Binds": ["/srv/link:/conf"]}}
    plan = stack_overwrite(
        containers=(container_step(name="db"), container_step(body=body)),
        bind_sources=("/srv/link",),
        compose=compose_write("/srv/shared/new"),
    )
    run = Run(fake, plan, staged=compose_staged())
    with pytest.raises(
        apply.ApplyError, match="The compose directory /srv/shared/new is mounted by container web"
    ):
        run()
    assert mutations(fake) == [] and len(run.journal) == 1


def test_compose_dir_may_inherit_its_parents_setgid_bit(fake: FakeAPI) -> None:
    """mkdir gives a new directory the setgid bit of its parent whatever -m says."""
    stack_originals(fake)
    setgid = 1 << 22  # Go's os.ModeSetgid
    fake.hooks["head"] = lambda: fake.box_dirs.update({"/t/new": setgid | 0o700})
    run = Run(fake, stack_overwrite(), staged=compose_staged())
    run()
    assert "compose_problem" not in run.journal[-1]
    assert run.log.lines[-1] == "Wrote 2 compose files to /srv/new."
