"""Stacks: depends_on parsing, start order, discovery, health wait, manifest fields.

Pure: the Docker API is faked. The inspect documents are trimmed to the keys
engine.stacks reads.
"""

import hashlib
import itertools
import threading
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import docker.errors
import pydantic
import pytest

from drydock.archive import manifest as m
from drydock.engine import capture, stacks
from drydock.engine.stacks import Dependency
from drydock.hosts import helper
from drydock.restore import plan as restore_plan

PROJECT = "app"
INSTANCE = "instance-1"


def hexid(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def info(
    name: str,
    *,
    service: str | None = None,
    depends_on: str | None = None,
    number: str = "1",
    healthcheck: list[str] | None = None,
    host: dict[str, Any] | None = None,
    cid: str | None = None,
) -> dict[str, Any]:
    labels = {"com.docker.compose.project": PROJECT, "com.docker.compose.container-number": number}
    if service is not None:
        labels["com.docker.compose.service"] = service
    if depends_on is not None:
        labels[stacks.DEPENDS_ON_LABEL] = depends_on
    config: dict[str, Any] = {"Labels": labels}
    if healthcheck is not None:
        config["Healthcheck"] = {"Test": healthcheck}
    return {
        "Id": cid or hexid(name),
        "Name": "/" + name,
        "Config": config,
        "HostConfig": {"NetworkMode": "app_default"} | (host or {}),
    }


def service_info(service: str, **kwargs: Any) -> dict[str, Any]:
    return info(f"app-{service}-{kwargs.get('number', '1')}", service=service, **kwargs)


def names(members: list[stacks.Member]) -> list[str]:
    return [member.name for member in members]


# DEPENDS_ON


def test_parse_depends_on_formats() -> None:
    assert stacks.parse_depends_on("db:service_healthy:false,redis:service_started:true") == [
        Dependency("db", "service_healthy"),
        Dependency("redis", "service_started"),
    ]
    assert stacks.parse_depends_on("db,redis") == [Dependency("db", ""), Dependency("redis", "")]
    assert stacks.parse_depends_on("db:weird") == [Dependency("db", "")]
    assert stacks.parse_depends_on("db:service_completed_successfully") == [
        Dependency("db", "service_completed_successfully")
    ]
    assert stacks.parse_depends_on("  ,../x, db ") == [Dependency("db", "")]
    for value in (None, 123, "", b"db", ["db"]):
        assert stacks.parse_depends_on(value) == []
    assert stacks.parse_depends_on("db:service_healthy,db:service_started,db") == [
        Dependency("db", "service_healthy")
    ]
    many = ",".join(f"s{n}:service_started:false" for n in range(1000))
    parsed = stacks.parse_depends_on(many)
    assert len(parsed) == stacks.MAX_DEPENDENCIES
    assert parsed[0] == Dependency("s0", "service_started")
    assert parsed[-1].service == f"s{stacks.MAX_DEPENDENCIES - 1}"


# ORDER


def test_order_follows_depends_on_and_container_modes() -> None:
    db = service_info("db", healthcheck=["CMD-SHELL", "pg_isready"])
    redis = service_info("redis")
    app = service_info("app", depends_on="db:service_healthy:false,redis:service_started:false")
    sidecar = service_info("sidecar", host={"NetworkMode": f"container:{app['Id']}"})
    worker = service_info("worker", host={"VolumesFrom": ["app-db-1:ro"]})
    legacy = service_info("legacy", host={"Links": ["/app-redis-1:/app-legacy-1/cache"]})
    infos = [sidecar, legacy, app, worker, redis, db]

    members = stacks.order(infos)
    position = {member.name: n for n, member in enumerate(members)}
    assert position["app-db-1"] < position["app-app-1"]
    assert position["app-redis-1"] < position["app-app-1"]
    assert position["app-app-1"] < position["app-sidecar-1"]
    assert position["app-db-1"] < position["app-worker-1"]
    assert position["app-redis-1"] < position["app-legacy-1"]

    by_name = {member.name: member for member in members}
    assert by_name["app-app-1"].after == tuple(sorted((db["Id"], redis["Id"])))
    assert by_name["app-app-1"].healthy == (db["Id"],)
    assert by_name["app-app-1"].service == "app"
    assert by_name["app-sidecar-1"].after == (app["Id"],)
    assert by_name["app-worker-1"].after == (db["Id"],)
    assert by_name["app-legacy-1"].after == (redis["Id"],)
    assert by_name["app-db-1"].after == () and by_name["app-db-1"].healthy == ()

    for shuffled in itertools.permutations(infos):
        assert stacks.order(shuffled) == members


def test_healthy_needs_a_healthcheck() -> None:
    for healthcheck in (None, ["NONE"], []):
        db = service_info("db", healthcheck=healthcheck)
        app = service_info("app", depends_on="db:service_healthy:false")
        members = {member.name: member for member in stacks.order([app, db])}
        assert members["app-app-1"].after == (db["Id"],)
        assert members["app-app-1"].healthy == ()
    db = service_info("db", healthcheck=["CMD", "true"])
    app = service_info("app", depends_on="db:service_started:false")
    members = {member.name: member for member in stacks.order([app, db])}
    assert members["app-app-1"].healthy == ()


def test_scaled_service_edges_cover_every_replica() -> None:
    db1 = service_info("db", number="1", healthcheck=["CMD", "true"])
    db2 = service_info("db", number="2", healthcheck=["CMD", "true"])
    web = service_info("web", depends_on="db:service_healthy:false")
    members = stacks.order([web, db2, db1])
    assert names(members) == ["app-db-1", "app-db-2", "app-web-1"]
    assert members[2].after == tuple(sorted((db1["Id"], db2["Id"])))
    assert members[2].healthy == members[2].after

    # Numbers sort as numbers, not text.
    db10 = service_info("db", number="10")
    db9 = service_info("db", number="9")
    assert names(stacks.order([db10, db9])) == ["app-db-9", "app-db-10"]


def test_cycles_are_rejected() -> None:
    a = service_info("a", depends_on="b")
    b = service_info("b")
    b["HostConfig"]["NetworkMode"] = f"container:{a['Id']}"
    c = service_info("c")
    with pytest.raises(stacks.StackError) as caught:
        stacks.order([a, b, c])
    message = str(caught.value)
    assert message == "The containers app-a-1, app-b-1 depend on each other in a cycle."
    assert a["Id"][:12] not in message and b["Id"][:12] not in message

    # Members that only depend on the cycle are not named; members between two cycles are.
    d = service_info("d", depends_on="a")
    e = service_info("e", depends_on="d")
    with pytest.raises(stacks.StackError) as caught:
        stacks.order([a, b, c, d, e])
    assert str(caught.value) == "The containers app-a-1, app-b-1 depend on each other in a cycle."
    f = service_info("f", depends_on="g,h")
    g = service_info("g", depends_on="f")
    h = service_info("h", depends_on="b")
    with pytest.raises(stacks.StackError) as caught:
        stacks.order([a, b, c, d, e, f, g, h])
    assert str(caught.value) == (
        "The containers app-a-1, app-b-1, app-f-1, app-g-1, app-h-1 depend on each other"
        " in a cycle."
    )

    # A long cycle names a bounded number of members.
    ring = [service_info(f"r{n:02}", depends_on=f"r{(n + 1) % 30:02}") for n in range(30)]
    with pytest.raises(stacks.StackError) as caught:
        stacks.order(ring)
    shown = ", ".join(f"app-r{n:02}-1" for n in range(stacks.MAX_CYCLE_NAMES))
    assert str(caught.value) == (
        f"The containers {shown} and 20 more depend on each other in a cycle."
    )


def test_order_bounds_the_work_on_crafted_documents() -> None:
    # Every member depends on every other: edges grow with the square of the count.
    crowd = [info(f"x{n}", service="x", depends_on="x") for n in range(3000)]
    started = time.monotonic()
    with pytest.raises(stacks.StackError) as caught:
        stacks.order(crowd)
    assert str(caught.value) == "The stack has too many dependencies to order."
    assert time.monotonic() - started < 5

    # References read from one document are capped, wherever they appear.
    peers = [service_info(f"p{n}") for n in range(400)]
    refs = [f"app-p{n}-1" for n in range(400)]
    hub = service_info("hub", host={"VolumesFrom": refs[:200], "Links": [None] * 10})
    hub["NetworkSettings"] = {"Networks": {"app_default": {"Links": refs[200:]}}}
    members = {member.name: member for member in stacks.order([*peers, hub])}
    assert len(stacks.container_refs(hub)) == stacks.MAX_REFS
    assert len(members["app-hub-1"].after) == stacks.MAX_REFS


def test_refs_outside_the_stack_and_short_prefixes_are_ignored() -> None:
    db = service_info("db")
    outside = service_info("outside", host={"NetworkMode": f"container:{hexid('other')}"})
    short = service_info("short", host={"IpcMode": f"container:{db['Id'][:8]}"})
    prefix = service_info("prefix", host={"PidMode": f"container:{db['Id'][:12]}"})
    named = service_info("named", host={"VolumesFrom": ["not-a-member", "app-db-1:rw"]})
    members = {member.name: member for member in stacks.order([db, outside, short, prefix, named])}
    assert members["app-outside-1"].after == ()
    assert members["app-short-1"].after == ()
    assert members["app-prefix-1"].after == (db["Id"],)
    assert members["app-named-1"].after == (db["Id"],)

    # A prefix that matches two members is never resolved.
    shared = "abcdef012345"
    one = service_info("one", cid=shared + hexid("one")[12:])
    two = service_info("two", cid=shared + hexid("two")[12:])
    user = service_info("user", host={"NetworkMode": f"container:{shared}"})
    members = {member.name: member for member in stacks.order([one, two, user])}
    assert members["app-user-1"].after == ()

    # A self reference gives no edge.
    me = service_info("me", depends_on="me")
    me["HostConfig"]["VolumesFrom"] = [me["Id"]]
    assert stacks.order([me])[0].after == ()


def test_odd_archived_documents_do_not_raise() -> None:
    odd = {"Id": hexid("odd"), "Name": "/odd", "Config": None, "HostConfig": "x"}
    odd2 = {
        "Id": hexid("odd2"),
        "Name": "/odd2",
        "Config": {"Labels": ["x"], "Healthcheck": "x"},
        "HostConfig": {"NetworkMode": 5, "VolumesFrom": "x", "Links": [None, 3]},
    }
    odd3 = service_info("odd3", depends_on="odd:service_healthy", number="99999999999999999")
    assert names(stacks.order([odd, odd2, odd3])) == ["odd", "odd2", "app-odd3-99999999999999999"]


def test_label_less_stack_is_unordered_but_keeps_other_edges() -> None:
    # On a project network Docker reports `links:` in the endpoint, not HostConfig.Links.
    alpha = service_info("alpha", host={"Links": None})
    alpha["NetworkSettings"] = {
        "Networks": {
            "app_default": {"Links": ["app-gamma-1:g", 7], "Aliases": ["alpha"]},
            "odd": None,
        }
    }
    beta = service_info("beta", host={"NetworkMode": f"container:{alpha['Id']}"})
    gamma = service_info("gamma")
    delta = service_info("delta")
    infos = [alpha, beta, gamma, delta]
    assert stacks.unordered(infos)
    assert names(stacks.order(infos)) == ["app-delta-1", "app-gamma-1", "app-alpha-1", "app-beta-1"]
    for odd in (None, "x", {"Networks": "x"}, {"Networks": {"n": {"Links": "x"}}}):
        assert stacks.container_refs({"Id": hexid("odd"), "NetworkSettings": odd}) == []
    assert not stacks.unordered([alpha])
    assert not stacks.unordered([])
    assert not stacks.unordered([alpha, service_info("epsilon", depends_on="")])


def test_project_re_follows_compose() -> None:
    for good in ("a", "0", "a_b-c", "a" * 63):
        assert stacks.PROJECT_RE.fullmatch(good), good
    for bad in ("", "A", "-a", "_a", "a.b", "a" * 64, "a\n", "é"):
        assert not stacks.PROJECT_RE.fullmatch(bad), bad


# DISCOVERY


class FakeContainers:
    def __init__(self, summaries: list[dict[str, Any]]) -> None:
        self.summaries = summaries
        self.calls: list[dict[str, Any]] = []

    def containers(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append(kwargs)
        return self.summaries


def summary(name: str, labels: dict[str, str]) -> dict[str, Any]:
    return {"Id": hexid(name), "Names": ["/" + name], "Labels": labels}


def test_discover_skips_oneoff_helpers_and_renamed_originals() -> None:
    base = {"com.docker.compose.project": PROJECT}
    summaries = [
        summary("app-web-1", base | {stacks.ONEOFF_LABEL: "False"}),
        summary("app-run-1", base | {stacks.ONEOFF_LABEL: "True"}),
        summary("helper", base | helper.helper_labels(INSTANCE)),
        summary("app-web-1-drydock-old", base),
        # A legacy link alias may sort before the container's own name.
        {
            "Id": hexid("app-db-1-drydock-old"),
            "Names": ["/app-app-1/db", "/app-db-1-drydock-old"],
            "Labels": base,
        },
        summary("bypass", {"com.docker.compose.project": "app2"}),
        summary("unlabelled", {}),
        summary("app-db-1", base | {"drydock.restore.run": "r1"}),
        summary("other-helper", base | helper.helper_labels("instance-2")),
    ]
    api = FakeContainers(summaries)
    found = stacks.discover(api, PROJECT, INSTANCE)
    assert found == sorted([hexid("app-web-1"), hexid("app-db-1"), hexid("other-helper")])
    assert api.calls == [{"all": True, "filters": {"label": "com.docker.compose.project=app"}}]


def test_old_suffix_matches_the_restore_planner() -> None:
    assert stacks.OLD_SUFFIX == restore_plan.OLD_SUFFIX


# HEALTH


class FakeHealth:
    def __init__(self, states: dict[str, list[Any]]) -> None:
        self.states = states
        self.calls: list[str] = []

    def inspect_container(self, cid: str) -> dict[str, Any]:
        self.calls.append(cid)
        queue = self.states[cid]
        state = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(state, Exception):
            raise state
        return {"Id": cid, "Name": "/" + cid, "State": state}


def health(status: str, running: bool = True) -> dict[str, Any]:
    return {"Running": running, "Health": {"Status": status}}


def test_wait_healthy_waits_until_healthy_and_gives_up_at_the_deadline(monkeypatch) -> None:
    monkeypatch.setattr(stacks, "HEALTH_POLL", 0.01)
    future = time.monotonic() + 30

    lines: list[str] = []
    api = FakeHealth({"db": [health("starting"), health("starting"), health("healthy")]})
    assert stacks.wait_healthy(api, ["db"], future, None, lines.append)
    assert lines == ["Waiting for container db to be healthy."]
    assert api.calls == ["db", "db", "db"]

    lines = []
    cancel = threading.Event()
    api = FakeHealth({"db": [health("starting")]})
    assert not stacks.wait_healthy(api, ["db"], time.monotonic() - 1, cancel, lines.append)
    assert lines == ["Container db is not healthy after waiting; starting the next one anyway."]

    lines = []
    api = FakeHealth({"db": [health("unhealthy")]})
    assert not stacks.wait_healthy(api, ["db"], time.monotonic() + 0.05, cancel, lines.append)
    assert lines == [
        "Waiting for container db to be healthy.",
        "Container db is not healthy after waiting; starting the next one anyway.",
    ]

    lines = []
    api = FakeHealth(
        {
            "stopped": [health("starting", running=False)],
            "plain": [{"Running": True}],
            "ok": [health("healthy")],
        }
    )
    assert stacks.wait_healthy(api, ["stopped", "plain", "ok"], future, None, lines.append)
    assert lines == []
    assert api.calls == ["stopped", "plain", "ok"]

    lines = []
    cancel.set()
    api = FakeHealth({"db": [health("starting")]})
    assert not stacks.wait_healthy(api, ["db"], future, cancel, lines.append)
    assert api.calls == [] and lines == []

    lines = []
    gone = "f" * 64
    api = FakeHealth({gone: [docker.errors.NotFound("gone")], "ok": [health("healthy")]})
    assert not stacks.wait_healthy(api, [gone, "ok"], future, None, lines.append)
    assert lines == ["Could not check the health of container ffffffffffff; starting anyway."]
    assert api.calls == [gone, "ok"]


def test_wait_healthy_stops_waiting_once_cancelled() -> None:
    cancel = threading.Event()
    api = FakeHealth({"db": [health("starting")]})
    timer = threading.Timer(0.05, cancel.set)
    timer.start()
    started = time.monotonic()
    try:
        assert not stacks.wait_healthy(api, ["db"], started + 30, cancel, lambda _: None)
    finally:
        timer.cancel()
    assert time.monotonic() - started < 5


# MANIFEST


def job_info(**fields: Any) -> dict[str, Any]:
    return {
        "uuid": "2f1c3c1e-0000-4000-8000-000000000000",
        "name": "nightly",
        "scope": "all",
        "consistency_mode": "stop",
        "images_reference_only_if_pullable": False,
    } | fields


def test_manifest_accepts_every_mode_and_old_archives() -> None:
    for mode in ("stop", "pause", "live"):
        assert m.JobInfo.model_validate(job_info(consistency_mode=mode)).consistency_mode == mode
    with pytest.raises(pydantic.ValidationError):
        m.JobInfo.model_validate(job_info(consistency_mode="freeze"))
    with pytest.raises(pydantic.ValidationError):
        m.JobInfo.model_validate(job_info(target_type="swarm"))

    old = {
        "schema_version": 1,
        "instance_id": INSTANCE,
        "drydock_version": "0.1.0",
        "created_at": "2026-01-01T00:00:00Z",
        "source": {
            "host_name": "local",
            "arch": "x86_64",
            "os": "linux",
            "api_version": "1.47",
            "engine_version": "27.0.0",
        },
        "job": job_info(),
        "containers": [],
        "members": [],
    }
    manifest = m.Manifest.model_validate(old)
    assert manifest.job.target_type == "container"
    assert manifest.job.project is None
    stack = m.JobInfo.model_validate(job_info(target_type="stack", project="app"))
    assert (stack.target_type, stack.project) == ("stack", "app")


def test_capture_job_fields_reach_the_manifest() -> None:
    job = capture.CaptureJob(
        uuid="2f1c3c1e-0000-4000-8000-000000000000",
        name="stack",
        scope="config",
        consistency_mode="pause",
        target_type="stack",
        project="app",
    )
    handle = SimpleNamespace(arch="x86_64", os="linux", api_version="1.47", engine_version="27")
    env = SimpleNamespace(handle=handle, host_name="local", instance_id=INSTANCE)
    manifest = capture.build_manifest(
        env,  # type: ignore[arg-type]
        job,
        capture.Plan(),
        [],
        {},
        datetime.now(UTC),
    )
    assert manifest.job.target_type == "stack"
    assert manifest.job.project == "app"
    assert manifest.job.consistency_mode == "pause"
    parsed = m.Manifest.model_validate_json(manifest.to_json())
    assert parsed.job == manifest.job

    default = capture.CaptureJob(uuid=job.uuid, name="one", scope="config")
    manifest = capture.build_manifest(
        env,  # type: ignore[arg-type]
        default,
        capture.Plan(),
        [],
        {},
        datetime.now(UTC),
    )
    assert (manifest.job.target_type, manifest.job.project) == ("container", None)
    assert manifest.job.consistency_mode == "stop"
