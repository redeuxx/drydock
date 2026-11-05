"""Planning an update and judging the new containers, without a daemon (the daemon side,
with a local registry: test_updates_docker.py), and the containers page's Update."""

import threading
from datetime import UTC, datetime
from typing import Any

import docker.errors
import pytest
import requests

from drydock.hosts.helper import helper_labels
from drydock.restore.apply import ApplyError
from drydock.updates import apply as update_apply
from drydock.updates.apply import UpdateError, plan_update, settled
from drydock.updates.check import HostChecks, Verdict
from tests.conftest import Browser, add_user
from tests.test_status import a_host_with_containers

pytestmark = pytest.mark.anyio

OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64
WEB = "a" * 64


def inspect(cid: str, image: str = "nginx:1.27", **extra: Any) -> dict[str, Any]:
    config = {"Image": image, "Labels": extra.pop("labels", {}), "Cmd": ["nginx"]}
    return {
        "Id": cid,
        "Name": f"/c{cid[:4]}",
        "Image": "sha256:" + cid[:1] * 64,
        "Config": config,
        "HostConfig": {"Binds": ["data:/data", "/srv/conf:/etc/x:ro"]},
        "Mounts": [{"Type": "volume", "Name": "data", "Destination": "/data"}],
        "NetworkSettings": {"Networks": {"bridge": {}}},
        "State": {"Running": True, "Status": "running"},
    } | extra


class Api:
    def __init__(self, boxes: dict[str, dict[str, Any]], latest: str = NEW) -> None:
        self.boxes = boxes
        self.latest = latest

    def containers(self, all: bool) -> list[dict[str, Any]]:
        return [
            {"Id": cid, "Names": [info["Name"]], "HostConfig": info.get("HostConfig") or {}}
            for cid, info in self.boxes.items()
        ]

    def inspect_container(self, cid: str) -> dict[str, Any]:
        if cid not in self.boxes:
            raise docker.errors.NotFound("gone")
        return self.boxes[cid]

    def inspect_image(self, image_id: str) -> dict[str, Any]:
        return {"RepoDigests": [f"nginx@{OLD}"]}

    def _url(self, path: str, *args: str) -> str:
        return path.format(*args)

    def _get(self, url: str, timeout: float) -> str:
        if self.latest == "fail":
            raise requests.ConnectionError("x")
        return url

    def _result(self, response: str, json: bool) -> dict[str, Any]:
        return {"Descriptor": {"digest": self.latest}}


def test_the_plan_pulls_by_digest_and_makes_the_container_again() -> None:
    api = Api({WEB: inspect(WEB, labels={"com.docker.compose.project": "app"})})
    planned = plan_update(api, 3, [WEB], frozenset(), "1.47")
    plan = planned.plan
    assert plan is not None and plan.recreate and plan.mode == "overwrite"
    (image,) = plan.images
    assert (image.action, image.pull, image.refs) == ("pull", f"nginx@{NEW}", ("nginx:1.27",))
    (original,) = plan.originals
    assert (original.name, original.old_name, original.stop_timeout) == (
        "caaaa",
        "caaaa-drydock-old",
        10,
    )
    (step,) = plan.containers
    assert step.body["Image"] == "nginx:1.27" and step.image_entry is None, "the tag, not an ID"
    assert step.body["HostConfig"]["Binds"] == ["data:/data", "/srv/conf:/etc/x:ro"]
    assert step.start and plan.projects == ("app",)
    assert set(plan.lock_keys) == {
        WEB,
        "name:3:container:caaaa",
        "name:3:project:app",
        "name:3:image:nginx:1.27",
    }
    assert planned.changes == (("caaaa", OLD, NEW),)
    assert plan.bind_sources == () and plan.data == () and plan.wipes == ()


def test_what_is_left_alone_and_what_is_refused() -> None:
    pinned, current, helper, own = "b" * 64, "c" * 64, "d" * 64, "e" * 64
    api = Api(
        {
            pinned: inspect(pinned, image=f"nginx@{OLD}"),
            current: inspect(current),
            helper: inspect(helper, labels=helper_labels("x")),
            own: inspect(own),
        },
        latest=OLD,
    )
    planned = plan_update(api, 1, [pinned, current], frozenset(), "1.47")
    assert planned.plan is None
    assert planned.notes == (
        "cbbbb: pinned by digest or image ID, so not updated.",
        "ccccc: already runs the newest nginx:1.27.",
    )
    for cid, message in [
        (own, "drydock does not update itself"),
        (helper, "helper containers are left to drydock"),
        ("f" * 64, "no longer exists"),
    ]:
        with pytest.raises(UpdateError, match=message):
            plan_update(api, 1, [cid], frozenset({own}), "1.47")
    with pytest.raises(UpdateError, match="registry lookup failed"):
        plan_update(Api({WEB: inspect(WEB)}, latest="fail"), 1, [WEB], frozenset(), "1.47")


class States:
    """inspect_container answers from a list of states, the last one repeating."""

    def __init__(self, states: list[dict[str, Any]], health: bool = False) -> None:
        self.states = states
        self.health = health

    def inspect_container(self, cid: str) -> dict[str, Any]:
        state = self.states.pop(0) if len(self.states) > 1 else self.states[0]
        test = ["CMD", "true"] if self.health else []
        return {
            "Name": "/web",
            "Config": {"Healthcheck": {"Test": test}},
            "State": state,
            "RestartCount": state.get("restarts", 0),
        }


def run(api: Any, **kwargs: Any) -> None:
    settled(api, [WEB], threading.Event(), lambda line: None, **kwargs)


def test_a_container_without_a_healthcheck_must_keep_running() -> None:
    up = {"Running": True}
    run(States([up]), settle=0.3)
    with pytest.raises(ApplyError, match="stopped after the update"):
        run(States([up, up, {"Running": False}]), settle=5)
    with pytest.raises(ApplyError, match="restarted after the update"):
        run(States([up, up, {"Running": True, "restarts": 1}]), settle=5)


def test_a_container_with_a_healthcheck_must_become_healthy(monkeypatch) -> None:
    monkeypatch.setattr(update_apply, "POLL", 0.01)
    starting = {"Running": True, "Health": {"Status": "starting"}}
    run(States([starting, starting, {"Running": True, "Health": {"Status": "healthy"}}], True))
    with pytest.raises(ApplyError, match="unhealthy"):
        run(States([starting, {"Running": True, "Health": {"Status": "unhealthy"}}], True))
    with pytest.raises(ApplyError, match="not healthy in time"):
        run(States([starting], True), health_wait=0.05)


# THE CONTAINERS PAGE


async def test_update_is_for_operators_audited_and_opens_its_run(
    admin: Browser, monkeypatch
) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    admin.app.state.updates._results[host_id] = HostChecks(
        datetime.now(UTC), {WEB: Verdict("update", "newer", "nginx:1.27", NEW)}
    )
    submitted: list[tuple] = []

    async def submit_update(host, ids, by, label) -> int:
        submitted.append((host, ids, by, label))
        return 77

    monkeypatch.setattr(admin.app.state.dispatcher, "submit_update", submit_update)
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert 'commandfor="ctr-1-update"' in page or "-update" in page
    assert f'name="container" value="{WEB}"' in page and "sha256:222222222222<" in page
    form = {"host": str(host_id), "container": WEB}
    assert (await admin.post("/containers/update", form, csrf=False)).status_code == 403
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    assert (await admin.post("/containers/update", form)).status_code == 403
    await admin.login("admin")
    done = await admin.post("/containers/update", form)
    assert done.status_code == 303 and done.headers["location"] == "/runs/77"
    assert submitted == [(host_id, [WEB], "admin", "web")]
    assert admin.sql(
        "SELECT target, outcome, details FROM audit_events WHERE action = 'container.update'"
    ) == [("container:web", "success", '{"host": "rigel", "run_id": 77}')]
    assert (await admin.post("/containers/update", form | {"container": "../x"})).status_code == 422


def test_what_the_old_image_set_is_left_to_the_new_one() -> None:
    image = {
        "Config": {
            "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27.1"],
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Entrypoint": ["/docker-entrypoint.sh"],
            "Labels": {"org.opencontainers.image.version": "1.27.1"},
            "ExposedPorts": {"80/tcp": {}},
        }
    }
    body = {
        "Image": "nginx:1.27",
        "Env": ["PATH=/usr/bin", "NGINX_VERSION=1.27.1", "SECRET=x"],
        "Cmd": ["nginx", "-g", "daemon off;"],
        "Entrypoint": ["/my-entrypoint.sh"],
        "Labels": {"org.opencontainers.image.version": "1.27.1", "com.docker.compose.project": "a"},
        "ExposedPorts": {"80/tcp": {}, "9000/tcp": {}},
        "HostConfig": {"Binds": []},
    }
    out = update_apply.without_image_defaults(body, image)
    assert out["Env"] == ["SECRET=x"] and "Cmd" not in out
    assert out["Entrypoint"] == ["/my-entrypoint.sh"], "set by the container: kept"
    assert out["Labels"] == {"com.docker.compose.project": "a"}
    assert out["ExposedPorts"] == {"9000/tcp": {}}
    assert out["Image"] == "nginx:1.27" and out["HostConfig"] == {"Binds": []}


def test_an_image_built_on_the_host_is_never_updated_from_a_registry() -> None:
    class Local(Api):
        def inspect_image(self, ref: str) -> dict[str, Any]:
            return {"Id": "sha256:" + "a" * 64, "RepoDigests": []}

    planned = plan_update(Local({WEB: inspect(WEB)}), 1, [WEB], frozenset(), "1.47")
    assert planned.plan is None
    assert planned.notes == ("caaaa: built on the host (no registry digest), so not updated.",)


def test_a_stack_member_waits_for_its_updated_healthy_dependencies() -> None:
    db, app, side = "d" * 64, "e" * 64, "f" * 64
    api = Api({db: inspect(db), app: inspect(app), side: inspect(side, image=f"x@{OLD}")})
    planned = plan_update(
        api, 1, [db, side, app], frozenset(), "1.47", {app: (db, side), side: (db,)}
    )
    plan = planned.plan
    assert plan is not None
    assert [s.name for s in plan.containers] == ["cdddd", "ceeee"], "the pinned one stays"
    assert plan.containers[1].wait_healthy == ("cdddd",), "only what is made again is waited for"
    assert [o.name for o in plan.originals] == ["ceeee", "cdddd"], "dependents stop first"
    assert len(plan.images) == 1, "one pull for one reference"


async def test_stack_update_is_for_operators_audited_and_opens_its_run(
    admin: Browser, monkeypatch
) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    admin.app.state.updates._results[host_id] = HostChecks(
        datetime.now(UTC), {"b" * 64: Verdict("update", "newer", "postgres:17", NEW)}
    )
    submitted: list[tuple] = []

    async def submit_update(host, ids, by, label, *, project=None) -> int:
        submitted.append((host, ids, by, label, project))
        return 78

    monkeypatch.setattr(admin.app.state.dispatcher, "submit_update", submit_update)
    page = (await admin.get(f"/containers?host={host_id}&stack=app")).text
    assert "Update stack app" in page and "1 of its containers has a newer image." in page
    assert "Update stack" not in (await admin.get(f"/containers?host={host_id}")).text
    form = {"host": str(host_id), "stack": "app"}
    assert (await admin.post("/containers/update-stack", form, csrf=False)).status_code == 403
    assert (
        await admin.post("/containers/update-stack", form | {"stack": "nope"})
    ).status_code == 404
    done = await admin.post("/containers/update-stack", form)
    assert done.status_code == 303 and done.headers["location"] == "/runs/78"
    assert submitted == [(host_id, [], "admin", "stack app", "app")]
    assert admin.sql("SELECT target, outcome FROM audit_events WHERE action = 'stack.update'") == [
        ("stack:app", "success")
    ]


def test_containers_that_share_a_network_are_made_again_together() -> None:
    vpn, client, other = "1" * 64, "2" * 64, "3" * 64
    joined = {"NetworkMode": f"container:{vpn}", "Binds": []}
    api = Api(
        {
            vpn: inspect(vpn),
            client: inspect(client, image=f"x@{OLD}", HostConfig=joined),
            other: inspect(other, HostConfig={"NetworkMode": f"container:{vpn}", "Binds": []}),
        }
    )
    # In a stack: the pinned client follows its VPN, by name (the new one keeps it).
    planned = plan_update(api, 1, [vpn, client], frozenset(), "1.47", stack=True)
    assert planned.plan is not None
    assert [s.name for s in planned.plan.containers] == ["c1111", "c2222"]
    assert planned.plan.containers[1].body["HostConfig"]["NetworkMode"] == "container:c1111"
    assert "c2222: made again with its own image, since it uses c1111." in planned.notes
    # Alone: another container on the host joins the VPN's network, so it is refused.
    with pytest.raises(UpdateError, match="uses the network of c1111: update their stack instead"):
        plan_update(api, 1, [vpn], frozenset(), "1.47")


def test_a_stack_leaves_alone_what_cannot_be_updated() -> None:
    mine, web = "4" * 64, "5" * 64
    api = Api({mine: inspect(mine), web: inspect(web)})
    planned = plan_update(api, 1, [mine, web], frozenset({mine}), "1.47", stack=True)
    assert [s.name for s in planned.plan.containers] == ["c5555"]
    assert (
        planned.notes[0] == "c4444: drydock does not update itself or its own project. Left alone."
    )
