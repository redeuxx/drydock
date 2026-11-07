"""Switching the tag a container or a stack's main service follows (updates/switch.py):
the rules, the plans they make (updates/apply.py), and the pages and policies that ask."""

import json
from typing import Any

import pytest

from drydock.hosts import status
from drydock.updates import apply as update_apply
from drydock.updates import switch
from drydock.updates.apply import UpdateError
from drydock.updates.switch import Part
from tests.conftest import Browser, add_user
from tests.test_jobs import add_host as add_named_host
from tests.test_status import a_host_with_containers
from tests.test_update_apply import OLD, WEB, Api, inspect
from tests.test_update_policies import policy_form

pytestmark = pytest.mark.anyio

SERVER, ML, CUDA, DB, REDIS = (c * 64 for c in "12345")
IMMICH = "ghcr.io/immich-app/"


def test_repository_and_namespace() -> None:
    assert switch.repository("nginx") == "nginx"
    assert switch.repository("nginx:1.27@sha256:" + "a" * 64) == "nginx"
    assert switch.repository("registry.local:5000/team/app:v1") == "registry.local:5000/team/app"
    assert switch.repository("sha256:" + "a" * 64) is None
    assert switch.namespace("nginx") == switch.namespace("docker.io/library/nginx")
    assert switch.namespace("nginx") == "docker.io/library"
    assert switch.namespace("bitnami/redis") == "docker.io/bitnami"
    assert switch.namespace("ghcr.io/immich-app/immich-server") == "ghcr.io/immich-app"
    assert switch.switched_ref("nginx@sha256:" + "a" * 64, "1.28") == "nginx:1.28"
    assert switch.switched_ref("a" * 64, "1.28") is None


def immich() -> list[Part]:
    """The server depends on the database and the cache and publishes a port; the machine
    learning containers stand alone."""
    return [
        Part(
            SERVER, "immich-server", IMMICH + "immich-server:v1.120", frozenset({DB, REDIS}), True
        ),
        Part(ML, "immich-ml", IMMICH + "immich-machine-learning:v1.120", frozenset(), False),
        Part(
            CUDA, "immich-cuda", IMMICH + "immich-machine-learning:v1.120-cuda", frozenset(), False
        ),
        Part(DB, "database", "tensorchord/pgvecto-rs:pg14-v0.2.0", frozenset(), False),
        Part(REDIS, "redis", "redis:6.2", frozenset(), False),
    ]


def test_the_main_service_and_who_follows_it() -> None:
    parts = immich()
    main = switch.main_service(parts)
    assert main is not None and main.service == "immich-server", "nobody needs it; it has ports"
    assert switch.followers(parts, main, "v1.121") == {
        SERVER: IMMICH + "immich-server:v1.121",
        ML: IMMICH + "immich-machine-learning:v1.121",
        CUDA: IMMICH + "immich-machine-learning:v1.121-cuda",
    }, "the database and the cache keep their tags"
    # Without ports, the first by service name; a pinned main moves alone.
    quiet = [Part(p.id, p.service, p.image, p.depends_on, False) for p in parts]
    assert switch.main_service(quiet).service == "immich-cuda"
    pinned = Part(SERVER, "immich-server", IMMICH + "immich-server@" + OLD, frozenset(), True)
    assert switch.followers([pinned, *parts[1:]], pinned, "v2") == {
        SERVER: IMMICH + "immich-server:v2"
    }
    # latest does not drag along another publisher's latest.
    app = Part(ML, "app", "acme/app:latest", frozenset({REDIS}), True)
    cache = Part(REDIS, "redis", "redis:latest", frozenset(), False)
    assert switch.followers([app, cache], app, "2.0") == {ML: "acme/app:2.0"}
    worker = Part(CUDA, "worker", "acme/app-worker:latest", frozenset(), False)
    assert switch.followers([app, worker], app, "2.0") == {ML: "acme/app:2.0"}, "not on latest"


def test_official_images_and_other_apps_of_a_publisher_keep_their_tags() -> None:
    cloud = Part(SERVER, "app", "nextcloud:29", frozenset({DB, REDIS}), True)
    db = Part(DB, "db", "mariadb:29", frozenset(), False)  # the same tag, by chance
    assert switch.followers([cloud, db], cloud, "30") == {SERVER: "nextcloud:30"}
    press = Part(SERVER, "wordpress", "bitnami/wordpress:6.4", frozenset({DB}), True)
    maria = Part(DB, "mariadb", "bitnami/mariadb:6.4", frozenset(), False)
    assert switch.followers([press, maria], press, "6.5") == {SERVER: "bitnami/wordpress:6.5"}
    # Replicas of the main service move with it, pinned or not.
    pinned = "acme/app@" + OLD
    one = Part(SERVER, "app", pinned, frozenset(), True)
    two = Part(ML, "app", pinned, frozenset(), True)
    assert switch.followers([one, two], one, "3") == {SERVER: "acme/app:3", ML: "acme/app:3"}
    assert switch.family("ghcr.io/immich-app/immich-machine-learning") == "immich"


def test_parts_from_the_status_cache() -> None:
    def member(cid: str, service: str, image: str, **extra: Any) -> status.ContainerStatus:
        base = dict.fromkeys(status.ContainerStatus.__dataclass_fields__)
        return status.ContainerStatus(
            **base
            | {"id": cid, "name": service, "image": image, "state": "running", "status": "Up"}
            | {"service": service, "ips": (), "ports": (), "labels": ()}
            | extra
        )

    port = status.Port(public=8080, private=80, protocol="tcp")
    parts = switch.from_cache(
        [
            member(
                SERVER,
                "server",
                "acme/app:1",
                ports=(port,),
                labels=(
                    (
                        "com.docker.compose.depends_on",
                        "db:service_healthy:false,gone:service_started:false",
                    ),
                ),
            ),
            member(DB, "db", "postgres:17"),
        ]
    )
    assert parts == [
        Part(SERVER, "server", "acme/app:1", frozenset({DB}), True),
        Part(DB, "db", "postgres:17", frozenset(), False),
    ]
    assert switch.main_service(parts).id == SERVER


# PLANS


def test_a_switch_pulls_the_new_tag_and_makes_the_container_from_it() -> None:
    api = Api({WEB: inspect(WEB)}, latest=OLD)  # the new tag names the same image: still moves
    planned = update_apply.plan_containers(api, 3, [WEB], frozenset(), "1.47", tag="1.28")
    plan = planned.plan
    assert plan is not None
    (image,) = plan.images
    assert (image.label, image.pull, image.refs) == ("nginx:1.28", f"nginx@{OLD}", ("nginx:1.28",))
    (step,) = plan.containers
    assert step.body["Image"] == "nginx:1.28"
    assert "name:3:image:nginx:1.28" in plan.lock_keys
    assert "caaaa: switching from nginx:1.27 to nginx:1.28." in planned.notes
    # The tag it already follows: an ordinary update.
    same = update_apply.plan_containers(
        Api({WEB: inspect(WEB)}), 3, [WEB], frozenset(), "1.47", tag="1.27"
    )
    assert same.plan is not None and same.plan.images[0].refs == ("nginx:1.27",)
    with pytest.raises(UpdateError, match=r"nginx:1\.28: The registry lookup failed"):
        update_apply.plan_containers(
            Api({WEB: inspect(WEB)}, latest="fail"), 3, [WEB], frozenset(), "1.47", tag="1.28"
        )
    with pytest.raises(UpdateError, match="no repository to follow"):
        update_apply.plan_containers(
            Api({WEB: inspect(WEB, image="b" * 64)}), 3, [WEB], frozenset(), "1.47", tag="1.28"
        )


class StackApi(Api):
    def containers(self, all: bool, filters: dict | None = None) -> list[dict[str, Any]]:
        return [
            {
                "Id": cid,
                "Names": [info["Name"]],
                "Labels": info["Config"]["Labels"],
                "HostConfig": info.get("HostConfig") or {},
            }
            for cid, info in self.boxes.items()
        ]


def test_a_stack_switch_moves_its_main_service_and_its_followers() -> None:
    def box(cid: str, service: str, image: str, **extra: Any) -> dict[str, Any]:
        labels = {
            "com.docker.compose.project": "immich",
            "com.docker.compose.service": service,
        } | extra.pop("labels", {})
        return inspect(cid, image=image, labels=labels, **extra)

    ports = {"Binds": [], "PortBindings": {"2283/tcp": [{"HostPort": "2283"}]}}
    api = StackApi(
        {
            SERVER: box(
                SERVER,
                "server",
                IMMICH + "immich-server:v1.120",
                labels={"com.docker.compose.depends_on": "redis:service_started:false"},
                HostConfig=ports,
            ),
            ML: box(ML, "ml", IMMICH + "immich-machine-learning:v1.120"),
            REDIS: box(REDIS, "redis", "redis:6.2"),
        }
    )
    planned = update_apply.plan_stack(api, 1, "immich", "x", frozenset(), "1.47", tag="v1.121")
    assert planned.plan is not None
    images = {s.name: s.body["Image"] for s in planned.plan.containers}
    assert images == {
        "c5555": "redis:6.2",  # its newest 6.2, first: the server depends on it
        "c1111": IMMICH + "immich-server:v1.121",
        "c2222": IMMICH + "immich-machine-learning:v1.121",
    }
    assert "Main service server: c1111, c2222 follow tag v1.121." in planned.notes
    chosen = update_apply.plan_stack(
        api, 1, "immich", "x", frozenset(), "1.47", tag="v9", main="ml"
    )
    assert {s.body["Image"] for s in chosen.plan.containers} >= {
        IMMICH + "immich-machine-learning:v9"
    }
    with pytest.raises(UpdateError, match="has no service nope"):
        update_apply.plan_stack(api, 1, "immich", "x", frozenset(), "1.47", tag="v9", main="nope")


# PAGES AND POLICIES


async def test_switching_from_the_containers_and_stacks_pages(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    submitted: list[tuple] = []

    async def submit_update(host, ids, by, label, **kwargs) -> int:
        submitted.append((ids, label, kwargs))
        return 81

    monkeypatch.setattr(admin.app.state.dispatcher, "submit_update", submit_update)
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert 'popovertarget="about-tag"' in page and "Switch tag</label>" in page
    form = {"host": str(host_id), "container": WEB, "tag": "1.38"}
    done = await admin.post("/containers/update", form)
    assert done.status_code == 303 and done.headers["location"] == "/runs/81"
    assert submitted == [([WEB], "web to tag 1.38", {"tag": "1.38"})]
    bad = await admin.post(
        "/containers/update", form | {"tag": "-x"}, headers={"HX-Request": "true"}
    )
    assert "A tag is up to 128 letters" in bad.text and len(submitted) == 1

    stacks = (await admin.get(f"/stacks?host={host_id}")).text
    assert "main: db" in stacks and "Switch the tag of app" in stacks
    assert 'popovertarget="about-main"' in stacks and 'popovertarget="about-tags"' in stacks
    stack = {"host": str(host_id), "stack": "app", "tag": "2"}
    assert (await admin.post("/containers/update-stack", stack)).headers["location"] == "/runs/81"
    assert submitted[-1] == ([], "stack app to tag 2", {"project": "app", "tag": "2", "main": None})
    refused = await admin.post(
        "/containers/update-stack", stack | {"main": "nope"}, headers={"HX-Request": "true"}
    )
    assert "Choose a tag and one of the stack&#39;s services" in refused.text
    assert len(submitted) == 2
    assert [
        json.loads(d).get("tag")
        for (d,) in admin.sql(
            "SELECT details FROM audit_events WHERE action IN ('container.update', 'stack.update')"
            " ORDER BY id"
        )
    ] == ["1.38", "-x", "2", "2"]

    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert "Switch tag</label>" not in page and 'popovertarget="about-tag"' in page


async def test_a_policy_names_the_tag_and_main_service_its_runs_switch_to(admin: Browser) -> None:
    host_id = add_named_host(admin, "web-host")
    for fields, message in [
        ({"tag": "-bad"}, "A tag is up to 128 letters"),
        ({"main_service": "web"}, "Only a policy for one stack has a main service."),
        ({"target_type": "stack", "target": "app", "main_service": "web"}, "Enter the tag"),
        ({"target_type": "stack", "target": "*", "tag": "2"}, "follows each stack"),
    ]:
        refused = await admin.post("/updates", policy_form(host_id, name="x", **fields))
        assert refused.status_code == 422 and message in refused.text, fields
    await admin.post("/updates", policy_form(host_id, tag="1.28"))
    await admin.post(
        "/updates",
        policy_form(
            host_id, name="stack", target_type="stack", target="app", tag="v2", main_service="api"
        ),
    )
    rows = admin.sql("SELECT id, tag, main_service FROM update_policies ORDER BY id")
    assert [r[1:] for r in rows] == [("1.28", None), ("v2", "api")]
    listed = (await admin.get("/updates")).text
    assert "tag 1.28</span>" in listed and "tag v2</span>" in listed
    edit = (await admin.get(f"/updates/{rows[1][0]}")).text
    assert 'name="tag" value="v2"' in edit and 'name="main_service" value="api"' in edit
    dispatcher = admin.app.state.dispatcher
    plans = [
        json.loads(admin.sql("SELECT plan FROM runs WHERE id = ?", (run,))[0][0])["update"]
        for run in (dispatcher._create_policy_run(r[0], "the schedule") for r in rows)
    ]
    assert (plans[0]["tag"], "main" in plans[0]) == ("1.28", False)
    assert (plans[1]["tag"], plans[1]["main"]) == ("v2", "api")
    assert (
        json.loads(
            admin.sql(
                "SELECT details FROM audit_events WHERE action = 'update_policy.create'"
                " ORDER BY id DESC LIMIT 1"
            )[0][0]
        )["main_service"]
        == "api"
    )
