"""Stack restores in the planner: new Compose projects, dependency order, project lock keys
and the compose output directory.

Pure: no Docker daemon. The stack is a Compose v2 project 'app' with three services: db
(a healthcheck and a named volume), cache (depends on db being started) and web (depends
on db being healthy and links it), all on the project network app_default.
"""

import json
from typing import Any

import pytest

from drydock.archive import manifest as m
from drydock.engine import stacks
from drydock.engine.capture import compose_basename
from drydock.restore import plan as p
from tests.restore_support import container_inspect, network_inspect
from tests.test_restore_plan import (
    FACTS,
    IMAGE_ID,
    OTHER_ID,
    build,
    choice,
    hexid,
    image,
    make_archive,
    refused,
    target,
)

DB_ID = hexid("app-db")
WEB_ID = hexid("app-web")
CACHE_ID = hexid("app-cache")
SIDE_ID = hexid("app-side")
NET_ID = hexid("app-default")
PROJECT = "com.docker.compose.project"
DEPENDS = "com.docker.compose.depends_on"
WORKING_DIR = "com.docker.compose.project.working_dir"
DROPPED = (
    WORKING_DIR,
    "com.docker.compose.project.config_files",
    "com.docker.compose.project.environment_file",
    "com.docker.compose.replace",
    "com.docker.compose.unknown",
)
COMPOSE = (
    ("config_file", "/srv/app/compose.yaml", b"services: {}\n"),
    ("env_file", "/srv/app/env/app.env", b"TOKEN=s3cret\n"),
)


# FIXTURES


def labels(service: str, *, depends: str = "", project: str = "app") -> dict[str, str]:
    """The labels Compose v2 sets, plus one it does not (unknown)."""
    out = {
        PROJECT: project,
        "com.docker.compose.service": service,
        "com.docker.compose.container-number": "1",
        "com.docker.compose.oneoff": "False",
        "com.docker.compose.version": "2.40.0",
        "com.docker.compose.config-hash": hexid(f"hash-{service}"),
        "com.docker.compose.image": IMAGE_ID,
        WORKING_DIR: "/srv/app",
        "com.docker.compose.project.config_files": "/srv/app/compose.yaml",
        "com.docker.compose.project.environment_file": "/srv/app/.env",
        "com.docker.compose.replace": hexid(f"replaced-{service}"),
        "com.docker.compose.unknown": "x",
        "keep.me": "yes",
    }
    if depends:
        out[DEPENDS] = depends
    return out


def member(
    service: str,
    cid: str,
    *,
    depends: str = "",
    endpoint: dict[str, Any] | None = None,
    running: bool = True,
    **changes: Any,
) -> dict[str, Any]:
    """A container of project app on app_default, as Docker 29 inspects it."""
    changes.setdefault("network_mode", "app_default")
    if changes["network_mode"] == "app_default":
        changes.setdefault("networks", {"app_default": {"NetworkID": NET_ID, **(endpoint or {})}})
    return container_inspect(
        f"app-{service}-1",
        id=cid,
        image="nginx:1.29",
        image_id=IMAGE_ID,
        labels=labels(service, depends=depends),
        running=running,
        **changes,
    )


def db(**changes: Any) -> dict[str, Any]:
    info = member("db", DB_ID, mounts=[("app_data", "/var/lib/postgresql/data")], **changes)
    info["Config"]["Healthcheck"] = {"Test": ["CMD", "pg_isready"], "Interval": 1_000_000_000}
    return info


def web(**changes: Any) -> dict[str, Any]:
    endpoint = {"Links": ["app-db-1:db", "app-db-1:app-db-1"], "Aliases": ["web", "app-web-1"]}
    changes.setdefault("endpoint", endpoint)
    return member("web", WEB_ID, depends="db:service_healthy:false", **changes)


def cache(**changes: Any) -> dict[str, Any]:
    return member("cache", CACHE_ID, depends="db:service_started:false", **changes)


def app_network() -> dict[str, Any]:
    return network_inspect(
        "app_default",
        id=NET_ID,
        labels={PROJECT: "app", "com.docker.compose.network": "default", "keep.me": "yes"},
    )


def app_volume(name: str = "app_data", short: str = "data") -> dict[str, Any]:
    return {
        "Name": name,
        "Driver": "local",
        "Options": None,
        "Labels": {PROJECT: "app", "com.docker.compose.volume": short, "keep.me": "yes"},
        "Scope": "local",
        "Mountpoint": f"/var/lib/docker/volumes/{name}/_data",
    }


def stack(
    infos: list[dict[str, Any]],
    *,
    project: str | None = "app",
    target_type: str = "stack",
    compose: tuple[tuple[str, str, bytes], ...] = (),
    networks: tuple[dict[str, Any], ...] | None = None,
    volume_configs: dict[str, dict[str, Any]] | None = None,
    compose_projects: dict[str, str | None] | None = None,
    data: bool = True,
) -> tuple[m.Manifest, dict[str, Any]]:
    """An archive of infos as capture writes one for a stack job (or, with target_type
    container, for a container job), with compose files."""
    manifest, configs = make_archive(
        infos,
        networks=(app_network(),) if networks is None else networks,
        volume_configs={"app_data": app_volume()} | (volume_configs or {}),
        images=[image()],
        data=data,
    )
    document = manifest.model_dump()
    document["job"] |= {"target_type": target_type, "project": project}
    for entry, info in zip(document["containers"], infos, strict=True):
        found = info["Config"]["Labels"].get(PROJECT)
        entry["compose_project"] = (compose_projects or {}).get(entry["name"], found)
        entry["compose_service"] = info["Config"]["Labels"].get("com.docker.compose.service")
    files = [
        {
            "n": n,
            "role": role,
            "host_path": path,
            "member": f"compose/{n}/{compose_basename(path)}",
            "size": len(data),
        }
        for n, (role, path, data) in enumerate(compose)
    ]
    document["compose_files"] = files
    ranks = [m.member_rank(name) for name in manifest.members]
    document["members"] = [
        *(name for name, rank in zip(manifest.members, ranks, strict=True) if rank == 1),
        *(f["member"] for f in files),
        *(name for name, rank in zip(manifest.members, ranks, strict=True) if rank == 2),
    ]
    return m.Manifest.model_validate(document), configs


def app(**kwargs: Any) -> tuple[m.Manifest, dict[str, Any]]:
    return stack([web(), db(), cache()], **kwargs)


def single(**kwargs: Any) -> tuple[m.Manifest, dict[str, Any]]:
    """Container web of project app, backed up by a container job."""
    return stack([web(endpoint={})], target_type="container", project=None, **kwargs)


def body_of(plan: p.RestorePlan, name: str) -> dict[str, Any]:
    return next(step.body for step in plan.containers if step.name == name)


def endpoint_of(plan: p.RestorePlan, name: str, network: str) -> dict[str, Any]:
    return body_of(plan, name)["NetworkingConfig"]["EndpointsConfig"][network]


def originals_target(**changes: Any) -> p.TargetInfo:
    """The source host: the stack runs."""
    infos = {info["Name"].lstrip("/"): info for info in (web(), db(), cache())}
    values: dict[str, Any] = {
        "containers": infos,
        "networks": {"app_default": app_network()},
        "volumes": {"app_data": app_volume()},
        "volume_users": {"app_data": (p.ContainerUse(DB_ID, "app-db-1", "running"),)},
        "projects": {"app": tuple(sorted(infos))},
    }
    return target(**(values | changes))


# NEW PROJECT


def test_new_project_renames_everything_and_shares_nothing() -> None:
    legacy = {"Links": ["/app-db-1:/app-web-1/app-db-1", "/app-db-1:/app-web-1/db"]}
    plan = build(
        stack([web(host_config=legacy), db(), cache()]),
        target(),
        choice("new-name", new_name="copy"),
    )

    assert [c.name for c in plan.containers] == ["copy-db-1", "copy-cache-1", "copy-web-1"]
    assert [v.name for v in plan.volumes] == ["copy_data"]
    assert [n.name for n in plan.networks] == ["copy_default"]
    assert plan.project == "copy" and plan.projects == ("copy",)
    assert endpoint_of(plan, "copy-web-1", "copy_default")["Links"] == [
        "copy-db-1:db",
        "copy-db-1:copy-db-1",
    ]
    assert endpoint_of(plan, "copy-web-1", "copy_default")["Aliases"] == ["web"]
    assert body_of(plan, "copy-web-1")["HostConfig"]["Links"] == [
        "copy-db-1:copy-db-1",
        "copy-db-1:db",
    ]
    steps = {step.name: step for step in plan.containers}
    assert steps["copy-web-1"].wait_healthy == ("copy-db-1",)
    assert steps["copy-cache-1"].wait_healthy == () and steps["copy-db-1"].wait_healthy == ()
    assert body_of(plan, "copy-db-1")["HostConfig"]["Binds"] == [
        "copy_data:/var/lib/postgresql/data"
    ]

    # Kept labels name services, never containers, volumes or networks.
    bodies = [s.body for s in plan.containers]
    creates = [n.create for n in plan.networks]
    text = json.dumps([bodies, creates, [v.labels for v in plan.volumes]])
    for original in ("app-db-1", "app-web-1", "app-cache-1", "app_data", "app_default", "/srv/app"):
        assert original not in text, original
    for cid in (DB_ID, WEB_ID, CACHE_ID, NET_ID):
        assert cid[:12] not in text
    label_sets = [b["Labels"] for b in bodies] + [c["labels"] for c in creates]
    label_sets += [v.labels for v in plan.volumes]
    for found in label_sets:
        assert found[PROJECT] == "copy"
        assert found["keep.me"] == "yes"
        assert not set(DROPPED) & set(found)
    web_labels = body_of(plan, "copy-web-1")["Labels"]
    assert web_labels[DEPENDS] == "db:service_healthy:false"
    assert web_labels["com.docker.compose.service"] == "web"
    assert creates[0]["labels"]["com.docker.compose.network"] == "default"
    assert plan.volumes[0].labels["com.docker.compose.volume"] == "data"
    assert any(
        w.startswith("Dropped the labels com.docker.compose.project.config_files")
        for w in plan.warnings
    )
    keys = set(plan.lock_keys)
    assert {
        "name:1:project:copy",
        "name:1:container:copy-web-1",
        "name:1:volume:copy_data",
        "name:1:network:copy_default",
    } <= keys
    assert not plan.originals
    document = p.summary(plan, "local")
    assert document["project"] == "copy" and "compose" not in document
    assert document["containers"] == ["copy-db-1", "copy-cache-1", "copy-web-1"]


def test_links_to_containers_outside_the_archive_are_dropped() -> None:
    endpoint = {"Links": ["other-1:other", "app-db-1:db"], "Aliases": ["web"]}
    lonely = {"Links": ["other-1:other"], "Aliases": None}
    infos = [
        web(endpoint=endpoint, host_config={"Links": ["/other-1:/app-web-1/other"]}),
        db(),
        cache(endpoint=lonely),
    ]
    plan = build(stack(infos), target(), choice("new-name", new_name="copy"))
    web_body = body_of(plan, "copy-web-1")
    assert web_body["NetworkingConfig"]["EndpointsConfig"]["copy_default"]["Links"] == [
        "copy-db-1:db"
    ]
    assert "Links" not in web_body["HostConfig"]
    assert "Links" not in endpoint_of(plan, "copy-cache-1", "copy_default")
    note = "Dropped the link of copy-web-1 to other-1: that container is not in the archive."
    assert note in plan.warnings
    assert (
        "Dropped the link of copy-cache-1 to other-1: that container is not in the archive."
        in plan.warnings
    )
    assert "other-1" not in json.dumps([s.body for s in plan.containers])


def test_service_network_mode_is_rewritten_to_the_new_member() -> None:
    side = member("side", SIDE_ID, network_mode=f"container:{WEB_ID}", networks={})
    plan = build(stack([side, web(), db(), cache()]), target(), choice("new-name", new_name="copy"))
    names = [c.name for c in plan.containers]
    assert names.index("copy-side-1") > names.index("copy-web-1")
    assert body_of(plan, "copy-side-1")["HostConfig"]["NetworkMode"] == "container:copy-web-1"
    assert not [f for f in plan.risk if f.field == "NetworkMode"]  # an archive member


def test_endpoint_aliases_follow_the_new_names() -> None:
    infos = [
        web(endpoint={"Aliases": ["web", "app-db-1", "app-web-1", "app-db-1"]}),
        db(endpoint={"Aliases": ["db", "app-db-1", DB_ID[:12]]}),
        cache(),
    ]
    plan = build(stack(infos), target(), choice("new-name", new_name="copy"))
    assert endpoint_of(plan, "copy-web-1", "copy_default")["Aliases"] == ["web", "copy-db-1"]
    assert endpoint_of(plan, "copy-db-1", "copy_default")["Aliases"] == ["db"]


def test_mapped_name_collisions_and_existing_project_are_refused() -> None:
    copy = choice("new-name", new_name="copy")
    error = refused(app(), target(containers={"copy-web-1": web()}), copy)
    assert "A container named copy-web-1 already exists on host local." in error
    error = refused(app(), target(projects={"copy": ("copy-other-1", "copy-x-1")}), copy)
    assert (
        "Compose project copy already has containers on host local: copy-other-1, copy-x-1. "
        "Choose another name." in error
    )
    error = refused(app(), target(volumes={"copy_data": app_volume("copy_data")}), copy)
    assert "Volume copy_data already exists on host local." in error
    error = refused(app(), target(networks={"copy_default": app_network()}), copy)
    assert "Network copy_default already exists on host local." in error

    second = db()
    second["HostConfig"]["Binds"].append("app_data2:/backup")
    second["Mounts"].append(
        {"Type": "volume", "Name": "app_data2", "Destination": "/backup", "RW": True}
    )
    archive = stack(
        [web(), second, cache()], volume_configs={"app_data2": app_volume("app_data2", "data")}
    )
    error = refused(archive, target(), copy)
    assert "Volumes app_data and app_data2 would both be named copy_data." in error
    # The same archive restores in place.
    build(archive, target(), choice("overwrite"))


@pytest.mark.parametrize("name", ["Copy", "a.b", "-a", "a" * 64, "a/b", ""])
def test_stack_project_name_rules(name: str) -> None:
    error = refused(app(), target(), choice("new-name", new_name=name))
    assert "The new project name must hold 1 to 63 lowercase letters" in error


def test_stack_project_names_compose_accepts() -> None:
    for name in ("a", "a_b-1", "0" * 63):
        plan = build(app(), target(), choice("new-name", new_name=name))
        assert plan.containers[0].name == f"{name}-db-1"
    # A single container keeps the container name rule.
    plan = build(single(), target(), choice("new-name", new_name="web.v2"))
    assert [c.name for c in plan.containers] == ["web.v2"]
    assert "The new name must start with a letter" in refused(
        single(), target(), choice("new-name", new_name="a")
    )


def test_label_less_stack_warns_name_order() -> None:
    def bare(service: str, cid: str, **changes: Any) -> dict[str, Any]:
        info = member(service, cid, **changes)
        info["Config"]["Labels"].pop(DEPENDS, None)
        return info

    infos = [
        bare("a", CACHE_ID, network_mode=f"container:{WEB_ID}", networks={}),
        bare("b", WEB_ID),
    ]
    plan = build(stack(infos), target(), choice("overwrite"))
    assert "The containers record no dependency order; they start in name order." in plan.warnings
    assert [c.name for c in plan.containers] == ["app-b-1", "app-a-1"]
    plan = build(app(), target(), choice("overwrite"))
    assert not [w for w in plan.warnings if "no dependency order" in w]


def test_overwrite_stack_stops_in_reverse_and_creates_forward() -> None:
    extra = ("app-cache-1", "app-db-1", "app-extra-1", "app-web-1")
    on = originals_target(projects={"app": extra})
    plan = build(app(), on, choice("overwrite"))
    assert [c.name for c in plan.containers] == ["app-db-1", "app-cache-1", "app-web-1"]
    assert [o.name for o in plan.originals] == ["app-web-1", "app-cache-1", "app-db-1"]
    assert "name:1:project:app" in plan.lock_keys
    assert plan.projects == ("app",) and plan.project == "app"
    assert (
        "Container app-extra-1 of project app is not in the archive and keeps running."
        in plan.warnings
    )
    assert [w for w in plan.warnings if "keeps running" in w] == [
        "Container app-extra-1 of project app is not in the archive and keeps running."
    ]
    # Overwrite keeps the Compose labels: the containers rejoin their project.
    assert body_of(plan, "app-web-1")["Labels"][WORKING_DIR] == "/srv/app"
    document = p.summary(plan, "local")
    assert document["project"] == "app"
    assert document["originals"] == ["app-web-1", "app-cache-1", "app-db-1"]


def phase3_summary(mode: str, name: str) -> dict[str, Any]:
    """What Phase 3 stored for the single-container archive below (single())."""
    return {
        "mode": mode,
        "host_id": 1,
        "host_name": "local",
        "containers": [name],
        "originals": ["app-web-1"] if mode == "overwrite" else [],
        "images": [{"label": "nginx:1.29", "action": "load", "moves": []}],
        "networks": [
            {
                "name": "app_default" if mode == "overwrite" else f"{name}-app_default",
                "action": "reuse" if mode == "overwrite" else "create",
                "differences": [],
            }
        ],
        "volumes": [],
        "wipes": [],
        "data": [],
        "risk": [],
        "warnings": PHASE3_WARNINGS[mode],
    }


PHASE3_WARNINGS = {
    # Networks are planned before the container body (check_body needs the created ones).
    "new-name": [
        "Dropped the labels com.docker.compose.network, com.docker.compose.project of network "
        "copy-app_default.",
        "Dropped the labels com.docker.compose.config-hash, com.docker.compose.container-number, "
        "com.docker.compose.depends_on, com.docker.compose.image, com.docker.compose.oneoff, "
        "com.docker.compose.project, "
        "com.docker.compose.project.config_files, com.docker.compose.project.environment_file, "
        "com.docker.compose.project.working_dir, com.docker.compose.replace, "
        "com.docker.compose.service, com.docker.compose.unknown, com.docker.compose.version of "
        "copy: they tie it to the original's Compose project, proxy routes or updater.",
        "Dropped a MAC address: it belongs to the original container.",
    ],
    "overwrite": [],
}


def test_single_container_overwrite_of_a_member_holds_the_project_key() -> None:
    on = target(containers={"app-web-1": web(endpoint={})}, networks={"app_default": app_network()})
    plan = build(single(), on, choice("overwrite"))
    assert "name:1:project:app" in plan.lock_keys
    assert plan.projects == ("app",) and plan.project is None
    assert p.summary(plan, "local") == phase3_summary("overwrite", "app-web-1")

    plan = build(single(), target(), choice("new-name"))
    assert not [k for k in plan.lock_keys if ":project:" in k]
    assert plan.projects == ()
    assert p.summary(plan, "local") == phase3_summary("new-name", "copy")

    # A label value Compose could not have written names no project.
    odd = web(endpoint={})
    odd["Config"]["Labels"][PROJECT] = "Bad Name"
    on = target(containers={"app-web-1": odd}, networks={"app_default": app_network()})
    archive = stack(
        [web(endpoint={})],
        target_type="container",
        project=None,
        compose_projects={"app-web-1": None},
    )
    plan = build(archive, on, choice("overwrite"))
    assert plan.projects == () and not [k for k in plan.lock_keys if ":project:" in k]


def test_summary_of_a_single_container_plan_is_unchanged() -> None:
    plan = build(single(), target(), choice("new-name"))
    document = p.summary(plan, "local")
    assert "project" not in document and "compose" not in document
    assert document == phase3_summary("new-name", "copy")
    assert plan.containers[0].wait_healthy == ()


def test_stack_archive_must_hold_one_valid_project() -> None:
    error = refused(stack([web(), db(), cache()], project="Bad"), target(), choice("overwrite"))
    assert "The archive holds an invalid Compose project 'Bad'." in error
    error = refused(app(compose_projects={"app-cache-1": "other"}), target(), choice("overwrite"))
    assert "The archive's containers do not all belong to Compose project app." in error
    with pytest.raises(p.PlanError, match="invalid Compose project"):
        manifest, configs = stack([web()], project=None)
        p.lookups(manifest, configs, choice("overwrite"))
    assert p.OLD_SUFFIX == stacks.OLD_SUFFIX


def test_cycle_is_a_plan_error() -> None:
    infos = [web(), db(), cache()]
    infos[1]["Config"]["Labels"][DEPENDS] = "web:service_started:false"
    error = refused(stack(infos), target(), choice("overwrite"))
    assert "The containers app-db-1, app-web-1 depend on each other in a cycle." in error


def test_started_container_on_a_stopped_provider_is_refused() -> None:
    side = member("side", SIDE_ID, network_mode=f"container:{WEB_ID}", networks={})
    infos = [side, web(running=False), db(), cache()]
    error = refused(stack(infos), target(), choice("new-name", new_name="copy"))
    assert (
        "Container copy-side-1 shares the namespaces of copy-web-1, which the archive records "
        "as stopped, so it cannot start." in error
    )
    # A stopped dependency is no wait.
    plan = build(stack([web(), db(running=False), cache()]), target(), choice("overwrite"))
    assert {s.name: s.wait_healthy for s in plan.containers}["app-web-1"] == ()


def test_non_stack_multi_container_new_name_is_refused_and_overwrite_allowed() -> None:
    archive = stack([web(), db(), cache()], target_type="container", project=None)
    error = refused(archive, target(), choice("new-name", new_name="copy"))
    assert "Only a stack archive can be restored under a new name with several containers." in error
    plan = build(archive, target(), choice("overwrite"))
    assert [c.name for c in plan.containers] == ["app-db-1", "app-cache-1", "app-web-1"]
    assert plan.project is None and plan.projects == ("app",)
    assert "project" not in p.summary(plan, "local")


# COMPOSE OUTPUT


def test_compose_output_layout() -> None:
    files = (
        *COMPOSE,
        ("environment_file", "/opt/shared/common.env", b"A=1\n"),
        ("dotenv", "/srv/app/sub/../.env", b"B=2\n"),
        ("env_file", "/srv/app/a b/x.env", b"C=3\n"),
    )
    plan = build(app(compose=files), target(), choice("overwrite", compose_dir="/srv/new"))
    assert plan.compose is not None
    assert [(f.path, f.member, f.size) for f in plan.compose.files] == [
        ("compose.yaml", "compose/0/compose.yaml", 13),
        ("env/app.env", "compose/1/app.env", 13),
        ("external/2-common.env", "compose/2/common.env", 4),
        ("external/3-.env", "compose/3/.env", 4),
        ("external/4-x.env", "compose/4/x.env", 4),
    ]
    assert p.summary(plan, "local")["compose"] == {
        "dir": "/srv/new",
        "files": [
            "compose.yaml",
            "env/app.env",
            "external/2-common.env",
            "external/3-.env",
            "external/4-x.env",
        ],
    }
    twice = (*COMPOSE, ("config_file", "/srv/app/compose.yaml", b"again\n"))
    error = refused(app(compose=twice), target(), choice("overwrite", compose_dir="/srv/new"))
    assert (
        "Compose files /srv/app/compose.yaml and /srv/app/compose.yaml would be written to the "
        "same place." in error
    )
    # A file where another needs a directory.
    clash = (("config_file", "/srv/app/env", b"x\n"), *COMPOSE)
    error = refused(app(compose=clash), target(), choice("overwrite", compose_dir="/srv/new"))
    assert "would be written to the same place" in error
    # Relative bind mounts in the compose files still name the original directory.
    with_bind = web()
    with_bind["HostConfig"]["Binds"] = ["/srv/app/static:/static:ro"]
    with_bind["Mounts"].append(
        {"Type": "bind", "Source": "/srv/app/static", "Destination": "/static", "RW": False}
    )
    archive = stack([with_bind, db(), cache()], compose=COMPOSE)
    plan = build(archive, target(), choice("overwrite", compose_dir="/srv/new"))
    assert (
        "Relative bind mounts in the compose files point at the original directory /srv/app, "
        "not at /srv/new." in plan.warnings
    )


def test_stack_compose_dir_warnings() -> None:
    plan = build(
        app(compose=COMPOSE), target(), choice("new-name", new_name="copy", compose_dir="/srv/new")
    )
    assert (
        "Compose files are copies of the originals. Drydock started the containers itself; "
        "the files are for reference and for running docker compose later." in plan.warnings
    )
    assert (
        "The compose files still name project app and its containers, volumes and networks. "
        "Edit them before running docker compose -p copy with them." in plan.warnings
    )
    assert not plan.write_targets and "/srv/new" not in plan.written


def test_single_container_compose_dir_new_name_and_overwrite() -> None:
    on = target(containers={"app-web-1": web(endpoint={})}, networks={"app_default": app_network()})
    for mode, where in (("new-name", target()), ("overwrite", on)):
        plan = build(single(compose=COMPOSE), where, choice(mode, compose_dir="/srv/new"))
        assert plan.compose == p.ComposeWrite(
            "/srv/new",
            (
                p.ComposeOut("compose/0/compose.yaml", "compose.yaml", 13),
                p.ComposeOut("compose/1/app.env", "env/app.env", 13),
            ),
        )
        document = p.summary(plan, "local")
        assert document["compose"] == {"dir": "/srv/new", "files": ["compose.yaml", "env/app.env"]}
        assert "project" not in document
        assert "name:1:path:/srv/new" in plan.lock_keys
        old_name = "The compose files still name container app-web-1."
        assert (old_name in plan.warnings) is (mode == "new-name")
        assert not plan.risk


@pytest.mark.parametrize("mode", ["new-name", "overwrite"])
@pytest.mark.parametrize(
    ("directory", "message"),
    [
        ("/etc/stack", "Drydock never writes to /etc/stack."),
        ("/etc", "Drydock never writes to /etc."),
        ("/root/x", "Drydock never writes to /root/x."),
        ("/", "Drydock never writes to /."),
        ("/x", "Choose a directory below an existing directory, not the root."),
        ("/var/x", "Drydock cannot create a directory in /var: Binding /var is refused"),
        ("/run/user/x", "Drydock never writes to /run/user/x."),
        ("/srv/a:b", "without ':' or control characters"),
        ("srv/new", "Host path srv/new must be absolute."),
        ("/srv/../etc/x", "may not contain .."),
    ],
)
def test_compose_dir_under_etc_is_rejected(mode: str, directory: str, message: str) -> None:
    error = refused(app(compose=COMPOSE), target(), choice(mode, compose_dir=directory))
    assert message in error


def test_compose_dir_outside_the_data_trees_needs_a_superadmin() -> None:
    plan = build(app(compose=COMPOSE), target(), choice("overwrite", compose_dir="/srv/new"))
    assert not plan.risk
    for directory in ("/opt/stack", "/home/user/.compose"):
        plan = build(app(compose=COMPOSE), target(), choice("overwrite", compose_dir=directory))
        assert [(f.key, f.subject, f.field, f.value) for f in plan.risk] == [
            (f"compose-dir:{directory}", directory, "compose files", "written here")
        ]
    own = target(own_paths=frozenset({"/srv/drydock"}))
    error = refused(app(compose=COMPOSE), own, choice("overwrite", compose_dir="/srv/drydock/x"))
    assert "Host path /srv/drydock/x belongs to drydock's own deployment." in error


def test_compose_dir_under_a_live_bind_is_warned() -> None:
    users = (p.BindUse(OTHER_ID, "reader", "running", "/srv/shared"),)
    plan = build(
        app(compose=COMPOSE),
        target(bind_users=users),
        choice("overwrite", compose_dir="/srv/shared/new"),
    )
    assert (
        "Container reader mounts /srv/shared, so it can read the restored .env files."
        in plan.warnings
    )
    assert plan.compose is not None and plan.compose.dir == "/srv/shared/new"


def test_compose_dir_mounted_by_a_restored_container_is_refused() -> None:
    with_bind = web()
    with_bind["HostConfig"]["Binds"] = ["/srv/new/conf:/conf:ro"]
    with_bind["Mounts"].append(
        {"Type": "bind", "Source": "/srv/new/conf", "Destination": "/conf", "RW": False}
    )
    archive = stack([with_bind, db(), cache()], compose=COMPOSE)
    error = refused(archive, target(), choice("overwrite", compose_dir="/srv/new"))
    assert "The compose directory /srv/new is mounted by container app-web-1." in error


def test_compose_dir_in_a_volume_device_is_refused() -> None:
    """A host-backed volume the overwrite mounts but writes no data into (job data off):
    every member that mounts it would see the .env files. (A new-name copy of such a
    volume is refused anyway: it would share the original's directory.)"""
    device = {"Options": {"type": "none", "o": "bind", "device": "/srv/appdata"}}
    archive = stack(
        [web(), db(), cache()],
        compose=COMPOSE,
        data=False,
        volume_configs={"app_data": app_volume() | device},
    )
    assert all(v.data_member is None for v in archive[0].volumes)
    error = refused(archive, target(), choice("overwrite", compose_dir="/srv/appdata/x"))
    assert "The compose directory /srv/appdata/x is mounted by volume app_data." in error
    plan = build(archive, target(), choice("overwrite", compose_dir="/srv/new"))
    assert plan.compose is not None


def test_resolved_compose_dir_mounted_by_a_restored_container_is_refused() -> None:
    """/srv/link is a symbolic link to /srv/shared on the host: the lexical check cannot see
    that web would mount the compose directory's parent."""
    with_bind = web()
    with_bind["HostConfig"]["Binds"] = ["/srv/link:/conf:ro"]
    with_bind["Mounts"].append(
        {"Type": "bind", "Source": "/srv/link", "Destination": "/conf", "RW": False}
    )
    archive = stack([with_bind, db(), cache()], compose=COMPOSE)
    plan = build(archive, target(), choice("overwrite", compose_dir="/srv/shared/new"))
    assert "/srv/link" in plan.bind_sources
    assert p.resolved_problems(plan, {"/srv/link": "/srv/link", "/srv/shared": "/srv/shared"}) == []
    assert p.resolved_problems(
        plan, {"/srv/link": "/srv/shared", "/srv/shared": "/srv/shared"}
    ) == ["The compose directory /srv/shared/new is mounted by container app-web-1."]


def test_compose_dir_is_refused_outside_new_name_and_overwrite() -> None:
    for mode in ("data-only", "image-only"):
        error = refused(app(compose=COMPOSE), target(), choice(mode, compose_dir="/srv/new"))
        assert "Compose files are written only in new-name and overwrite modes." in error
    error = refused(app(), target(), choice("overwrite", compose_dir="/srv/new"))
    assert "This archive holds no compose files." in error
    with pytest.raises(p.PlanError, match="holds no compose files"):
        manifest, configs = app()
        p.lookups(manifest, configs, choice("overwrite", compose_dir="/srv/new"))


def test_two_restores_with_one_compose_dir_share_a_lock_key() -> None:
    keys = [
        build(app(compose=COMPOSE), target(), choice("overwrite", compose_dir=d)).lock_keys
        for d in ("/srv/new", "/srv//new/", "/srv/./new")
    ]
    paths = [[k for k in found if ":path:" in k] for found in keys]
    assert paths == [["name:1:path:/srv/new"]] * 3


def test_resolution_paths_include_the_compose_parent_without_binds() -> None:
    users = (
        p.BindUse(OTHER_ID, "reader", "running", "/srv/shared"),
        p.BindUse(OTHER_ID, "old", "exited", "/srv/stopped"),
    )
    on = target(bind_users=users, own_paths=frozenset({"/var/lib/docker", "/srv/drydock/data"}))
    plan = build(app(compose=COMPOSE), on, choice("overwrite", compose_dir="/srv/new"))
    assert not plan.bind_sources and not plan.write_targets and not plan.written
    assert p.resolution_paths(plan) == sorted(
        {"/srv", "/var/lib/docker", "/srv/drydock/data", "/srv/shared"}
    )
    plan = build(app(), on, choice("overwrite"))
    assert p.resolution_paths(plan) == []


def test_resolved_compose_dir_is_checked_again() -> None:
    plan = build(app(compose=COMPOSE), target(), choice("overwrite", compose_dir="/srv/new"))
    assert p.resolved_problems(plan, {"/srv": "/srv"}) == []
    assert p.resolved_problems(plan, {}) == ["Host path /srv was not resolved on the host."]
    assert p.resolved_problems(plan, {"/srv": "/"}) == [
        "/srv leads to the root directory on the host. Choose another directory."
    ]
    assert p.resolved_problems(plan, {"/srv": "/etc"}) == [
        "/srv leads to /etc: Binding /etc is refused for every role."
    ]
    assert p.resolved_problems(plan, {"/srv": "/usr/local"}) == [
        "Drydock never writes to /usr/local/new."
    ]
    assert p.resolved_problems(plan, {"/srv": "/opt"}) == [
        "Host path /srv/new leads to /opt/new, which needs a superadmin's acknowledgement. "
        "Restore it with /opt/new itself."
    ]
    on = target(own_paths=frozenset({"/data/drydock"}))
    plan = build(app(compose=COMPOSE), on, choice("overwrite", compose_dir="/srv/drydock"))
    assert "Host path /data/drydock belongs to drydock's own deployment." in p.resolved_problems(
        plan, {"/srv": "/data", "/data/drydock": "/data/drydock"}
    )


def test_compose_live_notes_name_users_the_plan_did_not() -> None:
    users = (
        p.BindUse(OTHER_ID, "reader", "running", "/srv/link"),
        p.BindUse(OTHER_ID, "named", "running", "/srv"),
    )
    plan = build(
        app(compose=COMPOSE), target(bind_users=users), choice("overwrite", compose_dir="/srv/new")
    )
    resolved = {"/srv": "/srv", "/srv/link": "/srv"}
    assert p.compose_live_notes(plan, resolved) == [
        "Container reader mounts /srv on the host, so it can read the restored .env files."
    ]


def test_choice_round_trips_compose_dir() -> None:
    chosen = p.Choice(host_id=2, mode="overwrite", compose_dir="/srv/new")
    stored = json.loads(json.dumps(chosen.to_dict()))
    assert stored["compose_dir"] == "/srv/new"
    assert p.Choice.from_dict(stored) == chosen
    phase3 = {k: v for k, v in stored.items() if k != "compose_dir"}
    assert p.Choice.from_dict(phase3) == p.Choice(host_id=2, mode="overwrite")
    with pytest.raises(p.PlanError, match="compose_dir is not valid"):
        p.Choice.from_dict(stored | {"compose_dir": 5})


def test_stack_lookups_list_the_project() -> None:
    manifest, configs = app()
    lookup = p.lookups(manifest, configs, choice("new-name", new_name="copy"))
    assert lookup.projects == frozenset({"copy"})
    # A project name is no container name: a short hex one could match container IDs.
    assert "copy" not in lookup.containers
    assert "a" not in p.lookups(manifest, configs, choice("new-name", new_name="a")).containers
    assert {"copy-db-1", "copy-web-1", "copy-cache-1"} <= lookup.containers
    assert {"copy_data", "app_data"} <= lookup.volumes
    assert p.lookups(manifest, configs, choice("overwrite")).projects == frozenset({"app"})
    assert p.lookups(manifest, configs, choice("image-only")).projects == frozenset()
    manifest, configs = single()
    assert p.lookups(manifest, configs, choice("overwrite")).projects == frozenset()
    assert "fresh" in p.lookups(manifest, configs, choice("new-name", new_name="fresh")).containers


def test_facts_are_unused_by_stack_checks() -> None:
    """build_plan takes the archive facts unchanged for stacks."""
    manifest, configs = app()
    plan = p.build_plan(manifest, configs, target(), choice("overwrite"), FACTS)
    assert [d.member for d in plan.data] == ["volumes/app_data.tar"]
