"""Restore planner: create bodies, host paths, risk flags, own deployment, images and modes.

Pure: no Docker daemon. The inspect documents are trimmed copies of what Docker 29 returns
for a Compose service with a named volume, an anonymous volume, a bind mount and a custom
network.
"""

import copy
import hashlib
import json
import re
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import docker.errors
import pytest

from drydock.archive import manifest as m
from drydock.engine.capture import stem
from drydock.hosts import inventory
from drydock.restore import plan as p
from drydock.restore import risk
from drydock.security import hostpaths
from drydock.security.hostpaths import HostPathError


def hexid(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


WEB_ID = hexid("web")
OWN_ID = hexid("drydock")
OTHER_ID = hexid("other")
NET_ID = hexid("net")
ANON = hexid("anon")
ANON2 = hexid("anon2")
IMAGE_ID = "sha256:" + hexid("image")
CONFIG_DIGEST = "sha256:" + hexid("config")
FOREIGN_ID = "sha256:" + hexid("foreign")
REPO_DIGEST = "nginx@sha256:" + hexid("digest")
MAC = "02:42:ac:1e:00:0a"
SPLIT = re.compile(r"[:/,=.\s]+")
FACTS = p.ArchiveFacts()


# FIXTURES


def web_info() -> dict[str, Any]:
    """A running Compose service 'web' of project 'shop'."""
    return {
        "Id": WEB_ID,
        "Name": "/web",
        "Image": IMAGE_ID,
        "State": {"Status": "running", "Running": True},
        "Config": {
            "Hostname": WEB_ID[:12],
            "Domainname": "",
            "User": "",
            "Env": ["PATH=/usr/bin", "A=1"],
            "Cmd": ["nginx", "-g", "daemon off;"],
            "Image": "nginx:1.29",
            "Volumes": {"/cache": {}},
            "ExposedPorts": {"80/tcp": {}},
            "Labels": {
                "com.docker.compose.project": "shop",
                "com.docker.compose.service": "web",
                "com.docker.compose.container-number": "1",
                "traefik.http.routers.web.rule": "Host(`shop.example`)",
                "keep.me": "yes",
            },
            "MacAddress": MAC,
            "StopTimeout": 30,
        },
        "HostConfig": {
            "Binds": [
                "shop_content:/usr/share/nginx/html:rw",
                "/srv/shop/conf:/etc/nginx/conf.d:ro",
            ],
            # A Compose anonymous volume: only the runtime Mounts entry names it.
            "Mounts": [{"Type": "volume", "Target": "/cache", "VolumeOptions": {}}],
            "NetworkMode": "shop_backend",
            "PortBindings": {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]},
            "Links": ["/db:/web/db"],
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "AutoRemove": False,
            "ContainerIDFile": "",
            "MaskedPaths": ["/proc/kcore"],
            "ReadonlyPaths": ["/proc/bus"],
            "Dns": [],
            "ExtraHosts": [],
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": "shop_content",
                "Source": "/var/lib/docker/volumes/shop_content/_data",
                "Destination": "/usr/share/nginx/html",
                "Driver": "local",
                "RW": True,
            },
            {
                "Type": "bind",
                "Source": "/srv/shop/conf",
                "Destination": "/etc/nginx/conf.d",
                "RW": False,
            },
            {
                "Type": "volume",
                "Name": ANON,
                "Source": f"/var/lib/docker/volumes/{ANON}/_data",
                "Destination": "/cache",
                "Driver": "local",
                "RW": True,
            },
        ],
        "NetworkSettings": {
            "Networks": {
                "shop_backend": {
                    "IPAMConfig": {"IPv4Address": "172.30.0.10"},
                    "Links": None,
                    "Aliases": [WEB_ID[:12], "web", "db"],
                    "MacAddress": "",
                    "DriverOpts": None,
                    "GwPriority": 0,
                    "NetworkID": NET_ID,
                    "EndpointID": hexid("endpoint"),
                    "Gateway": "172.30.0.1",
                    "IPAddress": "172.30.0.10",
                    "DNSNames": ["web", WEB_ID[:12], "db"],
                }
            }
        },
    }


def net_info(
    name: str = "shop_backend",
    net_id: str = NET_ID,
    *,
    driver: str = "bridge",
    options: dict[str, str] | None = None,
    subnet: str = "172.30.0.0/16",
) -> dict[str, Any]:
    return {
        "Name": name,
        "Id": net_id,
        "Driver": driver,
        "Scope": "local",
        "EnableIPv6": False,
        "Internal": False,
        "Attachable": False,
        "ConfigOnly": False,
        "ConfigFrom": {"Network": ""},
        "IPAM": {
            "Driver": "default",
            "Options": None,
            "Config": [{"Subnet": subnet, "Gateway": "172.30.0.1"}],
        },
        "Options": {"com.docker.network.enable_ipv4": "true"} if options is None else options,
        "Labels": {"com.docker.compose.network": "backend", "com.docker.compose.project": "shop"},
        "Containers": {WEB_ID: {"Name": "web"}},
    }


def vol_info(name: str, *, driver: str = "local", options: dict | None = None) -> dict[str, Any]:
    return {
        "Name": name,
        "Driver": driver,
        "Options": options,
        "Labels": {"com.docker.compose.project": "shop", "com.docker.compose.volume": "content"},
        "Scope": "local",
        "Mountpoint": f"/var/lib/docker/volumes/{name}/_data",
    }


def image(**changes: Any) -> m.ImageEntry:
    values: dict[str, Any] = {
        "id": IMAGE_ID,
        "refs": ["nginx:1.29"],
        "repo_digests": [REPO_DIGEST],
        "os": "linux",
        "architecture": "amd64",
        "saved": True,
        "data_member": f"images/{IMAGE_ID.removeprefix('sha256:')}.tar",
    }
    return m.ImageEntry(**(values | changes))


def with_binds(info: dict[str, Any], binds: list[tuple[str, str, bool]]) -> dict[str, Any]:
    """Replaces the bind mounts of info with (source, destination, read-write) entries."""
    host = info["HostConfig"]
    host["Binds"] = [b for b in host["Binds"] if not b.startswith("/")]
    host["Binds"] += [f"{src}:{dst}{'' if rw else ':ro'}" for src, dst, rw in binds]
    info["Mounts"] = [mt for mt in info["Mounts"] if mt["Type"] != "bind"]
    info["Mounts"] += [
        {"Type": "bind", "Source": src, "Destination": dst, "RW": rw} for src, dst, rw in binds
    ]
    return info


def make_archive(
    infos: list[dict[str, Any]],
    *,
    networks: tuple[dict[str, Any], ...] | None = None,
    volume_configs: dict[str, dict] | None = None,
    images: list[m.ImageEntry] | None = None,
    kinds: dict[str, str] | None = None,
    data: bool = True,
    host_name: str = "local",
) -> tuple[m.Manifest, dict[str, Any]]:
    """A manifest and its config members, laid out the way capture writes them."""
    configs: dict[str, Any] = {}
    containers = []
    volumes: dict[str, list[m.MountRef]] = {}
    binds: dict[str, list[m.MountRef]] = {}
    for info in infos:
        member = f"config/containers/{info['Id']}.json"
        configs[member] = info
        containers.append(
            m.ContainerEntry(
                id=info["Id"],
                name=info["Name"].lstrip("/"),
                image=info["Config"]["Image"],
                image_id=info["Image"],
                config_member=member,
            )
        )
        for mount in info["Mounts"]:
            ref = m.MountRef(
                container=info["Id"], destination=mount["Destination"], read_only=not mount["RW"]
            )
            if mount["Type"] == "volume":
                volumes.setdefault(mount["Name"], []).append(ref)
            elif mount["Type"] == "bind":
                binds.setdefault(mount["Source"], []).append(ref)
    if images is None:
        images = [image()] if infos else []
    if networks is None:
        networks = (net_info(),) if infos else ()
    network_entries = []
    for network in networks:
        member = f"config/networks/{network['Id']}.json"
        configs[member] = network
        network_entries.append(
            m.NetworkEntry(
                id=network["Id"],
                name=network["Name"],
                driver=network["Driver"],
                config_member=member,
            )
        )
    volume_entries = []
    for name, refs in volumes.items():
        member = f"config/volumes/{stem(name)}.json"
        configs[member] = (volume_configs or {}).get(name) or vol_info(name)
        volume_entries.append(
            m.VolumeEntry(
                name=name,
                driver=configs[member]["Driver"],
                mounts=refs,
                config_member=member,
                data_member=f"volumes/{stem(name)}.tar" if data else None,
            )
        )
    bind_entries = [
        m.BindEntry(
            n=n,
            source=source,
            kind=(kinds or {}).get(source, "dir"),  # type: ignore[arg-type]
            mounts=refs,
            data_member=f"binds/{n}.tar" if data else None,
        )
        for n, (source, refs) in enumerate(binds.items())
    ]
    members = (
        [c.config_member for c in containers]
        + [i.config_member for i in images if i.config_member]
        + [n.config_member for n in network_entries]
        + [v.config_member for v in volume_entries]
        + [v.data_member for v in volume_entries if v.data_member]
        + [b.data_member for b in bind_entries if b.data_member]
        + [i.data_member for i in images if i.data_member]
    )
    manifest = m.Manifest(
        instance_id="test",
        drydock_version="0.1.0",
        created_at=datetime(2026, 10, 14, tzinfo=UTC),
        source=m.Source(
            host_name=host_name, arch="amd64", os="linux", api_version="1.52", engine_version="29"
        ),
        job=m.JobInfo(
            uuid=str(uuid.uuid4()),
            name="web",
            scope="all",
            consistency_mode="stop",
            images_reference_only_if_pullable=False,
        ),
        containers=containers,
        networks=network_entries,
        volumes=volume_entries,
        binds=bind_entries,
        images=images,
        members=members,  # type: ignore[arg-type]
    )
    return manifest, configs


def web_archive(**kwargs: Any) -> tuple[m.Manifest, dict[str, Any]]:
    return make_archive([web_info()], networks=(net_info(),), **kwargs)


def target(**changes: Any) -> p.TargetInfo:
    return p.TargetInfo(host_id=1, host_name="local", api_version="1.52", arch="x86_64", **changes)


def choice(mode: str = "new-name", **changes: Any) -> p.Choice:
    values: dict[str, Any] = {"host_id": 1, "mode": mode}
    if mode == "new-name":
        values["new_name"] = "copy"
    return p.Choice(**(values | changes))


def build(
    archive: tuple[m.Manifest, dict[str, Any]],
    on: p.TargetInfo,
    chosen: p.Choice,
    facts: p.ArchiveFacts = FACTS,
) -> p.RestorePlan:
    manifest, configs = archive
    return p.build_plan(manifest, configs, on, chosen, facts)


def refused(
    archive: tuple[m.Manifest, dict[str, Any]],
    on: p.TargetInfo,
    chosen: p.Choice,
    facts: p.ArchiveFacts = FACTS,
) -> str:
    with pytest.raises(p.PlanError) as caught:
        build(archive, on, chosen, facts)
    return str(caught.value)


def leaves(value: Any) -> list[str]:
    """Every string in a JSON-like document, dict keys included."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*leaves(k), *leaves(v))]
    if isinstance(value, list | tuple):
        return [s for item in value for s in leaves(item)]
    return []


def keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [k for k, v in value.items() for k in (k, *keys(v))]
    if isinstance(value, list | tuple):
        return [k for item in value for k in keys(item)]
    return []


def overwrite_target(**changes: Any) -> p.TargetInfo:
    """The source host itself: the original runs, its network and volumes exist."""
    values: dict[str, Any] = {
        "containers": {"web": web_info()},
        "networks": {"shop_backend": net_info()},
        "volumes": {"shop_content": vol_info("shop_content"), ANON: vol_info(ANON)},
        "volume_users": {
            "shop_content": (p.ContainerUse(WEB_ID, "web", "running"),),
            ANON: (p.ContainerUse(WEB_ID, "web", "running"),),
        },
        "bind_users": (p.BindUse(WEB_ID, "web", "running", "/srv/shop/conf"),),
    }
    return target(**(values | changes))


# CREATE BODIES


def test_new_name_bodies_hold_no_original_name_or_id() -> None:
    plan = build(web_archive(), target(), choice("new-name"))

    documents = [s.body for s in plan.containers] + [n.create for n in plan.networks]
    strings = leaves(documents) + [v.name for v in plan.volumes]
    tokens = {token for s in strings for token in SPLIT.split(s)}
    forbidden = {"web", WEB_ID, WEB_ID[:12], "shop_backend", NET_ID, "shop_content", ANON}
    assert not tokens & forbidden
    assert not [k for k in keys(documents) if k.startswith(("com.docker.compose.", "traefik."))]
    body = plan.containers[0].body
    assert plan.containers[0].name == "copy"
    assert body["Labels"] == {"keep.me": "yes"}
    assert "Hostname" not in body
    assert "MacAddress" not in body
    assert "PortBindings" not in body["HostConfig"]
    assert body["HostConfig"]["Links"] == ["db:db"]
    assert body["HostConfig"]["NetworkMode"] == "copy-shop_backend"
    endpoint = body["NetworkingConfig"]["EndpointsConfig"]["copy-shop_backend"]
    assert endpoint == {"Aliases": ["db"]}
    assert {v.name for v in plan.volumes} == {"copy-shop_content", f"copy-{ANON[:12]}"}
    assert all("Config" not in n.create["ipam"] for n in plan.networks)
    assert any("traefik.http.routers.web.rule" in w for w in plan.warnings)
    assert any("published ports" in w for w in plan.warnings)
    assert any("static IP" in w for w in plan.warnings)


def test_compose_anonymous_volume_gets_its_source() -> None:
    info = web_info()
    # An image VOLUME that neither Binds nor Mounts names.
    info["Config"]["Volumes"]["/var/cache/nginx"] = {}
    info["Mounts"].append(
        {"Type": "volume", "Name": ANON2, "Destination": "/var/cache/nginx", "RW": True}
    )
    archive = make_archive([info], networks=(net_info(),))

    new = build(archive, target(), choice("new-name")).containers[0].body["HostConfig"]
    assert new["Mounts"] == [{"Type": "volume", "Target": "/cache", "Source": f"copy-{ANON[:12]}"}]
    assert f"copy-{ANON2[:12]}:/var/cache/nginx" in new["Binds"]

    old = build(archive, target(), choice("overwrite")).containers[0].body["HostConfig"]
    assert old["Mounts"] == [{"Type": "volume", "Target": "/cache", "Source": ANON}]
    assert f"{ANON2}:/var/cache/nginx" in old["Binds"]
    assert old["Binds"][:2] == [
        "shop_content:/usr/share/nginx/html:rw",
        "/srv/shop/conf:/etc/nginx/conf.d:ro",
    ]


def test_container_network_mode_body_drops_conflicting_fields() -> None:
    manifest, _ = web_archive()
    names = p.name_map(manifest, choice("overwrite"))
    info = web_info()
    info["Config"]["Hostname"] = "vpn"  # Docker copies the peer's hostname
    info["Config"]["Domainname"] = "example.com"
    info["HostConfig"].update(
        NetworkMode="container:vpn",
        Dns=["1.1.1.1"],
        DnsOptions=["ndots:1"],
        DnsSearch=["example.com"],
        ExtraHosts=["db:10.0.0.2"],
        PublishAllPorts=True,
    )
    info["NetworkSettings"]["Networks"] = {}
    body = p.container_body(info, names=names, mode="overwrite", api_version="1.52", bind_map={})
    for key in ("Hostname", "Domainname", "ExposedPorts", "MacAddress"):
        assert key not in body
    for key in ("PortBindings", "PublishAllPorts", "Links", "Dns", "DnsOptions", "DnsSearch"):
        assert key not in body["HostConfig"]
    assert "ExtraHosts" not in body["HostConfig"]
    assert body["HostConfig"]["NetworkMode"] == "container:vpn"
    assert "NetworkingConfig" not in body

    info = web_info()
    info["Config"]["Hostname"] = "buildhost"
    info["HostConfig"]["NetworkMode"] = "host"
    info["NetworkSettings"]["Networks"] = {"host": {"NetworkID": hexid("host")}}
    warnings: list[str] = []
    body = p.container_body(
        info, names=names, mode="overwrite", api_version="1.52", bind_map={}, warnings=warnings
    )
    assert "Hostname" not in body
    assert "MacAddress" not in body
    assert "NetworkingConfig" not in body
    assert any("hostname" in w for w in warnings)


def test_overwrite_body_keeps_identity() -> None:
    plan = build(web_archive(), overwrite_target(), choice("overwrite"))

    step = plan.containers[0]
    assert step.name == "web"
    assert step.start is True
    body = step.body
    assert "MacAddress" not in body
    assert "Hostname" not in body  # it was the original's short ID
    assert body["HostConfig"]["PortBindings"] == {"80/tcp": [{"HostIp": "", "HostPort": "8080"}]}
    assert body["HostConfig"]["NetworkMode"] == "shop_backend"
    for key in ("ContainerIDFile", "MaskedPaths", "ReadonlyPaths"):
        assert key not in body["HostConfig"]
    assert body["Labels"]["com.docker.compose.project"] == "shop"
    endpoint = body["NetworkingConfig"]["EndpointsConfig"]["shop_backend"]
    assert endpoint == {
        "IPAMConfig": {"IPv4Address": "172.30.0.10"},
        "Aliases": ["db"],
        "MacAddress": MAC,
    }
    assert [(n.name, n.action, n.differences) for n in plan.networks] == [
        ("shop_backend", "reuse", ())
    ]
    assert plan.originals == (p.Original(WEB_ID, "web", "web-drydock-old", True, 30),)

    manifest, _ = web_archive()
    names = p.name_map(manifest, choice("overwrite"))
    info = web_info()
    info["NetworkSettings"]["Networks"]["shop_backend"]["GwPriority"] = 5
    old = p.container_body(info, names=names, mode="overwrite", api_version="1.47", bind_map={})
    new = p.container_body(info, names=names, mode="overwrite", api_version="1.48", bind_map={})
    assert "GwPriority" not in old["NetworkingConfig"]["EndpointsConfig"]["shop_backend"]
    assert new["NetworkingConfig"]["EndpointsConfig"]["shop_backend"]["GwPriority"] == 5


def test_mac_address_goes_to_the_primary_endpoint_even_when_it_is_empty() -> None:
    manifest, _ = web_archive()
    names = p.name_map(manifest, choice("overwrite"))
    info = web_info()
    networks = info["NetworkSettings"]["Networks"]
    # Nothing of the primary endpoint survives the filter, and another network sorts first.
    networks["shop_backend"] = {"Aliases": [WEB_ID[:12], "web"], "NetworkID": NET_ID}
    networks["a_other"] = {"Aliases": ["x"], "NetworkID": hexid("other-net")}
    body = p.container_body(info, names=names, mode="overwrite", api_version="1.52", bind_map={})
    assert body["NetworkingConfig"]["EndpointsConfig"] == {
        "a_other": {"Aliases": ["x"]},
        "shop_backend": {"MacAddress": MAC},
    }


def test_drydock_labels_are_never_restored() -> None:
    """The helper labels would make a restored object pass for one of drydock's helpers:
    hidden from the inventory, never backed up and removed by the reaper."""
    own = {"drydock.helper": "1", "drydock.instance": "abc", p.RESTORE_LABEL: "7"}
    info = web_info()
    info["Config"]["Labels"] |= own
    network = net_info()
    network["Labels"] |= own
    volume = vol_info("shop_content")
    volume["Labels"] |= own
    archive = make_archive([info], networks=(network,), volume_configs={"shop_content": volume})
    for mode in ("new-name", "overwrite"):
        plan = build(archive, target(), choice(mode))
        documents = [
            plan.containers[0].body["Labels"],
            *(n.create["labels"] for n in plan.networks),
            *(v.labels for v in plan.volumes),
        ]
        assert not [k for d in documents for k in d if k.startswith("drydock.")]
        dropped = [w for w in plan.warnings if "drydock.helper, drydock.instance, drydock." in w]
        assert len(dropped) == 3
        assert plan.containers[0].body["Labels"]["keep.me"] == "yes"


def test_new_name_needs_two_characters() -> None:
    """moby's container names are [a-zA-Z0-9][a-zA-Z0-9_.-]+."""
    message = refused(web_archive(), target(), choice(new_name="a"))
    assert "hold 2 to 63 letters" in message
    assert build(web_archive(), target(), choice(new_name="ab")).containers[0].name == "ab"


def test_unknown_endpoint_network_is_dropped_in_new_name_and_refused_in_overwrite_when_missing():
    info = web_info()
    info["NetworkSettings"]["Networks"]["legacy"] = {"Aliases": ["web"], "NetworkID": hexid("x")}
    archive = make_archive([info], networks=(net_info(),))

    plan = build(archive, target(), choice("new-name"))
    assert set(plan.containers[0].body["NetworkingConfig"]["EndpointsConfig"]) == {
        "copy-shop_backend"
    }
    assert any("Dropped network legacy" in w for w in plan.warnings)

    assert "Network legacy does not exist on host local" in refused(
        archive, target(), choice("overwrite")
    )
    plan = build(
        archive, target(networks={"legacy": net_info("legacy", hexid("x"))}), choice("overwrite")
    )
    assert set(plan.containers[0].body["NetworkingConfig"]["EndpointsConfig"]) == {
        "shop_backend",
        "legacy",
    }


def test_with_sources_rewrites_bind_sources() -> None:
    body = {
        "Image": "nginx:1.29",
        "HostConfig": {
            "Binds": ["/srv/a:/a:ro", "vol:/v", "/srv/c:/c"],
            "Mounts": [
                {"Type": "bind", "Source": "/srv/b", "Target": "/b"},
                {"Type": "volume", "Source": "/srv/b", "Target": "/v2"},
            ],
        },
    }
    original = copy.deepcopy(body)
    out = p.with_sources(body, {"/srv/a": "/data/a", "/srv/b": "/data/b"})
    assert out["HostConfig"]["Binds"] == ["/data/a:/a:ro", "vol:/v", "/srv/c:/c"]
    assert out["HostConfig"]["Mounts"][0]["Source"] == "/data/b"
    assert out["HostConfig"]["Mounts"][1]["Source"] == "/srv/b"
    assert body == original


# HOST PATHS


@pytest.mark.parametrize("mode", ["new-name", "overwrite"])
@pytest.mark.parametrize("path", ["/etc/x", "/root", "/etc"])
def test_bind_remap_onto_etc_or_root_is_rejected(mode: str, path: str) -> None:
    # The planner takes no role, so this holds for every role, superadmin included.
    message = refused(web_archive(), target(), choice(mode, bind_remaps={0: path}))
    assert f"Drydock never writes to {path}." in message


def test_wipe_of_home_is_rejected() -> None:
    archive = make_archive([with_binds(web_info(), [("/home", "/data", True)])])
    message = refused(archive, target(), choice("overwrite", wipe_binds=frozenset({0})))
    assert "Drydock never writes to /home." in message
    with pytest.raises(HostPathError):
        hostpaths.check_write_target("/home")
    assert hostpaths.check_write_target("/home/user/x") == "/home/user/x"


def test_overwrite_never_wipes_a_bind_that_was_not_opted_in() -> None:
    info = with_binds(web_info(), [("/srv/a", "/a", True), ("/srv/b", "/b", True)])
    archive = make_archive([info])

    plan = build(archive, target(), choice("overwrite", wipe_binds=frozenset({1})))
    assert sorted((w.kind, w.target) for w in plan.wipes) == [
        ("bind", "/srv/b"),
        ("volume", ANON),
        ("volume", "shop_content"),
    ]
    assert "/srv/b" in plan.write_targets
    assert [d.label for d in plan.data if d.kind == "bind-dir"] == [
        "bind mount /srv/a",
        "bind mount /srv/b",
    ]

    plan = build(archive, target(), choice("overwrite"))
    assert {w.kind for w in plan.wipes} == {"volume"}

    message = refused(
        archive, target(), choice("new-name", wipe_binds=frozenset({1}), skip_binds={0, 1})
    )
    assert "Only an overwrite restore wipes bind mounts." in message


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/var/run/docker.sock",
        "/run",
        "/run/containerd",
        "/var/lib/docker/volumes",
        "/home/u/podman.sock",
        "/proc/1",
        "/etc",
        "/var/run",
        "/var/lib/containerd/io",
        "/run/user/1000/docker.sock",
        # A rootless daemon's runtime directory holds its docker.sock.
        "/run/user/1000",
        "/var/run/user/1000/app",
        "/run/crio",
        "/var/run/podman",
        "/run/k3s/containerd",
        "/srv/crio.sock",
        "/run/cri-dockerd.sock",
    ],
)
def test_denylisted_create_binds_are_rejected(path: str) -> None:
    with pytest.raises(HostPathError, match="refused for every role"):
        hostpaths.check_bind(path)
    archive = make_archive([with_binds(web_info(), [(path, "/x", False)])], data=False)
    assert "refused for every role" in refused(archive, target(), choice("overwrite"))


@pytest.mark.parametrize(
    "path",
    [
        "/var/lib/containers/storage",
        "/var/lib/rancher/k3s",
        "/var/lib/kubelet",
        "/var/lib/buildkit",
        "/run/buildkit/buildkitd.sock",
        "/srv/buildkitd.sock",
        "/etc/rancher/k3s",
        "/etc/kubernetes/admin.conf",
    ],
)
def test_other_runtimes_state_and_sockets_are_refused(path: str) -> None:
    with pytest.raises(HostPathError, match="refused for every role"):
        hostpaths.check_bind(path)
    with pytest.raises(HostPathError, match="Drydock never writes to"):
        hostpaths.check_write_target(path)


@pytest.mark.parametrize(
    "path",
    [
        "/var/home",
        "/var/roothome",
        "/var/roothome/.ssh",
        "/var/usrlocal/bin",
        "/sysroot/ostree/deploy/fcos/var/roothome",
        "/ostree/deploy",
    ],
)
def test_ostree_real_paths_are_never_written(path: str) -> None:
    # /home, /root and /usr/local are symbolic links into /var there, so the real path
    # resolves to itself and only the denylist can stop it.
    with pytest.raises(HostPathError, match="Drydock never writes to"):
        hostpaths.check_write_target(path)
    archive = make_archive([with_binds(web_info(), [(path, "/x", True)])])
    assert f"Drydock never writes to {path}." in refused(archive, target(), choice("overwrite"))
    assert hostpaths.check_write_target("/var/home/u/app") == "/var/home/u/app"


@pytest.mark.parametrize("path", ["/bin", "/sbin/x", "/lib", "/lib32", "/lib64/x", "/libx32"])
def test_system_binaries_are_never_written(path: str) -> None:
    with pytest.raises(HostPathError, match="Drydock never writes to"):
        hostpaths.check_write_target(path)
    archive = make_archive([with_binds(web_info(), [(path, "/x", True)])])
    assert f"Drydock never writes to {path}." in refused(archive, target(), choice("overwrite"))


def test_allowed_create_binds_pass() -> None:
    assert hostpaths.check_bind("/etc/nginx") == "/etc/nginx"
    assert hostpaths.check_bind("/srv") == "/srv"
    assert hostpaths.check_bind("/run/app") == "/run/app"


def test_normalize_rejects_dotdot_and_cleans_dots() -> None:
    assert hostpaths.normalize("/srv/./a//b") == "/srv/a/b"
    assert hostpaths.normalize("//srv/a/") == "/srv/a"
    for bad in ("/srv/../etc", "/srv/..", "srv/a", "", "/a\0b", "/" + "a" * 5000, "/a\nb"):
        with pytest.raises(HostPathError):
            hostpaths.normalize(bad)
    # ':' separates the fields of a Binds entry: '/etc:/x' would bind /etc.
    for check in (hostpaths.normalize, hostpaths.check_bind, hostpaths.check_write_target):
        with pytest.raises(HostPathError, match="without ':'"):
            check("/etc:/x")
    message = refused(web_archive(), target(), choice("overwrite", bind_remaps={0: "/etc:/x"}))
    assert "without ':'" in message
    with pytest.raises(HostPathError):
        hostpaths.normalize(None)  # type: ignore[arg-type]


def test_resolve_follows_symlinks_like_realpath() -> None:
    tree: dict[str, tuple[str, str | None]] = {
        "/srv": ("dir", None),
        "/srv/link": ("link", "/etc"),
        "/etc": ("dir", None),
        "/srv/rel": ("link", "data/x"),
        "/srv/data": ("dir", None),
        "/srv/data/x": ("link", "../real"),
        "/srv/real": ("dir", None),
        "/srv/file": ("file", None),
        "/loop": ("dir", None),
        "/loop/a": ("link", "b"),
        "/loop/b": ("link", "/loop/a"),
    }
    lstat = tree.get
    assert hostpaths.resolve("/srv/link", lstat) == "/etc"
    assert hostpaths.resolve("/srv/link/nginx", lstat) == "/etc/nginx"
    assert hostpaths.resolve("/srv/rel/conf", lstat) == "/srv/real/conf"
    assert hostpaths.resolve("/srv/missing/a/b", lstat) == "/srv/missing/a/b"
    assert hostpaths.resolve("/srv/file", lstat) == "/srv/file"
    assert hostpaths.resolve("/", lstat) == "/"
    with pytest.raises(HostPathError, match="too many symbolic links"):
        hostpaths.resolve("/loop/a", lstat)
    with pytest.raises(HostPathError):
        hostpaths.resolve("/srv/file/x", lstat)
    with pytest.raises(HostPathError):
        hostpaths.resolve("/srv/../etc", lstat)


def test_host_backed_volumes_count_as_host_paths() -> None:
    bind_opts = {"type": "none", "o": "bind", "device": "/etc"}
    assert hostpaths.host_volume_device("local", bind_opts) == "/etc"
    assert hostpaths.host_volume_device("local", {"o": "rbind,ro", "device": "/x"}) == "/x"
    nfs = {"type": "nfs", "o": "addr=10.0.0.1,password=hunter2", "device": ":/export"}
    assert hostpaths.host_volume_device("local", nfs) is None
    assert hostpaths.host_volume_device("other", bind_opts) is None
    assert hostpaths.host_volume_device("local", None) is None

    archive = web_archive(
        volume_configs={"shop_content": vol_info("shop_content", options=bind_opts)}
    )
    assert "Binding /etc is refused for every role." in refused(
        archive, target(), choice("new-name")
    )

    srv = {"type": "none", "o": "bind", "device": "/srv/data"}
    archive = web_archive(volume_configs={"shop_content": vol_info("shop_content", options=srv)})
    plan = build(archive, target(), choice("overwrite"))
    assert "volume:shop_content:driver" in {f.key for f in plan.risk}
    assert "/srv/data" in plan.bind_sources
    assert "/srv/data" in plan.write_targets
    step = next(v for v in plan.volumes if v.name == "shop_content")
    assert (step.action, step.device) == ("create", "/srv/data")
    # A copy would bind the directory the original's volume holds, whatever it is called.
    assert (
        "Volume shop_content keeps its data in host path /srv/data, so a copy would share it "
        "with the original." in refused(archive, target(), choice("new-name"))
    )
    # On another host the device is a host path like any other: checked and flagged.
    elsewhere = replace(target(), host_name="other")
    plan = build(archive, elsewhere, choice("new-name"))
    step = next(v for v in plan.volumes if v.name == "copy-shop_content")
    assert (step.action, step.device) == ("create", "/srv/data")
    assert "volume:copy-shop_content:driver" in {f.key for f in plan.risk}
    assert "/srv/data" in plan.bind_sources
    assert "/srv/data" in plan.write_targets
    # Unless the original volume is there too, over the same directory.
    on = replace(elsewhere, volumes={"shop_content": vol_info("shop_content", options=srv)})
    assert "would share it with the original" in refused(archive, on, choice("new-name"))

    # Local volumes that mount anything but a bind, tmpfs or a network share are refused.
    overlay = {
        "type": "overlay",
        "device": "overlay",
        "o": "lowerdir=/srv/l,upperdir=/etc/cron.d,workdir=/etc/w",
    }
    for options in (overlay, {"type": "ext4", "device": "/dev/sda1"}, {"device": "/dev/sda1"}):
        with pytest.raises(HostPathError, match="refused for every role"):
            hostpaths.check_volume("local", options)
        archive = web_archive(
            volume_configs={"shop_content": vol_info("shop_content", options=options)}
        )
        for mode in ("new-name", "overwrite"):
            message = refused(archive, target(), choice(mode))
            assert "local volume that mounts a device or a filesystem" in message
        on = target(volumes={"tv": vol_info("tv", options=options)})
        assert "refused for every role" in refused(
            archive, on, choice("data-only", volume_map={"shop_content": "tv"})
        )
    assert hostpaths.check_volume("local", {"type": "tmpfs", "device": "tmpfs"}) is None
    assert hostpaths.check_volume("local", nfs) is None
    assert hostpaths.check_volume("local", {"type": "cifs", "device": "//nas/share"}) is None
    assert hostpaths.check_volume("local", bind_opts) == "/etc"
    assert hostpaths.check_volume("local", {}) is None
    assert hostpaths.check_volume("rexray", {"type": "ext4"}) is None

    archive = web_archive(volume_configs={"shop_content": vol_info("shop_content", options=nfs)})
    flag = next(f for f in build(archive, target(), choice("overwrite")).risk if "volume:" in f.key)
    assert "hunter2" not in flag.value
    assert "nfs" in flag.value

    home = {"type": "none", "o": "bind", "device": "/home"}
    on = overwrite_target(
        volumes={"shop_content": vol_info("shop_content", options=home), ANON: vol_info(ANON)}
    )
    assert "Drydock never writes to /home." in refused(web_archive(), on, choice("overwrite"))

    info = web_info()
    info["HostConfig"]["Mounts"][0]["VolumeOptions"] = {
        "NoCopy": True,
        "DriverConfig": {"Name": "local", "Options": {"device": "/", "o": "bind"}},
        "Labels": {"com.docker.compose.volume": "cache"},
    }
    plan = build(make_archive([info], networks=(net_info(),)), target(), choice("overwrite"))
    mounts = plan.containers[0].body["HostConfig"]["Mounts"]
    assert mounts == [
        {"Type": "volume", "Target": "/cache", "Source": ANON, "VolumeOptions": {"NoCopy": True}}
    ]


@pytest.mark.parametrize(
    ("driver", "options"),
    [
        ("local", {"type": "nfs", "o": "addr=10.0.0.1", "device": ":/export"}),
        ("local", {"type": "nfs4", "o": "addr=10.0.0.1", "device": ":/export"}),
        ("local", {"type": "cifs", "device": "//nas/share"}),
        ("local", {"type": "smb3", "device": "//nas/share"}),
        ("rexray", None),
        ("vieux/sshfs", {"sshcmd": "u@nas:/export"}),
    ],
)
def test_new_name_copies_of_shared_storage_are_refused(driver: str, options: dict | None) -> None:
    config = vol_info("shop_content", driver=driver, options=options)
    archive = web_archive(volume_configs={"shop_content": config})
    message = "so a copy would share it with the original. Restore it in overwrite mode instead."
    # On the source host and on any other: the share is the same storage.
    for on in (target(), replace(target(), host_name="other")):
        assert message in refused(archive, on, choice("new-name"))
    build(archive, target(), choice("overwrite"))
    # tmpfs and plain local volumes are private to each copy.
    tmpfs = vol_info("shop_content", options={"type": "tmpfs", "device": "tmpfs"})
    build(web_archive(volume_configs={"shop_content": tmpfs}), target(), choice("new-name"))


def test_setid_data_written_into_host_backed_volumes_is_flagged() -> None:
    srv = {"type": "none", "o": "bind", "device": "/srv/content"}
    archive = web_archive(volume_configs={"shop_content": vol_info("shop_content", options=srv)})
    facts = p.ArchiveFacts(setid_members=frozenset({"volumes/shop_content.tar"}))
    plan = build(archive, target(), choice("overwrite"), facts)
    flag = next(f for f in plan.risk if f.key == "volume-data:shop_content:setid")
    assert (flag.subject, flag.field) == ("shop_content", "setid")
    # Not without such files, and not in a volume Docker keeps.
    plan = build(archive, target(), choice("overwrite"))
    assert not [f for f in plan.risk if f.field == "setid"]
    plan = build(web_archive(), target(), choice("overwrite"), facts)
    assert not [f for f in plan.risk if f.field == "setid"]

    # Data-only into a host-backed target volume.
    volumes = {"tv": vol_info("tv", options=srv)}
    chosen = choice("data-only", volume_map={"shop_content": "tv"})
    plan = build(web_archive(), target(volumes=volumes), chosen, facts)
    assert "volume-data:tv:setid" in {f.key for f in plan.risk}
    plan = build(web_archive(), target(volumes={"tv": vol_info("tv")}), chosen, facts)
    assert not [f for f in plan.risk if f.field == "setid"]


def test_nested_write_targets_are_refused() -> None:
    info = with_binds(web_info(), [("/srv/app", "/app", True), ("/srv/app/sub", "/sub", True)])
    message = refused(make_archive([info]), target(), choice("overwrite"))
    assert "/srv/app/sub lies inside /srv/app, which this restore writes." in message

    # A read-only bind below a written directory could be redirected just the same.
    info = with_binds(web_info(), [("/srv/app", "/app", True), ("/srv/app/conf", "/c", False)])
    archive = make_archive([info])
    plan_choice = choice("overwrite", skip_binds=frozenset({1}))
    assert "lies inside /srv/app" in refused(archive, target(), plan_choice)

    # Side by side is fine, and so are two file binds in one directory.
    info = with_binds(
        web_info(),
        [("/srv/app/a.ini", "/a.ini", True), ("/srv/app/b.ini", "/b.ini", True)],
    )
    kinds = {"/srv/app/a.ini": "file", "/srv/app/b.ini": "file"}
    plan = build(make_archive([info], kinds=kinds), target(), choice("overwrite"))
    files = [(d.kind, d.target, d.rename_to) for d in plan.data if d.kind == "bind-file"]
    assert files == [
        ("bind-file", "/srv/app/a.ini", "a.ini"),
        ("bind-file", "/srv/app/b.ini", "b.ini"),
    ]
    assert plan.write_targets == ("/srv/app",)


def test_live_bind_users_block_writes() -> None:
    info = with_binds(web_info(), [("/srv/app", "/app", True)])
    archive = make_archive([info])
    for source in ("/srv/app/logs", "/srv/app", "/srv"):
        on = target(bind_users=(p.BindUse(OTHER_ID, "tail", "running", source),))
        message = refused(archive, on, choice("overwrite"))
        assert "Bind mount /srv/app is also used by running container tail. Stop it first." in (
            message
        )
    # A container that binds the host root sees every write target.
    on = target(bind_users=(p.BindUse(OTHER_ID, "cadvisor", "running", "/"),))
    assert "Bind mount /srv/app is also used by running container cadvisor." in refused(
        archive, on, choice("overwrite")
    )
    on = target(bind_users=(p.BindUse(OTHER_ID, "tail", "running", "//srv/app/"),))
    assert "also used by running container tail" in refused(archive, on, choice("overwrite"))
    on = target(bind_users=(p.BindUse(OTHER_ID, "tail", "exited", "/srv/app"),))
    build(archive, on, choice("overwrite"))
    on = target(bind_users=(p.BindUse(OTHER_ID, "tail", "running", "/srv/other"),))
    build(archive, on, choice("overwrite"))
    # The original itself is stopped by the restore.
    on = overwrite_target(bind_users=(p.BindUse(WEB_ID, "web", "running", "/srv/app"),))
    build(archive, on, choice("overwrite"))


def test_live_users_of_host_backed_volumes_block_writes() -> None:
    """The container list shows a host-backed volume's mount as a volume, so inspect_target
    reports its device as a BindUse. The TargetInfo here is built that way: the database's
    volume is not one the restore looks up."""
    pg = {"type": "none", "o": "bind", "device": "/srv/pg"}
    archive = web_archive()
    volumes = {"restored": vol_info("restored", options=pg)}
    chosen = choice("data-only", volume_map={"shop_content": "restored"})
    plan = build(archive, target(volumes=volumes), chosen)
    assert plan.write_targets == ("/srv/pg",)

    # Another volume over the same directory, used by a running database.
    db = (p.BindUse(OTHER_ID, "db", "running", "/srv/pg"),)
    message = refused(archive, target(volumes=volumes, bind_users=db), chosen)
    assert "Bind mount /srv/pg is also used by running container db. Stop it first." in message
    on = target(volumes=volumes, bind_users=(p.BindUse(OTHER_ID, "db", "paused", "/srv/pg/x"),))
    assert "also used by paused container db" in refused(archive, on, chosen)

    # Overwrite: a bind written into the directory a live container's volume holds.
    info = with_binds(web_info(), [("/srv/pg", "/pg", True)])
    message = refused(make_archive([info]), target(bind_users=db), choice("overwrite"))
    assert "Bind mount /srv/pg is also used by running container db." in message

    # A looked-up volume's own users are matched by its device as well.
    volumes["db_data"] = vol_info("db_data", options=pg)
    users = {"db_data": (p.ContainerUse(OTHER_ID, "db", "running"),)}
    message = refused(archive, target(volumes=volumes, volume_users=users), chosen)
    assert "Bind mount /srv/pg is also used by running container db." in message


def test_two_items_never_write_one_host_path() -> None:
    info = with_binds(web_info(), [("/srv/a", "/a", True), ("/srv/b", "/b", True)])
    archive = make_archive([info])
    chosen = choice("overwrite", bind_remaps={0: "/srv/b"}, wipe_binds=frozenset({1}))
    message = refused(archive, target(), chosen)
    assert "Host path /srv/b is the target of more than one item." in message
    # Onto the device of a host-backed volume this restore writes.
    backed = {"type": "none", "o": "bind", "device": "/srv/vol"}
    archive = make_archive(
        [info], volume_configs={"shop_content": vol_info("shop_content", options=backed)}
    )
    message = refused(archive, target(), choice("overwrite", bind_remaps={0: "/srv/vol"}))
    assert "Host path /srv/vol is the target of more than one item." in message
    # Data-only: two volumes over one directory.
    volumes = {
        "t1": vol_info("t1", options=backed),
        "t2": vol_info("t2", options=backed),
    }
    chosen = choice("data-only", volume_map={"shop_content": "t1", ANON: "t2"})
    message = refused(web_archive(), target(volumes=volumes), chosen)
    assert "Host path /srv/vol is the target of more than one item." in message
    # A bind's data and its own wipe are one item.
    plan = build(archive, target(), choice("overwrite", wipe_binds=frozenset({0})))
    assert ("bind", "/srv/a") in {(w.kind, w.target) for w in plan.wipes}


def test_only_binds_the_container_makes_are_written() -> None:
    """The manifest's bind list comes from the runtime mounts. A bind the archived config
    does not make gets no data and no wipe, however the archive was put together."""
    info = with_binds(web_info(), [("/srv/app", "/app", True)])
    manifest, configs = make_archive([info])
    cron = m.BindEntry(
        n=1,
        source="/var/spool/cron/crontabs",
        kind="dir",
        mounts=[m.MountRef(container=WEB_ID, destination="/cron", read_only=False)],
        data_member="binds/1.tar",
    )
    manifest = manifest.model_copy(update={"binds": [*manifest.binds, cron]})
    plan = build((manifest, configs), target(), choice("overwrite"))
    assert {d.target for d in plan.data if d.kind.startswith("bind")} == {"/srv/app"}
    assert "/var/spool/cron/crontabs" not in plan.write_targets
    assert any("/var/spool/cron/crontabs is not restored" in w for w in plan.warnings)
    for chosen in (
        choice("overwrite", wipe_binds=frozenset({1})),
        choice("overwrite", bind_remaps={1: "/srv/cron"}),
    ):
        assert "is not a bind of the archived container" in refused(
            (manifest, configs), target(), chosen
        )

    # A bind of the config whose record names another container is refused.
    foreign = m.MountRef(container=OTHER_ID, destination="/app", read_only=False)
    stray = manifest.binds[0].model_copy(update={"mounts": [foreign]})
    manifest = manifest.model_copy(update={"binds": [stray]})
    message = refused((manifest, configs), target(), choice("overwrite"))
    assert "record of bind mount /srv/app does not match its container" in message

    # A bind of the config that the manifest leaves out is refused, so a new-name copy
    # cannot share it without the remap, skip or share choice.
    manifest = manifest.model_copy(update={"binds": []})
    message = refused((manifest, configs), target(), choice("new-name"))
    assert "The archive does not describe bind mount /srv/app." in message

    # Writable in the config while the record says read-only still needs the choice.
    ro = manifest.model_copy(
        update={
            "binds": [
                m.BindEntry(
                    n=0,
                    source="/srv/app",
                    kind="dir",
                    mounts=[m.MountRef(container=WEB_ID, destination="/app", read_only=True)],
                )
            ]
        }
    )
    assert "would be shared with the original" in refused((ro, configs), target(), choice())


def test_writes_outside_the_data_trees_are_flagged() -> None:
    # Writing and wiping a data tree's root needs a superadmin.
    for root in ("/mnt", "/srv"):
        info = with_binds(web_info(), [(root, "/x", True)])
        wipe = choice("overwrite", wipe_binds=frozenset({0}))
        plan = build(make_archive([info]), target(), wipe)
        assert {f"bind-write:{root}", f"web:bind:{root}"} <= {f.key for f in plan.risk}
        assert ("bind", root) in {(w.kind, w.target) for w in plan.wipes}
    info = with_binds(web_info(), [("/var/www/html", "/html", True)])
    plan = build(make_archive([info]), target(), choice("overwrite"))
    assert {"bind-write:/var/www/html", "web:bind:/var/www/html"} <= {f.key for f in plan.risk}
    info = with_binds(web_info(), [("/srv/www", "/html", True)])
    plan = build(make_archive([info]), target(), choice("overwrite"))
    assert not [f for f in plan.risk if "/srv/www" in f.key]


def test_resolved_paths_are_checked_again() -> None:
    own = frozenset({"/srv/drydock-backups"})
    info = with_binds(web_info(), [("/srv/app", "/app", True), ("/srv/conf", "/c", False)])
    plan = build(make_archive([info]), target(own_paths=own), choice("overwrite"))
    assert plan.own_paths == ("/srv/drydock-backups",)
    same = {path: path for path in (*plan.bind_sources, *plan.write_targets)}
    assert p.resolved_problems(plan, same) == []

    def problems(**changes: str) -> str:
        return " ".join(p.resolved_problems(plan, same | changes))

    # A symbolic link to a path the denylist refuses, to drydock's own paths, or to one
    # that needs a superadmin's acknowledgement.
    assert "Drydock never writes to /etc." in problems(**{"/srv/app": "/etc"})
    assert "Binding /run/docker.sock is refused" in problems(**{"/srv/conf": "/run/docker.sock"})
    message = problems(**{"/srv/conf": "/srv/drydock-backups/x"})
    assert "Host path /srv/drydock-backups/x belongs to drydock's own deployment." in message
    message = problems(**{"/srv/conf": "/etc/cron.d"})
    assert "Host path /srv/conf leads to /etc/cron.d, which needs a superadmin's" in message
    # A link inside the data trees is fine; a path left unresolved is not.
    assert p.resolved_problems(plan, same | {"/srv/conf": "/data/conf"}) == []
    del same["/srv/conf"]
    assert "Host path /srv/conf was not resolved" in " ".join(p.resolved_problems(plan, same))


def test_resolved_paths_are_related_again() -> None:
    """A symbolic link can make two paths one, so the own-path, live-user, one-writer and
    nesting checks run again on the resolved paths."""
    # Drydock's own data given through /home, a link to /var/home (Fedora Atomic).
    own = frozenset({"/home/u/drydock/data"})
    info = with_binds(web_info(), [("/var/home/u/drydock/data", "/app", True)])
    wipe = choice("overwrite", wipe_binds=frozenset({0}))
    plan = build(make_archive([info]), target(own_paths=own), wipe)
    paths = p.resolution_paths(plan)
    assert "/home/u/drydock/data" in paths
    same = {path: path for path in paths}
    assert p.resolved_problems(plan, same) == []
    links = same | {"/home/u/drydock/data": "/var/home/u/drydock/data"}
    message = " ".join(p.resolved_problems(plan, links))
    assert "Host path /var/home/u/drydock/data belongs to drydock's own deployment." in message

    # A live container binds the real directory of a written link.
    info = with_binds(web_info(), [("/srv/link", "/app", True)])
    on = target(bind_users=(p.BindUse(OTHER_ID, "db", "running", "//srv/real/"),))
    plan = build(make_archive([info]), on, wipe)
    assert plan.live_users == (p.BindUse(OTHER_ID, "db", "running", "/srv/real"),)
    paths = p.resolution_paths(plan)
    assert "/srv/real" in paths
    same = {path: path for path in paths}
    assert p.resolved_problems(plan, same) == []
    message = " ".join(p.resolved_problems(plan, same | {"/srv/link": "/srv/real"}))
    assert "Bind mount /srv/link is also used by running container db. Stop it first." in message
    on = target(bind_users=(p.BindUse(OTHER_ID, "db", "exited", "/srv/real"),))
    assert build(make_archive([info]), on, wipe).live_users == ()

    # One written path resolves inside, or onto, another.
    info = with_binds(web_info(), [("/srv/a", "/a", True), ("/srv/b", "/b", True)])
    plan = build(make_archive([info]), target(), wipe)
    assert plan.written == ("/srv/a", "/srv/b")
    same = {path: path for path in p.resolution_paths(plan)}
    assert p.resolved_problems(plan, same) == []
    message = " ".join(p.resolved_problems(plan, same | {"/srv/b": "/srv/a/sub"}))
    assert "/srv/b leads to /srv/a/sub, inside /srv/a, which this restore writes." in message
    message = " ".join(p.resolved_problems(plan, same | {"/srv/b": "/srv/a"}))
    assert "Host paths /srv/a and /srv/b both lead to /srv/a" in message
    # Nothing to mount or write: nothing to resolve.
    image_only = build(make_archive([], images=[image()]), target(), choice("image-only"))
    assert p.resolution_paths(image_only) == []


# RISK AND OWN DEPLOYMENT


def test_risk_flags_cover_the_plan_list() -> None:
    body = {
        "HostConfig": {
            "Privileged": True,
            "CapAdd": ["SYS_ADMIN"],
            "Devices": [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm"}],
            "DeviceCgroupRules": ["b *:* rwm"],
            "DeviceRequests": [{"Driver": "nvidia", "Count": -1}],
            "PidMode": "host",
            "IpcMode": "host",
            "UsernsMode": "host",
            "UTSMode": "host",
            "CgroupnsMode": "host",
            "SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined", "apparmor=custom"],
            "Runtime": "nvidia",
            "Sysctls": {"net.ipv4.ip_forward": "1"},
            "Binds": [
                "/:/host:rshared",
                "/etc:/e",
                "/root:/r",
                "/proc:/p",
                "/sys:/s",
                "/dev:/d",
                "/boot:/b",
                "/var/lib/x:/x",
                "/srv/app.sock:/app.sock",
                "/srv/ok:/ok",
                "data:/data",
            ],
            "Mounts": [
                {"Type": "bind", "Source": "/srv/m", "BindOptions": {"Propagation": "rshared"}}
            ],
            "VolumesFrom": ["other:ro"],
        }
    }
    found = risk.flags("web", body)
    assert {f.key for f in found} == {
        "web:Privileged",
        "web:CapAdd",
        "web:Devices",
        "web:DeviceCgroupRules",
        "web:DeviceRequests",
        "web:PidMode",
        "web:IpcMode",
        "web:UsernsMode",
        "web:UTSMode",
        "web:CgroupnsMode",
        "web:SecurityOpt",
        "web:Runtime",
        "web:Sysctls",
        "web:propagation:/",
        "web:propagation:/srv/m",
        "web:bind:/",
        "web:bind:/etc",
        "web:bind:/root",
        "web:bind:/proc",
        "web:bind:/sys",
        "web:bind:/dev",
        "web:bind:/boot",
        "web:bind:/var/lib/x",
        "web:bind:/srv/app.sock",
        "web:VolumesFrom",
    }
    assert [f.key for f in risk.flags("web", body)] == [f.key for f in found]
    security = next(f for f in found if f.field == "SecurityOpt")
    assert security.value == "seccomp=unconfined, apparmor=custom"
    assert all(f.subject == "web" for f in found)

    for mode in ("NetworkMode", "PidMode", "IpcMode"):
        sidecar = {"HostConfig": {mode: "container:vpn"}}
        assert [f.key for f in risk.flags("web", sidecar)] == [f"web:{mode}"]
        assert risk.flags("web", sidecar, frozenset({"vpn"})) == []
    assert [f.key for f in risk.flags("web", {"HostConfig": {"NetworkMode": "host"}})] == [
        "web:NetworkMode"
    ]
    quiet = {"HostConfig": {"SecurityOpt": ["no-new-privileges"], "Runtime": "runc"}}
    assert risk.flags("web", quiet) == []
    # moby reads key=value (and the deprecated key:value) with Go's ParseBool.
    for option in ("no-new-privileges:true", "no-new-privileges=true", "no-new-privileges=1"):
        assert risk.flags("web", {"HostConfig": {"SecurityOpt": [option]}}) == []
    # Turning it off undoes a daemon that sets it by default.
    for option in ("no-new-privileges=false", "no-new-privileges:0", "no-new-privileges=yes"):
        flagged = risk.flags("web", {"HostConfig": {"SecurityOpt": [option]}})
        assert [f.key for f in flagged] == ["web:SecurityOpt"]
    assert risk.flags("web", {"HostConfig": {"VolumesFrom": ["mine"]}}, frozenset({"mine"})) == []

    # Remapping a flagged bind removes its flag.
    info = with_binds(web_info(), [("/etc/nginx", "/etc/nginx", False)])
    archive = make_archive([info], data=False)
    plan = build(archive, target(), choice("overwrite"))
    assert "web:bind:/etc/nginx" in {f.key for f in plan.risk}
    plan = build(archive, target(), choice("overwrite", bind_remaps={0: "/srv/nginx"}))
    assert not [f for f in plan.risk if f.field == "bind"]


@pytest.mark.parametrize(
    "source",
    [
        "/usr",
        "/bin",
        "/opt/cni/bin",
        "/var/spool/cron/crontabs",
        "/run/systemd",
        "/var/run/dbus",
        "/tmp/x",  # noqa: S108 (a host path in a create body, not a file)
        "/var/www",
        "/home",
        "/home/u",
        "/home/u/.ssh",
        "/home/u/app/.config/autostart",
        # On every login's PATH on Debian and Ubuntu.
        "/home/u/bin",
        "/home/u/bin/sudo",
        "/srv/run/app.sock",
        # The roots themselves: every mounted disk, every application's data.
        "/srv",
        "/mnt",
        "/media",
        "/data",
    ],
)
def test_binds_outside_the_data_trees_are_flagged(source: str) -> None:
    body = {"HostConfig": {"Binds": [f"{source}:/x"]}}
    assert [f.key for f in risk.flags("web", body)] == [f"web:bind:{source}"]
    body = {"HostConfig": {"Mounts": [{"Type": "bind", "Source": source, "Target": "/x"}]}}
    assert [f.key for f in risk.flags("web", body)] == [f"web:bind:{source}"]


@pytest.mark.parametrize("source", ["/srv/app", "/mnt/disk", "/media/u", "/data/x"])
def test_binds_inside_the_data_trees_are_not_flagged(source: str) -> None:
    assert risk.flags("web", {"HostConfig": {"Binds": [f"{source}:/x"]}}) == []
    assert risk.flags("web", {"HostConfig": {"Binds": ["/home/u/app:/x:ro"]}}) == []
    assert risk.flags("web", {"HostConfig": {"Binds": ["/home/u/app/bin:/x"]}}) == []


def test_cgroup_oom_and_volume_driver_fields_are_flagged() -> None:
    body = {
        "HostConfig": {
            "CgroupParent": "/",
            "OomScoreAdj": -1000,
            "OomKillDisable": True,
            "VolumeDriver": "rexray",
        }
    }
    found = {f.key: f.value for f in risk.flags("web", body)}
    assert found == {
        "web:CgroupParent": "/",
        "web:OomScoreAdj": "-1000",
        "web:OomKillDisable": "true",
        "web:VolumeDriver": "rexray",
    }
    quiet = {
        "HostConfig": {
            "CgroupParent": "",
            "OomScoreAdj": 500,
            "OomKillDisable": False,
            "VolumeDriver": "local",
        }
    }
    assert risk.flags("web", quiet) == []
    assert risk.flags("web", {"HostConfig": {"OomScoreAdj": 0, "VolumeDriver": ""}}) == []


def test_own_deployment_cannot_be_joined() -> None:
    proxy_id = hexid("proxy-net")
    info = web_info()
    info["HostConfig"]["NetworkMode"] = "drydock_docker-proxy"
    info["NetworkSettings"]["Networks"] = {"drydock_docker-proxy": {"Aliases": []}}
    archive = make_archive([info], networks=(net_info("drydock_docker-proxy", proxy_id),))
    on = target(
        networks={"drydock_docker-proxy": net_info("drydock_docker-proxy", proxy_id)},
        own_networks=frozenset({"drydock_docker-proxy", proxy_id}),
    )
    assert "Network drydock_docker-proxy belongs to drydock's own deployment." in refused(
        archive, on, choice("overwrite")
    )

    on = target(own_volumes=frozenset({"shop_content"}))
    assert "Volume shop_content belongs to drydock's own deployment." in refused(
        web_archive(), on, choice("overwrite")
    )

    own = {"Id": OWN_ID, "Name": "/drydock", "State": {"Status": "running"}}
    info = web_info()
    info["HostConfig"]["VolumesFrom"] = ["drydock:ro"]
    archive = make_archive([info], networks=(net_info(),))
    assert "drydock" in p.lookups(*archive, choice("overwrite")).containers
    on = target(containers={"drydock": own}, own=frozenset({OWN_ID}))
    assert "Container drydock belongs to drydock's own deployment." in refused(
        archive, on, choice("overwrite")
    )

    info = web_info()
    info["HostConfig"]["NetworkMode"] = f"container:{OWN_ID}"
    info["NetworkSettings"]["Networks"] = {}
    archive = make_archive([info], networks=(net_info(),))
    on = target(own=frozenset({OWN_ID}))
    assert f"Container {OWN_ID} belongs to drydock's own deployment." in refused(
        archive, on, choice("overwrite")
    )

    on = target(containers={"web": {**web_info(), "Id": OWN_ID}}, own=frozenset({OWN_ID}))
    assert "Container web belongs to drydock's own deployment." in refused(
        web_archive(), on, choice("overwrite")
    )

    # A container named like part of an own ID would stand in for it in name lookups.
    on = target(own=frozenset({OWN_ID}))
    for name in (OWN_ID[:12], OWN_ID[:40]):
        message = refused(web_archive(), on, choice("new-name", new_name=name))
        assert f"Container name {name} names drydock's own deployment." in message
    build(web_archive(), on, choice("new-name", new_name=OTHER_ID[:12]))


def test_own_host_paths_cannot_be_mounted_or_written() -> None:
    own = frozenset({"/opt/drydock/drydock_secret_key", "/srv/drydock-backups", "/srv/docker"})
    on = target(own_paths=own)
    for source in ("/opt/drydock", "/opt", "/srv/docker/volumes/x/_data", "/srv"):
        info = with_binds(web_info(), [(source, "/x", False)])
        archive = make_archive([info], data=False)
        message = refused(archive, on, choice("overwrite"))
        assert f"Host path {source} belongs to drydock's own deployment." in message
    # Written into a remapped bind, and through a host-backed volume.
    message = refused(
        web_archive(), on, choice("overwrite", bind_remaps={0: "/srv/drydock-backups/x"})
    )
    assert "Host path /srv/drydock-backups/x belongs to drydock's own deployment." in message
    backed = {"o": "bind", "device": "/srv/drydock-backups"}
    volumes = {"tv": vol_info("tv", options=backed)}
    message = refused(
        web_archive(),
        target(volumes=volumes, own_paths=own),
        choice("data-only", volume_map={"shop_content": "tv"}),
    )
    assert "Host path /srv/drydock-backups belongs to drydock's own deployment." in message
    # Beside them is fine.
    build(
        make_archive([with_binds(web_info(), [("/srv/app", "/x", True)])]), on, choice("overwrite")
    )


def test_network_driver_and_options_are_flagged() -> None:
    macvlan = net_info(driver="macvlan", options={"parent": "eth0"})
    plan = build(make_archive([web_info()], networks=(macvlan,)), target(), choice("overwrite"))
    flag = next(f for f in plan.risk if f.key == "network:shop_backend:driver")
    assert flag.value == "driver macvlan, parent eth0"
    assert plan.networks[0].create["ipam"]["Config"] == [
        {"Subnet": "172.30.0.0/16", "Gateway": "172.30.0.1"}
    ]

    bridge = net_info(options={"com.docker.network.bridge.name": "br-shop"})
    plan = build(make_archive([web_info()], networks=(bridge,)), target(), choice("new-name"))
    create = plan.networks[0].create
    assert create["name"] == "copy-shop_backend"
    assert create["options"] == {}
    assert create["labels"] == {}
    assert not [f for f in plan.risk if f.key.startswith("network:")]
    assert any("bridge interface name" in w for w in plan.warnings)

    plan = build(web_archive(), target(), choice("overwrite"))
    assert not [f for f in plan.risk if f.key.startswith("network:")]


def test_existing_host_networks_that_a_restore_joins_are_flagged() -> None:
    macvlan = net_info(driver="macvlan", options={"parent": "eth0"})
    # Reused: the archive's network exists on the target as a macvlan.
    on = overwrite_target(networks={"shop_backend": macvlan})
    plan = build(web_archive(), on, choice("overwrite"))
    assert plan.networks[0].action == "reuse"
    flag = next(f for f in plan.risk if f.key == "network:shop_backend:driver")
    assert flag.value == "driver macvlan, parent eth0"

    # Joined, but not in the archive: an endpoint and the network mode.
    info = web_info()
    info["HostConfig"]["NetworkMode"] = "lan"
    info["NetworkSettings"]["Networks"] = {"lan": {"Aliases": []}}
    archive = make_archive([info], networks=())
    on = target(networks={"lan": net_info("lan", hexid("lan"), driver="ipvlan", options={})})
    plan = build(archive, on, choice("overwrite"))
    assert [f.key for f in plan.risk if f.key.startswith("network:")] == ["network:lan:driver"]
    on = target(networks={"lan": net_info("lan", hexid("lan"))})
    plan = build(archive, on, choice("overwrite"))
    assert not [f for f in plan.risk if f.key.startswith("network:")]


def test_config_cannot_carry_networking_or_host_config() -> None:
    info = web_info()
    info["NetworkSettings"]["Networks"] = {}
    info["HostConfig"]["NetworkMode"] = "none"
    lan = {"IPAMConfig": {"IPv4Address": "192.168.1.50"}, "MacAddress": MAC}
    info["Config"]["NetworkingConfig"] = {"EndpointsConfig": {"lan": lan}}
    info["Config"]["HostConfig"] = {"Privileged": True}
    archive = make_archive([info], networks=())
    on = target(networks={"lan": net_info("lan", hexid("lan"), driver="macvlan")})
    for mode in ("new-name", "overwrite"):
        plan = build(archive, on, choice(mode))
        body = plan.containers[0].body
        assert "NetworkingConfig" not in body
        assert body["HostConfig"]["NetworkMode"] == "none"
        assert "Privileged" not in body["HostConfig"]
        assert "lan" not in leaves(body)
        assert "Ignored HostConfig, NetworkingConfig in the Config of " in " ".join(plan.warnings)


# IMAGES


def image_plan(entry: m.ImageEntry, on: p.TargetInfo, facts: p.ArchiveFacts = FACTS) -> p.ImageStep:
    plan = build(make_archive([], images=[entry]), on, choice("image-only"), facts)
    assert len(plan.images) == 1
    return plan.images[0]


def test_images_prefer_present_then_pull_then_load() -> None:
    step = image_plan(image(), target(images={IMAGE_ID: IMAGE_ID}))
    assert (step.action, step.member, step.pull, step.moves) == ("present", None, None, ())

    facts = p.ArchiveFacts(loaded_ids={IMAGE_ID: frozenset({IMAGE_ID, CONFIG_DIGEST})})
    step = image_plan(image(), target(images={"nginx:1.29": CONFIG_DIGEST}), facts)
    assert step.action == "present"
    step = image_plan(
        image(refs=["nginx:1.29", REPO_DIGEST]), target(images={REPO_DIGEST: IMAGE_ID})
    )
    assert step.action == "present"

    pulled = image(saved=False, data_member=None, confirmed_digest=REPO_DIGEST)
    step = image_plan(pulled, target())
    assert (step.action, step.pull, step.member) == ("pull", REPO_DIGEST, None)
    # A confirmed digest is pulled even when the archive also saved the image.
    step = image_plan(image(confirmed_digest=REPO_DIGEST), target())
    assert step.action == "pull"

    step = image_plan(image(), target(), facts)
    assert step.action == "load"
    assert step.member == f"images/{IMAGE_ID.removeprefix('sha256:')}.tar"
    assert step.refs == ("nginx:1.29",)
    assert set(step.accepted_ids) == {IMAGE_ID, CONFIG_DIGEST}

    with pytest.raises(p.PlanError, match="neither in the archive nor pullable"):
        image_plan(image(saved=False, data_member=None), target())

    plan = build(
        make_archive([], images=[image(architecture="arm64")]), target(), choice("image-only")
    )
    assert any("is for arm64, but host local is x86_64" in w for w in plan.warnings)
    plan = build(make_archive([], images=[image()]), target(), choice("image-only"))
    assert plan.warnings == ()


def test_tag_moves_are_flagged_and_protected_repos_refused() -> None:
    entry = image(refs=["nginx:1.29", REPO_DIGEST])
    on = target(images={"nginx:1.29": FOREIGN_ID})
    plan = build(make_archive([], images=[entry]), on, choice("image-only"))
    assert plan.images[0].moves == ("nginx:1.29",)
    assert plan.images[0].refs == ("nginx:1.29",)
    assert [f.key for f in plan.risk] == ["image:nginx:1.29:tag"]

    on = target(
        images={"nginx:1.29": FOREIGN_ID}, protected_repos=frozenset({"docker.io/library/nginx"})
    )
    with pytest.raises(
        p.PlanError, match=re.escape("would move tag nginx:1.29, which drydock itself uses")
    ):
        build(make_archive([], images=[entry]), on, choice("image-only"))

    on = target(images={"nginx:1.29": FOREIGN_ID}, protected_repos=frozenset({"busybox"}))
    build(make_archive([], images=[entry]), on, choice("image-only"))

    # A numeric tag is a tag, not a registry port.
    for ref, repo in (("redis:7", "redis"), ("postgres:18", "postgres")):
        assert p.repository(ref) == repo
        on = target(images={ref: FOREIGN_ID}, protected_repos=frozenset({repo}))
        with pytest.raises(p.PlanError, match=re.escape(f"would move tag {ref}")):
            build(make_archive([], images=[image(refs=[ref])]), on, choice("image-only"))
    assert p.repository("registry:5000/app:1") == "registry:5000/app"
    assert p.repository("registry:5000/app") == "registry:5000/app"
    assert p.repository("docker.io/library/redis:7@sha256:" + hexid("d")) == "redis"
    assert p.familiar("docker.io/library/nginx") == "nginx:latest"


def test_digest_ref_image_is_replaced_by_loaded_id() -> None:
    info = web_info()
    info["Config"]["Image"] = REPO_DIGEST
    entry = image(refs=[REPO_DIGEST])
    archive = make_archive([info], networks=(net_info(),), images=[entry])

    plan = build(archive, target(), choice("overwrite"))
    assert plan.images[0].action == "load"
    assert plan.containers[0].image_entry == IMAGE_ID
    assert plan.containers[0].body["Image"] == REPO_DIGEST
    assert any("Config.Image will be the loaded image ID" in w for w in plan.warnings)

    plan = build(
        archive, target(images={IMAGE_ID: IMAGE_ID, REPO_DIGEST: IMAGE_ID}), choice("overwrite")
    )
    assert plan.images[0].action == "present"
    assert plan.containers[0].image_entry is None

    # A tag is moved by the load itself, so it needs no ID.
    plan = build(web_archive(), target(), choice("overwrite"))
    assert plan.containers[0].image_entry is None
    for same in ("docker.io/library/nginx:1.29", "nginx:1.29"):
        info = web_info()
        info["Config"]["Image"] = same
        plan = build(make_archive([info], networks=(net_info(),)), target(), choice("overwrite"))
        assert plan.containers[0].image_entry is None
    # A tag the load does not set still names whatever the target has: use the ID.
    for other in ("nginx:latest", "nginx", "app:1.2"):
        info = web_info()
        info["Config"]["Image"] = other
        plan = build(make_archive([info], networks=(net_info(),)), target(), choice("overwrite"))
        assert plan.containers[0].image_entry == IMAGE_ID
    # Present by ID while the tag names another image: the body gets the ID.
    on = target(images={IMAGE_ID: IMAGE_ID, "nginx:1.29": FOREIGN_ID})
    plan = build(web_archive(), on, choice("overwrite"))
    assert plan.images[0].action == "present"
    assert plan.containers[0].image_entry == IMAGE_ID


def test_digest_refs_the_target_resolves_make_an_image_present() -> None:
    """A digest names content, so the image stores' different IDs for it (index digest
    under containerd, config digest under the classic store) all mean this image."""
    # Saved on a containerd-store host, present on a classic one only by digest (no tag).
    tagged = "nginx:1.29@sha256:" + hexid("digest")
    facts = p.ArchiveFacts(loaded_ids={IMAGE_ID: frozenset({IMAGE_ID})})
    entry = image(refs=["nginx:1.29", tagged])
    on = target(images={tagged: CONFIG_DIGEST})
    step = image_plan(entry, on, facts)
    assert (step.action, step.moves) == ("present", ())
    # apply finds the image again by the digest ref.
    assert step.refs == ("nginx:1.29", tagged)
    assert CONFIG_DIGEST in step.accepted_ids
    plan = build(make_archive([web_info()], images=[entry]), on, choice("overwrite"), facts)
    assert plan.containers[0].image_entry == IMAGE_ID

    # Saved on a classic host, pulled on a containerd-store host: the tag names it already.
    digest = "nginx@sha256:" + hexid("index")
    index_id = "sha256:" + hexid("index")
    on = target(
        images={digest: index_id, "nginx:1.29": index_id}, protected_repos=frozenset({"nginx"})
    )
    entry = image(confirmed_digest=digest)
    plan = build(make_archive([], images=[entry]), on, choice("image-only"))
    assert (plan.images[0].action, plan.images[0].moves, plan.risk) == ("present", (), ())
    assert plan.images[0].refs == ("nginx:1.29", digest)
    plan = build(make_archive([web_info()], images=[entry]), on, choice("overwrite"))
    assert plan.containers[0].image_entry is None

    # A tag alone still has to name an accepted ID.
    on = target(images={"nginx:1.29": FOREIGN_ID})
    assert image_plan(image(confirmed_digest=digest), on).action == "pull"


def test_invalid_archive_names_and_refs_are_refused_before_lookup() -> None:
    info = web_info()
    info["Mounts"][0]["Name"] = "../x"
    info["HostConfig"]["Binds"][0] = "../x:/usr/share/nginx/html:rw"
    archive = make_archive([info], networks=(net_info(),))
    with pytest.raises(p.PlanError, match=r"invalid volume name '\.\./x'"):
        p.lookups(*archive, choice("overwrite"))

    archive = make_archive([web_info()], networks=(net_info(),), images=[image(refs=["a/../b"])])
    with pytest.raises(p.PlanError, match=re.escape("invalid image reference 'a/../b'")):
        p.lookups(*archive, choice("overwrite"))

    bad_digest = "a/../b@sha256:" + hexid("d")
    archive = make_archive([], images=[image(confirmed_digest=bad_digest)])
    with pytest.raises(p.PlanError, match="invalid image digest"):
        p.lookups(*archive, choice("image-only"))

    archive = make_archive([web_info()], networks=(net_info("bad name", NET_ID),))
    with pytest.raises(p.PlanError, match="invalid network name"):
        p.lookups(*archive, choice("overwrite"))

    bad = web_info()
    bad["HostConfig"]["Binds"] = "shop_content:/usr/share/nginx/html"
    with pytest.raises(p.PlanError, match="configuration of container web is not valid"):
        p.lookups(*make_archive([bad]), choice("overwrite"))
    archive = make_archive([web_info()], networks=(net_info() | {"Options": "x"},))
    with pytest.raises(p.PlanError, match="configuration of network shop_backend is not valid"):
        p.lookups(*archive, choice("overwrite"))
    archive = web_archive(
        volume_configs={"shop_content": vol_info("shop_content") | {"Labels": []}}
    )
    with pytest.raises(p.PlanError, match="configuration of volume shop_content is not valid"):
        p.lookups(*archive, choice("overwrite"))

    # Fields the planner reads inside list items and endpoints are typed too.
    def breaks(change) -> None:
        manifest, configs = web_archive()
        change(configs[f"config/containers/{WEB_ID}.json"])
        for mode in ("overwrite", "new-name"):
            with pytest.raises(p.PlanError, match="configuration of container web is not valid"):
                build((manifest, configs), target(), choice(mode))

    breaks(lambda i: i["Mounts"][0].update(Destination=5))
    breaks(lambda i: i["HostConfig"]["Mounts"][0].update(Target=["/cache"]))
    breaks(lambda i: i["HostConfig"]["Mounts"][0].update(VolumeOptions=["x"]))
    breaks(lambda i: i["HostConfig"].update(Mounts=[{"Type": "bind", "Source": {}}]))
    breaks(lambda i: i["NetworkSettings"]["Networks"]["shop_backend"].update(IPAMConfig=["x"]))
    breaks(lambda i: i["NetworkSettings"]["Networks"]["shop_backend"].update(Aliases="web"))
    breaks(lambda i: i["NetworkSettings"]["Networks"]["shop_backend"].update(Aliases=[5]))
    breaks(
        lambda i: i["NetworkSettings"]["Networks"]["shop_backend"].update(
            IPAMConfig={"IPv4Address": 5}
        )
    )
    breaks(lambda i: i["HostConfig"].update(SecurityOpt=[["x"]]))

    with pytest.raises(p.PlanError, match="new name must start"):
        p.lookups(*web_archive(), choice("new-name", new_name="-x"))
    with pytest.raises(p.PlanError, match="not a valid container or volume name"):
        p.lookups(*web_archive(), choice("data-only", volume_map={"shop_content": "../v"}))

    lookup = p.lookups(*web_archive(), choice("new-name"))
    assert {"copy", "web"} <= lookup.containers
    assert {"copy-shop_content", f"copy-{ANON[:12]}", "shop_content"} <= lookup.volumes
    assert {"copy-shop_backend", "shop_backend"} <= lookup.networks
    assert {IMAGE_ID, "nginx:1.29"} <= lookup.images
    lookup = p.lookups(*web_archive(), choice("overwrite"))
    assert "web-drydock-old" in lookup.containers

    # A new_name left over from another mode is checked too, and never looked up.
    stale = p.Choice.from_dict({"host_id": 1, "mode": "overwrite", "new_name": "../../images/x"})
    with pytest.raises(p.PlanError, match="new name must start"):
        p.lookups(*web_archive(), stale)
    lookup = p.lookups(*web_archive(), choice("overwrite", new_name="spare"))
    assert "spare" not in lookup.containers


# PLANNING


def test_overwrite_refuses_own_container_leftover_old_name_and_live_users() -> None:
    archive = web_archive()
    on = overwrite_target(own=frozenset({WEB_ID}))
    assert "Container web belongs to drydock's own deployment." in refused(
        archive, on, choice("overwrite")
    )

    containers = {"web": web_info(), "web-drydock-old": web_info()}
    assert "Container web-drydock-old already exists on host local. Remove it first." in refused(
        archive, overwrite_target(containers=containers), choice("overwrite")
    )

    for state in ("paused", "restarting", "running", "removing"):
        users = {"shop_content": (p.ContainerUse(OTHER_ID, "reader", state),)}
        message = refused(archive, overwrite_target(volume_users=users), choice("overwrite"))
        assert (
            f"Volume shop_content is also used by {state} container reader. Stop it first."
            in message
        )
    users = {"shop_content": (p.ContainerUse(OTHER_ID, "reader", "exited"),)}
    plan = build(archive, overwrite_target(volume_users=users), choice("overwrite"))
    assert OTHER_ID in plan.lock_keys

    # Stopped users of a written host path are locked too: a stop-mode backup of one could
    # otherwise start it again on the path mid-restore.
    info = with_binds(web_info(), [("/srv/shared", "/shared", True)])
    bind_archive = make_archive([info])
    for source in ("/srv/shared", "/srv/shared/sub", "/srv"):
        on = target(bind_users=(p.BindUse(OTHER_ID, "x", "exited", source),))
        plan = build(bind_archive, on, choice("overwrite", wipe_binds=frozenset({0})))
        assert OTHER_ID in plan.lock_keys
        assert plan.live_users == ()
    on = target(bind_users=(p.BindUse(OTHER_ID, "x", "exited", "/srv/other"),))
    assert OTHER_ID not in build(bind_archive, on, choice("overwrite")).lock_keys
    # And a stopped user of a host-backed volume over a written directory.
    pg = {"type": "none", "o": "bind", "device": "/srv/pg"}
    volumes = {
        "restored": vol_info("restored", options=pg),
        "db_data": vol_info("db_data", options=pg),
    }
    users = {"db_data": (p.ContainerUse(OTHER_ID, "db", "exited"),)}
    chosen = choice("data-only", volume_map={"shop_content": "restored"})
    plan = build(archive, target(volumes=volumes, volume_users=users), chosen)
    assert OTHER_ID in plan.lock_keys

    removing = web_info()
    removing["HostConfig"]["AutoRemove"] = True
    assert "removes itself when stopped" in refused(
        archive, overwrite_target(containers={"web": removing}), choice("overwrite")
    )
    stopped = web_info()
    stopped["State"] = {"Status": "exited", "Running": False}
    stopped["Config"]["StopTimeout"] = -1
    plan = build(archive, overwrite_target(containers={"web": stopped}), choice("overwrite"))
    assert plan.originals == (p.Original(WEB_ID, "web", "web-drydock-old", False, 600),)


def test_new_name_requires_remap_skip_or_share_for_rw_binds() -> None:
    info = with_binds(web_info(), [("/srv/shop/data", "/data", True)])
    archive = make_archive([info], networks=(net_info(),))
    message = refused(archive, target(), choice("new-name"))
    assert (
        "Bind mount /srv/shop/data would be shared with the original. Remap it, skip its "
        "data, or choose to share it." in message
    )

    for chosen in (choice("new-name", skip_binds={0}), choice("new-name", share_binds={0})):
        plan = build(archive, target(), chosen)
        assert not [d for d in plan.data if d.kind.startswith("bind")]
        assert "Bind mount /srv/shop/data is shared with the original container." in plan.warnings
        assert "/srv/shop/data:/data" in plan.containers[0].body["HostConfig"]["Binds"]

    plan = build(archive, target(), choice("new-name", bind_remaps={0: "/srv/copy/data"}))
    assert [(d.kind, d.target) for d in plan.data if d.kind.startswith("bind")] == [
        ("bind-dir", "/srv/copy/data")
    ]
    assert "/srv/copy/data:/data" in plan.containers[0].body["HostConfig"]["Binds"]
    assert "bind-write:/srv/copy/data" in {f.key for f in plan.risk}

    # Bind data written on another host than the one it came from is flagged too.
    plan = build(make_archive([info], host_name="nas"), target(), choice("overwrite"))
    assert "bind-write:/srv/shop/data" in {f.key for f in plan.risk}
    facts = p.ArchiveFacts(setid_members=frozenset({"binds/0.tar"}))
    plan = build(make_archive([info]), target(), choice("overwrite"), facts)
    assert "bind-data:0:setid" in {f.key for f in plan.risk}


def test_data_only_maps_volumes_and_binds_by_name_and_by_container_destination() -> None:
    info = with_binds(
        web_info(),
        [("/srv/shop/conf", "/etc/nginx/conf.d", False), ("/srv/shop/app.ini", "/app.ini", True)],
    )
    archive = make_archive([info], networks=(net_info(),), kinds={"/srv/shop/app.ini": "file"})
    volumes = {
        name: vol_info(name) for name in ("restored", "conf", "files", "tv-content", "tv-conf")
    }

    chosen = choice(
        "data-only",
        volume_map={"shop_content": "restored"},
        bind_volume_map={0: "conf", 1: "files"},
    )
    plan = build(archive, target(volumes=volumes), chosen)
    assert [(d.member, d.kind, d.target, d.label, d.rename_to) for d in plan.data] == [
        ("volumes/shop_content.tar", "volume", "restored", "volume restored", None),
        ("binds/0.tar", "volume", "conf", "volume conf", None),
        ("binds/1.tar", "volume", "files", "volume files", "app.ini"),
    ]
    assert (plan.wipes, plan.containers, plan.networks, plan.volumes, plan.originals) == (
        (),
        (),
        (),
        (),
        (),
    )
    assert plan.write_targets == ()
    assert f"The data of volume {ANON} is not restored." in plan.warnings

    holder = {
        "Id": OTHER_ID,
        "Name": "/target-web",
        "State": {"Status": "exited"},
        "Mounts": [
            {"Type": "volume", "Name": "tv-content", "Destination": "/usr/share/nginx/html/"},
            {"Type": "volume", "Name": "tv-conf", "Destination": "/etc/nginx/conf.d"},
            {"Type": "bind", "Source": "/srv/x", "Destination": "/x"},
        ],
    }
    users = {"tv-content": (p.ContainerUse(OTHER_ID, "target-web", "exited"),)}
    on = target(volumes=volumes, containers={"target-web": holder}, volume_users=users)
    plan = build(archive, on, choice("data-only", data_container="target-web"))
    assert [(d.member, d.target) for d in plan.data] == [
        ("volumes/shop_content.tar", "tv-content"),
        ("binds/0.tar", "tv-conf"),
    ]
    assert OTHER_ID in plan.lock_keys
    assert "name:1:volume:tv-content" in plan.lock_keys

    users = {"tv-content": (p.ContainerUse(OTHER_ID, "target-web", "running"),)}
    on = target(volumes=volumes, containers={"target-web": holder}, volume_users=users)
    assert "Volume tv-content is also used by running container target-web. Stop it first." in (
        refused(archive, on, choice("data-only", data_container="target-web"))
    )

    assert "Volume missing does not exist on host local." in refused(
        archive,
        target(volumes=volumes),
        choice("data-only", volume_map={"shop_content": "missing"}),
    )
    assert "is the target of more than one item" in refused(
        archive,
        target(volumes=volumes),
        choice("data-only", volume_map={"shop_content": "conf"}, bind_volume_map={0: "conf"}),
    )
    assert "Choose the target volumes" in refused(
        archive, target(volumes=volumes), choice("data-only")
    )
    home = {"tv-content": vol_info("tv-content", options={"o": "bind", "device": "/home"})}
    assert "Drydock never writes to /home." in refused(
        archive,
        target(volumes=home),
        choice("data-only", volume_map={"shop_content": "tv-content"}),
    )
    assert "belongs to drydock's own deployment" in refused(
        archive,
        target(volumes=volumes, own_volumes=frozenset({"restored"})),
        choice("data-only", volume_map={"shop_content": "restored"}),
    )


def test_image_only_has_only_image_steps() -> None:
    plan = build(web_archive(), target(), choice("image-only"))
    assert [i.action for i in plan.images] == ["load"]
    assert (
        plan.networks,
        plan.volumes,
        plan.originals,
        plan.wipes,
        plan.data,
        plan.containers,
        plan.bind_sources,
        plan.write_targets,
        plan.lock_keys,
    ) == ((), (), (), (), (), (), (), (), ())
    with pytest.raises(p.PlanError, match="holds no images"):
        build(web_archive(images=[]), target(), choice("image-only"))


def test_lock_keys_and_archive_order() -> None:
    info = with_binds(web_info(), [("/srv/a", "/a", True)])
    users = {
        "shop_content": (
            p.ContainerUse(WEB_ID, "web", "running"),
            p.ContainerUse(OTHER_ID, "reader", "created"),
        )
    }
    on = overwrite_target(volume_users=users, networks={})
    plan = build(make_archive([info], networks=(net_info(),)), on, choice("overwrite"))
    assert plan.lock_keys == tuple(
        sorted(
            {
                WEB_ID,
                OTHER_ID,
                "name:1:container:web",
                "name:1:network:shop_backend",
                # The original carries com.docker.compose.project=shop (decision 7).
                "name:1:project:shop",
                "name:1:volume:shop_content",
                f"name:1:volume:{ANON}",
            }
        )
    )
    assert plan.projects == ("shop",) and plan.project is None
    assert [d.member for d in plan.data] == [
        "volumes/shop_content.tar",
        f"volumes/{ANON}.tar",
        "binds/0.tar",
    ]
    assert [(v.name, v.action) for v in plan.volumes] == [
        ("shop_content", "reuse"),
        (ANON, "reuse"),
    ]

    plan = build(web_archive(), target(), choice("new-name"))
    assert plan.lock_keys == tuple(
        sorted(
            {
                "name:1:container:copy",
                "name:1:network:copy-shop_backend",
                "name:1:volume:copy-shop_content",
                f"name:1:volume:copy-{ANON[:12]}",
            }
        )
    )
    with pytest.raises(p.PlanError, match="already exists on host local"):
        build(web_archive(), target(containers={"copy": web_info()}), choice("new-name"))
    with pytest.raises(p.PlanError, match="Volume copy-shop_content already exists"):
        build(web_archive(), target(volumes={"copy-shop_content": {}}), choice("new-name"))
    with pytest.raises(p.PlanError, match="for another host"):
        build(web_archive(), target(), choice("new-name", host_id=2))


def test_several_containers_and_missing_configs_are_refused() -> None:
    """Several containers that are not a stack go back only in overwrite mode."""
    second = web_info()
    second["Id"], second["Name"] = OTHER_ID, "/worker"
    archive = make_archive([web_info(), second], networks=(net_info(),))
    with pytest.raises(p.PlanError, match="Only a stack archive can be restored under a new"):
        build(archive, target(), choice("new-name"))
    plan = build(archive, target(), choice("overwrite"))
    assert [c.name for c in plan.containers] == ["web", "worker"]
    manifest, configs = web_archive()
    configs = {k: v for k, v in configs.items() if not k.startswith("config/containers/")}
    with pytest.raises(p.PlanError, match="no valid configuration for container web"):
        p.build_plan(manifest, configs, target(), choice("overwrite"), FACTS)


def test_data_step_labels_have_the_fixed_format() -> None:
    plan = build(web_archive(), target(), choice("new-name", bind_remaps={0: "/srv/copy/conf"}))
    assert [d.label for d in plan.data] == [
        "volume copy-shop_content",
        f"volume copy-{ANON[:12]}",
        "bind mount /srv/copy/conf",
    ]
    plan = build(web_archive(), overwrite_target(), choice("overwrite"))
    assert [w.label for w in plan.wipes] == ["volume shop_content", f"volume {ANON}"]
    assert [d.label for d in plan.data][-1] == "bind mount /srv/shop/conf"


def test_choice_round_trips_and_rejects_bad_types() -> None:
    chosen = p.Choice(
        host_id=3,
        mode="overwrite",
        new_name="",
        bind_remaps={0: "/srv/a", 2: "/srv/b"},
        skip_binds=frozenset({1}),
        wipe_binds=frozenset({0}),
        share_binds=frozenset({2}),
        volume_map={"data": "other"},
        bind_volume_map={4: "vol"},
        data_container="holder",
        acknowledged=frozenset({"web:Privileged", "image:nginx:1.29:tag"}),
    )
    stored = json.loads(json.dumps(chosen.to_dict()))
    assert p.Choice.from_dict(stored) == chosen
    assert p.Choice.from_dict({"host_id": 1, "mode": "image-only"}) == p.Choice(1, "image-only")

    good = chosen.to_dict()
    for bad in (
        None,
        [],
        {"mode": "overwrite"},
        good | {"host_id": "3"},
        good | {"host_id": True},
        good | {"host_id": 0},
        good | {"mode": "everything"},
        good | {"new_name": 5},
        good | {"skip_binds": ["1"]},
        good | {"skip_binds": [True]},
        good | {"skip_binds": "1"},
        good | {"bind_remaps": {"x": "/srv"}},
        good | {"bind_remaps": {"-1": "/srv"}},
        good | {"bind_remaps": {"0": 5}},
        good | {"bind_remaps": ["/srv"]},
        good | {"volume_map": {"a": 1}},
        good | {"acknowledged": "web:Privileged"},
        good | {"acknowledged": [1]},
        good | {"extra": 1},
    ):
        with pytest.raises(p.PlanError):
            p.Choice.from_dict(bad)


def test_summary_core_ignores_warnings() -> None:
    plan = build(web_archive(), overwrite_target(), choice("overwrite", wipe_binds={0}))
    document = p.summary(plan, "local")
    text = json.dumps(document)
    assert "A=1" not in text
    assert "Env" not in text
    assert document["mode"] == "overwrite"
    assert document["containers"] == ["web"]
    assert document["originals"] == ["web"]
    assert document["images"] == [{"label": "nginx:1.29", "action": "load", "moves": []}]
    assert document["networks"] == [{"name": "shop_backend", "action": "reuse", "differences": []}]
    assert document["wipes"] == [
        "volume shop_content",
        f"volume {ANON}",
        "bind mount /srv/shop/conf",
    ]
    assert {"label": "volume shop_content", "target": "shop_content"} in document["data"]
    core = p.summary_core(document)
    assert "warnings" not in core
    assert core == p.summary_core(document | {"warnings": ["something else"]})
    assert core != p.summary_core(document | {"wipes": []})

    changed = overwrite_target(networks={"shop_backend": net_info(subnet="10.9.0.0/16")})
    with pytest.raises(p.PlanError, match="lies outside every subnet"):
        build(web_archive(), changed, choice("overwrite"))


def test_static_addresses_need_a_subnet_of_their_version() -> None:
    # An IPv6-only network, or one without configured subnets, takes no static IPv4 address.
    for subnet in ("fd00:30::/64", ""):
        changed = overwrite_target(networks={"shop_backend": net_info(subnet=subnet)})
        with pytest.raises(p.PlanError, match=r"172\.30\.0\.10 of web lies outside every subnet"):
            build(web_archive(), changed, choice("overwrite"))
    manifest, configs = web_archive()
    ipam = configs[f"config/containers/{WEB_ID}.json"]["NetworkSettings"]["Networks"]
    ipam["shop_backend"]["IPAMConfig"]["IPv6Address"] = "fd00:31::10"
    with pytest.raises(p.PlanError, match="fd00:31::10 of web lies outside every subnet"):
        build((manifest, configs), overwrite_target(), choice("overwrite"))
    dual = net_info()
    dual["IPAM"]["Config"].append({"Subnet": "fd00:31::/64"})
    build(
        (manifest, configs), overwrite_target(networks={"shop_backend": dual}), choice("overwrite")
    )
    assert p.inside("172.30.0.10", ["172.30.0.0/16"])
    assert not p.inside("172.30.0.10", [])
    assert not p.inside("bad", ["172.30.0.0/16"])


# SHARED CONTAINER FACTS


def test_inventory_shared_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    assert inventory.stop_timeout({"Config": {"StopTimeout": 30}}) == 30
    assert inventory.stop_timeout({"Config": {"StopTimeout": -1}}) == inventory.MAX_STOP_TIMEOUT
    assert inventory.stop_timeout({"Config": {"StopTimeout": 10**6}}) == inventory.MAX_STOP_TIMEOUT
    assert inventory.stop_timeout({"Config": {"StopTimeout": True}}) == 10
    assert inventory.stop_timeout({}) == inventory.DEFAULT_STOP_TIMEOUT
    for state in ("running", "paused", "restarting", "removing", "something-new"):
        assert inventory.in_use(state)
    for state in ("created", "exited", "dead"):
        assert not inventory.in_use(state)
    assert all(inventory.in_use(s) for s in inventory.LIVE_STATES)

    proxy = hexid("proxy")
    # A container named like drydock's short ID, which a by-name inspect would return.
    impostor = hexid("impostor")
    calls: list[dict[str, Any]] = []

    class API:
        def __init__(self) -> None:
            self.listed = [{"Id": OWN_ID}, {"Id": "ab" + OWN_ID[:12] + "0" * 50}]

        def inspect_container(self, ref: str) -> dict[str, Any]:
            if ref == OWN_ID[:12]:
                return {"Id": impostor, "Config": {"Labels": {}}}
            if ref != OWN_ID:
                raise docker.errors.NotFound("No such container")
            labels = {inventory.PROJECT_LABEL: "drydock"}
            return {"Id": OWN_ID, "Config": {"Labels": labels}}

        def containers(self, **kwargs: Any) -> list[dict[str, Any]]:
            calls.append(kwargs)
            if "id" in kwargs["filters"]:
                return self.listed  # a pattern match anywhere in the ID
            return [{"Id": OWN_ID}, {"Id": proxy}]

    monkeypatch.setattr(inventory, "MOUNTINFO", "/nonexistent/mountinfo")
    monkeypatch.setattr(inventory.socket, "gethostname", lambda: OWN_ID[:12])
    assert inventory.own_ids(API()) == frozenset({OWN_ID, proxy})
    assert calls == [
        {"all": True, "filters": {"id": OWN_ID[:12]}},
        {"all": True, "filters": {"label": "com.docker.compose.project=drydock"}},
    ]
    api = API()
    api.listed = [{"Id": impostor}]
    assert inventory.own_container(api) is None
    monkeypatch.setattr(inventory.socket, "gethostname", lambda: "not-a-container")
    assert inventory.own_ids(API()) == frozenset()


def test_own_container_is_found_without_an_id_hostname(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A compose 'hostname:' or the host's UTS namespace hides the ID from the hostname;
    the files Docker bind-mounts from the container's directory still name it."""
    mountinfo = tmp_path / "mountinfo"
    root = "/var/lib/docker/containers"
    mountinfo.write_text(
        f"1 0 0:1 / / rw - overlay overlay rw\n"
        f"2 1 8:1 {root}/{OWN_ID}/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n"
        f"3 1 8:1 {root}/{OWN_ID}/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(inventory, "MOUNTINFO", str(mountinfo))
    monkeypatch.setattr(inventory.socket, "gethostname", lambda: "drydock")
    assert inventory.own_id_candidates() == [OWN_ID]
    inspected: list[str] = []

    class API:
        def containers(self, **kwargs: Any) -> list[dict[str, Any]]:
            if "id" in kwargs["filters"]:
                return [{"Id": OWN_ID}] if kwargs["filters"]["id"] == OWN_ID else []
            return [{"Id": OWN_ID}]

        def inspect_container(self, ref: str) -> dict[str, Any]:
            inspected.append(ref)
            return {"Id": ref, "Config": {"Labels": {inventory.PROJECT_LABEL: "drydock"}}}

    assert inventory.own_ids(API()) == frozenset({OWN_ID})
    assert inspected == [OWN_ID]

    # On another daemon the ID names nothing.
    class Remote(API):
        def containers(self, **kwargs: Any) -> list[dict[str, Any]]:
            return []

    assert inventory.own_container(Remote()) is None


def test_mounts_the_job_skipped_get_no_wipe_and_no_data() -> None:
    """An archive whose job skipped a volume and a bind: the containers still mount both,
    an overwrite neither wipes nor writes them, and the plan warns about the bind."""
    info = with_binds(web_info(), [("/srv/cache", "/cache", True)])
    manifest, configs = make_archive([info])
    reason = "the job skips it"
    skipped_volumes = [
        v.model_copy(update={"data_member": None, "skipped": reason})
        if v.name == "shop_content"
        else v
        for v in manifest.volumes
    ]
    skipped_binds = [
        b.model_copy(update={"data_member": None, "skipped": reason}) for b in manifest.binds
    ]
    members = [
        member
        for member in manifest.members
        if member not in {b.data_member for b in manifest.binds} | {"volumes/shop_content.tar"}
    ]
    manifest = manifest.model_copy(
        update={"volumes": skipped_volumes, "binds": skipped_binds, "members": members}
    )

    plan = build((manifest, configs), target(), choice("overwrite"))
    assert ("volume", "shop_content") not in {(w.kind, w.target) for w in plan.wipes}
    assert not [d for d in plan.data if d.target in ("shop_content", "/srv/cache")]
    assert any(v.name == "shop_content" for v in plan.volumes)  # still created or reused
    assert any(
        "Bind mount /srv/cache is not in the archive (the job skips it)" in w for w in plan.warnings
    )
