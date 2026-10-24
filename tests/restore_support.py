"""Builders for the restore tests: inner tars, docker-save image tars, realistic container
inspect documents, and whole archives written by the real ArchiveWriter.

Archives are named and laid out exactly as capture names them (capture.build_manifest,
capture.stem, capture.as_json), from inspect documents that look like Docker's. Not a
test module: pytest does not collect it.
"""

import hashlib
import io
import json
import os
import tarfile
import tempfile
import threading
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import docker.errors

from drydock.archive import manifest as m
from drydock.archive.writer import ArchiveWriter
from drydock.crypto import Crypto
from drydock.engine import capture, compose_files
from drydock.restore.verify import normalize_ref
from drydock.storage.base import archive_name

MTIME = 1_760_000_000
REGULAR = (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE)
SAVE_CHUNK = 64 * 1024


def hex64() -> str:
    return os.urandom(32).hex()


# INNER TARS


@dataclass(frozen=True)
class TarEntry:
    name: str
    type: bytes = tarfile.REGTYPE
    data: bytes = b""
    uid: int = 0
    gid: int = 0
    mode: int = 0o644
    linkname: str = ""
    pax: Mapping[str, str] | None = None


def inner_tar(entries: Iterable[TarEntry]) -> bytes:
    """A PAX tar of exactly these entries, names as given (Docker's look like "./a/b").

    Any type may carry data, so tests can build raw extension headers ("x", "L", "g")."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w|", format=tarfile.PAX_FORMAT) as tar:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.type = entry.type
            info.size = len(entry.data)
            info.uid, info.gid, info.mode = entry.uid, entry.gid, entry.mode
            info.linkname = entry.linkname
            info.mtime = MTIME
            if entry.pax:
                info.pax_headers = dict(entry.pax)
            tar.addfile(info, io.BytesIO(entry.data) if entry.data else None)
    return buffer.getvalue()


def root_only_tar(mode: int = 0o755, uid: int = 0, gid: int = 0) -> bytes:
    return inner_tar([TarEntry("./", tarfile.DIRTYPE, mode=mode, uid=uid, gid=gid)])


def pax_body(records: Sequence[tuple[str, str]]) -> bytes:
    """A PAX extended header body holding exactly these records, duplicates included."""
    body = b""
    for key, value in records:
        payload = f" {key}={value}\n".encode()
        length = len(payload) + 1
        while len(str(length)) + len(payload) != length:
            length += 1
        body += str(length).encode() + payload
    return body


# IMAGES


def image_tar(image_id: str, refs: Sequence[str], *, oci: bool = True) -> bytes:
    """A minimal docker save of one image with no layers.

    oci=True is the format of Docker 25 and later: index.json (one descriptor per tag,
    annotated with io.containerd.image.name), manifest.json, oci-layout and the blobs.
    oci=False is the legacy format: manifest.json, repositories and <config hex>.json."""
    tags = [r for r in refs if "@" not in r]
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
            "comment": image_id,
        }
    ).encode()
    config_hex = hashlib.sha256(config).hexdigest()
    entries = []
    if oci:
        manifest_blob = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": f"sha256:{config_hex}",
                    "size": len(config),
                },
                "layers": [],
            }
        ).encode()
        manifest_hex = hashlib.sha256(manifest_blob).hexdigest()
        descriptor = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": f"sha256:{manifest_hex}",
            "size": len(manifest_blob),
        }
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                descriptor
                | {
                    "annotations": {
                        "io.containerd.image.name": normalize_ref(tag),
                        "org.opencontainers.image.ref.name": tag.rsplit(":", 1)[-1],
                    }
                }
                for tag in tags
            ]
            or [descriptor],
        }
        docker_manifest = [{"Config": f"blobs/sha256/{config_hex}", "RepoTags": tags, "Layers": []}]
        entries += [
            TarEntry("blobs/", tarfile.DIRTYPE, mode=0o755),
            TarEntry("blobs/sha256/", tarfile.DIRTYPE, mode=0o755),
            TarEntry(f"blobs/sha256/{config_hex}", data=config),
            TarEntry(f"blobs/sha256/{manifest_hex}", data=manifest_blob),
            TarEntry("index.json", data=json.dumps(index).encode()),
            TarEntry("manifest.json", data=json.dumps(docker_manifest).encode()),
            TarEntry("oci-layout", data=b'{"imageLayoutVersion":"1.0.0"}'),
        ]
    else:
        docker_manifest = [{"Config": f"{config_hex}.json", "RepoTags": tags, "Layers": []}]
        repositories: dict[str, dict[str, str]] = {}
        for tag in tags:
            repo, _, version = tag.rpartition(":")
            repositories.setdefault(repo, {})[version] = config_hex
        entries += [
            TarEntry(f"{config_hex}.json", data=config),
            TarEntry("manifest.json", data=json.dumps(docker_manifest).encode()),
            TarEntry("repositories", data=json.dumps(repositories).encode()),
        ]
    return inner_tar(entries)


def image_inspect(image_id: str, refs: Sequence[str], confirmed: str | None = None) -> dict:
    return {
        "Id": image_id,
        "RepoTags": [r for r in refs if "@" not in r],
        "RepoDigests": [confirmed] if confirmed else [],
        "Created": "2026-10-01T00:00:00Z",
        "Os": "linux",
        "Architecture": "amd64",
        "Size": 4096,
        "Config": {"Env": ["PATH=/usr/bin:/bin"], "Cmd": ["sh"], "Labels": None},
        "RootFS": {"Type": "layers", "Layers": []},
    }


# CONTAINERS AND NETWORKS


def container_inspect(
    name: str = "web",
    *,
    id: str | None = None,
    image: str = "busybox:1.37",
    image_id: str | None = None,
    env: Sequence[str] = (),
    binds: Sequence[str] = (),
    mounts: Sequence[tuple] = (),
    host_mounts: Sequence[dict[str, Any]] = (),
    networks: Mapping[str, dict[str, Any]] | None = None,
    labels: Mapping[str, str] | None = None,
    host_config: Mapping[str, Any] | None = None,
    network_mode: str = "bridge",
    running: bool = True,
) -> dict[str, Any]:
    """A container inspect document shaped like Docker 29's.

    binds are HostConfig.Binds strings ("/host:/dest[:ro]" or "volume:/dest[:ro]").
    mounts are volume mounts (name or None for an anonymous volume, destination[,
    read_only]); named ones go into HostConfig.Binds, anonymous ones into Config.Volumes.
    host_mounts are HostConfig.Mounts entries (--mount); bind and volume ones also appear
    in Mounts. networks maps network names to endpoint fields to set (IPAMConfig,
    Aliases, NetworkID, ...)."""
    cid = id or hex64()
    short = cid[:12]
    config_volumes: dict[str, dict] = {}
    all_binds = list(binds)
    container_mounts = []
    for spec in binds:
        source, destination, *options = spec.split(":")
        read_only = "ro" in options
        if source.startswith("/"):
            container_mounts.append(bind_mount(source, destination, read_only))
        else:
            container_mounts.append(volume_mount(source, destination, read_only))
    for volume, destination, *rest in mounts:
        read_only = bool(rest and rest[0])
        if volume is None:
            volume = hex64()
            config_volumes[destination] = {}
        else:
            all_binds.append(f"{volume}:{destination}" + (":ro" if read_only else ""))
        container_mounts.append(volume_mount(volume, destination, read_only))
    for mount in host_mounts:
        read_only = bool(mount.get("ReadOnly"))
        if mount.get("Type") == "bind":
            container_mounts.append(bind_mount(mount["Source"], mount["Target"], read_only))
        elif mount.get("Type") == "volume":
            source = mount.get("Source") or hex64()
            container_mounts.append(volume_mount(source, mount["Target"], read_only))
    if networks is None:
        networks = {} if network_mode.startswith("container:") else {network_mode: {}}
    endpoints = {}
    for index, (network, extra) in enumerate(networks.items()):
        endpoint = {
            "IPAMConfig": None,
            "Links": None,
            "Aliases": None,
            "MacAddress": f"02:42:ac:11:00:{index + 2:02x}",
            "DriverOpts": None,
            "GwPriority": 0,
            "NetworkID": hex64(),
            "EndpointID": hex64() if running else "",
            "Gateway": "172.17.0.1" if running else "",
            "IPAddress": f"172.17.0.{index + 2}" if running else "",
            "IPPrefixLen": 16 if running else 0,
            "IPv6Gateway": "",
            "GlobalIPv6Address": "",
            "GlobalIPv6PrefixLen": 0,
            "DNSNames": None if network in ("bridge", "host", "none") else [name, short],
        }
        endpoint.update(extra)
        endpoints[network] = endpoint
    port_bindings = dict((host_config or {}).get("PortBindings") or {})
    hc: dict[str, Any] = {
        "Binds": all_binds or None,
        "ContainerIDFile": "",
        "LogConfig": {"Type": "json-file", "Config": {}},
        "NetworkMode": network_mode,
        "PortBindings": port_bindings,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "AutoRemove": False,
        "VolumeDriver": "",
        "VolumesFrom": None,
        "ConsoleSize": [0, 0],
        "CapAdd": None,
        "CapDrop": None,
        "CgroupnsMode": "private",
        "Dns": [],
        "DnsOptions": [],
        "DnsSearch": [],
        "ExtraHosts": None,
        "GroupAdd": None,
        "IpcMode": "private",
        "Cgroup": "",
        "Links": None,
        "OomScoreAdj": 0,
        "PidMode": "",
        "Privileged": False,
        "PublishAllPorts": False,
        "ReadonlyRootfs": False,
        "SecurityOpt": None,
        "UTSMode": "",
        "UsernsMode": "",
        "ShmSize": 67108864,
        "Runtime": "runc",
        "Isolation": "",
        "CpuShares": 0,
        "Memory": 0,
        "NanoCpus": 0,
        "CgroupParent": "",
        "BlkioWeight": 0,
        "Devices": [],
        "DeviceRequests": None,
        "MemoryReservation": 0,
        "MemorySwap": 0,
        "MemorySwappiness": None,
        "OomKillDisable": None,
        "PidsLimit": None,
        "Ulimits": [],
        "Mounts": list(host_mounts) or None,
        "MaskedPaths": [
            "/proc/asound",
            "/proc/acpi",
            "/proc/kcore",
            "/proc/keys",
            "/sys/firmware",
        ],
        "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys"],
    }
    hc.update(host_config or {})
    return {
        "Id": cid,
        "Created": "2026-10-01T00:00:00.000000000Z",
        "Path": "sh",
        "Args": [],
        "State": {
            "Status": "running" if running else "exited",
            "Running": running,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 4242 if running else 0,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "2026-10-01T00:00:01.000000000Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
        },
        "Image": image_id or f"sha256:{hex64()}",
        "ResolvConfPath": f"/var/lib/docker/containers/{cid}/resolv.conf",
        "HostnamePath": f"/var/lib/docker/containers/{cid}/hostname",
        "HostsPath": f"/var/lib/docker/containers/{cid}/hosts",
        "LogPath": f"/var/lib/docker/containers/{cid}/{cid}-json.log",
        "Name": f"/{name}",
        "RestartCount": 0,
        "Driver": "overlayfs",
        "Platform": "linux",
        "MountLabel": "",
        "ProcessLabel": "",
        "AppArmorProfile": "",
        "ExecIDs": None,
        "HostConfig": hc,
        "Mounts": container_mounts,
        "Config": {
            "Hostname": short,
            "Domainname": "",
            "User": "",
            "AttachStdin": False,
            "AttachStdout": False,
            "AttachStderr": False,
            "ExposedPorts": {port: {} for port in port_bindings} or None,
            "Tty": False,
            "OpenStdin": False,
            "StdinOnce": False,
            "Env": [*env, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Cmd": ["sh"],
            "Image": image,
            "Volumes": config_volumes or None,
            "WorkingDir": "",
            "Entrypoint": None,
            "OnBuild": None,
            "Labels": dict(labels or {}),
        },
        "NetworkSettings": {
            "SandboxID": hex64() if running else "",
            "SandboxKey": f"/var/run/docker/netns/{short}" if running else "",
            "Ports": {},
            "Networks": endpoints,
        },
    }


def bind_mount(source: str, destination: str, read_only: bool) -> dict[str, Any]:
    return {
        "Type": "bind",
        "Source": source,
        "Destination": destination,
        "Mode": "ro" if read_only else "",
        "RW": not read_only,
        "Propagation": "rprivate",
    }


def volume_mount(name: str, destination: str, read_only: bool) -> dict[str, Any]:
    return {
        "Type": "volume",
        "Name": name,
        "Source": f"/var/lib/docker/volumes/{name}/_data",
        "Destination": destination,
        "Driver": "local",
        "Mode": "z",
        "RW": not read_only,
        "Propagation": "",
    }


def network_inspect(
    name: str,
    *,
    id: str | None = None,
    driver: str = "bridge",
    subnet: str | None = None,
    gateway: str | None = None,
    labels: Mapping[str, str] | None = None,
    options: Mapping[str, str] | None = None,
    containers: Mapping[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """A network inspect document shaped like Docker 29's."""
    config = [{"Subnet": subnet} | ({"Gateway": gateway} if gateway else {})] if subnet else []
    return {
        "Name": name,
        "Id": id or hex64(),
        "Created": "2026-10-01T00:00:00.000000000Z",
        "Scope": "local",
        "Driver": driver,
        "EnableIPv4": True,
        "EnableIPv6": False,
        "IPAM": {"Driver": "default", "Options": None, "Config": config},
        "Internal": False,
        "Attachable": False,
        "Ingress": False,
        "ConfigFrom": {"Network": ""},
        "ConfigOnly": False,
        "Containers": dict(containers or {}),
        "Options": dict(options or {}),
        "Labels": dict(labels or {}),
    }


def volume_inspect(name: str) -> dict[str, Any]:
    return {
        "CreatedAt": "2026-10-01T00:00:00Z",
        "Driver": "local",
        "Labels": None,
        "Mountpoint": f"/var/lib/docker/volumes/{name}/_data",
        "Name": name,
        "Options": None,
        "Scope": "local",
    }


# ARCHIVES


def build_archive(
    root: Path,
    crypto: Crypto,
    *,
    job_uuid: str | None = None,
    job_name: str = "web",
    created_at: datetime | None = None,
    scope: m.Scope = "all",
    containers: Sequence[dict[str, Any]] = (),
    networks: Sequence[dict[str, Any]] = (),
    volumes: Mapping[str, bytes] | None = None,
    volume_configs: Mapping[str, dict[str, Any]] | None = None,
    binds: Sequence[tuple[str, str, bytes]] = (),
    images: Sequence[tuple[str, Sequence[str], bytes | None, str | None]] = (),
    compose: Sequence[tuple[str, str, bytes]] = (),
    encrypt: bool = False,
    raw_members: Mapping[str, bytes] | None = None,
) -> tuple[str, m.Manifest]:
    """Writes an archive into root as capture would and returns its name and manifest.

    containers are inspect documents (container_inspect). Their volume and bind mounts
    and their non-default networks (found by NetworkID or name in networks) are
    collected by capture's own add_mounts and add_networks; every network in networks is
    included either way.
    volumes maps volume names to inner tar data (default: just a root directory); names
    no container mounts are added too. volume_configs replaces volume inspect documents.
    binds are (host source, "dir" or "file", inner tar data); a bind no container mounts
    is added too, and a mounted bind not listed is a "dir" holding only its root.
    images are (image ID, refs, docker-save tar or None, confirmed registry digest or
    None); the tar is saved only when given and no digest is confirmed.
    compose are (role, host path, content) compose files.
    raw_members replaces the content of the named members, still signed.
    encrypt uses crypto.job_passphrase(job_uuid) and needs the age CLI."""
    job_uuid = job_uuid or str(uuid.uuid4())
    created_at = created_at or datetime.now(UTC).replace(microsecond=0)
    volumes = dict(volumes or {})
    volume_configs = dict(volume_configs or {})
    bind_data = {source: (kind, data) for source, kind, data in binds}
    parts = capture.SCOPE_PARTS[scope]
    by_network = {n["Id"]: n for n in networks} | {n["Name"]: n for n in networks}
    by_image = {
        image_id: image_inspect(image_id, refs, confirmed)
        for image_id, refs, _, confirmed in images
    }

    def inspect_network(ref: str) -> dict[str, Any]:
        if ref not in by_network:
            raise docker.errors.NotFound(f"network {ref} not found")
        return by_network[ref]

    api = SimpleNamespace(
        inspect_volume=lambda name: volume_configs.get(name) or volume_inspect(name),
        inspect_network=inspect_network,
    )
    plan = capture.Plan()
    for container in containers:
        plan.containers.append(container)
        plan.images.setdefault(container["Image"], by_image.get(container["Image"]))
        plan.image_refs.setdefault(container["Image"], [])
        capture.add_networks(api, plan, container, lambda _: None)
        capture.add_mounts(api, plan, container, lambda _: None)
    for network in networks:
        plan.networks.setdefault(network["Id"], network)
    for name in volumes:
        if name not in plan.volumes:
            plan.volumes[name] = api.inspect_volume(name)
            plan.volume_mounts[name] = []
    for source in bind_data:
        plan.binds.setdefault(source, [])
        if compose_files.system_path(source):
            plan.refused_binds[source] = "a system path"
    plan.compose = [
        compose_files.CapturedFile(compose_files.ComposeRef(role, host_path), data)
        for role, host_path, data in compose
    ]
    entries = []
    for image_id, refs, tar, confirmed in images:
        saved = tar is not None and "image" in parts and confirmed is None
        hex_digest = capture.hex_id(image_id)
        entries.append(
            m.ImageEntry(
                id=image_id,
                refs=list(refs),
                repo_digests=[confirmed] if confirmed else [],
                os="linux",
                architecture="amd64",
                saved=saved,
                confirmed_digest=confirmed,
                config_member=f"config/images/{hex_digest}.json" if "config" in parts else None,
                data_member=f"images/{hex_digest}.tar" if saved else None,
            )
        )
    bind_kinds = {
        source: bind_data.get(source, ("dir", b""))[0]
        for source in plan.binds
        if source not in plan.refused_binds
    }
    handle = SimpleNamespace(arch="amd64", os="linux", api_version="1.52", engine_version="29.0.0")
    with tempfile.TemporaryDirectory() as staging:
        env = capture.CaptureEnv(
            handle=handle,  # type: ignore[arg-type]
            host_name="local",
            helper_image="busybox",
            instance_id="test",
            staging_dir=Path(staging),
            crypto=crypto,
        )
        job = capture.CaptureJob(uuid=job_uuid, name=job_name, scope=scope, encrypted=encrypt)
        manifest = capture.build_manifest(env, job, plan, entries, bind_kinds, created_at)
        content = member_content(manifest, plan, entries, by_image, volumes, bind_data, images)
        content.update(raw_members or {})
        name = archive_name(job_uuid, job_name, created_at, encrypt)
        passphrase = crypto.job_passphrase(uuid.UUID(job_uuid)) if encrypt else None
        with ArchiveWriter(
            root / name,
            Path(staging),
            crypto,
            mtime=int(created_at.timestamp()),
            passphrase=passphrase,
            cancel=threading.Event(),
        ) as writer:
            writer.add_manifest(manifest)
            for member in manifest.members:
                data = content[member]
                if m.member_rank(member) == 1:
                    writer.add_bytes(member, data)
                else:
                    chunks = (data[i : i + SAVE_CHUNK] for i in range(0, len(data), SAVE_CHUNK))
                    writer.add_stream(member, chunks)
            writer.close()
    return name, manifest


def member_content(
    manifest: m.Manifest,
    plan: capture.Plan,
    entries: list[m.ImageEntry],
    by_image: dict[str, dict],
    volumes: dict[str, bytes],
    bind_data: dict[str, tuple[str, bytes]],
    images: Sequence[tuple[str, Sequence[str], bytes | None, str | None]],
) -> dict[str, bytes]:
    """Each member's bytes, as capture.write_members would write them."""
    by_id = {c["Id"]: c for c in plan.containers}
    tars = {image_id: tar for image_id, _, tar, _ in images}
    content: dict[str, bytes] = {}
    for entry in manifest.containers:
        if entry.config_member:
            content[entry.config_member] = capture.as_json(by_id[entry.id])
    for image in entries:
        if image.config_member:
            content[image.config_member] = capture.as_json(by_image[image.id])
        if image.data_member:
            content[image.data_member] = tars[image.id] or b""
    for entry in manifest.networks:
        if entry.config_member:
            content[entry.config_member] = capture.as_json(plan.networks[entry.id])
    for entry in manifest.volumes:
        if entry.config_member:
            content[entry.config_member] = capture.as_json(plan.volumes[entry.name])
        if entry.data_member:
            content[entry.data_member] = volumes.get(entry.name) or root_only_tar()
    for entry, captured in zip(manifest.compose_files, plan.compose, strict=True):
        content[entry.member] = captured.data
    for entry in manifest.binds:
        if entry.data_member:
            kind, data = bind_data.get(entry.source, ("dir", b""))
            if not data:
                data = inner_tar([TarEntry(f"b{entry.n}")]) if kind == "file" else root_only_tar()
            content[entry.data_member] = data
    return content
