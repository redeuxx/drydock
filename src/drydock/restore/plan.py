"""The restore planner: what a restore will do on one target host, decided before it does it.

build_plan is recomputed at execute time against fresh target state; only summary() is
stored. The dispatcher compares summary_core() of the fresh plan with the confirmed one,
so the user always confirmed exactly what runs.

Modes:
- new-name: one container restored beside the original under a new name. Its volumes and
  networks are renamed '<new>-<name>', and everything that would tie the copy to the
  original or its routing is dropped with a warning: Compose and reverse-proxy labels,
  published host ports, static IPs, MAC addresses and explicit subnets. A host-backed
  volume is refused where the original is (its copy would bind the same directory), and a
  network share or a non-local driver everywhere (its copy would mount the same storage).
  For a stack archive (manifest.job.target_type "stack") the new name is a new Compose
  project: containers become '<new>-<service>-<number>', Compose volumes and networks
  '<new>_<short name>', the project label is rewritten and peer names in links and aliases
  follow the new names, so the copy shares nothing with the original.
- overwrite: the originals (where present) are stopped and renamed '<name>-drydock-old',
  their volumes and opted-in bind mounts are wiped and rewritten, and new containers take
  the names. Works across hosts: with no original, the original names are created.

Several containers are ordered by engine.stacks.order from their archived inspect
documents: originals stop in reverse dependency order, containers are created and started
in forward order. new-name and overwrite can also write the archive's compose files into
a new directory on the target (Choice.compose_dir), after the restore committed.
- data-only: volume and bind data written into existing target volumes, chosen by name or
  by the volumes of a chosen container at the same destination. Never into host paths,
  never wiped.
- image-only: only images.

Security (every role, superadmin included): archive-supplied names are validated before
any lookup uses them; every host path passes the hostpaths denylist (host-backed local
volumes count as host paths); nothing joins or mounts drydock's own containers, networks
or volumes, and no tag of a repository drydock itself uses moves; nested write targets
are refused, because restored data could plant a symlink that redirects a later mount.
Everything a superadmin may accept becomes a RiskFlag. drydock's own labels are never
restored. apply resolves resolution_paths(plan) on the host and refuses the restore when
resolved_problems finds anything, since a symbolic link can defeat any lexical check.

Pure: no Docker calls and no I/O. restore.apply gathers the TargetInfo and runs the plan.
"""

import copy
import hashlib
import ipaddress
import posixpath
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, get_args

from drydock.archive import manifest as m
from drydock.engine import stacks
from drydock.engine.capture import COMPOSE_LABEL_PREFIX, REPO_DIGEST_RE
from drydock.engine.compose_files import WORKING_DIR_LABEL, under
from drydock.hosts import inventory
from drydock.hosts.client import api_tuple
from drydock.hosts.inventory import PROJECT_LABEL, SERVICE_LABEL
from drydock.restore import risk
from drydock.restore.risk import RiskFlag
from drydock.security import hostpaths
from drydock.security.hostpaths import HostPathError

Mode = Literal["new-name", "overwrite", "data-only", "image-only"]
MODES: tuple[Mode, ...] = get_args(Mode)
OLD_SUFFIX = stacks.OLD_SUFFIX
# moby's container name rule, [a-zA-Z0-9][a-zA-Z0-9_.-]+: at least two characters.
NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{1,62}", re.ASCII)
OBJECT_NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}", re.ASCII)
IMAGE_REF_RE = re.compile(
    r"(?P<repo>[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?::\d+)?"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)"
    r"(?::(?P<tag>\w[\w.-]{0,127}))?(?:@(?P<digest>sha256:[0-9a-f]{64}))?",
    re.ASCII,
)
ID_RE = re.compile(r"(sha256:)?[0-9a-f]{64}", re.ASCII)
HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
HEX_PREFIX_RE = re.compile(r"[0-9a-f]{1,64}", re.ASCII)
INDEX_RE = re.compile(r"\d{1,6}", re.ASCII)
ROUTING_LABEL_PREFIXES = ("traefik.", "caddy", "com.centurylinklabs.watchtower.")
RESTORE_LABEL = "drydock.restore.run"
# drydock's own labels (RESTORE_LABEL, and helper.HELPER_LABEL with helper.INSTANCE_LABEL,
# which mark a disposable helper that inventory hides and the reaper removes). Never restored.
DRYDOCK_LABEL_PREFIX = "drydock."
DEFAULT_NETWORKS = ("bridge", "host", "none", "default")
BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"
GW_PRIORITY_API = (1, 48)
ENDPOINT_KEYS = ("IPAMConfig", "Links", "Aliases", "MacAddress", "DriverOpts", "GwPriority")
IPAM_POOL_KEYS = ("Subnet", "IPRange", "Gateway", "AuxiliaryAddresses")
CONTAINER_MODE_FIELDS = ("NetworkMode", "IpcMode", "PidMode")
# moby refuses these on a container that joins another's network namespace.
CONTAINER_NETWORK_DROPS = (
    "PortBindings",
    "PublishAllPorts",
    "Links",
    "Dns",
    "DnsOptions",
    "DnsSearch",
    "ExtraHosts",
)
ARCH_ALIASES = {"x86_64": "amd64", "aarch64": "arm64"}
# The create body's keys beside Config's own.
BODY_KEYS = ("HostConfig", "NetworkingConfig")
NOT_A_MEMBER = "that container is not in the archive."
# A path component of a written compose file, and how deep one may lie.
COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]{1,255}", re.ASCII)
MAX_COMPONENTS = 16
# The Compose labels (after "com.docker.compose.") a new-name stack keeps: they describe
# the service, not the original's files. The project label is rewritten; every other
# Compose label is dropped, these first: they name the original's directory and files, or
# the container a recreate replaced.
KEPT_COMPOSE_LABELS = frozenset(
    {
        "service",
        "container-number",
        "oneoff",
        "version",
        "image",
        "depends_on",
        "config-hash",
        "network",
        "volume",
    }
)
DROPPED_COMPOSE_LABELS = frozenset(
    {"project.working_dir", "project.config_files", "project.environment_file", "replace"}
)


class PlanError(Exception):
    """The restore cannot be planned. Every message is safe to show."""

    def __init__(self, errors: str | Iterable[str]) -> None:
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__(" ".join(self.errors))


# CHOICE


@dataclass(frozen=True)
class Choice:
    """What the user chose on the plan form. Stored as to_dict() JSON in runs.plan."""

    host_id: int
    mode: Mode
    new_name: str = ""
    bind_remaps: dict[int, str] = field(default_factory=dict)  # bind n: new host path
    skip_binds: frozenset[int] = frozenset()
    wipe_binds: frozenset[int] = frozenset()
    share_binds: frozenset[int] = frozenset()
    volume_map: dict[str, str] = field(default_factory=dict)  # archive volume: target volume
    bind_volume_map: dict[int, str] = field(default_factory=dict)  # bind n: target volume
    data_container: str = ""
    compose_dir: str = ""  # new-name and overwrite: a new directory for the compose files
    acknowledged: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "mode": self.mode,
            "new_name": self.new_name,
            "bind_remaps": {str(n): p for n, p in sorted(self.bind_remaps.items())},
            "skip_binds": sorted(self.skip_binds),
            "wipe_binds": sorted(self.wipe_binds),
            "share_binds": sorted(self.share_binds),
            "volume_map": dict(sorted(self.volume_map.items())),
            "bind_volume_map": {str(n): v for n, v in sorted(self.bind_volume_map.items())},
            "data_container": self.data_container,
            "compose_dir": self.compose_dir,
            "acknowledged": sorted(self.acknowledged),
        }

    @classmethod
    def from_dict(cls, data: object) -> Choice:
        """Strict: unknown keys and wrong types raise PlanError. Map keys that are bind
        numbers may be ints or decimal strings (JSON object keys are strings)."""
        if not isinstance(data, dict):
            raise PlanError("The restore choice is not valid.")
        unknown = set(data) - {f for f in cls.__dataclass_fields__}
        if unknown or "host_id" not in data or "mode" not in data:
            raise PlanError("The restore choice is not valid.")
        host_id = data["host_id"]
        if not isinstance(host_id, int) or isinstance(host_id, bool) or host_id < 1:
            raise PlanError("The restore choice names no valid host.")
        if data["mode"] not in MODES:
            raise PlanError("The restore choice names no valid mode.")
        return cls(
            host_id=host_id,
            mode=data["mode"],
            new_name=text(data.get("new_name", ""), "new_name"),
            bind_remaps=int_map(data.get("bind_remaps", {}), "bind_remaps"),
            skip_binds=int_set(data.get("skip_binds", []), "skip_binds"),
            wipe_binds=int_set(data.get("wipe_binds", []), "wipe_binds"),
            share_binds=int_set(data.get("share_binds", []), "share_binds"),
            volume_map=str_map(data.get("volume_map", {}), "volume_map"),
            bind_volume_map=int_map(data.get("bind_volume_map", {}), "bind_volume_map"),
            data_container=text(data.get("data_container", ""), "data_container"),
            compose_dir=text(data.get("compose_dir", ""), "compose_dir"),
            acknowledged=frozenset(
                text(k, "acknowledged") for k in sequence(data.get("acknowledged", []))
            ),
        )


def text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise PlanError(f"The restore choice field {name} is not valid.")
    return value


def sequence(value: object) -> list[Any]:
    if not isinstance(value, list | tuple | set | frozenset):
        raise PlanError("The restore choice is not valid.")
    return list(value)


def index(value: object, name: str) -> int:
    if isinstance(value, str) and INDEX_RE.fullmatch(value):
        return int(value)
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**6:
        return value
    raise PlanError(f"The restore choice field {name} is not valid.")


def int_set(value: object, name: str) -> frozenset[int]:
    if not isinstance(value, list | tuple | set | frozenset):
        raise PlanError(f"The restore choice field {name} is not valid.")
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in value):
        raise PlanError(f"The restore choice field {name} is not valid.")
    return frozenset(index(v, name) for v in value)


def int_map(value: object, name: str) -> dict[int, str]:
    if not isinstance(value, dict):
        raise PlanError(f"The restore choice field {name} is not valid.")
    return {index(k, name): text(v, name) for k, v in value.items()}


def str_map(value: object, name: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise PlanError(f"The restore choice field {name} is not valid.")
    return {text(k, name): text(v, name) for k, v in value.items()}


# TARGET STATE AND FACTS


@dataclass(frozen=True)
class ContainerUse:
    id: str
    name: str
    state: str


@dataclass(frozen=True)
class BindUse:
    id: str
    name: str
    state: str
    source: str


@dataclass(frozen=True)
class ArchiveFacts:
    """What pass 1 learned: the image IDs each saved image may load as, and the data
    members holding setuid, setgid or file-capability files."""

    loaded_ids: Mapping[str, frozenset[str]] = field(default_factory=dict)
    setid_members: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Lookup:
    """The names restore.apply.inspect_target looks up on the target."""

    containers: frozenset[str]
    volumes: frozenset[str]
    networks: frozenset[str]
    images: frozenset[str]
    projects: frozenset[str] = frozenset()  # Compose projects whose containers to list


@dataclass(frozen=True)
class TargetInfo:
    host_id: int
    host_name: str
    api_version: str
    arch: str
    containers: dict[str, dict] = field(default_factory=dict)  # exact-name matches, inspect
    volumes: dict[str, dict] = field(default_factory=dict)  # inspect
    volume_users: dict[str, tuple[ContainerUse, ...]] = field(default_factory=dict)
    # Every host path any container on the host mounts: bind sources, and the device of
    # each host-backed volume it mounts. The container list shows those as Type volume with
    # the Mountpoint as Source, so inspect_target inspects every mounted local volume.
    bind_users: tuple[BindUse, ...] = ()
    networks: dict[str, dict] = field(default_factory=dict)  # inspect
    images: dict[str, str] = field(default_factory=dict)  # ref or ID: image Id
    own: frozenset[str] = frozenset()  # drydock's own container IDs
    own_networks: frozenset[str] = frozenset()  # names and IDs
    own_volumes: frozenset[str] = frozenset()
    # Host paths of drydock's own deployment: its containers' bind sources (the secret key
    # file, the backup storage), its volumes' Mountpoints and the daemon's DockerRootDir.
    # inspect_target must fill it; the empty default protects nothing.
    own_paths: frozenset[str] = frozenset()
    protected_repos: frozenset[str] = frozenset()
    # Lookup.projects: the names of each project's containers (helpers and originals an
    # overwrite renamed are left out).
    projects: dict[str, tuple[str, ...]] = field(default_factory=dict)


# STEPS


@dataclass(frozen=True)
class ImageStep:
    id: str  # ImageEntry.id
    label: str
    action: Literal["load", "pull", "present"]
    member: str | None  # images/<hex>.tar, for load
    pull: str | None  # the confirmed repo@digest, for pull
    # load and pull: the tag refs (no '@') that must name the image afterwards. present:
    # those tags and the digest refs the target resolves, so apply can find the image.
    refs: tuple[str, ...]
    os: str
    architecture: str
    variant: str | None
    accepted_ids: tuple[str, ...]
    moves: tuple[str, ...]  # tags that now name another image on the target


@dataclass(frozen=True)
class NetworkStep:
    name: str
    action: Literal["create", "reuse"]
    create: dict[str, Any]  # docker-py create_network kwargs, for create
    differences: tuple[str, ...]  # for reuse


@dataclass(frozen=True)
class VolumeStep:
    name: str
    action: Literal["create", "reuse"]
    driver: str
    driver_opts: dict[str, Any]
    labels: dict[str, Any]
    device: str | None  # the host path a local bind-backed volume mounts


@dataclass(frozen=True)
class Original:
    id: str
    name: str
    old_name: str
    running: bool
    stop_timeout: int


@dataclass(frozen=True)
class Wipe:
    kind: Literal["volume", "bind"]
    target: str
    label: str


@dataclass(frozen=True)
class DataStep:
    member: str
    kind: Literal["volume", "bind-dir", "bind-file"]
    target: str  # the volume name, or the host path (bind-file: the file itself)
    label: str  # 'volume <name>' or 'bind mount <path>', exactly
    rename_to: str | None  # a file bind's single member is written under this name


@dataclass(frozen=True)
class ContainerStep:
    name: str
    body: dict[str, Any]
    start: bool
    image_entry: str | None  # ImageEntry.id whose resolved target ID replaces body['Image']
    # Created containers (by name) whose healthcheck must pass before this one starts.
    wait_healthy: tuple[str, ...] = ()


@dataclass(frozen=True)
class ComposeOut:
    member: str  # compose/<n>/<basename>
    path: str  # relative to the compose directory, '/'-separated
    size: int


@dataclass(frozen=True)
class ComposeWrite:
    dir: str  # normalized
    files: tuple[ComposeOut, ...]  # sorted by path


@dataclass(frozen=True)
class MakeDir:
    """A directory the archive's job skipped, created where it is missing so the
    container can bind it: one level (its parent must exist), with the archived owner."""

    path: str  # normalized and checked as a write target
    owner: str  # "uid:gid"
    mode: int  # permission bits, setgid and sticky only
    label: str


@dataclass(frozen=True)
class RestorePlan:
    mode: Mode
    host_id: int
    images: tuple[ImageStep, ...]
    networks: tuple[NetworkStep, ...]
    volumes: tuple[VolumeStep, ...]
    originals: tuple[Original, ...]
    wipes: tuple[Wipe, ...]
    data: tuple[DataStep, ...]
    containers: tuple[ContainerStep, ...]
    risk: tuple[RiskFlag, ...]
    warnings: tuple[str, ...]
    lock_keys: tuple[str, ...]
    bind_sources: tuple[str, ...]  # normalized host paths that will be mounted
    write_targets: tuple[str, ...]  # host paths written into or wiped
    # TargetInfo.own_paths, which apply checks the resolved paths against again.
    own_paths: tuple[str, ...] = ()
    # What restored data or a wipe changes (dir targets, devices and the files of file
    # binds), and the host paths of live containers other than the originals (sources
    # normalized). resolved_problems checks both again as resolved.
    written: tuple[str, ...] = ()
    live_users: tuple[BindUse, ...] = ()
    project: str | None = None  # the Compose project a stack restore creates or replaces
    # Every Compose project whose lock key the plan holds, sorted.
    projects: tuple[str, ...] = ()
    compose: ComposeWrite | None = None
    mkdirs: tuple[MakeDir, ...] = ()


@dataclass(frozen=True)
class NameMap:
    containers: dict[str, str]  # archive name: target name
    ids: dict[str, str]  # archive container ID (and its 12-character prefix): target name
    volumes: dict[str, str]
    networks: dict[str, str]


# ARCHIVE VALIDATION


def shown(value: object) -> str:
    text_value = repr(value)
    return text_value if len(text_value) <= 80 else text_value[:77] + "..."


def valid_ref(value: object) -> bool:
    return isinstance(value, str) and IMAGE_REF_RE.fullmatch(value) is not None


def valid_image(value: object) -> bool:
    return valid_ref(value) or (isinstance(value, str) and ID_RE.fullmatch(value) is not None)


def container_refs(info: dict[str, Any]) -> list[str]:
    """The other containers a config refers to: VolumesFrom and container:X modes."""
    host = info.get("HostConfig") or {}
    refs = [str(entry).split(":", 1)[0] for entry in host.get("VolumesFrom") or []]
    for key in CONTAINER_MODE_FIELDS:
        value = host.get(key)
        if isinstance(value, str) and value.startswith("container:"):
            refs.append(value.removeprefix("container:"))
    return refs


def network_mode_network(info: dict[str, Any]) -> str | None:
    mode = (info.get("HostConfig") or {}).get("NetworkMode") or ""
    if not mode or mode in DEFAULT_NETWORKS or mode.startswith("container:"):
        return None
    return mode


def endpoint_networks(info: dict[str, Any]) -> list[str]:
    return list(((info.get("NetworkSettings") or {}).get("Networks") or {}).keys())


# The parts of archived inspect documents the planner reads, and their types.
Shapes = tuple[tuple[tuple[str, ...], type], ...]
SHAPES: Shapes = (
    (("Config",), dict),
    (("HostConfig",), dict),
    (("State",), dict),
    (("NetworkSettings",), dict),
    (("Mounts",), list),
    (("Config", "Labels"), dict),
    (("HostConfig", "Binds"), list),
    (("HostConfig", "Mounts"), list),
    (("HostConfig", "Links"), list),
    (("HostConfig", "VolumesFrom"), list),
    (("HostConfig", "SecurityOpt"), list),
    (("NetworkSettings", "Networks"), dict),
)
ITEM_TYPES: Shapes = (
    (("Mounts",), dict),
    (("HostConfig", "Binds"), str),
    (("HostConfig", "Mounts"), dict),
    (("HostConfig", "Links"), str),
    (("HostConfig", "VolumesFrom"), str),
    (("HostConfig", "SecurityOpt"), str),
)
# The fields of list items and endpoints the planner reads, when present.
MOUNT_SHAPES: Shapes = (
    (("Type",), str),
    (("Name",), str),
    (("Source",), str),
    (("Destination",), str),
)
HOST_MOUNT_SHAPES: Shapes = (
    (("Type",), str),
    (("Source",), str),
    (("Target",), str),
    (("VolumeOptions",), dict),
    (("BindOptions",), dict),
)
ENDPOINT_SHAPES: Shapes = (
    (("IPAMConfig",), dict),
    (("IPAMConfig", "IPv4Address"), str),
    (("IPAMConfig", "IPv6Address"), str),
    (("Aliases",), list),
    (("Links",), list),
    (("DriverOpts",), dict),
    (("MacAddress",), str),
)
ENDPOINT_ITEM_TYPES: Shapes = ((("Aliases",), str), (("Links",), str))
NETWORK_SHAPES: Shapes = (
    (("IPAM",), dict),
    (("IPAM", "Config"), list),
    (("IPAM", "Options"), dict),
    (("Options",), dict),
    (("Labels",), dict),
    (("ConfigFrom",), dict),
)
NETWORK_ITEM_TYPES: Shapes = ((("IPAM", "Config"), dict),)
VOLUME_SHAPES: Shapes = ((("Options",), dict), (("Labels",), dict))


def nested(document: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = document
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def shaped(document: dict[str, Any], shapes: Shapes, items: Shapes = ()) -> bool:
    for path, kind in shapes:
        value = nested(document, path)
        if value is not None and not isinstance(value, kind):
            return False
    return all(
        all(isinstance(item, kind) for item in nested(document, path) or []) for path, kind in items
    )


def shape_ok(info: dict[str, Any]) -> bool:
    if not shaped(info, SHAPES, ITEM_TYPES):
        return False
    endpoints = nested(info, ("NetworkSettings", "Networks")) or {}
    if not all(
        ep is None or (isinstance(ep, dict) and shaped(ep, ENDPOINT_SHAPES, ENDPOINT_ITEM_TYPES))
        for ep in endpoints.values()
    ):
        return False
    if not all(shaped(mt, MOUNT_SHAPES) for mt in info.get("Mounts") or []):
        return False
    host = info.get("HostConfig") or {}
    if not all(shaped(mt, HOST_MOUNT_SHAPES) for mt in host.get("Mounts") or []):
        return False
    return all(isinstance(host.get(k) or "", str) for k in CONTAINER_MODE_FIELDS)


def archive_problems(manifest: m.Manifest, configs: Mapping[str, Any]) -> list[str]:
    """Every archive-supplied name and ref that a Docker call could see, checked."""
    problems: list[str] = []

    def check(kind: str, value: object, ok: bool) -> None:
        if not ok:
            problems.append(f"The archive holds an invalid {kind} {shown(value)}.")

    def name(kind: str, value: object) -> None:
        check(
            f"{kind} name", value, isinstance(value, str) and bool(OBJECT_NAME_RE.fullmatch(value))
        )

    def config(member: str | None, what: str) -> dict[str, Any] | None:
        if member is None:
            return None
        document = configs.get(member)
        if not isinstance(document, dict):
            problems.append(f"The archive holds no valid configuration for {what}.")
            return None
        return document

    for entry in manifest.containers:
        name("container", entry.name)
        check("container ID", entry.id, bool(HEX64_RE.fullmatch(entry.id)))
        check("image", entry.image, valid_image(entry.image))
        check("image ID", entry.image_id, bool(ID_RE.fullmatch(entry.image_id)))
        info = config(entry.config_member, f"container {entry.name}")
        if info is None:
            continue
        if not shape_ok(info):
            problems.append(f"The configuration of container {entry.name} is not valid.")
            continue
        if info.get("Id") != entry.id or info.get("Name") != f"/{entry.name}":
            problems.append(f"The configuration of container {entry.name} does not match.")
        image = (info.get("Config") or {}).get("Image")
        if image is not None:
            check("image", image, valid_image(image))
        for network in endpoint_networks(info):
            name("network", network)
        mode_network = network_mode_network(info)
        if mode_network is not None:
            name("network", mode_network)
        for mount in info.get("Mounts") or []:
            if mount.get("Type") == "volume":
                name("volume", mount.get("Name"))
        for ref in container_refs(info):
            name("container", ref)
    for network in manifest.networks:
        name("network", network.name)
        check("network ID", network.id, bool(HEX64_RE.fullmatch(network.id)))
        document = config(network.config_member, f"network {network.name}")
        if document is not None and (
            document.get("Name") != network.name
            or not shaped(document, NETWORK_SHAPES, NETWORK_ITEM_TYPES)
        ):
            problems.append(f"The configuration of network {network.name} is not valid.")
    for volume in manifest.volumes:
        name("volume", volume.name)
        document = config(volume.config_member, f"volume {volume.name}")
        if document is not None and (
            document.get("Name") != volume.name or not shaped(document, VOLUME_SHAPES)
        ):
            problems.append(f"The configuration of volume {volume.name} is not valid.")
    for image in manifest.images:
        check("image ID", image.id, bool(ID_RE.fullmatch(image.id)))
        for ref in image.refs:
            check("image reference", ref, valid_ref(ref))
        if image.confirmed_digest is not None:
            digest = image.confirmed_digest
            ok = valid_ref(digest) and REPO_DIGEST_RE.fullmatch(digest) is not None
            check("image digest", digest, ok)
    if is_stack(manifest):
        project = manifest.job.project
        valid = isinstance(project, str) and stacks.PROJECT_RE.fullmatch(project) is not None
        check("Compose project", project, valid)
        if valid and any(c.compose_project != project for c in manifest.containers):
            problems.append(
                f"The archive's containers do not all belong to Compose project {project}."
            )
    return problems


def is_stack(manifest: m.Manifest) -> bool:
    return manifest.job.target_type == "stack"


def stack_project(manifest: m.Manifest) -> str | None:
    return manifest.job.project if is_stack(manifest) else None


def choice_problems(manifest: m.Manifest, choice: Choice) -> list[str]:
    problems = []
    if choice.mode not in MODES:
        problems.append("Choose a restore mode.")
    # Checked in every mode: a stale new_name must never reach a Docker call unchecked.
    named = choice.mode == "new-name" or bool(choice.new_name)
    if named and is_stack(manifest):
        # A new Compose project: the same rule as Compose's own.
        if not stacks.PROJECT_RE.fullmatch(choice.new_name):
            problems.append(
                "The new project name must hold 1 to 63 lowercase letters, digits, '_' or "
                "'-', starting with a letter or digit."
            )
    elif named and not NAME_RE.fullmatch(choice.new_name):
        problems.append(
            "The new name must start with a letter or digit and hold 2 to 63 letters, "
            "digits, '_', '.' or '-'."
        )
    if choice.compose_dir:
        if choice.mode not in ("new-name", "overwrite"):
            problems.append("Compose files are written only in new-name and overwrite modes.")
        try:
            hostpaths.normalize(choice.compose_dir)
        except HostPathError as exc:
            problems.append(str(exc))
        if not manifest.compose_files:
            problems.append("This archive holds no compose files.")
    targets = [choice.data_container] if choice.data_container else []
    targets += [*choice.volume_map.values(), *choice.bind_volume_map.values()]
    problems += [
        f"{shown(t)} is not a valid container or volume name."
        for t in targets
        if not OBJECT_NAME_RE.fullmatch(t)
    ]
    volumes = {v.name for v in manifest.volumes}
    problems += [
        f"Volume {shown(v)} is not in the archive." for v in choice.volume_map if v not in volumes
    ]
    binds = {b.n for b in manifest.binds}
    for numbers in (
        choice.bind_remaps,
        choice.skip_binds,
        choice.wipe_binds,
        choice.share_binds,
        choice.bind_volume_map,
    ):
        problems += [
            f"Bind mount {n} is not in the archive." for n in sorted(numbers) if n not in binds
        ]
    return problems


# NAMES


def derived(new: str, name: str) -> str:
    candidate = f"{new}-{name[:12] if HEX64_RE.fullmatch(name) else name}"
    if OBJECT_NAME_RE.fullmatch(candidate):
        return candidate
    return f"{new}-{hashlib.sha256(name.encode()).hexdigest()[:12]}"


def name_map(
    manifest: m.Manifest, choice: Choice, configs: Mapping[str, Any] | None = None
) -> NameMap:
    """The target name of every archived container, volume and network. A new-name stack
    names them the way Compose would under the new project, from their archived labels in
    configs."""
    if choice.mode != "new-name":
        return NameMap(
            containers={c.name: c.name for c in manifest.containers},
            ids={key: c.name for c in manifest.containers for key in (c.id, c.id[:12])},
            volumes={v.name: v.name for v in manifest.volumes},
            networks={n.name: n.name for n in manifest.networks},
        )
    new = choice.new_name
    if not is_stack(manifest):
        return NameMap(
            containers={c.name: new for c in manifest.containers},
            ids={key: new for c in manifest.containers for key in (c.id, c.id[:12])},
            volumes={v.name: derived(new, v.name) for v in manifest.volumes},
            networks={n.name: derived(new, n.name) for n in manifest.networks},
        )
    old = manifest.job.project

    def config_of(member: str | None) -> dict[str, Any]:
        document = (configs or {}).get(member) if member else None
        return document if isinstance(document, dict) else {}

    def container(entry: m.ContainerEntry) -> str:
        labels = stacks.labels_of(config_of(entry.config_member))
        service, number = labels.get(SERVICE_LABEL), labels.get(stacks.NUMBER_LABEL)
        if (
            isinstance(service, str)
            and stacks.SERVICE_RE.fullmatch(service)
            and isinstance(number, str)
            and number.isascii()
            and number.isdigit()
            and OBJECT_NAME_RE.fullmatch(candidate := f"{new}-{service}-{number}")
        ):
            return candidate
        return derived(new, entry.name)

    def compose_object(member: str | None, label: str, name: str) -> str:
        labels = config_of(member).get("Labels")
        labels = labels if isinstance(labels, dict) else {}
        short = labels.get(label)
        if (
            labels.get(PROJECT_LABEL) == old
            and isinstance(short, str)
            and OBJECT_NAME_RE.fullmatch(short)
            and OBJECT_NAME_RE.fullmatch(candidate := f"{new}_{short}")
        ):
            return candidate
        return derived(new, name)

    containers = {c.name: container(c) for c in manifest.containers}
    return NameMap(
        containers=containers,
        ids={key: containers[c.name] for c in manifest.containers for key in (c.id, c.id[:12])},
        volumes={
            v.name: compose_object(v.config_member, stacks.VOLUME_LABEL, v.name)
            for v in manifest.volumes
        },
        networks={
            n.name: compose_object(n.config_member, stacks.NETWORK_LABEL, n.name)
            for n in manifest.networks
        },
    )


def lookups(manifest: m.Manifest, configs: Mapping[str, Any], choice: Choice) -> Lookup:
    """The names to inspect on the target. Raises PlanError for any invalid archive name or
    ref before a Docker call can use it."""
    problems = archive_problems(manifest, configs) + choice_problems(manifest, choice)
    if problems:
        raise PlanError(problems)
    names = name_map(manifest, choice, configs)
    containers = {c.name for c in manifest.containers} | set(names.containers.values())
    if choice.mode == "overwrite":
        containers |= {c.name + OLD_SUFFIX for c in manifest.containers}
    if choice.mode == "new-name" and not is_stack(manifest):
        # A stack's new name is a project, not a container: its members' mapped names are
        # looked up instead, and a short hex project name could match container IDs.
        containers.add(choice.new_name)
    if choice.data_container:
        containers.add(choice.data_container)
    volumes = set(names.volumes) | set(names.volumes.values())
    volumes |= set(choice.volume_map.values()) | set(choice.bind_volume_map.values())
    networks = set(names.networks) | set(names.networks.values())
    for entry in manifest.containers:
        info = configs.get(entry.config_member) if entry.config_member else None
        if not isinstance(info, dict):
            continue
        containers |= set(container_refs(info))
        networks |= {n for n in endpoint_networks(info) if n not in DEFAULT_NETWORKS}
        if (mode_network := network_mode_network(info)) is not None:
            networks.add(mode_network)
    images = {c.image for c in manifest.containers}
    for image in manifest.images:
        images |= {image.id, *image.refs}
        if image.confirmed_digest:
            images.add(image.confirmed_digest)
    project = restored_project(manifest, choice)
    return Lookup(
        frozenset(containers),
        frozenset(volumes),
        frozenset(networks),
        frozenset(images),
        frozenset({project} if project else ()),
    )


def restored_project(manifest: m.Manifest, choice: Choice) -> str | None:
    """The Compose project a stack restore creates (new-name) or replaces (overwrite)."""
    if not is_stack(manifest):
        return None
    if choice.mode == "new-name":
        return choice.new_name
    if choice.mode == "overwrite":
        return manifest.job.project
    return None


# CREATE BODIES


def dropped_label(key: str, *, routing: bool = True, compose: bool = True) -> bool:
    return (compose and key.startswith(COMPOSE_LABEL_PREFIX)) or (
        routing and key.startswith(ROUTING_LABEL_PREFIXES)
    )


def compose_label_set(
    labels: dict[str, Any], project: str, what: str, notes: list[str]
) -> dict[str, Any]:
    """labels with their Compose keys made those of the new project: the project label is
    project, KEPT_COMPOSE_LABELS stay, every other Compose key goes (with one note), so the
    copy never joins the original's project or names its files. Other keys are untouched."""
    out: dict[str, Any] = {}
    dropped = []
    for key, value in labels.items():
        suffix = key.removeprefix(COMPOSE_LABEL_PREFIX)
        if not key.startswith(COMPOSE_LABEL_PREFIX):
            out[key] = value
        elif key == PROJECT_LABEL:
            out[key] = project
        elif suffix in KEPT_COMPOSE_LABELS and suffix not in DROPPED_COMPOSE_LABELS:
            out[key] = value
        else:
            dropped.append(key)
    if dropped:
        notes.append(
            f"Dropped the labels {', '.join(sorted(dropped))} of {what}: they name the "
            "original's compose files or are unknown to drydock."
        )
    return out


def without_own_labels(labels: dict[str, Any], what: str, notes: list[str]) -> dict[str, Any]:
    """labels minus drydock's own, with a warning. A restored object carrying the helper
    labels would pass for one of drydock's helpers: hidden, never backed up, reaped."""
    dropped = sorted(k for k in labels if k.startswith(DRYDOCK_LABEL_PREFIX))
    if not dropped:
        return labels
    notes.append(f"Dropped the labels {', '.join(dropped)} of {what}: drydock sets its own.")
    return {k: v for k, v in labels.items() if k not in dropped}


def norm_dest(path: str) -> str:
    return posixpath.normpath(path) if path else path


def container_body(
    info: dict[str, Any],
    *,
    names: NameMap,
    mode: Mode,
    api_version: str,
    bind_map: Mapping[str, str],
    warnings: list[str] | None = None,
    project: str | None = None,
) -> dict[str, Any]:
    """The /containers/create body for one archived container inspect.

    bind_map maps each normalized archive bind source to its final host path. Warnings for
    everything dropped are appended to warnings. project is the new Compose project of a
    new-name stack restore: its Compose labels are rewritten for it, and links and aliases
    name archive members only by their new names. Raises PlanError.
    """
    notes = warnings if warnings is not None else []
    new_name = mode == "new-name"
    # A new-name stack's members by original name and ID: what links and aliases may name.
    peers = {**names.containers, **names.ids} if new_name and project is not None else None
    container_id = info["Id"]
    original = info["Name"].lstrip("/")
    name = names.containers.get(original, original)
    config = copy.deepcopy(info.get("Config") or {})
    host = copy.deepcopy(info.get("HostConfig") or {})
    # The body is Config with HostConfig and NetworkingConfig beside it, so a Config that
    # holds either would reach Docker past every check made here.
    stray = sorted(k for k in BODY_KEYS if config.pop(k, None) is not None)
    if stray:
        notes.append(f"Ignored {', '.join(stray)} in the Config of {name}.")

    def volume(source: str) -> str:
        if source not in names.volumes:
            raise PlanError(f"Volume {source} of container {name} is not in the archive.")
        return names.volumes[source]

    def bind(source: str) -> str:
        try:
            normalized = hostpaths.normalize(source)
        except HostPathError as exc:
            raise PlanError(str(exc)) from None
        return bind_map.get(normalized, normalized)

    def container(ref: str) -> str:
        return names.containers.get(ref) or names.ids.get(ref) or ref

    # CONFIG
    if config.get("Hostname") == container_id[:12]:
        config.pop("Hostname")
    if config.get("Domainname") == "":
        config.pop("Domainname")
    mac = config.pop("MacAddress", None) or None
    if config.get("Labels"):
        config["Labels"] = without_own_labels(config["Labels"], name, notes)
    if new_name:
        labels = config.get("Labels") or {}
        if project is not None and labels:
            labels = config["Labels"] = compose_label_set(labels, project, name, notes)
        dropped = sorted(k for k in labels if dropped_label(k, compose=project is None))
        if dropped:
            config["Labels"] = {k: v for k, v in labels.items() if k not in dropped}
            notes.append(
                f"Dropped the labels {', '.join(dropped)} of {name}: they tie it to the "
                "original's Compose project, proxy routes or updater."
            )

    # HOSTCONFIG
    for key in ("ContainerIDFile", "MaskedPaths", "ReadonlyPaths"):
        host.pop(key, None)
    covered: set[str] = set()
    if host.get("Binds") is not None:
        binds = []
        for entry in host["Binds"]:
            source, destination, options = risk.split_bind(entry)
            covered.add(norm_dest(destination))
            source = bind(source) if source.startswith("/") else volume(source)
            binds.append(":".join([source, destination, *([options] if options else [])]))
        host["Binds"] = binds
    if host.get("Mounts") is not None:
        mounts = []
        for mount in host["Mounts"]:
            kind = mount.get("Type")
            target = mount.get("Target") or ""
            covered.add(norm_dest(target))
            if kind == "volume":
                source = mount.get("Source") or anonymous_volume(info, target)
                if not source:
                    raise PlanError(f"The volume of {name} at {target} has no name.")
                mount["Source"] = volume(source)
                options = {
                    k: v
                    for k, v in (mount.get("VolumeOptions") or {}).items()
                    if k not in ("DriverConfig", "Labels")
                }
                if options:
                    mount["VolumeOptions"] = options
                else:
                    mount.pop("VolumeOptions", None)
            elif kind == "bind":
                mount["Source"] = bind(str(mount.get("Source") or ""))
            elif kind != "tmpfs":
                raise PlanError(
                    f"Container {name} has a {kind} mount, which a restore does not support."
                )
            mounts.append(mount)
        host["Mounts"] = mounts
    for mount in info.get("Mounts") or []:
        destination = norm_dest(mount.get("Destination") or "")
        if mount.get("Type") == "volume" and destination not in covered:
            read_only = "" if mount.get("RW", True) else ":ro"
            host["Binds"] = [
                *(host.get("Binds") or []),
                f"{volume(mount['Name'])}:{destination}{read_only}",
            ]
            covered.add(destination)
    if host.get("Links"):
        links = []
        for link in host["Links"]:
            peer, _, alias = link.partition(":")
            peer = peer.lstrip("/")
            if peers is not None and peer not in peers:
                notes.append(f"Dropped the link of {name} to {peer}: {NOT_A_MEMBER}")
                continue
            alias = posixpath.basename(alias)
            if peers is not None and (not alias or alias in peers):
                alias = peers[peer]  # an alias naming an original container
            links.append(f"{container(peer)}:{alias}")
        if links:
            host["Links"] = links
        else:
            host.pop("Links")
    if host.get("VolumesFrom"):
        host["VolumesFrom"] = [
            ":".join([container(ref), *rest])
            for ref, *rest in (entry.split(":", 1) for entry in host["VolumesFrom"])
        ]
    for key in CONTAINER_MODE_FIELDS:
        value = host.get(key)
        if isinstance(value, str) and value.startswith("container:"):
            host[key] = "container:" + container(value.removeprefix("container:"))
    network_mode = host.get("NetworkMode") or ""
    if network_mode in names.networks:
        network_mode = host["NetworkMode"] = names.networks[network_mode]
    if new_name and host.get("PortBindings"):
        host.pop("PortBindings")
        notes.append(
            f"Dropped the published ports of {name}: the original holds them. "
            "Publish ports again by hand if needed."
        )
    if network_mode.startswith("container:"):
        for key in ("Hostname", "Domainname", "ExposedPorts"):
            config.pop(key, None)
        for key in CONTAINER_NETWORK_DROPS:
            host.pop(key, None)
        mac = None
    elif network_mode == "host":
        if config.pop("Hostname", None):
            notes.append(f"{name} uses the host network, so it takes the target host's hostname.")
        mac = None

    # NETWORKINGCONFIG
    endpoints: dict[str, dict[str, Any]] = {}
    if network_mode not in ("host", "none") and not network_mode.startswith("container:"):
        networks = (info.get("NetworkSettings") or {}).get("Networks") or {}
        for network, endpoint in sorted(networks.items()):
            if network in DEFAULT_NETWORKS:
                mapped = network
            elif network in names.networks:
                mapped = names.networks[network]
            elif new_name:
                notes.append(f"Dropped network {network} from {name}: it is not in the archive.")
                continue
            else:
                mapped = network
            endpoints[mapped] = endpoint_config(
                endpoint or {},
                info,
                new_name=new_name,
                api_version=api_version,
                notes=notes,
                peers=peers,
            )
        if (
            new_name
            and network_mode
            and network_mode not in DEFAULT_NETWORKS
            and network_mode not in endpoints
        ):
            network_mode = host["NetworkMode"] = next(iter(endpoints), "bridge")
    # Overwrite keeps every endpoint MAC. Inspect does not say whether Docker generated it
    # (a generated one changes on every start) or it was configured, so a generated MAC
    # becomes a fixed one; dropping it instead would lose configured MACs.
    if mac and not new_name and endpoints:
        primary = (
            endpoints[network_mode] if network_mode in endpoints else next(iter(endpoints.values()))
        )
        primary.setdefault("MacAddress", mac)
    body: dict[str, Any] = {**config, "HostConfig": host}
    if endpoints:
        body["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return body


def anonymous_volume(info: dict[str, Any], target: str) -> str:
    """The volume Docker created for a Compose anonymous volume, which HostConfig.Mounts
    records without a Source: only the runtime Mounts entry names it."""
    for mount in info.get("Mounts") or []:
        if mount.get("Type") == "volume" and norm_dest(mount.get("Destination") or "") == norm_dest(
            target
        ):
            return str(mount.get("Name") or "")
    return ""


def endpoint_config(
    endpoint: dict[str, Any],
    info: dict[str, Any],
    *,
    new_name: bool,
    api_version: str,
    notes: list[str],
    peers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """One EndpointsConfig entry. peers (new-name stacks only) maps every archive member's
    original name, ID and short ID to its new name: aliases and links that name a member
    name it by its new name, and links to containers outside the archive are dropped."""
    container_id = info["Id"]
    original = info["Name"].lstrip("/")
    out = {key: copy.deepcopy(endpoint[key]) for key in ENDPOINT_KEYS if endpoint.get(key)}
    if "GwPriority" in out and api_tuple(api_version) < GW_PRIORITY_API:
        out.pop("GwPriority")
    if isinstance(out.get("IPAMConfig"), dict):
        ipam = {k: v for k, v in out["IPAMConfig"].items() if v}
        if ipam:
            out["IPAMConfig"] = ipam
        else:
            out.pop("IPAMConfig")
    aliases = [
        a for a in out.get("Aliases") or [] if a not in (container_id, container_id[:12], original)
    ]
    if peers is not None:
        own = peers.get(original, original)
        aliases = list(dict.fromkeys(a for a in (peers.get(a, a) for a in aliases) if a != own))
        links = []
        for link in out.get("Links") or []:
            peer, _, alias = link.partition(":")
            peer = peer.lstrip("/")
            if peer not in peers:
                notes.append(f"Dropped the link of {own} to {peer}: {NOT_A_MEMBER}")
                continue
            if not alias or alias in peers:
                alias = peers[peer]
            links.append(f"{peers[peer]}:{alias}")
        if links:
            out["Links"] = links
        else:
            out.pop("Links", None)
    if aliases:
        out["Aliases"] = aliases
    else:
        out.pop("Aliases", None)
    if new_name:
        if out.pop("IPAMConfig", None):
            notes.append("Dropped a static IP address: it belongs to the original container.")
        if out.pop("MacAddress", None):
            notes.append("Dropped a MAC address: it belongs to the original container.")
    return out


def with_sources(body: dict[str, Any], mapping: Mapping[str, str]) -> dict[str, Any]:
    """A copy of body whose bind sources are replaced by mapping[source] where present, so
    apply mounts exactly the paths it resolved and checked."""
    out = copy.deepcopy(body)
    host = out.get("HostConfig") or {}
    if host.get("Binds"):
        binds = []
        for entry in host["Binds"]:
            source, destination, options = risk.split_bind(entry)
            if source.startswith("/") and source in mapping:
                source = mapping[source]
            binds.append(":".join([source, destination, *([options] if options else [])]))
        host["Binds"] = binds
    for mount in host.get("Mounts") or []:
        if mount.get("Type") == "bind" and mount.get("Source") in mapping:
            mount["Source"] = mapping[mount["Source"]]
    return out


# PLANNING


@dataclass
class Draft:
    manifest: m.Manifest
    configs: Mapping[str, Any]
    target: TargetInfo
    choice: Choice
    facts: ArchiveFacts
    names: NameMap
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    images: dict[str, ImageStep] = field(default_factory=dict)
    networks: list[NetworkStep] = field(default_factory=list)
    volumes: list[VolumeStep] = field(default_factory=list)
    originals: list[Original] = field(default_factory=list)
    wipes: list[Wipe] = field(default_factory=list)
    data: list[DataStep] = field(default_factory=list)
    containers: list[ContainerStep] = field(default_factory=list)
    risk: list[RiskFlag] = field(default_factory=list)
    bind_sources: set[str] = field(default_factory=set)
    write_targets: set[str] = field(default_factory=set)
    # What restored data or a wipe changes (dir targets, devices and file targets), and the
    # item ('bind <n>' or 'volume <name>') that writes each.
    written: dict[str, str] = field(default_factory=dict)
    written_volumes: set[str] = field(default_factory=set)
    live_users: list[BindUse] = field(default_factory=list)
    created_volumes: set[str] = field(default_factory=set)
    created_networks: set[str] = field(default_factory=set)
    lock_ids: set[str] = field(default_factory=set)
    project: str | None = None
    projects: set[str] = field(default_factory=set)
    compose: ComposeWrite | None = None
    mkdirs: list[MakeDir] = field(default_factory=list)
    ordered: list[m.ContainerEntry] = field(default_factory=list)  # in start order

    @property
    def host(self) -> str:
        return self.target.host_name

    def path(self, check, path: str) -> str | None:
        try:
            return check(path)
        except HostPathError as exc:
            self.errors.append(str(exc))
            return None

    def write(self, path: str, item: str) -> None:
        """Records that item writes into or wipes path. Two items on one host path would
        merge their data in one directory, the way two items in one volume would."""
        if self.written.setdefault(path, item) != item:
            self.errors.append(
                f"Host path {path} is the target of more than one item. Restore them separately."
            )

    def own_network(self, network: str) -> bool:
        existing = self.target.networks.get(network) or {}
        return network in self.target.own_networks or existing.get("Id") in self.target.own_networks

    def own_container(self, ref: str) -> bool:
        """Docker resolves a reference by exact name first, then by ID prefix."""
        own = self.target.own
        if ref in self.target.containers:
            return self.target.containers[ref].get("Id") in own
        return HEX_PREFIX_RE.fullmatch(ref) is not None and any(i.startswith(ref) for i in own)


def build_plan(
    manifest: m.Manifest,
    configs: Mapping[str, Any],
    target: TargetInfo,
    choice: Choice,
    facts: ArchiveFacts,
) -> RestorePlan:
    """The plan, or PlanError listing every problem found."""
    problems = archive_problems(manifest, configs) + choice_problems(manifest, choice)
    if problems:
        raise PlanError(problems)
    if choice.host_id != target.host_id:
        raise PlanError("The plan was made for another host.")
    draft = Draft(manifest, configs, target, choice, facts, name_map(manifest, choice, configs))
    if choice.mode in ("new-name", "overwrite"):
        plan_containers(draft)
    elif choice.mode == "data-only":
        plan_data_only(draft)
    else:
        if not manifest.images:
            raise PlanError("This archive holds no images.")
        plan_images(draft, manifest.images)
    check_users(draft)
    if choice.compose_dir:
        plan_compose(draft)
    check_own_paths(draft)
    check_nested(draft)
    if draft.errors:
        raise PlanError(dict.fromkeys(draft.errors))
    return finish(draft)


def plan_containers(draft: Draft) -> None:
    manifest, choice, target = draft.manifest, draft.choice, draft.target
    if not manifest.containers:
        raise PlanError("This archive holds no container.")
    if choice.mode == "new-name" and len(manifest.containers) > 1 and not is_stack(manifest):
        raise PlanError(
            "Only a stack archive can be restored under a new name with several containers. "
            "Restore it in overwrite mode."
        )
    for entry in manifest.containers:
        if entry.config_member is None or entry.config_member not in draft.configs:
            raise PlanError(
                f"The archive holds no configuration of container {entry.name}; "
                "restore its data or images instead."
            )
    infos = [draft.configs[e.config_member] for e in manifest.containers]  # type: ignore[index]
    try:
        members = stacks.order(infos)
    except stacks.StackError as exc:
        raise PlanError(str(exc)) from None
    by_id = {e.id: e for e in manifest.containers}
    if len(by_id) != len(manifest.containers):
        raise PlanError("The archive holds two containers with one ID.")
    draft.ordered = [by_id[member.id] for member in members]
    if stacks.unordered(infos):
        draft.warnings.append(
            "The containers record no dependency order; they start in name order."
        )
    check_distinct(draft)
    for name in sorted(set(draft.names.containers.values())):
        # Docker resolves a name before an ID prefix: a container named like part of an own
        # container's ID would stand in for it wherever drydock looks it up.
        if HEX_PREFIX_RE.fullmatch(name) and any(i.startswith(name) for i in target.own):
            draft.errors.append(f"Container name {name} names drydock's own deployment.")
    if choice.mode == "new-name":
        for name in sorted(set(draft.names.containers.values())):
            if name in target.containers:
                draft.errors.append(
                    f"A container named {name} already exists on host {draft.host}."
                )
    else:
        plan_originals(draft)
    plan_projects(draft)
    plan_networks(draft)
    plan_volumes(draft)
    bind_map = plan_binds(draft)
    ids = {c.image_id for c in manifest.containers}
    plan_images(draft, [i for i in manifest.images if i.id in ids])
    created = frozenset(draft.names.containers.values())
    running = {
        e.id: bool((info.get("State") or {}).get("Running"))
        for e, info in zip(manifest.containers, infos, strict=True)
    }
    for member, entry in zip(members, draft.ordered, strict=True):
        info = draft.configs[entry.config_member]  # type: ignore[index]
        name = draft.names.containers[entry.name]
        try:
            body = container_body(
                info,
                names=draft.names,
                mode=choice.mode,
                api_version=target.api_version,
                bind_map=bind_map,
                warnings=draft.warnings,
                project=draft.project,
            )
        except PlanError as exc:
            draft.errors += exc.errors
            continue
        for source in risk.bind_sources(body):
            if (checked := draft.path(hostpaths.check_bind, source)) is not None:
                draft.bind_sources.add(checked)
        check_body(draft, name, body)
        host = body["HostConfig"]
        if host.get("Tmpfs") or any(mt.get("Type") == "tmpfs" for mt in host.get("Mounts") or []):
            draft.warnings.append(f"tmpfs mounts start empty: those of {name} hold no data.")
        draft.containers.append(
            ContainerStep(
                name=name,
                body=body,
                start=running[entry.id],
                image_entry=image_entry(draft, entry, info, name),
                wait_healthy=tuple(draft.names.ids[i] for i in member.healthy if running[i]),
            )
        )
        draft.risk += risk.flags(name, body, created)
    stopped = {draft.names.ids[i] for i, started in running.items() if not started}
    for step in draft.containers:
        for key in CONTAINER_MODE_FIELDS:
            value = step.body["HostConfig"].get(key)
            if not step.start or not isinstance(value, str) or not value.startswith("container:"):
                continue
            other = value.removeprefix("container:")
            if other in stopped and other != step.name:
                draft.errors.append(
                    f"Container {step.name} shares the namespaces of {other}, which the archive "
                    "records as stopped, so it cannot start."
                )


def check_distinct(draft: Draft) -> None:
    """No two archived containers, volumes or networks may get one target name."""
    names, manifest = draft.names, draft.manifest
    for kind, originals, mapping in (
        ("Containers", [c.name for c in manifest.containers], names.containers),
        ("Volumes", [v.name for v in manifest.volumes], names.volumes),
        ("Networks", [n.name for n in manifest.networks], names.networks),
    ):
        seen: dict[str, str] = {}
        for original in originals:
            mapped = mapping[original]
            if mapped in seen:
                draft.errors.append(
                    f"{kind} {seen[mapped]} and {original} would both be named {mapped}."
                )
            else:
                seen[mapped] = original


def plan_projects(draft: Draft) -> None:
    """The Compose projects whose lock keys the plan holds (stack backups of a project wait
    for it), and the checks of the project a stack restore creates or replaces."""
    manifest, choice, target = draft.manifest, draft.choice, draft.target
    draft.project = restored_project(manifest, choice)
    if draft.project:
        draft.projects.add(draft.project)
        names = target.projects.get(draft.project, ())
        if choice.mode == "new-name" and names:
            draft.errors.append(
                f"Compose project {draft.project} already has containers on host {draft.host}: "
                f"{', '.join(names)}. Choose another name."
            )
        if choice.mode == "overwrite":
            archived = {c.name for c in manifest.containers}
            draft.warnings += [
                f"Container {n} of project {draft.project} is not in the archive and keeps running."
                for n in names
                if n not in archived
            ]
    if choice.mode != "overwrite":
        return
    # An overwrite stops and renames the originals: a stack backup of their project must
    # not run meanwhile (stack discovery skips '<name>-drydock-old').
    found = [
        stacks.labels_of(target.containers[o.name]).get(PROJECT_LABEL) for o in draft.originals
    ]
    found += [c.compose_project for c in manifest.containers]
    draft.projects |= {
        p for p in found if isinstance(p, str) and stacks.PROJECT_RE.fullmatch(p) is not None
    }


def check_body(draft: Draft, name: str, body: dict[str, Any]) -> None:
    """Own deployment, networks that must exist (flagged when they sit on a host network),
    and static IPs of reused networks."""
    host = body["HostConfig"]
    endpoints = (body.get("NetworkingConfig") or {}).get("EndpointsConfig") or {}
    networks = set(endpoints)
    mode = host.get("NetworkMode") or ""
    if mode and mode not in DEFAULT_NETWORKS and not mode.startswith("container:"):
        networks.add(mode)
    for network in sorted(networks):
        if draft.own_network(network):
            draft.errors.append(f"Network {network} belongs to drydock's own deployment.")
        elif network in DEFAULT_NETWORKS or network in draft.created_networks:
            continue
        elif (existing := draft.target.networks.get(network)) is None:
            draft.errors.append(f"Network {network} does not exist on host {draft.host}.")
        elif (flag := existing_network_flag(network, existing)) is not None:
            draft.risk.append(flag)
    volumes = [
        source
        for source, _, _ in (risk.split_bind(b) for b in host.get("Binds") or [])
        if not source.startswith("/")
    ]
    volumes += [
        str(mt.get("Source")) for mt in host.get("Mounts") or [] if mt.get("Type") == "volume"
    ]
    for volume in volumes:
        if volume in draft.target.own_volumes:
            draft.errors.append(f"Volume {volume} belongs to drydock's own deployment.")
    refs = [str(e).split(":", 1)[0] for e in host.get("VolumesFrom") or []]
    for key in CONTAINER_MODE_FIELDS:
        value = host.get(key)
        if isinstance(value, str) and value.startswith("container:"):
            refs.append(value.removeprefix("container:"))
    for ref in refs:
        if draft.own_container(ref):
            draft.errors.append(f"Container {ref} belongs to drydock's own deployment.")
    if draft.choice.mode != "overwrite":
        return
    for network, endpoint in endpoints.items():
        existing = draft.target.networks.get(network)
        if existing is None or network in draft.created_networks:
            continue
        pools = (existing.get("IPAM") or {}).get("Config") or []
        subnets = [str(p.get("Subnet") or "") for p in pools if isinstance(p, dict)]
        for key in ("IPv4Address", "IPv6Address"):
            address = (endpoint.get("IPAMConfig") or {}).get(key)
            if address and not inside(address, subnets):
                draft.errors.append(
                    f"Address {address} of {name} lies outside every subnet of network "
                    f"{network} on host {draft.host}."
                )


def inside(address: str, subnets: list[str]) -> bool:
    """Whether address lies in one of the subnets. Docker accepts a static address only on
    a subnet the network was configured with."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for subnet in subnets:
        try:
            if ip in ipaddress.ip_network(subnet, strict=False):
                return True
        except ValueError:
            continue
    return False


def plan_originals(draft: Draft) -> None:
    """The originals an overwrite stops and renames, dependents first."""
    target = draft.target
    for entry in reversed(draft.ordered):
        info = target.containers.get(entry.name)
        if info is None:
            continue
        if info.get("Id") in target.own:
            draft.errors.append(f"Container {entry.name} belongs to drydock's own deployment.")
            continue
        old_name = entry.name + OLD_SUFFIX
        if old_name in target.containers:
            draft.errors.append(
                f"Container {old_name} already exists on host {draft.host}. Remove it first."
            )
        live = inventory.in_use(str((info.get("State") or {}).get("Status") or ""))
        if live and (info.get("HostConfig") or {}).get("AutoRemove"):
            draft.errors.append(
                f"Container {entry.name} removes itself when stopped (--rm), so it cannot be "
                "overwritten."
            )
        draft.originals.append(
            Original(info["Id"], entry.name, old_name, live, inventory.stop_timeout(info))
        )


def plan_networks(draft: Draft) -> None:
    new_name = draft.choice.mode == "new-name"
    for entry in draft.manifest.networks:
        name = draft.names.networks[entry.name]
        config = draft.configs.get(entry.config_member) if entry.config_member else None
        if not isinstance(config, dict):
            draft.errors.append(f"The archive holds no configuration of network {entry.name}.")
            continue
        if (
            config.get("ConfigOnly")
            or ((config.get("ConfigFrom") or {}).get("Network"))
            or (config.get("Scope") or "local") != "local"
        ):
            draft.errors.append(
                f"Network {entry.name} is a swarm or config-only network, which a restore "
                "does not support."
            )
            continue
        existing = draft.target.networks.get(name)
        if draft.own_network(name):
            draft.errors.append(f"Network {name} belongs to drydock's own deployment.")
            continue
        if existing is not None:
            if new_name:
                draft.errors.append(
                    f"Network {name} already exists on host {draft.host}. Choose another name."
                )
                continue
            differences = network_differences(config, existing)
            draft.networks.append(NetworkStep(name, "reuse", {}, differences))
            if (flag := existing_network_flag(name, existing)) is not None:
                draft.risk.append(flag)
            continue
        create = network_create(
            config, name, new_name=new_name, notes=draft.warnings, project=draft.project
        )
        draft.networks.append(NetworkStep(name, "create", create, ()))
        draft.created_networks.add(name)
        if (flag := network_flag(name, create["driver"], create["options"])) is not None:
            draft.risk.append(flag)


def network_flag(name: str, driver: str, options: dict[str, Any]) -> RiskFlag | None:
    """macvlan, ipvlan and every driver but bridge, and bridges on a named host interface:
    a container on one sits on a host network. Raised for networks a restore creates and
    for existing ones it joins."""
    if name in DEFAULT_NETWORKS:
        return None
    if driver == "bridge" and "parent" not in options and BRIDGE_NAME_OPTION not in options:
        return None
    value = f"driver {driver}"
    if options.get("parent"):
        value += f", parent {options['parent']}"
    if options.get(BRIDGE_NAME_OPTION):
        value += f", bridge {options[BRIDGE_NAME_OPTION]}"
    return RiskFlag(f"network:{name}:driver", name, "driver", value)


def existing_network_flag(name: str, existing: dict[str, Any]) -> RiskFlag | None:
    options = existing.get("Options")
    return network_flag(
        name, str(existing.get("Driver") or "bridge"), options if isinstance(options, dict) else {}
    )


def network_create(
    config: dict[str, Any],
    name: str,
    *,
    new_name: bool,
    notes: list[str],
    project: str | None = None,
) -> dict[str, Any]:
    """docker-py create_network kwargs from an archived network inspect. In new-name mode
    its Compose labels are those of project (a new-name stack), or dropped."""
    labels = without_own_labels(dict(config.get("Labels") or {}), f"network {name}", notes)
    options = dict(config.get("Options") or {})
    ipam = config.get("IPAM") or {}
    pools = [
        {k: v for k, v in pool.items() if k in IPAM_POOL_KEYS and v}
        for pool in ipam.get("Config") or []
        if isinstance(pool, dict)
    ]
    create_ipam: dict[str, Any] = {"Driver": ipam.get("Driver") or "default"}
    if new_name:
        if project is not None:
            labels = compose_label_set(labels, project, f"network {name}", notes)
        dropped = sorted(k for k in labels if dropped_label(k, compose=project is None))
        if dropped:
            labels = {k: v for k, v in labels.items() if k not in dropped}
            notes.append(f"Dropped the labels {', '.join(dropped)} of network {name}.")
        if options.pop(BRIDGE_NAME_OPTION, None):
            notes.append(
                f"Dropped the bridge interface name of network {name}: the original network "
                "holds it."
            )
        if pools:
            notes.append(
                f"Network {name} gets its subnet from Docker: the original network holds the "
                "archived one."
            )
    else:
        create_ipam["Config"] = pools
    create_ipam["Options"] = dict(ipam.get("Options") or {})
    return {
        "name": name,
        "driver": config.get("Driver") or "bridge",
        "options": options,
        "ipam": create_ipam,
        "internal": bool(config.get("Internal")),
        "labels": labels,
        "enable_ipv6": bool(config.get("EnableIPv6")),
        "attachable": bool(config.get("Attachable")),
    }


def network_differences(config: dict[str, Any], existing: dict[str, Any]) -> tuple[str, ...]:
    def subnets(document: dict[str, Any]) -> list[str]:
        pools = (document.get("IPAM") or {}).get("Config") or []
        return sorted(
            str(p.get("Subnet")) for p in pools if isinstance(p, dict) and p.get("Subnet")
        )

    def labels(document: dict[str, Any]) -> dict[str, Any]:
        return {
            k: v
            for k, v in (document.get("Labels") or {}).items()
            if not k.startswith(COMPOSE_LABEL_PREFIX)
        }

    fields = (
        ("Driver", lambda d: d.get("Driver") or ""),
        ("Internal", lambda d: bool(d.get("Internal"))),
        ("Attachable", lambda d: bool(d.get("Attachable"))),
        ("EnableIPv6", lambda d: bool(d.get("EnableIPv6"))),
        ("IPAM subnets", subnets),
        ("Options", lambda d: dict(d.get("Options") or {})),
        ("Labels", labels),
    )
    out = []
    for label, read in fields:
        archived, current = read(config), read(existing)
        if archived != current:
            out.append(
                f"{label}: {risk.describe(archived) or 'none'} in the archive, "
                f"{risk.describe(current) or 'none'} on the host"
            )
    return tuple(out)


def volume_flag(name: str, driver: str, options: dict[str, Any]) -> RiskFlag | None:
    """Non-local drivers and local mounts of devices or filesystems. The value never shows
    the o= option, which may hold credentials (cifs)."""
    if driver == "local" and "device" not in options and "type" not in options:
        return None
    parts = [f"driver {driver}"]
    for key in ("type", "device"):
        if options.get(key):
            parts.append(f"{key} {options[key]}")
    if options:
        parts.append(f"options {', '.join(sorted(map(str, options)))}")
    return RiskFlag(f"volume:{name}:driver", name, "driver", risk.describe(", ".join(parts)))


def plan_volumes(draft: Draft) -> None:
    mode = draft.choice.mode
    for entry in draft.manifest.volumes:
        name = draft.names.volumes[entry.name]
        config = draft.configs.get(entry.config_member) if entry.config_member else None
        config = config if isinstance(config, dict) else {}
        if name in draft.target.own_volumes:
            draft.errors.append(f"Volume {name} belongs to drydock's own deployment.")
            continue
        existing = draft.target.volumes.get(name)
        if existing is not None and mode == "new-name":
            draft.errors.append(
                f"Volume {name} already exists on host {draft.host}. Choose another name."
            )
            continue
        if existing is not None:
            driver = existing.get("Driver") or "local"
            options = dict(existing.get("Options") or {})
            archived = config.get("Driver") or entry.driver or "local"
            if archived != driver:
                draft.warnings.append(
                    f"Volume {name} uses driver {driver} on host {draft.host}, not {archived} as "
                    "in the archive."
                )
            labels = dict(existing.get("Labels") or {})
        else:
            driver = config.get("Driver") or entry.driver or "local"
            options = dict(config.get("Options") or {})
            labels = without_own_labels(
                dict(config.get("Labels") or {}), f"volume {name}", draft.warnings
            )
            if mode == "new-name" and draft.project is not None:
                labels = compose_label_set(labels, draft.project, f"volume {name}", draft.warnings)
            elif mode == "new-name":
                labels = {k: v for k, v in labels.items() if not dropped_label(k, routing=False)}
            draft.created_volumes.add(name)
        try:
            device = hostpaths.check_volume(driver, options)
        except HostPathError as exc:
            draft.errors.append(f"Volume {name}: {exc}")
            continue
        action: Literal["create", "reuse"] = "reuse" if existing is not None else "create"
        draft.volumes.append(VolumeStep(name, action, driver, options, labels, device))
        if (flag := volume_flag(name, driver, options)) is not None:
            draft.risk.append(flag)
        if device is not None and (checked := draft.path(hostpaths.check_bind, device)):
            draft.bind_sources.add(checked)
        if device is not None and mode == "new-name" and beside_original(draft, entry.name, device):
            # The copy's volume would bind the very directory the original's volume holds,
            # the way an unremapped bind would, and Docker shows that use as a volume.
            draft.errors.append(
                f"Volume {entry.name} keeps its data in host path {device}, so a copy would "
                "share it with the original. Restore it in overwrite mode instead."
            )
            continue
        if mode == "new-name" and shared_storage(driver, options):
            # A share's or a plugin's options name the storage, not the volume: the copy
            # would mount the original's live files, on this host or any other.
            draft.errors.append(
                f"Volume {entry.name} keeps its data on storage that driver {driver} and its "
                "options name, so a copy would share it with the original. Restore it in "
                "overwrite mode instead."
            )
            continue
        if entry.data_member is None:
            continue
        label = f"volume {name}"
        if mode == "overwrite":
            draft.wipes.append(Wipe("volume", name, label))
        draft.data.append(DataStep(entry.data_member, "volume", name, label, None))
        draft.written_volumes.add(name)
        if device is not None and (checked := draft.path(hostpaths.check_write_target, device)):
            draft.write_targets.add(checked)
            draft.write(checked, f"volume {name}")
            setid_flag(draft, entry.data_member, name)


def shared_storage(driver: str, options: dict[str, Any]) -> bool:
    """Whether every volume made with these options shares one storage: a network share of
    the local driver, or any other driver (a plugin keeps data wherever its options say)."""
    return driver != "local" or options.get("type") in hostpaths.NETWORK_VOLUME_TYPES


def setid_flag(draft: Draft, member: str, volume: str) -> None:
    """Setuid, setgid or capability files written into a host-backed volume land on the
    host, the way bind data does."""
    if member in draft.facts.setid_members:
        draft.risk.append(
            RiskFlag(
                f"volume-data:{volume}:setid", volume, "setid", "setuid, setgid or capability files"
            )
        )


def beside_original(draft: Draft, volume: str, device: str) -> bool:
    """Whether a new-name copy of a host-backed volume would share its device with the
    original: the target is the source host, or holds the original volume over that path.
    On another host the device is just a host path, checked and flagged like any other."""
    if draft.target.host_name == draft.manifest.source.host_name:
        return True
    original = draft.target.volumes.get(volume)
    if original is None:
        return False
    theirs = hostpaths.host_volume_device(
        original.get("Driver") or "local", original.get("Options")
    )
    return theirs is not None and hostpaths.overlaps(
        "/" + posixpath.normpath(theirs).lstrip("/"), "/" + posixpath.normpath(device).lstrip("/")
    )


def archived_binds(draft: Draft) -> dict[str, bool]:
    """The host paths the archived containers' configs bind (normalized), and whether any
    bind of each is writable. Sources that do not normalize are left to container_body,
    which refuses them."""
    found: dict[str, bool] = {}
    for entry in draft.manifest.containers:
        host = draft.configs[entry.config_member].get("HostConfig") or {}  # type: ignore[index]
        binds = [
            (source, "ro" not in options.split(","))
            for source, _, options in map(risk.split_bind, host.get("Binds") or [])
            if source.startswith("/")
        ]
        binds += [
            (str(mt.get("Source") or ""), not mt.get("ReadOnly"))
            for mt in host.get("Mounts") or []
            if mt.get("Type") == "bind"
        ]
        for source, writable in binds:
            try:
                normalized = hostpaths.normalize(source)
            except HostPathError:
                continue
            found[normalized] = found.get(normalized, False) or writable
    return found


def plan_binds(draft: Draft) -> dict[str, str]:
    """Data steps, wipes and flags of the archive's bind mounts. Returns the bind map:
    normalized archive source to final host path.

    Only binds the archived container's own config makes are planned. The manifest lists
    the runtime mounts, and an archive that disagrees with its config must not write or
    wipe a host path the restored container never mounts (no bind flag would show it).
    """
    choice, manifest = draft.choice, draft.manifest
    overwrite = choice.mode == "overwrite"
    if choice.wipe_binds and not overwrite:
        draft.errors.append("Only an overwrite restore wipes bind mounts.")
    mounted = archived_binds(draft)
    ids = {c.id for c in manifest.containers}
    described: set[str] = set()
    bind_map: dict[str, str] = {}
    for entry in manifest.binds:
        n = entry.n
        if (original := draft.path(hostpaths.normalize, entry.source)) is None:
            continue
        described.add(original)
        if original not in mounted:
            if n in choice.bind_remaps or n in choice.wipe_binds:
                draft.errors.append(
                    f"Bind mount {original} is not a bind of the archived container, so it "
                    "cannot be remapped or wiped."
                )
            elif entry.data_member is not None:
                draft.warnings.append(
                    f"The data of bind mount {original} is not restored: the archived "
                    "container does not bind it itself."
                )
            continue
        if not entry.mounts or any(ref.container not in ids for ref in entry.mounts):
            draft.errors.append(
                f"The archive's record of bind mount {original} does not match its container."
            )
            continue
        remap = choice.bind_remaps.get(n)
        if remap is not None:
            if (source := draft.path(hostpaths.normalize, remap)) is None:
                continue
            if draft.path(hostpaths.check_write_target, source) is None:
                continue
        else:
            source = original
        remapped = source != original
        bind_map[original] = source
        label = f"bind mount {source}"
        if choice.mode == "new-name" and not remapped:
            writable = mounted[original] or any(not ref.read_only for ref in entry.mounts)
            if writable and n not in choice.skip_binds | choice.share_binds:
                draft.errors.append(
                    f"Bind mount {source} would be shared with the original. Remap it, skip "
                    "its data, or choose to share it."
                )
            else:
                draft.warnings.append(f"Bind mount {source} is shared with the original container.")
        if entry.data_member is None and entry.skipped and entry.skipped != "a system path":
            plan_skipped_bind(draft, entry, source, remapped)
        has_data = (
            entry.data_member is not None and n not in choice.skip_binds and (overwrite or remapped)
        )
        if has_data:
            plan_bind_data(draft, entry, source, label, remapped)
        if n in choice.wipe_binds and overwrite:
            if not has_data or entry.kind != "dir":
                draft.errors.append(
                    f"Bind mount {source} gets no directory data in this restore, so drydock "
                    "does not wipe it."
                )
            elif (checked := draft.path(hostpaths.check_write_target, source)) is not None:
                draft.wipes.append(Wipe("bind", checked, label))
                draft.write_targets.add(checked)
                draft.write(checked, f"bind {n}")
    for source in sorted(set(mounted) - described):
        draft.errors.append(f"The archive does not describe bind mount {source}.")
    return bind_map


def plan_skipped_bind(draft: Draft, entry: m.BindEntry, source: str, remapped: bool) -> None:
    """A bind the archive's job skipped: the container still binds it, so a directory
    whose owner the archive records is created where it is missing (one level, below a
    path restored data may go to). Anything else only gets a warning to create it by
    hand, which is what an existing directory needs anyway: nothing."""
    owner = (entry.uid, entry.gid, entry.mode)
    creatable = entry.kind == "dir" and None not in owner and posixpath.dirname(source) != "/"
    try:
        checked = hostpaths.check_write_target(source) if creatable else None
    except HostPathError:
        checked = None
    if checked is None:
        draft.warnings.append(
            f"Bind mount {source} is not in the archive ({entry.skipped}). The container "
            "still binds it: create it on the target first if it is missing."
        )
        return
    uid, gid, mode = owner
    draft.mkdirs.append(
        MakeDir(checked, f"{uid}:{gid}", int(mode) & 0o3777, f"bind mount {checked}")
    )
    draft.write_targets.add(checked)
    if (
        remapped
        or draft.target.host_name != draft.manifest.source.host_name
        or risk.sensitive(checked)
    ):
        where = f"host {draft.target.host_name}"
        draft.risk.append(
            RiskFlag(
                f"bind-mkdir:{checked}", checked, "bind-write", f"creates a directory on {where}"
            )
        )


def plan_bind_data(
    draft: Draft, entry: m.BindEntry, source: str, label: str, remapped: bool
) -> None:
    member = entry.data_member
    if member is None:
        return
    if entry.kind == "dir":
        step = DataStep(member, "bind-dir", source, label, None)
        directory = source
    elif entry.kind == "file":
        step = DataStep(member, "bind-file", source, label, posixpath.basename(source))
        directory = posixpath.dirname(source)
    else:
        draft.errors.append(f"The archive does not say whether bind mount {source} is a file.")
        return
    if (checked := draft.path(hostpaths.check_write_target, directory)) is None:
        return
    draft.write_targets.add(checked)
    # A file bind's data is one member renamed to the file's basename: only that file changes.
    draft.write(source, f"bind {entry.n}")
    draft.data.append(step)
    if member in draft.facts.setid_members:
        draft.risk.append(
            RiskFlag(
                f"bind-data:{entry.n}:setid", source, "setid", "setuid, setgid or capability files"
            )
        )
    # Writes outside the data trees are flagged by their own path, whatever the body binds.
    if (
        remapped
        or draft.target.host_name != draft.manifest.source.host_name
        or risk.sensitive(source)
    ):
        where = f"host {draft.target.host_name}"
        draft.risk.append(
            RiskFlag(f"bind-write:{source}", source, "bind-write", f"writes on {where}")
        )


def norm_arch(arch: str) -> str:
    return ARCH_ALIASES.get(arch, arch)


def sha(value: str | None) -> str | None:
    if value is not None and HEX64_RE.fullmatch(value):
        return "sha256:" + value
    return value


def split_ref(ref: str) -> tuple[str, str | None]:
    """(repository, tag) the way Docker splits a ref: a ':' after the last '/' starts the
    tag, so 'redis:7' is redis tag 7 and 'host:5000/app' has no tag. A digest is dropped."""
    name = ref.split("@", 1)[0]
    repo, colon, tag = name.rpartition(":")
    if not colon or "/" in tag:
        return name, None
    return repo, tag


def repository(ref: str) -> str:
    """A ref's repository in Docker's familiar form (docker.io/library/x is x)."""
    repo = split_ref(ref)[0]
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if repo.startswith(prefix):
            repo = repo.removeprefix(prefix)
            break
    if repo.startswith("library/") and repo.count("/") == 1:
        repo = repo.removeprefix("library/")
    return repo


def familiar(ref: str) -> str:
    """A tag ref in Docker's familiar form with its tag: 'docker.io/library/x' is 'x:latest'."""
    return f"{repository(ref)}:{split_ref(ref)[1] or 'latest'}"


def plan_images(draft: Draft, entries: Iterable[m.ImageEntry]) -> None:
    target = draft.target
    protected = {repository(r) for r in target.protected_repos}
    for entry in entries:
        accepted = {sha(i) for i in draft.facts.loaded_ids.get(entry.id, frozenset({entry.id}))}
        accepted.add(sha(entry.id))
        label = entry.refs[0] if entry.refs else entry.id
        named = [*entry.refs, *([entry.confirmed_digest] if entry.confirmed_digest else [])]
        # A digest names content, so the image a digest ref resolves to is this one, whatever
        # ID the target's image store gives it (an index digest under the containerd store,
        # the config digest under the classic one). The archive could name that image in
        # Config.Image anyway, and a present image moves no tag.
        digests = tuple(dict.fromkeys(r for r in named if "@" in r and r in target.images))
        accepted |= {sha(target.images[r]) for r in digests}
        present = entry.id in target.images or any(
            sha(target.images.get(r)) in accepted for r in named if r in target.images
        )
        action: Literal["load", "pull", "present"]
        if present:
            action = "present"
        elif entry.confirmed_digest:
            action = "pull"
        elif entry.saved and entry.data_member:
            action = "load"
        else:
            draft.errors.append(
                f"Image {label} is neither in the archive nor pullable, and host {draft.host} "
                "does not have it."
            )
            continue
        tags = tuple(r for r in entry.refs if "@" not in r)
        moves: tuple[str, ...] = ()
        if action != "present":
            moves = tuple(
                r for r in tags if r in target.images and sha(target.images[r]) not in accepted
            )
        for ref in moves:
            if repository(ref) in protected:
                draft.errors.append(
                    f"Restoring image {label} would move tag {ref}, which drydock itself uses."
                )
            else:
                draft.risk.append(
                    RiskFlag(f"image:{ref}:tag", ref, "tag", f"moves to the image of {label}")
                )
        if entry.architecture != "unknown" and norm_arch(entry.architecture) != norm_arch(
            target.arch
        ):
            draft.warnings.append(
                f"Image {label} is for {entry.architecture}, but host {draft.host} is "
                f"{target.arch}."
            )
        draft.images[entry.id] = ImageStep(
            id=entry.id,
            label=label,
            action=action,
            member=entry.data_member if action == "load" else None,
            pull=entry.confirmed_digest if action == "pull" else None,
            refs=tags + digests if action == "present" else tags,
            os=entry.os,
            architecture=entry.architecture,
            variant=entry.variant,
            accepted_ids=tuple(sorted(i for i in accepted if i)),
            moves=moves,
        )


def image_entry(
    draft: Draft, entry: m.ContainerEntry, info: dict[str, Any], name: str
) -> str | None:
    """The ImageEntry.id whose resolved target ID replaces body['Image'], or None.

    docker load recreates no repo digest, so a digest ref or bare ID only names a loaded or
    pulled image by its ID, and a tag that is not one of the step's refs still names
    whatever the target had. A present image is named by ID when Config.Image names another
    image (or none) on the target.
    """
    step = draft.images.get(entry.image_id)
    if step is None:
        if not any(i.id == entry.image_id for i in draft.manifest.images):
            draft.errors.append(f"The archive does not describe the image of container {name}.")
        return None
    image = (info.get("Config") or {}).get("Image") or entry.image
    if step.action != "present":
        tagged = "@" not in image and not ID_RE.fullmatch(image)
        if tagged and familiar(image) in {familiar(r) for r in step.refs}:
            return None
        draft.warnings.append(f"Config.Image will be the loaded image ID for {name}.")
        return step.id
    if sha(draft.target.images.get(image)) in step.accepted_ids or image == step.id:
        return None
    draft.warnings.append(
        f"Config.Image will be the image ID for {name}: {image} does not name that image on "
        f"host {draft.host}."
    )
    return step.id


def plan_data_only(draft: Draft) -> None:
    manifest, choice, target = draft.manifest, draft.choice, draft.target
    volumes = [v for v in manifest.volumes if v.data_member]
    binds = [b for b in manifest.binds if b.data_member]
    if not volumes and not binds:
        raise PlanError("This archive holds no volume or bind mount data.")
    if not (choice.volume_map or choice.bind_volume_map or choice.data_container):
        raise PlanError("Choose the target volumes, or a container whose volumes to restore into.")
    with_data = {v.name for v in volumes}
    draft.errors += [
        f"Volume {v} holds no data in this archive."
        for v in choice.volume_map
        if v not in with_data
    ]
    bind_numbers = {b.n for b in binds}
    draft.errors += [
        f"Bind mount {n} holds no data in this archive."
        for n in sorted(choice.bind_volume_map)
        if n not in bind_numbers
    ]
    by_destination: dict[str, str] = {}
    if choice.data_container:
        info = target.containers.get(choice.data_container)
        if info is None:
            draft.errors.append(
                f"Container {choice.data_container} does not exist on host {draft.host}."
            )
        elif draft.own_container(choice.data_container):
            draft.errors.append(
                f"Container {choice.data_container} belongs to drydock's own deployment."
            )
        else:
            draft.lock_ids.add(info["Id"])
            by_destination = {
                norm_dest(str(mt.get("Destination") or "")): str(mt["Name"])
                for mt in info.get("Mounts") or []
                if mt.get("Type") == "volume" and mt.get("Name")
            }

    def by_mounts(refs: list[m.MountRef]) -> str | None:
        return next(
            (by_destination[d] for r in refs if (d := norm_dest(r.destination)) in by_destination),
            None,
        )

    used: set[str] = set()
    for volume in volumes:
        name = choice.volume_map.get(volume.name) or by_mounts(volume.mounts)
        if name is None:
            draft.warnings.append(f"The data of volume {volume.name} is not restored.")
            continue
        volume_target(draft, volume.data_member or "", name, None, used)
    for bind in binds:
        name = choice.bind_volume_map.get(bind.n) or by_mounts(bind.mounts)
        if name is None:
            draft.warnings.append(f"The data of bind mount {bind.source} is not restored.")
            continue
        if bind.kind == "dir":
            rename_to = None
        elif bind.kind == "file":
            if (source := draft.path(hostpaths.normalize, bind.source)) is None:
                continue
            rename_to = posixpath.basename(source)
            if not rename_to:
                draft.errors.append(f"Bind mount {source} has no file name.")
                continue
        else:
            draft.errors.append(
                f"The archive does not say whether bind mount {bind.source} is a file."
            )
            continue
        member = bind.data_member or ""
        if volume_target(draft, member, name, rename_to, used) and (
            member in draft.facts.setid_members
        ):
            draft.risk.append(
                RiskFlag(
                    f"bind-data:{bind.n}:setid", name, "setid", "setuid, setgid or capability files"
                )
            )
    if not draft.data and not draft.errors:
        draft.errors.append("None of the archive's data maps onto a target volume.")


def volume_target(
    draft: Draft, member: str, name: str, rename_to: str | None, used: set[str]
) -> bool:
    if name in used:
        draft.errors.append(f"Volume {name} is the target of more than one item.")
        return False
    used.add(name)
    info = draft.target.volumes.get(name)
    if info is None:
        draft.errors.append(f"Volume {name} does not exist on host {draft.host}.")
        return False
    if name in draft.target.own_volumes:
        draft.errors.append(f"Volume {name} belongs to drydock's own deployment.")
        return False
    driver = info.get("Driver") or "local"
    options = dict(info.get("Options") or {})
    try:
        device = hostpaths.check_volume(driver, options)
    except HostPathError as exc:
        draft.errors.append(f"Volume {name}: {exc}")
        return False
    if device is not None:
        if (checked := draft.path(hostpaths.check_write_target, device)) is None:
            return False
        draft.write_targets.add(checked)
        draft.write(checked, f"volume {name}")
        setid_flag(draft, member, name)
    if (flag := volume_flag(name, driver, options)) is not None:
        draft.risk.append(flag)
    draft.data.append(DataStep(member, "volume", name, f"volume {name}", rename_to))
    draft.written_volumes.add(name)
    return True


def check_users(draft: Draft) -> None:
    """Live containers other than the originals must not use what this restore writes."""
    originals = {o.id for o in draft.originals}
    for volume in sorted(draft.written_volumes):
        for use in draft.target.volume_users.get(volume, ()):
            if use.id in originals:
                continue
            draft.lock_ids.add(use.id)
            if inventory.in_use(use.state):
                draft.errors.append(
                    f"Volume {volume} is also used by {use.state} container {use.name}. "
                    "Stop it first."
                )
    # A host-backed volume mounts its device, which inspect shows as a volume, not a bind.
    device_users = [
        BindUse(use.id, use.name, use.state, device)
        for volume, info in sorted(draft.target.volumes.items())
        if volume not in draft.written_volumes
        and (
            device := hostpaths.host_volume_device(
                info.get("Driver") or "local", info.get("Options")
            )
        )
        for use in draft.target.volume_users.get(volume, ())
    ]
    for use in (*draft.target.bind_users, *device_users):
        if use.id in originals or not use.source.startswith("/"):
            continue
        live = inventory.in_use(use.state)
        source = "/" + posixpath.normpath(use.source).lstrip("/")
        if live and (clean := normalized_or_none(use.source)) is not None:
            draft.live_users.append(BindUse(use.id, use.name, use.state, clean))
        for path in sorted(draft.write_targets):
            if hostpaths.overlaps(source, path):
                # Locked like a volume's users, so a stop-mode backup of a stopped user
                # cannot start it again on the path mid-restore.
                draft.lock_ids.add(use.id)
                if live:
                    draft.errors.append(
                        f"Bind mount {path} is also used by {use.state} container {use.name}. "
                        "Stop it first."
                    )
                break


def normalized_or_none(path: str) -> str | None:
    try:
        return hostpaths.normalize(path)
    except HostPathError:
        return None


def own_path_problems(paths: Iterable[str], own_paths: Iterable[str]) -> list[str]:
    """Nothing a restore mounts or writes may hold, or lie in, a host path of drydock's own
    deployment: its secret key, its database and archives, Docker's own storage."""
    own = sorted(
        {"/" + posixpath.normpath(o).lstrip("/") for o in own_paths if str(o).startswith("/")}
    )
    return [
        f"Host path {path} belongs to drydock's own deployment."
        for path in sorted(set(paths))
        if any(hostpaths.overlaps(path, o) for o in own)
    ]


def check_own_paths(draft: Draft) -> None:
    draft.errors += own_path_problems(
        draft.bind_sources | draft.write_targets, draft.target.own_paths
    )


def resolution_paths(plan: RestorePlan) -> list[str]:
    """Every host path apply resolves before resolved_problems: what the plan mounts and
    writes, the parent of the compose directory and, when there is any, drydock's own paths
    and the paths live containers use. Each is normalized; an own or live path that does not
    normalize is compared as given."""
    paths = {*plan.bind_sources, *plan.write_targets, *plan.written}
    if plan.compose:
        paths.add(posixpath.dirname(plan.compose.dir))
    paths |= {posixpath.dirname(d.path) for d in plan.mkdirs}
    if not paths:
        return []
    paths |= {clean for own in plan.own_paths if (clean := normalized_or_none(own))}
    if plan.write_targets or plan.compose:
        paths |= {use.source for use in plan.live_users}
    return sorted(paths)


def resolved_problems(plan: RestorePlan, resolved: Mapping[str, str]) -> list[str]:
    """apply's check of the host paths as Docker resolved them (plan path: resolved path,
    for every path of resolution_paths), before the first mutation. Every message is safe
    to show; any problem must stop the restore.

    The denylist and drydock's own paths are checked on the resolved path. A path that
    resolves elsewhere into a path risk.sensitive flags is refused too: the user
    acknowledged (or was never asked about) the path in the plan, not where a symbolic link
    leads, so binding the resolved path directly is the way to restore it.

    The plan's lexical relations are checked again on the resolved paths, since a symbolic
    link can make two paths one: drydock's own paths (as given and as resolved), the paths
    live containers use, two items writing one directory and a path inside a written one.
    """
    problems: list[str] = []
    own = {*plan.own_paths}
    for path in plan.own_paths:
        if (clean := normalized_or_none(path)) is not None and clean in resolved:
            own.add(resolved[clean])
    checks = [(p, hostpaths.check_bind) for p in plan.bind_sources]
    checks += [(p, hostpaths.check_write_target) for p in plan.write_targets]
    for path, check in checks:
        real = resolved.get(path)
        if real is None:
            problems.append(f"Host path {path} was not resolved on the host.")
            continue
        try:
            real = check(real)
        except HostPathError as exc:
            problems.append(str(exc))
            continue
        if real != path and risk.sensitive(real):
            problems.append(
                f"Host path {path} leads to {real}, which needs a superadmin's "
                f"acknowledgement. Restore it with {real} itself."
            )
        problems += own_path_problems([real], own)
    if plan.compose:
        problems += compose_problems(plan.compose, plan.risk, resolved, own)
    problems += resolved_relations(plan, resolved)
    return list(dict.fromkeys(problems))


def compose_problems(
    compose: ComposeWrite,
    flags: Iterable[RiskFlag],
    resolved: Mapping[str, str],
    own: Iterable[str],
) -> list[str]:
    """The compose directory as its parent resolved: the parent is the one directory a
    helper bind-mounts writable, so it must pass check_bind and never be the root."""
    directory = compose.dir
    parent = posixpath.dirname(directory)
    real_parent = resolved.get(parent)
    if real_parent is None:
        return [f"Host path {parent} was not resolved on the host."]
    if real_parent == "/":
        return [f"{parent} leads to the root directory on the host. Choose another directory."]
    try:
        hostpaths.check_bind(real_parent)
    except HostPathError as exc:
        return [f"{parent} leads to {real_parent}: {exc}"]
    real = posixpath.join(real_parent, posixpath.basename(directory))
    try:
        hostpaths.check_write_target(real)
    except HostPathError as exc:
        return [str(exc)]
    problems = own_path_problems([real], own)
    flagged = {flag.key for flag in flags}
    if real != directory and risk.sensitive(real) and f"compose-dir:{real}" not in flagged:
        problems.append(
            f"Host path {directory} leads to {real}, which needs a superadmin's "
            f"acknowledgement. Restore it with {real} itself."
        )
    return problems


def compose_live_notes(plan: RestorePlan, resolved: Mapping[str, str]) -> list[str]:
    """Live containers that mount, as resolved, a directory holding the resolved compose
    directory, where the plan's lexical warning did not name them. apply logs these."""
    if plan.compose is None:
        return []
    directory = plan.compose.dir
    parent = posixpath.dirname(directory)
    real = posixpath.join(resolved.get(parent, parent), posixpath.basename(directory))
    notes = []
    for use in plan.live_users:
        source = resolved.get(use.source, use.source)
        if hostpaths.within(real, source) and not hostpaths.within(directory, use.source):
            notes.append(
                f"Container {use.name} mounts {source} on the host, so it can read the "
                "restored .env files."
            )
    return notes


def resolved_relations(plan: RestorePlan, resolved: Mapping[str, str]) -> list[str]:
    """check_users, Draft.write, check_nested and plan_compose's mount check again, on the
    resolved paths."""
    problems: list[str] = []
    if plan.compose is not None:
        directory = plan.compose.dir
        parent, base = posixpath.split(directory)
        directories = {directory, posixpath.join(resolved.get(parent, parent), base)}
        for what, source in compose_mounters(plan.containers, plan.volumes):
            sources = {source, resolved.get(source, source)}
            if any(hostpaths.overlaps(d, s) for d in directories for s in sources):
                problems.append(f"The compose directory {directory} is mounted by {what}.")
    targets = [(w, {w, resolved.get(w, w)}) for w in plan.write_targets]
    for use in plan.live_users:
        sources = {use.source, resolved.get(use.source, use.source)}
        for path, reals in targets:
            if any(hostpaths.overlaps(s, r) for s in sources for r in reals):
                problems.append(
                    f"Bind mount {path} is also used by {use.state} container {use.name}. "
                    "Stop it first."
                )
                break
    written: dict[str, str] = {}
    for path in plan.written:
        real = resolved.get(path, path)
        first = written.setdefault(real, path)
        if first != path:
            problems.append(
                f"Host paths {first} and {path} both lead to {real}, so more than one item "
                "writes it. Restore them separately."
            )
    reals = {path: resolved.get(path, path) for path in (*plan.bind_sources, *plan.write_targets)}
    for real_written, path in sorted(written.items()):
        for other, real in sorted(reals.items()):
            if other != path and real != real_written and under(real, (real_written,)):
                problems.append(
                    f"{other} leads to {real}, inside {real_written}, which this restore "
                    "writes. Restore them separately."
                )
    return problems


def check_nested(draft: Draft) -> None:
    """Restored data may plant a symlink, so nothing this restore mounts or writes may lie
    inside a directory it writes."""
    paths = draft.bind_sources | draft.write_targets
    for written in sorted(draft.written):
        for path in sorted(paths):
            if path != written and under(path, (written,)):
                draft.errors.append(
                    f"{path} lies inside {written}, which this restore writes. "
                    "Restore them separately."
                )


# COMPOSE OUTPUT


def plan_compose(draft: Draft) -> None:
    """Choice.compose_dir: a new directory the compose files are written into after the
    commit. Not a write target (check_users would refuse it below any live bind), but
    checked like one, and its parent like a bind: a helper bind-mounts the parent writable
    to create it. Run after check_users, which fills draft.live_users."""
    directory = draft.path(hostpaths.check_write_target, draft.choice.compose_dir)
    if directory is None:
        return
    parent = posixpath.dirname(directory)
    if directory == "/" or parent == "/":
        draft.errors.append("Choose a directory below an existing directory, not the root.")
        return
    try:
        hostpaths.check_bind(parent)
    except HostPathError as exc:
        draft.errors.append(f"Drydock cannot create a directory in {parent}: {exc}")
        return
    draft.errors += own_path_problems([directory], draft.target.own_paths)
    for written in sorted(draft.written):
        if under(directory, (written,)):
            draft.errors.append(
                f"{directory} lies inside {written}, which this restore writes. "
                "Restore them separately."
            )
    draft.errors += list(
        dict.fromkeys(
            f"The compose directory {directory} is mounted by {what}."
            for what, source in compose_mounters(draft.containers, draft.volumes)
            if hostpaths.overlaps(directory, source)
        )
    )
    if risk.sensitive(directory):
        draft.risk.append(
            RiskFlag(f"compose-dir:{directory}", directory, "compose files", "written here")
        )
    draft.warnings += [
        f"Container {use.name} mounts {use.source}, so it can read the restored .env files."
        for use in draft.live_users
        if hostpaths.within(directory, use.source)
    ]
    try:
        draft.compose = compose_output(draft.manifest, draft.configs, directory, draft.ordered)
    except PlanError as exc:
        draft.errors += exc.errors
        return
    draft.warnings.append(
        "Compose files are copies of the originals. Drydock started the containers itself; "
        "the files are for reference and for running docker compose later."
    )
    if draft.choice.mode == "new-name" and draft.project is not None:
        draft.warnings.append(
            f"The compose files still name project {draft.manifest.job.project} and its "
            "containers, volumes and networks. Edit them before running docker compose -p "
            f"{draft.project} with them."
        )
    elif draft.choice.mode == "new-name":
        draft.warnings.append(
            f"The compose files still name container {draft.manifest.containers[0].name}."
        )
    base = compose_base(draft.configs, draft.ordered)
    if base is not None and any(under(source, (base,)) for source in archived_binds(draft)):
        draft.warnings.append(
            f"Relative bind mounts in the compose files point at the original directory "
            f"{base}, not at {directory}."
        )


def compose_mounters(
    containers: Iterable[ContainerStep], volumes: Iterable[VolumeStep]
) -> list[tuple[str, str]]:
    """Every host path the restored containers mount, with what mounts it: their bind
    sources and the devices of host-backed volumes, normalized. The compose directory may
    lie in none of them: every service could read every .env file there."""
    mounters = [
        (f"container {step.name}", source)
        for step in containers
        for source in map(normalized_or_none, risk.bind_sources(step.body))
        if source is not None
    ]
    mounters += [
        (f"volume {volume.name}", device)
        for volume in volumes
        if volume.device and (device := normalized_or_none(volume.device)) is not None
    ]
    return mounters


def compose_base(configs: Mapping[str, Any], ordered: Iterable[m.ContainerEntry]) -> str | None:
    """The project directory: the working_dir label of the first container (in start order)
    that has one, normalized; None when there is none or it does not normalize."""
    for entry in ordered:
        info = configs.get(entry.config_member) if entry.config_member else None
        value = stacks.labels_of(info if isinstance(info, dict) else {}).get(WORKING_DIR_LABEL)
        if isinstance(value, str) and value:
            return normalized_or_none(value)
    return None


def compose_output(
    manifest: m.Manifest,
    configs: Mapping[str, Any],
    compose_dir: str,
    members_order: Iterable[m.ContainerEntry],
) -> ComposeWrite:
    """Where each archived compose file goes below compose_dir: its path relative to the
    project directory when it lies inside it, else external/<n>-<basename>. Archive host
    paths are attacker-influenced, so a component that is not a plain name sends the file
    to external/. Raises PlanError when two files would take one place."""
    base = compose_base(configs, members_order)
    where: dict[str, str] = {}  # output path: host path
    files = []
    for entry in sorted(manifest.compose_files, key=lambda f: f.n):
        path = relative_path(entry.host_path, base) or external_path(entry)
        if path in where:
            raise PlanError(
                f"Compose files {where[path]} and {entry.host_path} would be written to the "
                "same place."
            )
        where[path] = entry.host_path
        files.append(ComposeOut(entry.member, path, entry.size))
    for path, host_path in where.items():
        parts = path.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            if directory in where:
                raise PlanError(
                    f"Compose files {where[directory]} and {host_path} would be written to "
                    "the same place."
                )
    return ComposeWrite(compose_dir, tuple(sorted(files, key=lambda f: f.path)))


def relative_path(host_path: str, base: str | None) -> str | None:
    path = normalized_or_none(host_path)
    if base is None or path is None or path == base or not under(path, (base,)):
        return None
    parts = path[len(base) :].lstrip("/").split("/")
    if len(parts) > MAX_COMPONENTS or not all(
        COMPONENT_RE.fullmatch(p) and p not in (".", "..") for p in parts
    ):
        return None
    return "/".join(parts)


def external_path(entry: m.ComposeFile) -> str:
    basename = entry.member.rsplit("/", 1)[-1]
    if not COMPONENT_RE.fullmatch(basename) or basename in (".", ".."):
        basename = f"file-{entry.n}"
    for name in (f"{entry.n}-{basename}", f"{entry.n}-file"):
        if COMPONENT_RE.fullmatch(name):
            return f"external/{name}"
    raise PlanError(f"The archive holds an invalid compose file number {shown(entry.n)}.")


def finish(draft: Draft) -> RestorePlan:
    host_id = draft.target.host_id
    order = {name: i for i, name in enumerate(draft.manifest.members)}
    keys = {o.id for o in draft.originals} | draft.lock_ids
    keys |= {f"name:{host_id}:container:{c.name}" for c in draft.containers}
    keys |= {f"name:{host_id}:container:{o.name}" for o in draft.originals}
    keys |= {f"name:{host_id}:volume:{v}" for v in draft.created_volumes | draft.written_volumes}
    keys |= {f"name:{host_id}:network:{n}" for n in draft.created_networks}
    # Stack backups of these projects take the same key (common.md decision 7).
    keys |= {f"name:{host_id}:project:{p}" for p in draft.projects}
    if draft.compose:
        # Two restores with one compose directory never run together.
        keys.add(f"name:{host_id}:path:{draft.compose.dir}")
    flags = {flag.key: flag for flag in draft.risk}
    return RestorePlan(
        mode=draft.choice.mode,
        host_id=host_id,
        images=tuple(draft.images.values()),
        networks=tuple(draft.networks),
        volumes=tuple(draft.volumes),
        originals=tuple(draft.originals),
        wipes=tuple(draft.wipes),
        data=tuple(sorted(draft.data, key=lambda d: order.get(d.member, len(order)))),
        containers=tuple(draft.containers),
        risk=tuple(flags.values()),
        warnings=tuple(dict.fromkeys(draft.warnings)),
        lock_keys=tuple(sorted(keys)),
        bind_sources=tuple(sorted(draft.bind_sources)),
        write_targets=tuple(sorted(draft.write_targets)),
        own_paths=tuple(sorted(draft.target.own_paths)),
        written=tuple(sorted(draft.written)),
        live_users=tuple(dict.fromkeys(draft.live_users)),
        project=draft.project,
        projects=tuple(sorted(draft.projects)),
        compose=draft.compose,
        mkdirs=tuple(draft.mkdirs),
    )


# SUMMARY


def summary(plan: RestorePlan, host_name: str) -> dict[str, Any]:
    """What the user confirms, JSON-safe: no create bodies and no environment. Containers
    are in start order, originals in stop order. "project" and "compose" are there only
    when set, so a plan without them summarizes exactly as before stacks."""
    document: dict[str, Any] = {
        "mode": plan.mode,
        "host_id": plan.host_id,
        "host_name": host_name,
        "containers": [c.name for c in plan.containers],
        "originals": [o.name for o in plan.originals],
        "images": [
            {"label": i.label, "action": i.action, "moves": list(i.moves)} for i in plan.images
        ],
        "networks": [
            {"name": n.name, "action": n.action, "differences": list(n.differences)}
            for n in plan.networks
        ],
        "volumes": [{"name": v.name, "action": v.action} for v in plan.volumes],
        "wipes": [w.label for w in plan.wipes],
        "data": [{"label": d.label, "target": d.target} for d in plan.data],
        "risk": [asdict(flag) for flag in plan.risk],
        "warnings": list(plan.warnings),
    }
    if plan.project:
        document["project"] = plan.project
    if plan.mkdirs:
        document["mkdirs"] = [
            {"target": d.path, "owner": d.owner, "mode": f"{d.mode:04o}"} for d in plan.mkdirs
        ]
    if plan.compose:
        document["compose"] = {
            "dir": plan.compose.dir,
            "files": [f.path for f in plan.compose.files],
        }
    return document


def summary_core(document: dict[str, Any]) -> dict[str, Any]:
    """The summary without its warnings, compared at execute time."""
    return {k: v for k, v in document.items() if k != "warnings"}
