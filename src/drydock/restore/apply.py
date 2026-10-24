"""Pass 2 of a restore: carries out a RestorePlan on the target host, and rolls it back.

Blocking (docker-py). Run on the dispatcher's executor.

apply() runs the plan in this order, checking cancel between steps (and the archive reader
between data chunks):
0. The journal, written in full before anything else. A plan with data opens the archive
   now, so its identity (and an encrypted one's passphrase) is checked before anything
   changes. Then the host paths: every bind source and write target is resolved through
   Docker like realpath (check_paths) and checked again on the resolved path
   (plan.resolved_problems). Bind directories, the parent directories of file binds and
   bound wipe targets must exist, and a file bind must not end in a symbolic link. The
   compose directory's parent must exist as a directory, the directory itself must not, and
   no restored container or volume may mount it as resolved. These checks run whenever the
   plan mounts, writes or has a compose directory.
1. Images: every staged tar is opened (and checked to be the file pass 1 wrote), then
   every pull runs, then the tags of the pulled images move, then every load runs, so a
   missing tar or a failed pull changes nothing. A load is accepted only when its refs (or
   the IDs it reports) name one of the IDs pass 1 recorded for the image. Each tag a pull
   or load sets is journaled first with the image it named before, for the rollback.
2. Networks and 3. volumes the plan creates, labelled drydock.restore.run=<run_id>.
4. Overwrite: each original, in the plan's order (dependents first), is inspected, its
   restart policy (if any) journaled and turned off, so neither it nor a daemon restart
   starts it on half-written data, and it is stopped (whatever the plan saw) and renamed
   '<name>-drydock-old'.
5. Wipes: one helper with exactly WIPE_CAPS runs find -delete over every wiped target,
   after refusing any target that has another mount inside it.
6. Data: each member is streamed from the open archive into a helper with put_archive
   (noOverwriteDirNonDir), and an entry it holds is checked on disk afterwards. A bind
   directory is mounted non-recursively, so nothing is written through a host mount below
   it. Docker leaves the top directory's owner and mode alone, so the helper then starts
   with exactly ROOT_CAPS to give it the archived ones. The archive's identity is checked
   once more.
7. Containers: created (labelled like networks and volumes) and started in the plan's
   (dependency) order. Before a start, the created containers in its wait_healthy are
   waited for (stacks.wait_healthy, at most HEALTH_WAIT, cancellable); then it starts anyway.
8. Commit: the journal is marked committed, then the originals are removed. From the
   commit on nothing raises (a log line that cannot be written goes to the server log)
   and cancel is ignored: the restored containers stay.
9. Compose files (plan.compose): the files, as one tar of entries relative to the new
   directory (directories 0700, files 0600, owner root), are put into an anonymous volume
   of a helper with exactly MKDIR_CAPS, which then runs COMPOSE_SCRIPT: `mkdir -m 0700`
   (no -p: an existing path fails it), cd into it, check that its working directory is
   that new, empty, root-owned directory right below the parent, and extract the tar
   there. tar works through the working directory, so a directory renamed or replaced
   by a symbolic link in the parent never redirects a write. Checked afterwards. Best
   effort: a failure is logged and journaled as compose_problem, and never fails or rolls
   back the restore.
Every host path a helper or container mounts is resolved again right before that mount
(reresolve), after the originals stopped, and the resolved path is what gets mounted: a
symlink the restore's own data planted, or one a container swapped in meanwhile, stops the
restore instead of redirecting the mount.

THE JOURNAL
journal(doc) persists the whole dict before every mutation, and again after each create
records the new ID: host_id, mode, run_id; originals [{id, name, old_name, running,
stop_timeout, restart_policy (only when one was turned off)}]; tags [{ref, previous (the
image ID it named before, or None), image (the one the restore made it name, once
known)}]; created [{name, id, failed}]; networks [{name, id}];
volumes_created [names]; volumes [names written or wiped]; binds [host paths written or
wiped]; the flags wipe_started, data_started, committed and rolled_back; leftover [old
names that could not be removed]; projects [the Compose projects whose lock keys the plan
holds, only when there are any]; compose_problem (why the compose files were not written,
after the commit); compose_written (true once they were written).

rollback(api, doc, log) undoes what the journal records and never raises. It removes a
container, network or volume only when it carries this run's label, a container by its
journaled ID or by an exact name match (never Docker's ID-prefix fallback), never an
original, and never a volume or network in use. Originals start again in forward order
(the reverse of the order they were stopped in). The compose directory is never touched:
it is made only after the commit. rolled_back is set only when everything
was undone. Otherwise rollback_incomplete is set, leftover names what is still on the host
("container web", "network web-net", "volume data"), not_renamed the originals that did
not get their names back and tags_left the tags that still name the restore's images; and
rollback_unreachable is set when a call could not reach Docker, so the caller tries again.
"""

import contextlib
import copy
import io
import json
import logging
import posixpath
import tarfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any, BinaryIO

import docker.errors
import docker.utils
import requests
from docker.types import Mount

from drydock.archive.writer import Cancelled
from drydock.engine import stacks
from drydock.engine.capture import DATA_CHUNK, GO_MODE_DIR, PLATFORM_API
from drydock.engine.compose_files import GO_MODE_TYPE
from drydock.hosts import helper, inventory
from drydock.hosts.client import DockerHandle, api_tuple
from drydock.hosts.inventory import PROJECT_LABEL
from drydock.jobs.runlog import env_values
from drydock.restore import risk
from drydock.restore.plan import (
    DEFAULT_NETWORKS,
    HEX_PREFIX_RE,
    OBJECT_NAME_RE,
    OLD_SUFFIX,
    RESTORE_LABEL,
    BindUse,
    ComposeWrite,
    ContainerUse,
    DataStep,
    ImageStep,
    Lookup,
    RestorePlan,
    TargetInfo,
    compose_live_notes,
    resolution_paths,
    resolved_problems,
    with_sources,
)
from drydock.restore.verify import open_staged_image
from drydock.security import hostpaths
from drydock.security.hostpaths import HostPathError

logger = logging.getLogger("drydock.restore.apply")

WIPE_CAPS = ["DAC_OVERRIDE", "FOWNER"]
# For the top directory of written data: chown, chmod of a directory another uid owns, and
# keeping its setgid bit when root is not in its group.
ROOT_CAPS = ["CHOWN", "FOWNER", "FSETID"]
# For mkdir in a parent directory another uid owns; nothing else.
MKDIR_CAPS = ["DAC_OVERRIDE"]
COMPOSE_DIR_MODE = 0o700
COMPOSE_FILE_MODE = 0o600
PROBE_ROOT = "/host"  # where the probe helper mounts the host's /
TARGET = "/t"  # where a data helper mounts what it writes into
COMPOSE_SOURCE = "/src"  # the compose helper's anonymous volume, which holds COMPOSE_TAR
COMPOSE_TAR = "compose.tar"
SYMLINK_MODE = 1 << 27  # Go's os.ModeSymlink, as the archive stat header reports it
GO_SETUID = 1 << 23
GO_SETGID = 1 << 22
GO_STICKY = 1 << 20
# The socket proxy cuts any request idle for 10 minutes, so long waits poll.
WAIT_POLL = 60
PROBE_TIMEOUT = 30
MAX_LINK_READ = 64 * 1024
LINK_CHUNK = 16 * 1024
SNIFF_BYTES = 64 * 1024  # of a data stream, kept to name an entry that must exist afterwards
MAX_MESSAGE = 500
STAT_HEADER = "X-Docker-Container-Path-Stat"
CANCELLED = "The run was cancelled."
DOCKER_ERRORS = (docker.errors.DockerException, requests.RequestException)
GATEWAY_ERRORS = (502, 503, 504)  # the socket proxy answers so while the daemon is down
NO_RESTART = {"Name": "no"}
# A bind mount is recursive and find -xdev descends into a submount of the same filesystem,
# so a wipe root with any mount below it is refused before anything is deleted. Run with
# the roots as arguments ("sh -c SCRIPT sh /w0 /w1").
WIPE_SCRIPT = (
    'for root in "$@"; do '
    "awk -v r=\"$root/\" 'index($5, r) == 1 { exit 1 }' /proc/self/mountinfo || exit 3; "
    'done; exec find "$@" -xdev -mindepth 1 -delete'
)
WIPE_REFUSED = 3
# Run with the owner and the octal mode as arguments ("sh -c SCRIPT sh 999:999 750").
ROOT_SCRIPT = (
    f'chown "$1" {TARGET} && chmod "$2" {TARGET} && [ "$(stat -c %u:%g:%a {TARGET})" = "$1:$2" ]'
)
# Run with the new directory's name as its argument ("sh -c SCRIPT sh copy"). Someone who
# can write to the parent may rename the new directory and plant a symbolic link in its
# place before the cd. So the working directory must be root's, 0700 (the setgid bit a
# parent passes on is harmless), empty, right below the parent and still the parent's
# entry of that name (busybox stat does not follow a link); from then on tar writes through
# the working directory, whatever happens to the name.
COMPOSE_SCRIPT = (
    f'cd {TARGET} && mkdir -m 0{COMPOSE_DIR_MODE:o} -- "$1" || exit 2; '
    'cd -P -- "$1" && case "$(stat -c %u:%a .)" in 0:700|0:2700) ;; *) false ;; esac'
    f' && [ "$(stat -c %d:%i .)" = "$(stat -c %d:%i "{TARGET}/$1")" ]'
    f' && [ "$(stat -c %d:%i ..)" = "$(stat -c %d:%i {TARGET})" ]'
    ' && [ -z "$(ls -A)" ] || exit 3; '
    f"exec tar -x -f {COMPOSE_SOURCE}/{COMPOSE_TAR}"
)
COMPOSE_EXISTS = 2
COMPOSE_MOVED = 3

Lstat = tuple[str, str | None] | None


class ApplyError(Exception):
    """The restore cannot continue. The message is safe to show."""


@dataclass(frozen=True)
class ApplyEnv:
    handle: DockerHandle
    helper_image: str
    instance_id: str
    run_id: int


# TARGET STATE


def inspect_target(
    handle: DockerHandle, lookup: Lookup, *, host_id: int, host_name: str, helper_image: str
) -> TargetInfo:
    """The target state build_plan needs, from read-only calls.

    Besides the lookups, the planner's protections rely on these fields; an empty one
    protects nothing:
    - bind_users: a BindUse for every Mounts entry of Type bind of every container on the
      host, and one with the device as source for every host-backed volume a container
      mounts (inspect_volume each mounted local volume; hostpaths.host_volume_device).
    - volumes: also every volume a looked-up container mounts (data-only maps by
      destination and needs their Driver and Options).
    - own, own_networks, own_volumes, protected_repos: from inventory.own_ids.
    - own_paths: the bind Sources of every own container, the Mountpoints (and devices) of
      own_volumes and info()['DockerRootDir'].
    Names are kept only on an exact match: Docker falls back to an ID prefix.
    """
    api = handle.client.api
    containers: dict[str, dict] = {}
    for name in sorted(lookup.containers):
        info = by_name(api, name)
        if info is not None and str(info.get("Name") or "").lstrip("/") == name:
            containers[name] = info
    wanted = set(lookup.volumes)
    for info in containers.values():
        wanted |= set(mounted_volumes(info))
    volumes = {name: info for name in sorted(wanted) if (info := named(api.inspect_volume, name))}
    networks = {
        name: info for name in sorted(lookup.networks) if (info := named(api.inspect_network, name))
    }
    images = {
        ref: str(info["Id"])
        for ref in sorted(lookup.images)
        if (info := found(api.inspect_image, ref)) is not None
    }
    projects = {project: project_members(api, project) for project in sorted(lookup.projects)}

    devices: dict[str, str | None] = {}

    def device(volume: str) -> str | None:
        if volume not in devices:
            info = volumes.get(volume) or named(api.inspect_volume, volume) or {}
            devices[volume] = hostpaths.host_volume_device(
                info.get("Driver") or "local", info.get("Options")
            )
        return devices[volume]

    volume_users: dict[str, list[ContainerUse]] = {}
    bind_users: list[BindUse] = []
    for raw in api.containers(all=True):
        names = raw.get("Names") or []
        name = str(names[0]).lstrip("/") if names else str(raw["Id"])[:12]
        state = str(raw.get("State") or "")
        for mount in raw.get("Mounts") or []:
            volume = str(mount.get("Name") or "")
            if mount.get("Type") == "volume" and OBJECT_NAME_RE.fullmatch(volume):
                volume_users.setdefault(volume, []).append(ContainerUse(raw["Id"], name, state))
                if mount.get("Driver", "local") == "local" and (source := device(volume)):
                    bind_users.append(BindUse(raw["Id"], name, state, source))
            elif mount.get("Type") == "bind" and mount.get("Source"):
                bind_users.append(BindUse(raw["Id"], name, state, str(mount["Source"])))

    own = inventory.own_ids(api)
    own_networks: set[str] = set()
    own_volumes: set[str] = set()
    own_paths: set[str] = set()
    protected = {docker.utils.parse_repository_tag(helper_image)[0]}
    for container_id in sorted(own):
        info = found(api.inspect_container, container_id)
        if info is None or info.get("Id") != container_id:
            continue
        endpoints = (info.get("NetworkSettings") or {}).get("Networks") or {}
        for network, endpoint in endpoints.items():
            # Every container may join the default networks; they are nobody's own.
            if network in DEFAULT_NETWORKS:
                continue
            own_networks.add(network)
            if isinstance(endpoint, dict) and endpoint.get("NetworkID"):
                own_networks.add(str(endpoint["NetworkID"]))
        own_volumes |= set(mounted_volumes(info))
        own_paths |= {
            str(mt["Source"])
            for mt in info.get("Mounts") or []
            if mt.get("Type") == "bind" and mt.get("Source")
        }
        if image := (info.get("Config") or {}).get("Image"):
            protected.add(docker.utils.parse_repository_tag(str(image))[0])
        if (image_info := found(api.inspect_image, str(info.get("Image") or ""))) is not None:
            protected |= {
                docker.utils.parse_repository_tag(str(tag))[0]
                for tag in image_info.get("RepoTags") or []
            }
    for volume in sorted(own_volumes):
        info = volumes.get(volume) or named(api.inspect_volume, volume) or {}
        if info.get("Mountpoint"):
            own_paths.add(str(info["Mountpoint"]))
        if source := device(volume):
            own_paths.add(source)
    root = api.info().get("DockerRootDir")
    if isinstance(root, str) and root:
        own_paths.add(root)
    return TargetInfo(
        host_id=host_id,
        host_name=host_name,
        api_version=handle.api_version,
        arch=handle.arch,
        containers=containers,
        volumes=volumes,
        volume_users={k: tuple(v) for k, v in volume_users.items()},
        bind_users=tuple(bind_users),
        networks=networks,
        images=images,
        own=own,
        own_networks=frozenset(own_networks),
        own_volumes=frozenset(own_volumes),
        own_paths=frozenset(own_paths),
        protected_repos=frozenset(protected),
        projects=projects,
    )


def project_members(api, project: str) -> tuple[str, ...]:
    """The names of the containers labelled exactly with this Compose project, without
    drydock's helpers and the originals an overwrite renamed to '<name>-drydock-old'."""
    names = set()
    for raw in api.containers(all=True, filters={"label": f"{PROJECT_LABEL}={project}"}):
        labels = raw.get("Labels") or {}
        if labels.get(PROJECT_LABEL) != project or labels.get(helper.HELPER_LABEL) == "1":
            continue
        name = stacks.primary_name(raw)
        if name and not name.endswith(OLD_SUFFIX):
            names.add(name)
    return tuple(sorted(names))


def found(inspect: Callable[[str], dict], ref: str) -> dict | None:
    if not ref:
        return None
    try:
        return inspect(ref)
    except docker.errors.NotFound:
        return None


def by_name(api, name: str) -> dict | None:
    """A container inspect by name, or None. Docker tries the name before any ID prefix, so
    a name that is the prefix of several IDs (400, ambiguous) names no container."""
    try:
        return found(api.inspect_container, name)
    except docker.errors.APIError as exc:
        if exc.status_code == 400 and HEX_PREFIX_RE.fullmatch(name):
            return None
        raise


def named(inspect: Callable[[str], dict], name: str) -> dict | None:
    """A volume or network inspect, only when its Name is exactly name."""
    info = found(inspect, name)
    return info if info is not None and info.get("Name") == name else None


def mounted_volumes(info: dict[str, Any]) -> list[str]:
    return [
        str(mt["Name"])
        for mt in info.get("Mounts") or []
        if mt.get("Type") == "volume" and OBJECT_NAME_RE.fullmatch(str(mt.get("Name") or ""))
    ]


# HOST PATHS


def path_stat(api, container_id: str, path: str) -> dict[str, Any] | None:
    """The daemon's lstat of path inside a container (HEAD .../archive), or None when it
    does not exist. Uses docker-py's private _url and _raise_for_status, and the head()
    of its requests session (tests/test_restore_apply.py pins them)."""
    response = api.head(
        api._url("/containers/{0}/archive", container_id),
        params={"path": path},
        timeout=PROBE_TIMEOUT,
    )
    try:
        if response.status_code == 404:
            return None
        api._raise_for_status(response)
        encoded = response.headers.get(STAT_HEADER)
        try:
            stat = docker.utils.decode_json_header(encoded) if encoded else None
        except ValueError:
            stat = None
    finally:
        response.close()
    if not isinstance(stat, dict) or not isinstance(stat.get("mode"), int):
        raise ApplyError("Docker did not describe a host path.")
    return stat


class Probe:
    """lstat of host paths through a never-started helper that mounts the host's / at
    PROBE_ROOT, read-only. Each path handed to lstat is already resolved, so the daemon
    resolves nothing in it, and the basename is never followed."""

    def __init__(self, box) -> None:
        self.box = box
        self.api = box.client.api
        self.cache: dict[str, Lstat] = {}

    def lstat(self, path: str) -> Lstat:
        if path not in self.cache:
            self.cache[path] = self._lstat(path)
        return self.cache[path]

    def _lstat(self, path: str) -> Lstat:
        stat = path_stat(self.api, self.box.id, PROBE_ROOT + path)
        if stat is None:
            return None
        mode = stat["mode"]
        if mode & SYMLINK_MODE:
            # The header's linkTarget is resolved against the helper's root, not the host's.
            return "link", self.link_text(path)
        return ("dir" if mode & GO_MODE_DIR else "file"), None

    def link_text(self, path: str) -> str:
        data = bytearray()
        try:
            with helper.open_archive(self.box, PROBE_ROOT + path, LINK_CHUNK) as (chunks, _):
                for chunk in chunks:
                    data += chunk
                    if len(data) >= MAX_LINK_READ:
                        break
        except docker.errors.NotFound:
            raise ApplyError(f"{path} changed during the restore.") from None
        try:
            with tarfile.open(fileobj=io.BytesIO(bytes(data[:MAX_LINK_READ])), mode="r|") as tar:
                info = tar.next()
        except tarfile.TarError:
            info = None
        if info is None or not info.issym():
            raise ApplyError(f"Host path {path} could not be resolved.")
        return info.linkname

    def resolve(self, path: str) -> str:
        try:
            return hostpaths.resolve(path, self.lstat)
        except HostPathError as exc:
            raise ApplyError(str(exc)) from None


@contextlib.contextmanager
def probe(env: ApplyEnv) -> Iterator[Probe]:
    mounts = [Mount(PROBE_ROOT, "/", type="bind", read_only=True)]
    with helper.helper(env.handle.client, env.helper_image, env.instance_id, mounts=mounts) as box:
        yield Probe(box)


def resolve_paths(env: ApplyEnv, paths: Iterable[str]) -> dict[str, str]:
    """Each host path resolved like realpath on the target host. Raises ApplyError. A test
    seam: apply itself resolves through check_paths and reresolve."""
    with probe(env) as host:
        return {path: host.resolve(path) for path in sorted(set(paths))}


def reresolve(env: ApplyEnv, paths: Iterable[str], expected: Mapping[str, str]) -> dict[str, str]:
    """Resolves paths again right before a mount, with one probe helper, and returns them
    resolved. Raises ApplyError when one resolves elsewhere than it did when checked."""
    paths = sorted(set(paths))
    if not paths:
        return {}
    with probe(env) as host:
        for path in paths:
            if path not in expected:
                raise ApplyError(f"Host path {path} was not checked before the restore.")
            if host.resolve(path) != expected[path]:
                raise ApplyError(f"{path} changed during the restore.")
    return {path: expected[path] for path in paths}


def must_exist(plan: RestorePlan) -> list[str]:
    """The directories a restore writes into that it does not create: bind directories,
    the parents of file binds and bound wipe targets. Volumes and the files of file binds
    may be missing."""
    paths = [w.target for w in plan.wipes if w.kind == "bind"]
    for step in plan.data:
        if step.kind == "bind-dir":
            paths.append(step.target)
        elif step.kind == "bind-file":
            paths.append(posixpath.dirname(step.target))
    return sorted(set(paths))


def check_paths(
    env: ApplyEnv, plan: RestorePlan, log: Callable[[str], None] | None = None
) -> dict[str, str]:
    """Step 0: every bind source and write target, and the compose directory's parent,
    resolved on the host and checked again as resolved. Returns plan path: resolved path.
    log gets the live containers that can read the compose directory as resolved."""
    paths = resolution_paths(plan)
    if not paths:
        return {}
    with probe(env) as host:
        resolved = {path: host.resolve(path) for path in sorted(paths)}
        problems = resolved_problems(plan, resolved)
        if problems:
            raise ApplyError(" ".join(problems))
        for path in must_exist(plan):
            real = resolved.get(path) or host.resolve(path)
            stat = host.lstat(real)
            if stat is None:
                raise ApplyError(f"{path} does not exist on the host.")
            if stat[0] != "dir":
                raise ApplyError(f"{path} is not a directory on the host.")
        for step in plan.data:
            if step.kind == "bind-file":
                check_file_target(host, step.target, resolved)
        if plan.compose:
            check_compose_dir(host, plan.compose.dir, resolved)
    if log is not None:
        for line in compose_live_notes(plan, resolved):
            log(line)
    return resolved


def check_compose_dir(host: Probe, directory: str, resolved: Mapping[str, str]) -> None:
    """The compose directory is new: its resolved parent is a directory and nothing, not
    even a dangling symbolic link, has its name there."""
    parent = posixpath.dirname(directory)
    real_parent = resolved[parent]
    stat = host.lstat(real_parent)
    if stat is None:
        raise ApplyError(f"{parent} does not exist on the host.")
    if stat[0] != "dir":
        raise ApplyError(f"{parent} is not a directory on the host.")
    if host.lstat(posixpath.join(real_parent, posixpath.basename(directory))) is not None:
        raise ApplyError(
            f"{directory} already exists on the host. Choose a new directory: drydock never "
            "writes over existing files."
        )


def check_file_target(host: Probe, target: str, resolved: Mapping[str, str]) -> None:
    """A file bind is written as its name inside its resolved directory. Were the name a
    symbolic link, the write would replace the link, and the bind would then resolve
    elsewhere than it was checked; a directory there would refuse the file."""
    directory, name = posixpath.split(target)
    real = resolved.get(target) or host.resolve(target)
    written = posixpath.join(resolved.get(directory) or host.resolve(directory), name)
    if real != written:
        raise ApplyError(
            f"{target} is a symbolic link to {real} on the host. Restore the file onto "
            f"{real} itself."
        )
    stat = host.lstat(real)
    if stat is not None and stat[0] != "file":
        raise ApplyError(f"{target} is not a file on the host.")


# IMAGES


def sha(value: str) -> str:
    return value if value.startswith("sha256:") else "sha256:" + value


def message_of(line: object) -> str | None:
    """The error of a JSON progress line, if it reports one."""
    if not isinstance(line, dict):
        return None
    detail = line.get("errorDetail")
    error = line.get("error") or (detail.get("message") if isinstance(detail, dict) else detail)
    if not error:
        return None
    return str(error)[:MAX_MESSAGE]


def pull_image(api, step: ImageStep, cancel: threading.Event, log: Callable[[str], None]) -> str:
    """Pulls the confirmed digest. Returns the image ID; tag_image moves the refs once
    every pull succeeded."""
    if step.pull is None:
        raise ApplyError(f"Image {step.label} has nothing to pull.")
    log(f"Pulling image {step.label} ({step.pull}).")
    try:
        for line in api.pull(step.pull, stream=True, decode=True):
            if cancel.is_set():
                raise Cancelled(CANCELLED)
            if (error := message_of(line)) is not None:
                raise ApplyError(f"Pulling image {step.label} failed: {error}")
    except docker.errors.APIError as exc:
        raise ApplyError(f"Pulling image {step.label} failed: {explain(exc)}") from None
    info = found(api.inspect_image, step.pull)
    if info is None:
        raise ApplyError(f"Image {step.label} was pulled but is not on the host.")
    return str(info["Id"])


def tag_image(api, step: ImageStep, image_id: str) -> None:
    for ref in step.refs:
        repository, tag = docker.utils.parse_repository_tag(ref)
        api.tag(image_id, repository, tag)


def load_chunks(handle: BinaryIO, cancel: threading.Event) -> Iterator[bytes]:
    while chunk := handle.read(DATA_CHUNK):
        if cancel.is_set():
            raise Cancelled(CANCELLED)
        yield chunk


def load_image(
    api, handle: BinaryIO, step: ImageStep, api_version: str, cancel: threading.Event
) -> tuple[list[str], list[str]]:
    """docker load of a staged docker-save tar: (the image IDs and the names it reports).

    The only call without a client timeout: the daemon keeps writing progress lines, so
    the socket proxy's 10-minute idle timeout does not fire. Uses docker-py's private
    _post, _url and _raise_for_status (tests/test_restore_apply.py pins them).
    """
    params: dict[str, Any] = {"quiet": "0"}
    if api_tuple(api_version) >= PLATFORM_API:
        platform = {"os": step.os, "architecture": step.architecture}
        if step.variant:
            platform["variant"] = step.variant
        params["platform"] = json.dumps(platform, separators=(",", ":"))
    response = api._post(
        api._url("/images/load"),
        data=load_chunks(handle, cancel),
        params=params,
        headers={"Content-Type": "application/x-tar"},
        stream=True,
        timeout=None,
    )
    ids: list[str] = []
    names: list[str] = []
    try:
        api._raise_for_status(response)
        for raw in response.iter_lines():
            if not raw.strip():
                continue
            try:
                line = json.loads(raw)
            except ValueError:
                raise ApplyError(f"Loading image {step.label} gave an unreadable answer.") from None
            if (error := message_of(line)) is not None:
                raise ApplyError(f"Loading image {step.label} failed: {error}")
            text = str(line.get("stream") or "").strip() if isinstance(line, dict) else ""
            if text.startswith("Loaded image ID:"):
                ids.append(text.removeprefix("Loaded image ID:").strip())
            elif text.startswith("Loaded image:"):
                names.append(text.removeprefix("Loaded image:").strip())
    finally:
        response.close()
    return ids, names


def loaded_id(api, step: ImageStep, reported: list[str]) -> str:
    """The ID the loaded image has on the target. Every ref must name one of the IDs pass 1
    recorded for it (the stores name images differently); without refs, the ID the daemon
    reported must be one of them."""
    accepted = {sha(i) for i in step.accepted_ids}
    if step.refs:
        ids = []
        for ref in step.refs:
            info = found(api.inspect_image, ref)
            if info is None:
                raise ApplyError(f"Image {step.label} did not load {ref}.")
            if sha(str(info["Id"])) not in accepted:
                raise ApplyError(
                    f"Image {step.label} did not load as recorded: {ref} names another image."
                )
            ids.append(str(info["Id"]))
        return ids[0]
    for candidate in reported:
        info = found(api.inspect_image, candidate) if sha(candidate) in accepted else None
        if info is not None and sha(str(info["Id"])) in accepted:
            return str(info["Id"])
    raise ApplyError(f"Image {step.label} did not load as recorded.")


def present_id(api, step: ImageStep) -> str:
    """The target's ID of an image the plan found present: the image ID itself, or the
    first ref that names one of the accepted IDs."""
    accepted = {sha(i) for i in step.accepted_ids}
    for ref in (step.id, *step.refs):
        info = found(api.inspect_image, ref)
        if info is not None and (ref == step.id or sha(str(info["Id"])) in accepted):
            return str(info["Id"])
    raise ApplyError(f"Image {step.label} is no longer on the host.")


# DATA


def put_data(api, container_id: str, chunks: Iterable[bytes], *, path: str = TARGET) -> None:
    """PUT .../archive into path (TARGET by default). Content-Type is set (some daemons
    extract nothing without it), and noOverwriteDirNonDir keeps a directory from being
    replaced by a file or a symlink. No copyUIDGID: the archive's owners are kept. Uses
    docker-py's private _put, _url and _raise_for_status (tests/test_restore_apply.py pins
    them). The body is always an iterator: requests form-encodes a list or tuple body
    instead of streaming it."""
    response = api._put(
        api._url("/containers/{0}/archive", container_id),
        params={"path": path, "noOverwriteDirNonDir": "true"},
        data=iter(chunks),
        headers={"Content-Type": "application/x-tar"},
    )
    try:
        api._raise_for_status(response)
    finally:
        response.close()


class FirstEntry:
    """Passes a tar stream through and keeps its start, to name an entry Docker must have
    written."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self.chunks = chunks
        self.head = bytearray()

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self.chunks:
            if len(self.head) < SNIFF_BYTES:
                self.head += chunk[: SNIFF_BYTES - len(self.head)]
            yield chunk

    def name(self) -> str | None:
        """The first entry below the root, or None when the start names none."""
        try:
            with tarfile.open(fileobj=io.BytesIO(bytes(self.head)), mode="r|") as tar:
                while (info := tar.next()) is not None:
                    name = posixpath.normpath(info.name)
                    if name != "." and name.isprintable():
                        return name
        except tarfile.TarError, UnicodeError:
            return None
        return None


def unix_mode(go_mode: int) -> int:
    mode = go_mode & 0o777
    for bit, unix in ((GO_SETUID, 0o4000), (GO_SETGID, 0o2000), (GO_STICKY, 0o1000)):
        if go_mode & bit:
            mode |= unix
    return mode


def explain(exc: docker.errors.APIError) -> str:
    return str(exc.explanation or exc)[:MAX_MESSAGE]


# APPLY


def apply(
    env: ApplyEnv,
    plan: RestorePlan,
    staged: Any,  # restore.verify.Staged
    open_archive: Callable[[], AbstractContextManager[Any]],
    *,
    cancel: threading.Event,
    log: Callable[[str], None],
    journal: Callable[[dict[str, Any]], None],
) -> None:
    """Runs the plan, writing the journal before every mutation.

    Before the first mutation, every plan.bind_sources and plan.write_targets path (and the
    compose directory's parent) is resolved through Docker, and
    plan.resolved_problems(plan, resolved) must be empty (else ApplyError). The resolved
    paths are what gets mounted. Raises ApplyError,
    Cancelled, VerifyError (the archive changed) or a Docker error; the caller rolls back
    with the last journal.
    """
    Applier(env, plan, staged, open_archive, cancel, log, journal).run()


class Applier:
    def __init__(
        self,
        env: ApplyEnv,
        plan: RestorePlan,
        staged: Any,
        open_archive: Callable[[], AbstractContextManager[Any]],
        cancel: threading.Event,
        log: Callable[[str], None],
        journal: Callable[[dict[str, Any]], None],
    ) -> None:
        self.env = env
        self.api = env.handle.client.api
        self.plan = plan
        self.staged = staged
        self.open_archive = open_archive
        self.cancel = cancel
        self.log = log
        self._journal = journal
        self.label = {RESTORE_LABEL: str(env.run_id)}
        # Host path: the path it resolved to when checked. Devices of the volumes this
        # restore creates are already resolved, so they map to themselves.
        self.expected: dict[str, str] = {}
        self.images: dict[str, str] = {}  # ImageStep.id: the image ID on the target
        self.doc: dict[str, Any] = {
            "host_id": plan.host_id,
            "mode": plan.mode,
            "run_id": env.run_id,
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
        if plan.projects:
            # Read by dispatcher.journal_keys: a rollback holds the projects' keys too.
            self.doc["projects"] = list(plan.projects)

    def journal(self) -> None:
        self._journal(copy.deepcopy(self.doc))

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise Cancelled(CANCELLED)

    def run(self) -> None:
        self.journal()
        with contextlib.ExitStack() as archive:
            # Before the first mutation: a missing, replaced or undecryptable archive stops
            # the restore while nothing has changed. Its members are read in step 6.
            reader = archive.enter_context(self.open_archive()) if self.plan.data else None
            if self.plan.bind_sources or self.plan.write_targets or self.plan.compose:
                self.log("Checking host paths.")
                self.expected = check_paths(self.env, self.plan, self.log)
            for step in (
                self.bring_images,
                self.create_networks,
                self.create_volumes,
                self.stop_originals,
                self.wipe,
            ):
                self.check_cancel()
                step()
            self.check_cancel()
            self.write_data(reader)
        self.check_cancel()
        self.create_containers()
        self.commit()

    # STEP 1: IMAGES

    def bring_images(self) -> None:
        loads = {n: s for n, s in enumerate(self.plan.images) if s.action == "load"}
        with contextlib.ExitStack() as stack:
            # Every staged tar first: one that is gone stops the restore before a pull
            # moves a tag.
            handles: dict[int, BinaryIO] = {}
            for n, step in loads.items():
                if step.member is None:
                    raise ApplyError(f"Image {step.label} has nothing to load.")
                handles[n] = stack.enter_context(open_staged_image(self.staged, step.member))
            self.pull_images()
            self.load_images(handles)

    def journal_tags(self, refs: Iterable[str], image: str | None = None) -> None:
        """Before a pull's tags move or a load sets its own: the image each ref names now
        (previous, None when it names none) and the one it will name (image, once known),
        so a rollback can point it back."""
        known = {entry["ref"] for entry in self.doc["tags"]}
        for ref in refs:
            if ref not in known:
                info = found(self.api.inspect_image, ref)
                previous = str(info["Id"]) if info is not None and info.get("Id") else None
                self.doc["tags"].append({"ref": ref, "previous": previous, "image": image})
                known.add(ref)
        self.journal()

    def tagged(self, refs: Iterable[str], image: str) -> None:
        """After a load: the image its tags name now."""
        wanted = set(refs)
        for entry in self.doc["tags"]:
            if entry["ref"] in wanted and entry["image"] is None:
                entry["image"] = image
        self.journal()

    def pull_images(self) -> None:
        pulled = []
        for step in self.plan.images:
            if step.action == "pull":
                self.check_cancel()
                pulled.append((step, pull_image(self.api, step, self.cancel, self.log)))
        # Tags move only once every pull succeeded: a failed pull changes nothing.
        for step, image_id in pulled:
            self.journal_tags(step.refs, image_id)
            tag_image(self.api, step, image_id)
            self.images[step.id] = image_id

    def load_images(self, handles: Mapping[int, BinaryIO]) -> None:
        for n, step in enumerate(self.plan.images):
            if n in handles:
                self.check_cancel()
                self.journal_tags(step.refs)
                self.log(f"Loading image {step.label}.")
                reported, _ = load_image(
                    self.api, handles[n], step, self.env.handle.api_version, self.cancel
                )
                self.images[step.id] = loaded_id(self.api, step, reported)
                if step.refs:
                    self.tagged(step.refs, self.images[step.id])
        wanted = {c.image_entry for c in self.plan.containers if c.image_entry}
        for step in self.plan.images:
            if step.action == "present" and step.id in wanted:
                self.images[step.id] = present_id(self.api, step)

    # STEPS 2 AND 3: NETWORKS AND VOLUMES

    def create_networks(self) -> None:
        for step in self.plan.networks:
            self.check_cancel()
            if step.action != "create":
                self.log(f"Using the existing network {step.name}.")
                for difference in step.differences:
                    self.log(f"Network {step.name} differs from the archive: {difference}.")
                continue
            entry: dict[str, Any] = {"name": step.name, "id": None}
            self.doc["networks"].append(entry)
            self.journal()
            self.log(f"Creating network {step.name}.")
            create = {k: v for k, v in step.create.items() if k != "labels"}
            labels = {**(step.create.get("labels") or {}), **self.label}
            result = self.api.create_network(**create, labels=labels)
            entry["id"] = result.get("Id")
            self.journal()

    def create_volumes(self) -> None:
        for step in self.plan.volumes:
            self.check_cancel()
            if step.action != "create":
                continue
            self.doc["volumes_created"].append(step.name)
            self.journal()
            options = dict(step.driver_opts)
            if step.device is not None:
                device = self.expected.get(normalized(step.device))
                if device is None:
                    raise ApplyError(f"Host path {step.device} was not checked before the restore.")
                options["device"] = device
                self.expected[device] = device
            self.log(f"Creating volume {step.name}.")
            result = self.api.create_volume(
                step.name, step.driver, options, {**step.labels, **self.label}
            )
            # Docker hands back an existing volume of that name instead of failing.
            if (result.get("Labels") or {}).get(RESTORE_LABEL) != self.label[RESTORE_LABEL]:
                raise ApplyError(f"Volume {step.name} already exists on the host.")

    def volume_device(self, name: str) -> str | None:
        """The host path a volume binds, as checked in step 0, or None. A volume that does
        not exist yet binds nothing: container create makes a plain one."""
        info = found(self.api.inspect_volume, name) or {}
        device = hostpaths.host_volume_device(info.get("Driver") or "local", info.get("Options"))
        if device is None:
            return None
        path = normalized(device)
        if path not in self.expected:
            raise ApplyError(f"Volume {name} changed during the restore.")
        return path

    # STEP 4: ORIGINALS

    def stop_originals(self) -> None:
        for original in self.plan.originals:
            self.check_cancel()
            # The live state, not the plan's: pulls and loads may have taken minutes.
            info = self.api.inspect_container(original.id)
            if info.get("Id") != original.id:
                raise ApplyError(f"Container {original.name} changed during the restore.")
            entry: dict[str, Any] = {
                "id": original.id,
                "name": original.name,
                "old_name": original.old_name,
                "running": bool((info.get("State") or {}).get("Running")),
                "stop_timeout": original.stop_timeout,
            }
            policy = (info.get("HostConfig") or {}).get("RestartPolicy") or {}
            if policy.get("Name") not in (None, "", "no"):
                entry["restart_policy"] = {
                    "Name": str(policy["Name"]),
                    "MaximumRetryCount": int(policy.get("MaximumRetryCount") or 0),
                }
            self.doc["originals"].append(entry)
            self.journal()
            if "restart_policy" in entry:
                # Else Docker starts it again when the daemon restarts, on whatever data
                # the restore has written by then.
                self.log(f"Turning off the restart policy of container {original.name}.")
                self.api.update_container(original.id, restart_policy=NO_RESTART)
            # Always: one that was stopped when planned may have started since.
            self.log(f"Stopping container {original.name}.")
            self.api.stop(original.id, timeout=original.stop_timeout)
            self.log(f"Renaming container {original.name} to {original.old_name}.")
            self.api.rename(original.id, original.old_name)

    # STEP 5: WIPES

    def wipe(self) -> None:
        if not self.plan.wipes:
            return
        self.log(f"Wiping {', '.join(w.label for w in self.plan.wipes)}.")
        paths = [w.target for w in self.plan.wipes if w.kind == "bind"]
        paths += [
            device
            for w in self.plan.wipes
            if w.kind == "volume" and (device := self.volume_device(w.target)) is not None
        ]
        current = reresolve(self.env, paths, self.expected)
        mounts = [
            Mount(f"/w{n}", current[w.target], type="bind", read_only=False)
            if w.kind == "bind"
            else Mount(f"/w{n}", w.target, type="volume", read_only=False)
            for n, w in enumerate(self.plan.wipes)
        ]
        roots = [f"/w{n}" for n in range(len(self.plan.wipes))]
        written = {key: list(self.doc[key]) for key in ("volumes", "binds")}
        # Set right before the helper exists: until then nothing was deleted, and a
        # rollback starts the running originals again.
        self.doc["wipe_started"] = True
        for item in self.plan.wipes:
            self.doc["volumes" if item.kind == "volume" else "binds"].append(item.target)
        self.journal()
        with helper.helper(
            self.env.handle.client,
            self.env.helper_image,
            self.env.instance_id,
            command=["sh", "-c", WIPE_SCRIPT, "sh", *roots],
            mounts=mounts,
            start=True,
            cap_add=WIPE_CAPS,
        ) as box:
            code = wait_for_exit(self.api, box.id, self.cancel)
        if code == WIPE_REFUSED:
            self.doc["wipe_started"] = False  # the helper stopped before find ran
            self.doc |= written
            self.journal()
            raise ApplyError(
                "A wiped directory has another mount inside it, so nothing was wiped. "
                "Unmount it, or restore without wiping."
            )
        if code != 0:
            raise ApplyError(f"The wipe failed (exit {code}).")

    # STEP 6: DATA

    def write_data(self, reader: Any) -> None:
        if not self.plan.data:
            return
        for step in self.plan.data:
            self.check_cancel()
            reader.advance_to(step.member)  # before any request opens
            self.log(f"Restoring the data of {step.label}.")
            self.write_member(reader, step)
        reader.close()

    def write_member(self, reader: Any, step: DataStep) -> None:
        if step.kind == "volume":
            if (device := self.volume_device(step.target)) is not None:
                reresolve(self.env, [device], self.expected)
            mount = Mount(TARGET, step.target, type="volume", read_only=False)
            written = ("volumes", step.target)
        else:
            directory = step.target if step.kind == "bind-dir" else posixpath.dirname(step.target)
            source = reresolve(self.env, [directory], self.expected)[directory]
            mount = non_recursive(Mount(TARGET, source, type="bind", read_only=False))
            written = ("binds", step.target)
        root = root_metadata(step, reader.facts(step.member))
        # Set right before the first helper that writes: a path that changed before it
        # leaves the data untouched.
        self.doc["data_started"] = True
        if written[1] not in self.doc[written[0]]:
            self.doc[written[0]].append(written[1])
        self.journal()
        with helper.helper(
            self.env.handle.client,
            self.env.helper_image,
            self.env.instance_id,
            # Started only after the put, to give the top directory its archived metadata.
            command=["sh", "-c", ROOT_SCRIPT, "sh", *root] if root else None,
            mounts=[mount],
            cap_add=ROOT_CAPS if root else None,
        ) as box:
            chunks = FirstEntry(reader.data(step.member, step.rename_to))
            try:
                put_data(self.api, box.id, chunks)
            except docker.errors.APIError as exc:
                raise ApplyError(
                    f"Docker could not write the data of {step.label}: {explain(exc)}"
                ) from None
            name = step.rename_to or chunks.name()
            if name is not None and path_stat(self.api, box.id, f"{TARGET}/{name}") is None:
                raise ApplyError(f"Docker did not write the data of {step.label}.")
            if root:
                self.restore_root(box.id, step, root)

    def restore_root(self, box_id: str, step: DataStep, root: tuple[str, str]) -> None:
        """Docker merges the archive's './' into the existing TARGET without applying its
        owner or mode, so the helper sets them, and the result is checked."""
        self.api.start(box_id)
        code = wait_for_exit(self.api, box_id, self.cancel)
        stat = path_stat(self.api, box_id, TARGET) if code == 0 else None
        if stat is None or f"{unix_mode(stat['mode']):o}" != root[1]:
            raise ApplyError(
                f"The top directory of {step.label} did not get the owner and mode of the "
                f"archive (exit {code})."
            )

    # STEP 7: CONTAINERS

    def create_containers(self) -> None:
        for step in self.plan.containers:
            self.check_cancel()
            entry: dict[str, Any] = {"name": step.name, "id": None, "failed": False}
            self.doc["created"].append(entry)
            self.journal()
            paths = [normalized(source) for source in risk.bind_sources(step.body)]
            paths += [
                device
                for volume in body_volumes(step.body)
                if (device := self.volume_device(volume)) is not None
            ]
            current = reresolve(self.env, paths, self.expected)
            body = with_sources(step.body, current)
            body["Labels"] = {**(body.get("Labels") or {}), **self.label}
            if step.image_entry:
                if step.image_entry not in self.images:
                    raise ApplyError(f"The image of container {step.name} was not resolved.")
                body["Image"] = self.images[step.image_entry]
            self.log(f"Creating container {step.name}.")
            try:
                result = self.api.create_container_from_config(body, name=step.name)
            except docker.errors.APIError:
                entry["failed"] = True  # nothing was created; rollback must not look for it
                self.journal()
                raise
            entry["id"] = result["Id"]
            self.journal()
            if step.start:
                self.wait_for_dependencies(step.wait_healthy)
                self.log(f"Starting container {step.name}.")
                self.api.start(result["Id"])

    def wait_for_dependencies(self, names: Iterable[str]) -> None:
        """Waits for the healthchecks of the created containers named, the way Compose waits
        for service_healthy dependencies, then starts anyway; a cancel stops the restore."""
        wanted = set(names)
        if not wanted:
            return
        ids = [e["id"] for e in self.doc["created"] if e["name"] in wanted and e["id"]]
        deadline = time.monotonic() + stacks.HEALTH_WAIT
        if not stacks.wait_healthy(self.api, ids, deadline, self.cancel, self.log):
            self.check_cancel()

    # STEP 8: COMMIT

    def note(self, line: str) -> None:
        """Logs after the commit, where nothing may raise: a line the run log cannot take
        (a full disk) goes to the server log instead, redacted when the run log can."""
        try:
            self.log(line)
        except Exception as exc:
            redact = getattr(self.log, "redact", None)
            shown = redact(line) if callable(redact) else "(not shown)"
            logger.error("Could not write to the run log: %s. The line: %s", exc, shown)

    def commit(self) -> None:
        self.doc["committed"] = True
        self.journal()
        for original in self.doc["originals"]:
            self.note(f"Removing the original container {original['old_name']}.")
            if not remove_original(self.api, original, self.note, strict=True):
                self.doc["leftover"].append(original["old_name"])
                try:
                    self.journal()
                except Exception:
                    logger.exception("Could not journal the leftover %s", original["old_name"])
        if self.plan.compose:
            self.write_compose()

    # STEP 9: COMPOSE FILES

    def write_compose(self) -> None:
        """Creates the compose directory and writes the files into it. Never raises: the
        restore is done, so a failure is logged and journaled as compose_problem. A
        directory created before a later failure stays: it is new, root's and 0700."""
        compose = self.plan.compose
        if compose is None:
            return
        try:
            self.put_compose(compose)
        except Exception as exc:  # Cancelled included: after the commit nothing raises
            text = str(exc) if isinstance(exc, ApplyError | Cancelled) else error_text(exc)
            message = (
                f"Could not write the compose files to {compose.dir}: {text.rstrip('.')}. "
                "The restore itself is done."
            )
            self.note(message)
            self.doc["compose_problem"] = message
            try:
                self.journal()
            except Exception:
                logger.exception("Could not journal the compose problem")
            return
        self.note(f"Wrote {len(compose.files)} compose files to {compose.dir}.")
        self.doc["compose_written"] = True
        try:
            self.journal()
        except Exception:
            logger.exception("Could not journal the compose write")

    def put_compose(self, compose: ComposeWrite) -> None:
        parent, name = posixpath.split(compose.dir)
        tar = single_file_tar(COMPOSE_TAR, compose_tar(compose, self.staged))
        real_parent = reresolve(self.env, [parent], self.expected)[parent]
        self.note(f"Creating the directory {compose.dir}.")
        mounts = [
            non_recursive(Mount(TARGET, real_parent, type="bind", read_only=False)),
            Mount(COMPOSE_SOURCE, None, type="volume", read_only=False),  # anonymous
        ]
        inside = f"{TARGET}/{name}"
        with helper.helper(
            self.env.handle.client,
            self.env.helper_image,
            self.env.instance_id,
            # Its mkdir has no -p: an existing file, directory or symbolic link there fails
            # with EEXIST, so drydock never merges into a directory someone else made.
            command=["sh", "-c", COMPOSE_SCRIPT, "sh", name],
            mounts=mounts,
            cap_add=MKDIR_CAPS,
        ) as box:
            # Into the helper's own anonymous volume, before it starts: Docker's archive
            # extraction, which follows a link it meets, writes nothing below the parent.
            put_data(self.api, box.id, [tar], path=COMPOSE_SOURCE)
            self.api.start(box.id)
            # After the commit cancel is ignored: the helper may already have made the
            # directory, and only its exit code says so. It ends at once; the shutdown
            # fallback bounds a stuck daemon.
            code = wait_for_exit(self.api, box.id, threading.Event())
            if code == COMPOSE_EXISTS:
                raise ApplyError(
                    f"{compose.dir} could not be created on the host (it may have appeared "
                    "during the restore); the compose files were not written."
                )
            if code == COMPOSE_MOVED:
                raise ApplyError(
                    f"{compose.dir} was moved or replaced while drydock created it; the "
                    "compose files were not written."
                )
            if code != 0:
                raise ApplyError(f"The compose files could not be extracted (exit {code}).")
            self.check_compose_dir(box.id, compose)
            for item in compose.files:
                stat = path_stat(self.api, box.id, f"{inside}/{item.path}")
                if stat is None or stat["mode"] & GO_MODE_TYPE or stat.get("size") != item.size:
                    raise ApplyError(f"Docker did not write {item.path}.")

    def check_compose_dir(self, box_id: str, compose: ComposeWrite) -> None:
        stat = path_stat(self.api, box_id, f"{TARGET}/{posixpath.basename(compose.dir)}")
        # The setgid bit a parent passes on to new directories is harmless here.
        if (
            stat is None
            or not stat["mode"] & GO_MODE_DIR
            or stat["mode"] & SYMLINK_MODE
            or unix_mode(stat["mode"]) & ~0o2000 != COMPOSE_DIR_MODE
        ):
            raise ApplyError(f"Docker did not create {compose.dir} as expected.")


def compose_tar(compose: ComposeWrite, staged: Any) -> bytes:
    """The compose files as one tar, entries relative to the new directory and never naming
    it, so tar neither replaces nor re-chowns it: directories 0700 and files 0600, owned
    by root, bytes verbatim from staged.compose (env files hold secrets)."""
    mtime = int(staged.manifest.created_at.timestamp())
    directories = {
        "/".join(parts[:depth])
        for parts in (item.path.split("/") for item in compose.files)
        for depth in range(1, len(parts))
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for directory in sorted(directories):  # a parent sorts before what it holds
            info = tarfile.TarInfo(directory)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, COMPOSE_DIR_MODE, mtime
            tar.addfile(info)
        for item in compose.files:
            data = staged.compose.get(item.member)
            if data is None:
                raise ApplyError(f"The archive's compose file {item.path} was not staged.")
            if len(data) != item.size:
                raise ApplyError(
                    f"The archive's compose file {item.path} does not have the size the "
                    "archive records."
                )
            info = tarfile.TarInfo(item.path)
            info.size, info.mode, info.mtime = len(data), COMPOSE_FILE_MODE, mtime
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def single_file_tar(name: str, data: bytes) -> bytes:
    """A tar holding one regular file, root's and 0600."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), COMPOSE_FILE_MODE
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def root_metadata(step: DataStep, facts: Any) -> tuple[str, str] | None:
    """The archived owner and octal mode of a directory member's top directory, as the
    arguments of ROOT_SCRIPT, or None (a file, or no './' entry recorded)."""
    if step.rename_to or step.kind not in ("volume", "bind-dir"):
        return None
    values = (facts.root_uid, facts.root_gid, facts.root_mode)
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in values):
        return None
    uid, gid, mode = values
    return f"{uid}:{gid}", f"{mode & 0o7777:o}"


def non_recursive(mount: Mount) -> Mount:
    """A bind mount without the host mounts below its source (API 1.40). A recursive one
    would let data written into the bind directory land in whatever another mount below it
    shows (a bind of /etc at conf, say), which the planner and the host path checks never
    saw; this way it lands in the directory itself."""
    mount["BindOptions"] = {**(mount.get("BindOptions") or {}), "NonRecursive": True}
    return mount


def normalized(path: str) -> str:
    try:
        return hostpaths.normalize(path)
    except HostPathError as exc:
        raise ApplyError(str(exc)) from None


def body_volumes(body: dict[str, Any]) -> list[str]:
    """The named volumes a create body mounts."""
    host = body.get("HostConfig") or {}
    volumes = [
        source
        for source, _, _ in (risk.split_bind(b) for b in host.get("Binds") or [])
        if source and not source.startswith("/")
    ]
    volumes += [
        str(m["Source"])
        for m in host.get("Mounts") or []
        if m.get("Type") == "volume" and m.get("Source")
    ]
    return sorted(set(volumes))


def wait_for_exit(api, container_id: str, cancel: threading.Event) -> int:
    """The exit code of a started helper. Waits in WAIT_POLL slices, so no request idles
    long enough for the socket proxy to cut it; a read timeout means it still runs."""
    while True:
        if cancel.is_set():
            raise Cancelled(CANCELLED)
        try:
            result = api.wait(container_id, timeout=WAIT_POLL, condition="not-running")
        except requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError:
            state = api.inspect_container(container_id).get("State") or {}
            if not state.get("Running") and state.get("Status") in ("exited", "dead"):
                return int(state.get("ExitCode", -1))
            continue
        code = result.get("StatusCode") if isinstance(result, dict) else None
        return code if isinstance(code, int) else -1


def remove_original(
    api,
    original: dict[str, Any],
    log: Callable[[str], None],
    *,
    strict: bool,
    failed: Callable[[BaseException], None] | None = None,
) -> bool:
    """Removes an original renamed to its old name (volumes kept). Never raises. Returns
    False when it is still there: the removal failed (failed is called with the error), or
    (strict) it no longer has its old name. A missing original counts as removed."""
    container_id, old_name = original.get("id"), original.get("old_name")
    if not isinstance(container_id, str):
        return True
    try:
        info = api.inspect_container(container_id)
        if str(info.get("Name") or "").lstrip("/") != old_name or info.get("Id") != container_id:
            if strict:
                log(f"Could not remove {old_name}; remove it by hand.")
            return not strict
        api.remove_container(container_id, force=True, v=False)
        return True
    except docker.errors.NotFound:
        return True
    except DOCKER_ERRORS as exc:
        log(f"Could not remove {old_name}; remove it by hand. {error_text(exc)}")
        if failed is not None:
            failed(exc)
        return False


def error_text(exc: BaseException) -> str:
    if isinstance(exc, docker.errors.APIError):
        return explain(exc)
    return str(exc)[:MAX_MESSAGE]


def unreachable(exc: BaseException) -> bool:
    """Whether a call failed because Docker could not be reached (the SSH tunnel or the
    socket proxy is down), not because the daemon refused it: trying again later helps."""
    if isinstance(exc, docker.errors.APIError):
        return exc.status_code in GATEWAY_ERRORS
    return isinstance(exc, requests.RequestException)


# ROLLBACK


def rollback(api: Any, doc: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
    """Undoes what the journal records. Never raises; returns the updated journal.

    Committed: only the removal of the originals still named '<name>-drydock-old' is
    finished; the restored containers stay. Otherwise the created containers, networks and
    volumes are removed (each only with this run's label), the originals get their names
    back, the tags the restore moved point back at their earlier images and, if no data was
    touched yet, the originals get their restart policies back and the running ones start
    again; else every original is stopped (a restart policy or a daemon restart may have
    started one) and keeps its restart policy turned off.

    rolled_back is set only when all of it was done. Run it again on its own result while
    rollback_unreachable is set: what is done already is skipped.
    """
    doc = copy.deepcopy(doc) if isinstance(doc, dict) else {}
    for key in ("rollback_incomplete", "rollback_unreachable"):
        doc.pop(key, None)
    undo = Rollback(api, doc, log)
    try:
        if doc.get("committed"):
            undo.finish_commit()
        else:
            undo.run()
    except Exception:
        logger.exception("The rollback of a restore failed")
        log("The rollback could not finish; check the host by hand.")
        undo.fail()
    doc["rolled_back"] = not undo.failed
    if undo.failed:
        doc["rollback_incomplete"] = True
    if undo.unreachable:
        doc["rollback_unreachable"] = True
    return doc


def entries(doc: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = doc.get(key)
    return [e for e in value if isinstance(e, dict)] if isinstance(value, list) else []


def listed(doc: dict[str, Any], key: str) -> list[str]:
    value = doc.get(key)
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


MISSING = object()  # what Rollback.attempt returns when Docker has no such object


class Rollback:
    def __init__(self, api, doc: dict[str, Any], log: Callable[[str], None]) -> None:
        self.api = api
        self.doc = doc
        self.log = log
        run_id = doc.get("run_id")
        valid = isinstance(run_id, int) and not isinstance(run_id, bool)
        self.run_label = str(run_id) if valid else None
        self.originals = entries(doc, "originals")
        self.failed = False  # something is not undone
        self.unreachable = False  # a call could not reach Docker: trying again may help
        self.leftover: list[str] = []
        self.not_renamed: list[str] = []
        self.tags_left: list[str] = []
        self.renamed: set[str] = set()  # IDs of the originals that have their names back

    def ours(self, info: dict[str, Any]) -> bool:
        labels = (info.get("Config") or {}).get("Labels") or info.get("Labels") or {}
        return self.run_label is not None and labels.get(RESTORE_LABEL) == self.run_label

    def fail(self, exc: BaseException | None = None) -> None:
        self.failed = True
        if exc is not None and unreachable(exc):
            self.unreachable = True

    def attempt(self, what: str, call: Callable[[], Any]) -> Any:
        """The call's result; MISSING when Docker has no such object; None when it failed
        (logged, and the rollback is incomplete)."""
        try:
            return call()
        except docker.errors.NotFound:
            return MISSING
        except DOCKER_ERRORS as exc:
            self.log(f"Could not {what}: {error_text(exc)}")
            self.fail(exc)
            return None

    def left(self, what: str) -> None:
        self.failed = True
        if what not in self.leftover:
            self.leftover.append(what)

    def finish_commit(self) -> None:
        leftover = []
        if self.originals:
            self.log("Finishing the removal of the original containers.")
        for original in self.originals:
            if not remove_original(self.api, original, self.log, strict=False, failed=self.fail):
                leftover.append(original.get("old_name"))
        self.doc["leftover"] = leftover

    def run(self) -> None:
        self.remove_containers()
        self.rename_originals()
        self.remove_networks()
        self.remove_volumes()
        self.restore_tags()
        if not self.doc.get("wipe_started") and not self.doc.get("data_started"):
            self.restore_policies()
            self.start_originals()
        else:
            self.stop_originals()
            items = [f"volume {v}" for v in dict.fromkeys(listed(self.doc, "volumes"))]
            items += [f"bind mount {b}" for b in dict.fromkeys(listed(self.doc, "binds"))]
            if items:
                self.log(
                    f"The data in {', '.join(items)} may be partial. The original containers "
                    "were left stopped."
                )
            for original in self.originals:
                policy = original.get("restart_policy")
                if isinstance(policy, dict) and policy.get("Name"):
                    self.log(
                        f"Container {original.get('name')} keeps its restart policy turned off "
                        f"while its data may be partial; set it back to {policy['Name']} once "
                        "the data is right."
                    )
        self.doc["leftover"] = self.leftover
        self.doc["not_renamed"] = self.not_renamed
        self.doc["tags_left"] = self.tags_left

    def remove_containers(self) -> None:
        original_ids = {o.get("id") for o in self.originals}
        for entry in reversed(entries(self.doc, "created")):
            name, container_id = entry.get("name"), entry.get("id")
            if entry.get("failed") or not isinstance(name, str):
                continue
            ref = container_id if isinstance(container_id, str) else name
            info = self.attempt(
                f"inspect container {name}", lambda r=ref: self.api.inspect_container(r)
            )
            if info is None:
                self.left(f"container {name}")
            if not isinstance(info, dict):
                continue
            if isinstance(container_id, str):
                if info.get("Id") != container_id:
                    continue
            elif str(info.get("Name") or "").lstrip("/") != name:
                continue  # Docker matched an ID prefix, not the name
            if not self.ours(info) or info.get("Id") in original_ids:
                continue
            removed = self.attempt(
                f"remove container {name}",
                lambda i=info["Id"]: self.api.remove_container(i, force=True, v=False) or True,
            )
            if removed is None:
                self.left(f"container {name}")
            elif removed is True:
                self.log(f"Removed container {name}.")

    def rename_originals(self) -> None:
        for original in reversed(self.originals):
            container_id, name = original.get("id"), original.get("name")
            if not isinstance(container_id, str) or not isinstance(name, str):
                continue
            old_name = str(original.get("old_name") or container_id[:12])
            info = self.attempt(
                f"inspect container {old_name}",
                lambda c=container_id: self.api.inspect_container(c),
            )
            if info is MISSING:
                self.log(f"Container {old_name} no longer exists, so it cannot get {name} back.")
            if not isinstance(info, dict) or info.get("Id") != container_id:
                self.fail()
                self.not_renamed.append(old_name)
                continue
            if str(info.get("Name") or "").lstrip("/") == name:
                self.renamed.add(container_id)
                continue
            renamed = self.attempt(
                f"rename {old_name} back to {name}",
                lambda c=container_id, n=name: self.api.rename(c, n) or True,
            )
            if renamed is True:
                self.renamed.add(container_id)
                self.log(f"Renamed {old_name} back to {name}.")
            else:
                self.fail()
                self.not_renamed.append(old_name)

    def remove_networks(self) -> None:
        for entry in entries(self.doc, "networks"):
            name, network_id = entry.get("name"), entry.get("id")
            if not isinstance(name, str):
                continue
            ref = network_id if isinstance(network_id, str) else name
            info = self.attempt(
                f"inspect network {name}", lambda r=ref: self.api.inspect_network(r)
            )
            if info is None:
                self.left(f"network {name}")
            if not isinstance(info, dict) or info.get("Name") != name or not self.ours(info):
                continue
            if isinstance(network_id, str) and info.get("Id") != network_id:
                continue
            if info.get("Containers"):
                self.log(f"Kept network {name}: a container uses it.")
                self.left(f"network {name}")
                continue
            removed = self.attempt(
                f"remove network {name}",
                lambda i=info["Id"]: self.api.remove_network(i) or True,
            )
            if removed is None:
                self.left(f"network {name}")
            elif removed is True:
                self.log(f"Removed network {name}.")

    def remove_volumes(self) -> None:
        for name in listed(self.doc, "volumes_created"):
            info = self.attempt(f"inspect volume {name}", lambda n=name: self.api.inspect_volume(n))
            if info is None:
                self.left(f"volume {name}")
            if not isinstance(info, dict) or info.get("Name") != name or not self.ours(info):
                continue
            users = self.attempt(
                f"list the users of volume {name}",
                lambda n=name: self.api.containers(all=True, filters={"volume": n}),
            )
            if not isinstance(users, list) or users:
                self.log(f"Kept volume {name}: a container uses it.")
                self.left(f"volume {name}")
                continue
            removed = self.attempt(
                f"remove volume {name}", lambda n=name: self.api.remove_volume(n) or True
            )
            if removed is None:
                self.left(f"volume {name}")
            elif removed is True:
                self.log(f"Removed volume {name}.")

    def restore_tags(self) -> None:
        """Points each tag the restore set back at the image it named before; one that
        named nothing is removed again (and with it the image, unless something else names
        or uses it). A tag that names neither (moved by someone else since) is left alone."""
        for entry in reversed(entries(self.doc, "tags")):
            ref, previous, image = entry.get("ref"), entry.get("previous"), entry.get("image")
            if not isinstance(ref, str) or not ref:
                continue
            info = self.attempt(f"inspect image {ref}", lambda r=ref: self.api.inspect_image(r))
            if info is None:
                self.tag_left(ref)
                continue
            current = info.get("Id") if isinstance(info, dict) else None
            if current == previous:
                continue
            if isinstance(previous, str) and previous:
                if current is not None and isinstance(image, str) and current != image:
                    self.tag_left(ref)
                    continue
                repository, tag = docker.utils.parse_repository_tag(ref)
                done = self.attempt(
                    f"point {ref} back at its earlier image",
                    lambda i=previous, r=repository, t=tag: self.api.tag(i, r, t) or True,
                )
                if done is True:
                    self.log(f"Pointed {ref} back at its earlier image.")
                else:
                    self.tag_left(ref)
            elif current != image:
                self.tag_left(ref)
            else:
                done = self.attempt(
                    f"remove the tag {ref}",
                    lambda r=ref: self.api.remove_image(r, noprune=True) or True,
                )
                if done is None:
                    self.tag_left(ref)
                elif done is True:
                    self.log(f"Removed the tag {ref}.")

    def tag_left(self, ref: str) -> None:
        self.failed = True
        if ref not in self.tags_left:
            self.tags_left.append(ref)

    def restore_policies(self) -> None:
        """Only for the originals that have their names back: one that does not stays
        stopped, and a daemon restart must not start it next to the restored container."""
        for original in self.originals:
            container_id, policy = original.get("id"), original.get("restart_policy")
            if container_id not in self.renamed or not isinstance(policy, dict):
                continue
            done = self.attempt(
                f"set the restart policy of container {original.get('name')} back",
                lambda c=container_id, p=policy: (
                    self.api.update_container(c, restart_policy=p) or True
                ),
            )
            if done is MISSING:
                self.fail()

    def stop_originals(self) -> None:
        for original in self.originals:
            container_id = original.get("id")
            if not isinstance(container_id, str):
                continue
            info = self.attempt(
                f"inspect container {original.get('old_name')}",
                lambda c=container_id: self.api.inspect_container(c),
            )
            if not isinstance(info, dict) or info.get("Id") != container_id:
                continue  # rename_originals reported it
            if not (info.get("State") or {}).get("Running"):
                continue
            timeout = original.get("stop_timeout")
            if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 0:
                timeout = inventory.DEFAULT_STOP_TIMEOUT
            name = str(info.get("Name") or "").lstrip("/")
            stopped = self.attempt(
                f"stop container {name}",
                lambda c=container_id, t=timeout: self.api.stop(c, timeout=t) or True,
            )
            if stopped is True:
                self.log(f"Stopped container {name}: it had started again.")

    def start_originals(self) -> None:
        add_secrets = getattr(self.log, "add_secrets", None)
        # Journaled in stop order (dependents first): dependencies start first.
        for original in reversed(self.originals):
            container_id, name = original.get("id"), original.get("name")
            if not original.get("running") or not isinstance(container_id, str):
                continue
            # Only an original that got its name back: else a restored container that could
            # not be removed may still hold the name, and both would run on the same data.
            if container_id not in self.renamed:
                self.log(
                    f"Left container {original.get('old_name')} stopped: it did not get its "
                    f"name {name} back."
                )
                continue
            info = self.attempt(
                f"inspect container {name}", lambda c=container_id: self.api.inspect_container(c)
            )
            if not isinstance(info, dict) or info.get("Id") != container_id:
                self.fail()
                continue
            # Docker's error text is not trusted to leave the container's secrets out.
            if callable(add_secrets):
                add_secrets(env_values((info.get("Config") or {}).get("Env")))
            started = self.attempt(
                f"start container {name} again",
                lambda c=container_id: self.api.start(c) or True,
            )
            if started is True:
                self.log(f"Started container {name} again.")
            else:
                self.fail()
