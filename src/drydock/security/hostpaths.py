"""The host-path denylist for restores.

It applies to every role, superadmin included: no acknowledgement or recent
authentication lifts it. A restore checks every host path twice, lexically when it plans
(normalize, check_bind, check_write_target) and again at apply time on the path as
Docker resolves it (resolve, then the same checks), right before the mount that uses it.

- check_bind: what a restored container may bind-mount. The host root, the directories
  that hold every runtime socket (/run, /var/run, rootless daemons' /run/user) and the
  state of every container runtime are refused, as is any file named like a runtime
  socket.
- check_write_target: where drydock may write or wipe restored data. Stricter: no system
  configuration, no binaries or libraries (/usr, /bin, /sbin, /lib*) and no home
  directory root.

A volume of the local driver with a device and o=bind (or type none or bind) is a bind of
that device (host_volume_device), so the same checks apply to it. Any other local volume
that mounts something (overlay names host directories in o=, ext4 or xfs mount a host block
device) is refused outright (check_volume), except tmpfs and network shares.

Pure: no I/O. resolve() takes the lstat it walks with as a function.
"""

import posixpath
import re
from collections import deque
from collections.abc import Callable

from drydock.engine.compose_files import under

CREATE_DENIED_EXACT = ("/", "/etc", "/run", "/var/run", "/var", "/var/lib")
# Runtime state and sockets: /run/user/<uid> holds a rootless daemon's docker.sock.
RUNTIME_TREES = ("docker", "containerd", "podman", "crio", "k3s", "buildkit", "user")
CREATE_DENIED_TREES = (
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    *(f"{run}/{name}" for run in ("/run", "/var/run") for name in RUNTIME_TREES),
    "/var/lib/docker",
    "/var/lib/containerd",
    # podman and cri-o storage, k3s and kubelet state (cluster tokens), buildkitd state.
    "/var/lib/containers",
    "/var/lib/rancher",
    "/var/lib/kubelet",
    "/var/lib/buildkit",
    # Cluster admin credentials: k3s.yaml, kubeadm's admin.conf.
    "/etc/rancher",
    "/etc/kubernetes",
)
SOCKET_NAMES = (
    "docker.sock",
    "containerd.sock",
    "podman.sock",
    "crio.sock",
    "cri-dockerd.sock",
    "buildkitd.sock",
)
# On ostree hosts (Fedora CoreOS, Silverblue) /home, /root and /usr/local are symbolic links
# into /var, and /sysroot (with its alias /ostree) holds every deployment's /etc and /var.
# A path entered as its real location resolves to itself, so the real locations are listed.
WRITE_DENIED_EXACT = ("/", "/home", "/var", "/var/lib", "/var/home")
# /bin, /sbin and /lib are real directories on hosts without a merged /usr.
SYSTEM_TREES = ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
OSTREE_TREES = ("/var/roothome", "/var/usrlocal", "/sysroot", "/ostree")
WRITE_DENIED_TREES = (
    *CREATE_DENIED_TREES,
    *SYSTEM_TREES,
    *OSTREE_TREES,
    "/etc",
    "/usr",
    "/root",
    "/run",
    "/var/run",
)
MAX_PATH = 4096
MAX_LINKS = 40  # Linux's own limit on symbolic links followed in one lookup
# Local volume types that mount no host path: memory and network filesystems.
NETWORK_VOLUME_TYPES = ("nfs", "nfs4", "cifs", "smb3")
LOCAL_VOLUME_TYPES = ("tmpfs", *NETWORK_VOLUME_TYPES)
# ':' separates a Binds entry's fields, so no bind source can hold it.
REFUSED_CHARACTERS = re.compile(r"[\x00-\x1f\x7f:]")

# ('dir' | 'file', None), ('link', target), or None when the path does not exist.
Lstat = Callable[[str], tuple[str, str | None] | None]


class HostPathError(ValueError):
    """A host path is refused. The message is safe to show."""


def normalize(path: str) -> str:
    """The lexically normalized absolute path. A '..' component is refused, never resolved:
    it would mean something else once a symlink is involved."""
    if not isinstance(path, str):
        raise HostPathError("A host path must be text.")
    if not path or len(path) > MAX_PATH or REFUSED_CHARACTERS.search(path):
        raise HostPathError("A host path must be a valid path, without ':' or control characters.")
    if not path.startswith("/"):
        raise HostPathError(f"Host path {path} must be absolute.")
    if ".." in path.split("/"):
        raise HostPathError(f"Host path {path} may not contain ..")
    normalized = posixpath.normpath(path)
    # POSIX keeps exactly two leading slashes; Linux treats them as one.
    return "/" + normalized.lstrip("/")


def within(path: str, tree: str) -> bool:
    """Whether a normalized path is tree or lies under it. '/' holds every path."""
    return tree == "/" or path == tree or path.startswith(tree + "/")


def overlaps(a: str, b: str) -> bool:
    """Whether one normalized path is, or lies under, the other."""
    return within(a, b) or within(b, a)


def denied(path: str, exact: tuple[str, ...], trees: tuple[str, ...]) -> bool:
    return path in exact or under(path, trees) or posixpath.basename(path) in SOCKET_NAMES


def check_bind(path: str) -> str:
    """The normalized path, if a restored container may bind-mount it."""
    normalized = normalize(path)
    if denied(normalized, CREATE_DENIED_EXACT, CREATE_DENIED_TREES):
        raise HostPathError(f"Binding {normalized} is refused for every role.")
    return normalized


def check_write_target(path: str) -> str:
    """The normalized path, if drydock may write restored data into it or wipe it."""
    normalized = normalize(path)
    if denied(normalized, WRITE_DENIED_EXACT, WRITE_DENIED_TREES):
        raise HostPathError(f"Drydock never writes to {normalized}.")
    return normalized


def resolve(path: str, lstat: Lstat) -> str:
    """The path with every symbolic link resolved, like realpath on the host.

    lstat(p) describes one absolute, already resolved path. From the first component that
    does not exist on, the rest of the path is appended without lookups. Link text may hold
    '..' (resolved against the walk, as the kernel does); the path itself may not.
    """
    pending = deque(part for part in normalize(path).split("/") if part)
    current = "/"
    links = 0
    missing = False
    while pending:
        part = pending.popleft()
        if part == ".":
            continue
        if part == "..":
            current = posixpath.dirname(current)
            continue
        candidate = posixpath.join(current, part)
        found = None if missing else lstat(candidate)
        if found is None:
            missing = True
            current = candidate
            continue
        kind, target = found
        if kind == "link":
            links += 1
            if links > MAX_LINKS:
                raise HostPathError(f"Host path {path} has too many symbolic links.")
            if not isinstance(target, str) or not target or "\0" in target:
                raise HostPathError(f"Host path {path} has an invalid symbolic link.")
            if len(target) > MAX_PATH:
                raise HostPathError(f"Host path {path} has an invalid symbolic link.")
            if target.startswith("/"):
                current = "/"
            pending.extendleft(reversed([p for p in target.split("/") if p]))
            continue
        if kind == "dir" or (kind == "file" and not pending):
            current = candidate
            continue
        if kind == "file":
            raise HostPathError(f"Host path {path} goes through a file, {candidate}.")
        raise HostPathError(f"Host path {path} could not be resolved.")
    if len(current) > MAX_PATH:
        raise HostPathError(f"Host path {path} resolves to a path that is too long.")
    return current


def host_volume_device(driver: str, options: dict | None) -> str | None:
    """The host path a volume binds, or None. The local driver mounts its device option
    with o=bind (or type none or bind) as a plain bind of that host path."""
    if driver != "local" or not isinstance(options, dict):
        return None
    device = options.get("device")
    if not isinstance(device, str) or not device:
        return None
    tokens = {token.strip() for token in str(options.get("o") or "").split(",")}
    if tokens & {"bind", "rbind"} or options.get("type") in ("none", "bind"):
        return device
    return None


def check_volume(driver: str, options: dict | None) -> str | None:
    """The host path a volume binds (host_volume_device), or None. Raises HostPathError for
    a local volume that mounts anything else of the host: overlay takes host directories in
    its o= option and ext4, xfs or btrfs mount a host block device, so only binds, tmpfs and
    network shares pass."""
    device = host_volume_device(driver, options)
    if device is not None or driver != "local" or not isinstance(options, dict):
        return device
    kind = options.get("type")
    if kind in LOCAL_VOLUME_TYPES or (not kind and not options.get("device")):
        return None
    raise HostPathError(
        "A local volume that mounts a device or a filesystem other than a bind, tmpfs or a "
        "network share is refused for every role."
    )
