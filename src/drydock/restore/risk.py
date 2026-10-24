"""Risk flags: the fields of a restore that only a superadmin may accept.

A flag is raised for every create-body field that gives a container power over its host
(privileges, devices, host namespaces, security profiles, runtimes, sysctls, cgroup
placement, OOM-killer exemptions, volume drivers, propagating binds, and binds of anything
outside the data trees in SAFE_BIND_TREES or of a data tree's root itself) and for references
to containers this restore does not create. The planner adds flags for volume and network
drivers, image tag moves, setuid or capability files in bind data and bind writes to
another host, a remapped path or a path outside SAFE_BIND_TREES.

SAFE_BIND_TREES is broader than a list of system paths on purpose: a bind of /opt, /usr,
/var/spool or /var/www is as much a way onto the host as /etc, so only binds inside the
usual data trees go unflagged.

A signed archive only proves that this drydock wrote it, and admins can register hosts and
create jobs, so every flag needs a superadmin, a per-field acknowledgement and recent
authentication, signed or not.

Keys are stable across planning and execution: f'{container}:{field}' for container
fields (bind flags add the source, so remapping a bind drops its flag), and
'volume:{name}:driver', 'network:{name}:driver', 'image:{ref}:tag',
'bind-data:{n}:setid', 'volume-data:{name}:setid' and 'bind-write:{path}' for the planner's own.

Pure: no I/O.
"""

import json
import posixpath
from dataclasses import dataclass
from typing import Any

from drydock.engine.compose_files import under

HOST_MODES = ("PidMode", "IpcMode", "NetworkMode", "UsernsMode", "UTSMode", "CgroupnsMode")
CONTAINER_MODES = ("NetworkMode", "PidMode", "IpcMode")
LISTED_FIELDS = ("CapAdd", "Devices", "DeviceCgroupRules", "DeviceRequests")
NO_NEW_PRIVILEGES = "no-new-privileges"
# The values Go's strconv.ParseBool reads as true, which is how moby reads this option.
TRUE_VALUES = ("1", "t", "T", "TRUE", "true", "True")
SAFE_RUNTIMES = ("", "runc")
PROPAGATING = ("shared", "rshared")
# Binds of anything outside these trees are flagged: /usr, /opt, /var/spool, /run and the
# rest of the system give host root as surely as /etc does. The root of each tree (/mnt holds
# every mounted disk, /srv every application's data) is flagged too, and inside /home, a
# home directory itself, anything hidden (.ssh, .bashrc, .config) and ~/bin, which Debian
# and Ubuntu put on every login's PATH.
SAFE_BIND_TREES = ("/srv", "/mnt", "/media", "/data", "/home")
HOME_SENSITIVE = ("bin",)
SAFE_VOLUME_DRIVERS = ("", "local")
MAX_VALUE = 200  # characters of a field value shown next to its checkbox


@dataclass(frozen=True)
class RiskFlag:
    key: str
    subject: str
    field: str
    value: str


def describe(value: Any) -> str:
    if isinstance(value, list):
        text = ", ".join(v if isinstance(v, str) else json.dumps(v, sort_keys=True) for v in value)
    elif isinstance(value, dict):
        text = ", ".join(f"{k}={v}" for k, v in sorted(value.items()))
    else:
        text = str(value)
    return text if len(text) <= MAX_VALUE else text[: MAX_VALUE - 3] + "..."


def split_bind(entry: str) -> tuple[str, str, str]:
    """A HostConfig.Binds entry 'src:dst[:opts]' as (src, dst, opts)."""
    parts = entry.split(":", 2)
    return parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else ""


def bind_sources(body: dict[str, Any]) -> list[str]:
    """The host paths a create body binds: absolute Binds sources and Mounts of type bind."""
    host = body.get("HostConfig") or {}
    sources = [
        src for src, _, _ in (split_bind(b) for b in host.get("Binds") or []) if src.startswith("/")
    ]
    sources += [
        str(m.get("Source") or "") for m in host.get("Mounts") or [] if m.get("Type") == "bind"
    ]
    return sources


def propagating_sources(host: dict[str, Any]) -> list[str]:
    found = []
    for entry in host.get("Binds") or []:
        src, _, opts = split_bind(entry)
        if src.startswith("/") and set(opts.split(",")) & set(PROPAGATING):
            found.append(src)
    for mount in host.get("Mounts") or []:
        propagation = (mount.get("BindOptions") or {}).get("Propagation")
        if mount.get("Type") == "bind" and propagation in PROPAGATING:
            found.append(str(mount.get("Source") or ""))
    return found


def safe_security_opt(option: str) -> bool:
    """Whether a SecurityOpt entry only turns no-new-privileges on. moby takes it bare or
    as key=value (key:value is its deprecated form). Turning it off is flagged: that undoes
    a daemon that sets it by default."""
    if option == NO_NEW_PRIVILEGES:
        return True
    key, _, value = option.partition("=" if "=" in option else ":")
    return key == NO_NEW_PRIVILEGES and value in TRUE_VALUES


def sensitive(source: str) -> bool:
    """Whether binding or writing this host path needs a superadmin. Lexical: apply runs
    plan.resolved_problems on the paths Docker resolves, which refuses a path that only a
    symbolic link makes sensitive."""
    path = "/" + posixpath.normpath(source).lstrip("/") if source else "/"
    parts = path.split("/")
    if path in SAFE_BIND_TREES or not under(path, SAFE_BIND_TREES) or path.endswith(".sock"):
        return True
    return parts[1] == "home" and (
        len(parts) <= 3 or parts[3] in HOME_SENSITIVE or any(p.startswith(".") for p in parts)
    )


def flags(
    container: str, body: dict[str, Any], created: frozenset[str] = frozenset()
) -> list[RiskFlag]:
    """The risk flags of one final create body. created: the names of the containers this
    restore creates, which container:X and VolumesFrom may refer to unflagged."""
    host = body.get("HostConfig") or {}
    found: list[RiskFlag] = []

    def add(field: str, value: Any, key: str | None = None) -> None:
        found.append(RiskFlag(key or f"{container}:{field}", container, field, describe(value)))

    if host.get("Privileged"):
        add("Privileged", "true")
    for field in LISTED_FIELDS:
        if host.get(field):
            add(field, host[field])
    for field in HOST_MODES:
        if host.get(field) == "host":
            add(field, "host")
    security = [o for o in host.get("SecurityOpt") or [] if not safe_security_opt(o)]
    if security:
        add("SecurityOpt", security)
    runtime = host.get("Runtime") or ""
    if runtime not in SAFE_RUNTIMES:
        add("Runtime", runtime)
    if host.get("Sysctls"):
        add("Sysctls", host["Sysctls"])
    # A cgroup outside Docker's escapes its limits; a negative OOM score or a disabled OOM
    # killer makes the kernel kill host processes (sshd) first.
    if host.get("CgroupParent"):
        add("CgroupParent", host["CgroupParent"])
    oom_score = host.get("OomScoreAdj")
    if isinstance(oom_score, int | float) and oom_score < 0:
        add("OomScoreAdj", oom_score)
    if host.get("OomKillDisable"):
        add("OomKillDisable", "true")
    # The driver of the volumes Docker creates for this container by itself.
    volume_driver = host.get("VolumeDriver") or ""
    if volume_driver not in SAFE_VOLUME_DRIVERS:
        add("VolumeDriver", volume_driver)
    for source in propagating_sources(host):
        add("propagation", f"{source} (shared)", f"{container}:propagation:{source}")
    for source in bind_sources(body):
        if sensitive(source):
            add("bind", source, f"{container}:bind:{source}")
    for field in CONTAINER_MODES:
        mode = host.get(field)
        if (
            isinstance(mode, str)
            and mode.startswith("container:")
            and mode.removeprefix("container:") not in created
        ):
            add(field, mode)
    outside = [
        entry
        for entry in host.get("VolumesFrom") or []
        if str(entry).split(":", 1)[0] not in created
    ]
    if outside:
        add("VolumesFrom", outside)
    return found
