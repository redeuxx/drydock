"""Mounts a job skips: their keys, and the choices the job form offers.

A key is "bind:<host path>" or "volume:<volume name>". Capture leaves out the data of the
mounts a key names (engine.capture.skip_mounts); the containers still mount them, so a
restore recreates the mount and writes nothing into it.
"""

import json
import posixpath
import re
from dataclasses import dataclass

from drydock.hosts.inventory import ProjectGroup

MAX_SKIPS = 64
MAX_KEY = 1024
# Docker's own rule for volume names.
VOLUME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def key_error(key: str) -> str | None:
    """Why key cannot be stored, or None."""
    kind, _, value = key.partition(":")
    if len(key) > MAX_KEY or CONTROL_RE.search(key):
        return "A skipped mount is too long or holds control characters."
    if kind == "bind":
        if (
            not value.startswith("/")
            or posixpath.normpath(value) != value
            or value.startswith("//")
        ):
            return f"Skipped bind mount {value!r} is not a normalized absolute path."
        return None
    if kind == "volume":
        return (
            None
            if VOLUME_RE.fullmatch(value)
            else f"Skipped volume {value!r} is not a volume name."
        )
    return "A skipped mount must be a bind mount or a volume."


def check(keys: list[str]) -> tuple[list[str], str | None]:
    """The keys as stored (sorted, without duplicates), or the first error."""
    unique = sorted(set(keys))
    if len(unique) > MAX_SKIPS:
        return unique, f"A job skips at most {MAX_SKIPS} mounts."
    for key in unique:
        if error := key_error(key):
            return unique, error
    return unique, None


def stored(text: str | None) -> frozenset[str]:
    """A job's stored keys. Anything that is not a list of valid keys skips nothing, so a
    damaged value never leaves data out."""
    try:
        value = json.loads(text or "[]")
    except ValueError:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(k, str) for k in value):
        return frozenset()
    return frozenset(k for k in value if key_error(k) is None)


def label(key: str) -> str:
    kind, _, value = key.partition(":")
    return f"{'bind mount' if kind == 'bind' else 'volume'} {value}"


@dataclass(frozen=True)
class Choice:
    key: str
    kind: str  # bind or volume
    source: str  # host path or volume name
    used_by: tuple[str, ...]  # "container:destination"


def choices(groups: list[ProjectGroup], target_type: str, target: str) -> list[Choice] | None:
    """The bind mounts and volumes of the job's target in the inventory, or None when the
    target is not there (a stopped stack lists its containers too; a typo does not)."""
    if target_type == "stack":
        containers = [c for g in groups if g.project == target for c in g.containers]
    else:
        containers = [
            c
            for g in groups
            for c in g.containers
            if target in (c.name, c.id) or (len(target) >= 12 and c.id.startswith(target))
        ]
    if not containers:
        return None
    found: dict[str, tuple[str, str, list[str]]] = {}
    for container in containers:
        for mount in container.mounts:
            if mount.type == "bind" and mount.source:
                key = f"bind:{mount.source}"
                source = mount.source
            elif mount.type == "volume" and mount.name:
                key = f"volume:{mount.name}"
                source = mount.name
            else:
                continue  # tmpfs is never backed up anyway
            found.setdefault(key, (mount.type, source, []))[2].append(
                f"{container.name}:{mount.destination}"
            )
    return [
        Choice(key, kind, source, tuple(users))
        for key, (kind, source, users) in sorted(found.items())
        if key_error(key) is None
    ]
