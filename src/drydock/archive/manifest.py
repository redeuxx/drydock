"""The archive manifest (manifest.json, always the first member).

Strict: unknown fields are rejected, so a restore never acts on data it does not
understand. Bump SCHEMA_VERSION for any incompatible change. Fields added with defaults
keep older v1 archives readable.
"""

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
CHECKSUMS_NAME = "checksums.json"
# Inner member names are built by drydock from IDs, Docker volume names and counters.
MEMBER_RE = re.compile(
    r"config/(containers|networks|volumes|images)/[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\.json"
    r"|compose/\d{1,6}/[A-Za-z0-9._-]{1,255}"
    r"|volumes/[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\.tar"
    r"|binds/\d{1,6}\.tar"
    r"|images/[0-9a-f]{64}\.tar"
)
Scope = Literal["config", "data", "image", "all"]
ConsistencyMode = Literal["stop", "pause", "live"]
TargetType = Literal["container", "stack"]


def member_rank(name: str) -> int:
    """Members must appear in non-decreasing rank."""
    if name == MANIFEST_NAME:
        return 0
    if name.startswith(("config/", "compose/")):
        return 1
    if name.startswith(("volumes/", "binds/", "images/")):
        return 2
    if name == CHECKSUMS_NAME:
        return 3
    raise ValueError(f"unexpected member {name!r}")


def valid_member(name: str) -> bool:
    if not MEMBER_RE.fullmatch(name):
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Source(Strict):
    host_name: str
    arch: str
    os: str
    api_version: str
    engine_version: str


class JobInfo(Strict):
    uuid: str
    name: str
    scope: Scope
    consistency_mode: ConsistencyMode
    images_reference_only_if_pullable: bool
    target_type: TargetType = "container"
    project: str | None = None  # the Compose project of a stack job


class ContainerEntry(Strict):
    id: str
    name: str
    image: str  # Config.Image as the container was created
    image_id: str
    compose_project: str | None = None
    compose_service: str | None = None
    config_member: str | None = None


class NetworkEntry(Strict):
    id: str
    name: str
    driver: str
    config_member: str | None = None


class MountRef(Strict):
    container: str  # container ID
    destination: str
    read_only: bool


class VolumeEntry(Strict):
    name: str
    driver: str
    mounts: list[MountRef]
    config_member: str | None = None
    data_member: str | None = None  # volumes/<name>.tar, members named "./..."
    skipped: str | None = None  # why the data was not captured (the job skips it)


class BindEntry(Strict):
    n: int
    source: str  # host path
    kind: Literal["dir", "file"] | None = None  # known only when the data was captured
    mounts: list[MountRef]
    # binds/<n>.tar. A dir bind's members are "./..."; a file bind holds one member "b<n>".
    data_member: str | None = None
    skipped: str | None = None  # why the data was not captured (a system path, or the job)
    # A directory the job skips: its owner and mode (no setuid bit), so a restore can
    # create it where it is missing.
    uid: int | None = Field(default=None, ge=0, le=0xFFFFFFFE)
    gid: int | None = Field(default=None, ge=0, le=0xFFFFFFFE)
    mode: int | None = Field(default=None, ge=0, le=0o3777)


class ImageEntry(Strict):
    id: str
    refs: list[str]  # names the image was saved or referenced under
    repo_digests: list[str]
    os: str
    architecture: str
    variant: str | None = None
    saved: bool
    # The RepoDigest the registry confirmed (GET /distribution) when the image is stored by
    # reference only; a restore pulls exactly this.
    confirmed_digest: str | None = None
    config_member: str | None = None
    data_member: str | None = None  # images/<id>.tar, in docker save format


class ComposeFile(Strict):
    n: int
    role: Literal["config_file", "environment_file", "dotenv", "env_file"]
    host_path: str
    member: str
    size: int


class SkippedFile(Strict):
    role: str
    host_path: str
    reason: str


class TmpfsMount(Strict):
    container: str
    destination: str


class Encryption(Strict):
    method: Literal["age-scrypt"]
    # The passphrase is derived from the secret key and the job UUID (crypto.job_passphrase).
    derivation: Literal["hkdf-job-uuid"]


class Manifest(Strict):
    schema_version: Literal[1] = SCHEMA_VERSION
    instance_id: str
    drydock_version: str
    created_at: datetime
    source: Source
    job: JobInfo
    containers: list[ContainerEntry]
    networks: list[NetworkEntry] = Field(default_factory=list)
    volumes: list[VolumeEntry] = Field(default_factory=list)
    binds: list[BindEntry] = Field(default_factory=list)
    images: list[ImageEntry] = Field(default_factory=list)
    compose_files: list[ComposeFile] = Field(default_factory=list)
    skipped_compose_files: list[SkippedFile] = Field(default_factory=list)
    skipped_tmpfs: list[TmpfsMount] = Field(default_factory=list)
    encryption: Encryption | None = None
    # Every member between manifest.json and checksums.json, in archive order.
    members: list[str]

    @field_validator("members")
    @classmethod
    def check_members(cls, members: list[str]) -> list[str]:
        if len(set(members)) != len(members):
            raise ValueError("duplicate member names")
        ranks = [member_rank(m) if valid_member(m) else -1 for m in members]
        if any(rank not in (1, 2) for rank in ranks) or ranks != sorted(ranks):
            raise ValueError("invalid member list")
        return members

    @model_validator(mode="after")
    def check_references(self) -> Manifest:
        referenced = [
            member
            for entries in (self.containers, self.networks, self.volumes, self.binds, self.images)
            for entry in entries
            for member in (
                getattr(entry, "config_member", None),
                getattr(entry, "data_member", None),
            )
            if member is not None
        ] + [f.member for f in self.compose_files]
        if len(set(referenced)) != len(referenced) or set(referenced) != set(self.members):
            raise ValueError("members do not match the entries that reference them")
        return self

    def to_json(self) -> bytes:
        return self.model_dump_json(indent=2).encode()
