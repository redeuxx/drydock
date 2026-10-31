"""Restore verification: pass 1 before anything is touched, pass 2 while data is written.

Pass 1 (verify_archive) opens the archive exactly once and binds every read to that one
file descriptor: the format sniff, the age work-factor check, each passphrase attempt and
the verified stream all re-read it from offset 0 through a dup. Whatever happens to the
name in the storage directory meanwhile, the bytes verified are the bytes of the file
first opened, and its fstat identity (device, inode, size, mtime, ctime) is recorded and
checked again on the same descriptor afterwards. In the same single read:
- config/ and compose/ members pass tarfile's data filter, are capped by their declared
  sizes (config/ ones, which are parsed, more tightly), and are staged as Fernet tokens
  (Crypto.encrypt_bytes), so container env values and compose secrets never sit in the
  staging directory in plaintext;
- images/ members are staged as files after their inner tar passes the guard, and the
  names inside (manifest.json, index.json, repositories) must be names the manifest lists;
  each staged file's fstat identity is recorded, and open_staged_image refuses a file
  that changed since;
- volumes/ and binds/ members pass the inner tar guard and are discarded. The guard
  records the facts the planner needs: the root's mode and owner, and whether any file
  is setuid, setgid or carries a file capability.
Every member must be referenced by a manifest entry of the type its prefix names, and is
checked as what that entry restores it as.
Everything goes to $DRYDOCK_STAGING_DIR/restore-<run id>/ (0700, files 0600), named from
the run ID only, and is removed if anything fails. An archive on remote storage is first
downloaded whole into download/ there (Downloaded), and both passes read that copy.

Pass 2 (open_verified) opens the archive once more, again by a single descriptor whose
fstat must match pass 1, and streams the data members in archive order. Every member is
re-hashed against its pass-1 sum and every data member runs through a fresh inner tar
guard, which releases a tar header only after it passed its checks.

InnerTarGuard reads tar headers the way Docker's Go archive/tar does (names with the ustar
prefix, octal or base-256 numbers, PAX records split by their length prefixes), and
refuses anything where the two could disagree.

Blocking. Run on a worker thread.
"""

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import threading
import uuid
from collections.abc import Callable, Iterable, Iterator
from compression import zstd
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal

import pydantic

from drydock.archive.manifest import MANIFEST_NAME, BindEntry, ImageEntry, Manifest, VolumeEntry
from drydock.archive.verify import (
    AGE_MAGIC,
    BLOCK,
    MAX_MANIFEST_BYTES,
    MAX_METADATA_BYTES,
    MAX_PAX_HEADER,
    PAX_KEYS,
    ZSTD_MAGIC,
    HeaderGuard,
    MemberSink,
    NoKeyError,
    Opener,
    TrailerReader,
    VerifyError,
    decrypted,
    hash_member,
    pax_records,
    verify_source,
)
from drydock.archive.writer import (
    CHUNK,
    STAGING,
    Cancelled,
    MemberSum,
    create_new,
    disk_full_is_insufficient_space,
    ensure_space,
    pipe,
)
from drydock.crypto import Crypto, CryptoError
from drydock.engine.compose_files import dotenv_values
from drydock.jobs.runlog import env_values
from drydock.storage.base import StorageBackend, StorageError, check_name, parse_name
from drydock.storage.local import open_regular

RESTORE_DIR_RE = re.compile(r"restore-\d{1,12}")
DOWNLOAD_DIR = "download"  # a remote archive's copy, inside the restore directory
HEAD_BYTES = 2 * 1024 * 1024
FIRST_HEAD_BYTES = 64 * 1024  # what preview reads first
TOO_LARGE = "the manifest is larger than the preview"
MAX_INNER_ENTRIES = 10_000_000
MAX_INNER_LINKS = 1_000_000
MAX_LONG_NAME = 64 * 1024
MAX_STAGED_METADATA = 256 * 1024 * 1024
# load_staged parses every config/ member at once, on each plan page and request, and a
# parsed value takes some 20 times its JSON bytes ("[]," is an empty list), so configs
# are capped by size and by the values they can hold (see json_values).
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_STAGED_CONFIG = 32 * 1024 * 1024
MAX_CONFIG_VALUES = 1_000_000
MAX_IMAGE_META = 1024 * 1024
VERIFIED_NAME = "verified.json"
XATTR_PREFIX = "SCHILY.xattr."
CAPABILITY_XATTR = XATTR_PREFIX + "security.capability"
IMAGE_META_FILES = ("index.json", "manifest.json", "repositories")
CONFIG_PATH_RE = re.compile(r"blobs/sha256/([0-9a-f]{64})|([0-9a-f]{64})\.json")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
PAX_TIME_RE = re.compile(rb"-?(\d{1,19})(\.\d{1,20})?")
INT64_LIMIT = 2**63  # Go's archive/tar fails on any number from here up

GONE = "The verified data of this restore is gone. Start the restore again."
NO_KEY_HERE = (
    "No configured secret key decrypts this archive. If it is from another drydock, enter "
    "its passphrase."
)
NOT_DECRYPTED = "Neither the passphrase entered nor a configured secret key decrypts this archive."
UNUSABLE = "The staging directory is not usable."
CHANGED_SINCE = "The archive changed since it was verified. Start the restore again."
TOO_MUCH_CONFIG = "The archive's configuration is larger than drydock's limit."

Log = Callable[[str], None]
GuardKind = Literal["dir", "file", "image"]


# DIRECTORIES


def check_decrypts(path: Path, crypto: Crypto, name: str, passphrase: str | None) -> None:
    """Fails fast, at age's header and before any output, unless a candidate passphrase
    decrypts the encrypted archive at path. For an upload, which a restore uses up even
    when verification fails. Raises VerifyError or StorageError."""
    with open_regular(path) as handle:
        try:
            with decrypted(
                fd_opener(handle.fileno()),
                candidates(crypto, name, passphrase),
                require_complete=False,
            ):
                pass
        except NoKeyError:
            raise VerifyError(NOT_DECRYPTED if passphrase else NO_KEY_HERE) from None


def candidates(crypto: Crypto, name: str, passphrase: str | None) -> list[str]:
    """The passphrases to try, in the same order in both passes, so the index pass 1
    records still points at the one that worked: the entered one, then this drydock's."""
    derived = crypto.job_passphrases(parse_name(name).job_uuid)
    return [passphrase, *derived] if passphrase else derived


def restore_dir(staging: Path, run_id: int) -> Path:
    return staging / f"restore-{int(run_id)}"


def prepare_staging(staging: Path) -> None:
    """Creates the staging directory if needed (a fresh install has none yet)."""
    try:
        staging.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(staging)
    except OSError:
        raise VerifyError(UNUSABLE) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise VerifyError(UNUSABLE)


@contextlib.contextmanager
def staging_writes() -> Iterator[None]:
    """A full disk is InsufficientSpace; any other failure to write the staging directory
    is VerifyError(UNUSABLE), never blamed on the archive and never a bare OSError."""
    try:
        with disk_full_is_insufficient_space(STAGING):
            yield
    except OSError:
        raise VerifyError(UNUSABLE) from None


def remove_restore_dir(staging: Path, run_id: int) -> None:
    """Removes a run's staged data. Never follows a symlink; a missing directory is fine."""
    path = restore_dir(staging, run_id)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode):
        return
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(path)


class Downloaded:
    """A remote archive as a restore reads it: from its copy in the run's restore directory.

    Pass 1 gives the remote backend, so open downloads the archive there first (verify_archive
    has just made the directory, and removes it, copy and all, if anything fails). Pass 2
    gives none, so open reopens that same copy, whose fstat identity pass 1 recorded."""

    def __init__(
        self,
        dest: Path,
        remote: StorageBackend | None = None,
        cancel: threading.Event | None = None,
        log: Log | None = None,
    ) -> None:
        self.folder = dest / DOWNLOAD_DIR
        self.remote = remote
        self.cancel = cancel or threading.Event()
        self.log = log

    def open(self, name: str) -> BinaryIO:
        check_name(name)
        if self.remote is not None:
            with staging_writes():
                self.folder.mkdir(mode=0o700)
            if self.log is not None:
                self.log(f"Downloading {name} to the staging directory.")
            size = self.remote.get(name, self.folder / name, None, self.cancel)
            if self.log is not None:
                self.log(f"Downloaded {size} bytes.")
        try:
            return open_regular(self.folder / name)
        except StorageError:
            raise VerifyError(GONE) from None


# DATA SHAPES


@dataclass(frozen=True)
class FileIdentity:
    dev: int
    ino: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_fd(cls, fd: int) -> FileIdentity:
        info = os.fstat(fd)
        return cls(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True)
class MemberFacts:
    """What the inner tar of a volume or bind member holds, for the planner and apply."""

    root_mode: int | None
    root_uid: int | None
    root_gid: int | None
    setid: bool  # a setuid or setgid file, or a file capability
    entries: int


@dataclass(frozen=True)
class ImageFacts:
    names: tuple[str, ...]  # the names a load of this tar applies
    ids: tuple[str, ...]  # every image ID a load may produce


@dataclass(frozen=True)
class Verification:
    storage_target_id: int
    archive: str
    identity: FileIdentity
    signed: bool
    encrypted: bool
    passphrase_index: int | None
    members: tuple[MemberSum, ...]  # every member except checksums.json, in order
    data: dict[str, MemberFacts]  # by volumes/ and binds/ member
    images: dict[str, ImageFacts]  # by images/ member
    staged_images: dict[str, FileIdentity]  # by images/ member, the staged file

    def to_json(self) -> bytes:
        document = {
            "storage_target_id": self.storage_target_id,
            "archive": self.archive,
            "identity": dataclasses.asdict(self.identity),
            "signed": self.signed,
            "encrypted": self.encrypted,
            "passphrase_index": self.passphrase_index,
            "members": [m.as_dict() for m in self.members],
            "data": {k: dataclasses.asdict(v) for k, v in self.data.items()},
            "images": {
                k: {"names": list(v.names), "ids": list(v.ids)} for k, v in self.images.items()
            },
            "staged_images": {k: dataclasses.asdict(v) for k, v in self.staged_images.items()},
        }
        return json.dumps(document, sort_keys=True).encode()

    @classmethod
    def from_json(cls, data: bytes | str) -> Verification:
        """Parses to_json() output, checking every type. Raises VerifyError."""
        try:
            doc = typed(json.loads(data), dict)
            return cls(
                storage_target_id=typed(doc["storage_target_id"], int),
                archive=typed(doc["archive"], str),
                identity=file_identity(doc["identity"]),
                signed=typed(doc["signed"], bool),
                encrypted=typed(doc["encrypted"], bool),
                passphrase_index=typed(doc["passphrase_index"], int, optional=True),
                members=tuple(member_sum(m) for m in typed(doc["members"], list)),
                data={typed(k, str): member_facts(v) for k, v in typed(doc["data"], dict).items()},
                images={
                    typed(k, str): ImageFacts(
                        names=tuple(typed(n, str) for n in typed(typed(v, dict)["names"], list)),
                        ids=tuple(typed(i, str) for i in typed(v["ids"], list)),
                    )
                    for k, v in typed(doc["images"], dict).items()
                },
                staged_images={
                    typed(k, str): file_identity(v)
                    for k, v in typed(doc["staged_images"], dict).items()
                },
            )
        except ValueError, KeyError, TypeError:
            raise VerifyError(GONE) from None


def typed[T](value: object, kind: type[T], *, optional: bool = False) -> T:
    """value if it is exactly of kind (a bool is not an int here), else TypeError."""
    if value is None and optional:
        return value  # type: ignore[return-value]
    if type(value) is not kind:
        raise TypeError(kind.__name__)
    return value  # type: ignore[return-value]


def file_identity(value: object) -> FileIdentity:
    item = typed(value, dict)
    return FileIdentity(
        *(typed(item[k], int) for k in ("dev", "ino", "size", "mtime_ns", "ctime_ns"))
    )


def member_sum(value: object) -> MemberSum:
    item = typed(value, dict)
    return MemberSum(typed(item["name"], str), typed(item["size"], int), typed(item["sha256"], str))


def member_facts(value: object) -> MemberFacts:
    item = typed(value, dict)
    return MemberFacts(
        root_mode=typed(item["root_mode"], int, optional=True),
        root_uid=typed(item["root_uid"], int, optional=True),
        root_gid=typed(item["root_gid"], int, optional=True),
        setid=typed(item["setid"], bool),
        entries=typed(item["entries"], int),
    )


@dataclass(frozen=True)
class Staged:
    dest: Path
    manifest: Manifest
    configs: dict[str, dict]  # by config/ member, decrypted
    compose: dict[str, bytes]  # by compose/ member, decrypted
    images: dict[str, Path]  # by images/ member, the staged docker-save tar
    verification: Verification


# PASS 1


def verify_archive(
    storage: StorageBackend,
    storage_target_id: int,
    name: str,
    crypto: Crypto,
    staging: Path,
    run_id: int,
    *,
    cancel: threading.Event,
    log: Log,
    passphrase: str | None = None,
) -> Staged:
    """Verifies the archive name and stages what a restore needs. Raises VerifyError,
    StorageError, Cancelled or InsufficientSpace; nothing is left behind then.

    passphrase is one entered for an archive from another drydock, tried first; this
    drydock's own are re-derived from the job UUID in the name (candidates)."""
    info = parse_name(name)
    passphrases = candidates(crypto, name, passphrase)
    prepare_staging(staging)
    dest = restore_dir(staging, run_id)
    try:
        dest.mkdir(mode=0o700)
    except FileExistsError:
        raise VerifyError("This restore already has verified data.") from None
    except OSError:
        raise VerifyError(UNUSABLE) from None
    try:
        log(f"Verifying {name}.")
        handle = storage.open(name)
        try:
            fd = handle.fileno()
            identity = FileIdentity.from_fd(fd)
            stager = Stager(dest, crypto, cancel)
            try:
                verified = verify_source(
                    fd_opener(fd),
                    crypto,
                    passphrases=passphrases,
                    require_signed=False,
                    cancel=cancel,
                    on_member=stager,
                )
            except NoKeyError:
                if passphrase:
                    raise VerifyError(NOT_DECRYPTED) from None
                raise
            finally:
                stager.discard()
            try:
                named = uuid.UUID(verified.manifest.job.uuid) == info.job_uuid
            except ValueError:
                named = False
            if not named:
                raise VerifyError("The archive's name does not match its manifest.")
            if FileIdentity.from_fd(fd) != identity:
                raise VerifyError("The archive changed while it was being verified.")
        finally:
            handle.close()
        verification = Verification(
            storage_target_id=storage_target_id,
            archive=name,
            identity=identity,
            signed=verified.signed,
            encrypted=verified.encrypted,
            passphrase_index=verified.passphrase_index,
            members=verified.members,
            data=stager.data,
            images=stager.images,
            staged_images=stager.image_files,
        )
        with staging_writes():
            # The archive's own bytes, so load_staged can check them against their sum.
            with create_new(dest / MANIFEST_NAME) as out:
                out.write(verified.manifest_bytes)
            with create_new(dest / VERIFIED_NAME) as out:
                out.write(crypto.encrypt_bytes(verification.to_json()))
        staged = load_staged(dest, crypto)
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    signed = "signed" if verified.signed else "NOT signed by any configured key"
    encrypted = ", encrypted" if verified.encrypted else ""
    log(f"Verified {len(verified.members)} members; the archive is {signed}{encrypted}.")
    return staged


def fd_opener(fd: int) -> Opener:
    """Fresh handles on one open file, each starting at offset 0. They share the offset,
    so only one may be read at a time (verify_source and decrypted keep to that)."""

    def opener() -> BinaryIO:
        os.lseek(fd, 0, os.SEEK_SET)
        return os.fdopen(os.dup(fd), "rb")

    return opener


class Stager:
    """The on_member hook of pass 1: stages metadata and images, checks every inner tar."""

    def __init__(self, dest: Path, crypto: Crypto, cancel: threading.Event | None) -> None:
        self.dest = dest
        self.crypto = crypto
        self.cancel = cancel
        self.metadata_bytes = 0
        self.config_bytes = 0
        self.data: dict[str, MemberFacts] = {}
        self.images: dict[str, ImageFacts] = {}
        self.image_files: dict[str, FileIdentity] = {}
        self._open: list[BinaryIO] = []

    def __call__(self, manifest: Manifest, info: tarfile.TarInfo) -> MemberSink:
        name = info.name
        if name.startswith(("config/", "compose/")):
            if not metadata_referenced(manifest, name):
                raise VerifyError(f"{name} is not described by the manifest.")
            try:
                tarfile.data_filter(info, str(self.dest))
            except tarfile.FilterError:
                raise VerifyError(f"{name} cannot be staged safely.") from None
            config = name.startswith("config/")
            if info.size > (MAX_CONFIG_BYTES if config else MAX_METADATA_BYTES):
                raise VerifyError(f"{name} is too large.")
            self.metadata_bytes += info.size
            self.config_bytes += info.size if config else 0
            if self.metadata_bytes > MAX_STAGED_METADATA or self.config_bytes > MAX_STAGED_CONFIG:
                raise VerifyError(TOO_MUCH_CONFIG)
            return MetadataSink(self, name)
        entry = data_entry(manifest, name)
        if isinstance(entry, ImageEntry):
            return ImageSink(self, name, entry, info.size)
        kind, file_name = guard_kind(entry)
        return GuardSink(self, name, InnerTarGuard(kind, file_name=file_name, label=name))

    def track(self, handle: BinaryIO) -> BinaryIO:
        self._open.append(handle)
        return handle

    def release(self, handle: BinaryIO) -> None:
        self._open.remove(handle)
        handle.close()

    def discard(self) -> None:
        """Closes any staged file left open by a failure."""
        while self._open:
            with contextlib.suppress(OSError):
                self._open.pop().close()


def metadata_referenced(manifest: Manifest, member: str) -> bool:
    """Whether a config/ member is some entry's config_member, or a compose/ member some
    compose file's member."""
    if member.startswith("compose/"):
        return any(f.member == member for f in manifest.compose_files)
    entries = (*manifest.containers, *manifest.networks, *manifest.volumes, *manifest.images)
    return any(e.config_member == member for e in entries)


def data_entry(manifest: Manifest, member: str) -> VolumeEntry | BindEntry | ImageEntry:
    """The entry whose data member this is, of the type its prefix names: a manifest that
    lets, say, a file bind reference a volumes/ member is refused, so every member is
    checked (and later streamed) as what it will be restored as."""
    entries: dict[str, list[VolumeEntry] | list[BindEntry] | list[ImageEntry]] = {
        "volumes/": manifest.volumes,
        "binds/": manifest.binds,
        "images/": manifest.images,
    }
    for prefix, candidates in entries.items():
        if member.startswith(prefix):
            for entry in candidates:
                if entry.data_member == member:
                    return entry
    raise VerifyError(f"{member} is not described by the manifest.")


def guard_kind(entry: VolumeEntry | BindEntry | ImageEntry) -> tuple[GuardKind, str | None]:
    if isinstance(entry, VolumeEntry):
        return "dir", None
    if isinstance(entry, ImageEntry):
        return "image", None
    if entry.kind == "dir":
        return "dir", None
    if entry.kind == "file":
        return "file", f"b{entry.n}"
    raise VerifyError(f"{entry.data_member} has no recorded kind.")


def staged_path(dest: Path, member: str) -> Path:
    """dest / member, creating its parent directories 0700 (mkdir's parents=True would
    give the intermediate ones the default mode)."""
    parent = dest
    for part in member.split("/")[:-1]:
        parent /= part
        with contextlib.suppress(FileExistsError):
            parent.mkdir(mode=0o700)
    return dest / member


class MetadataSink:
    """Buffers a config or compose member and stages it encrypted."""

    def __init__(self, stager: Stager, name: str) -> None:
        self.stager = stager
        self.name = name
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data += data

    def close(self) -> None:
        token = self.stager.crypto.encrypt_bytes(bytes(self.data))
        with staging_writes(), create_new(staged_path(self.stager.dest, self.name)) as out:
            out.write(token)


class ImageSink:
    """Stages an image tar (only bytes the guard released) and records its facts and the
    staged file's identity, so a later change to the file is noticed."""

    def __init__(self, stager: Stager, name: str, entry: ImageEntry, size: int) -> None:
        self.stager = stager
        self.name = name
        self.entry = entry
        self.guard = InnerTarGuard("image", capture=IMAGE_META_FILES, label=name)
        with staging_writes():
            ensure_space(stager.dest, size, STAGING)
            self.out = stager.track(create_new(staged_path(stager.dest, name)))

    def write(self, data: bytes) -> None:
        released = self.guard.feed(data)
        with staging_writes():
            self.out.write(released)

    def close(self) -> None:
        self.guard.close()
        with staging_writes():
            self.out.flush()
            identity = FileIdentity.from_fd(self.out.fileno())
            self.stager.release(self.out)
        self.stager.images[self.name] = image_facts(self.guard.captured, self.entry)
        self.stager.image_files[self.name] = identity


class GuardSink:
    """Checks a volume or bind member's inner tar; the bytes are discarded."""

    def __init__(self, stager: Stager, name: str, guard: InnerTarGuard) -> None:
        self.stager = stager
        self.name = name
        self.guard = guard

    def write(self, data: bytes) -> None:
        self.guard.feed(data)

    def close(self) -> None:
        self.guard.close()
        self.stager.data[self.name] = self.guard.facts()


# IMAGE NAMES


def image_facts(captured: dict[str, bytes], entry: ImageEntry) -> ImageFacts:
    """The names a load of this image tar applies, which must all be names the manifest
    lists for it, and every image ID the load may produce: the ID recorded at capture,
    the config digest (graphdriver store) and the manifest digests (containerd store)."""
    label = entry.refs[0] if entry.refs else entry.id
    names: set[str] = set()
    ids = {entry.id}
    try:
        if "manifest.json" in captured:
            for item in typed(go_json(captured["manifest.json"]), list):
                item = go_fields(item, "Config", "RepoTags")
                match = CONFIG_PATH_RE.fullmatch(typed(item.get("Config"), str))
                if match is None:
                    raise ValueError("Config")
                ids.add(f"sha256:{match[1] or match[2]}")
                names.update(typed(t, str) for t in typed(item.get("RepoTags") or [], list))
        if "index.json" in captured:
            index = go_fields(go_json(captured["index.json"]), "manifests")
            for item in typed(index.get("manifests") or [], list):
                item = go_fields(item, "digest", "annotations")
                digest = typed(item.get("digest"), str)
                if not DIGEST_RE.fullmatch(digest):
                    raise ValueError("digest")
                ids.add(digest)
                annotations = typed(item.get("annotations") or {}, dict)
                name = typed(annotations.get("io.containerd.image.name"), str, optional=True)
                if name is not None:
                    names.add(name)
                ref = typed(
                    annotations.get("org.opencontainers.image.ref.name"), str, optional=True
                )
                if ref is not None and ("/" in ref or ":" in ref):
                    names.add(ref)
        if "repositories" in captured:
            for repo, tags in typed(go_json(captured["repositories"]), dict).items():
                names.update(f"{repo}:{tag}" for tag in typed(tags, dict))
    except ValueError, TypeError:
        raise VerifyError(f"Image {label} in the archive has malformed metadata.") from None
    allowed = {normalize_ref(r) for r in entry.refs if "@" not in r}
    if any(normalize_ref(n) not in allowed for n in names):
        raise VerifyError(f"Image {label} in the archive carries names its manifest does not list.")
    return ImageFacts(names=tuple(sorted(names)), ids=tuple(sorted(ids)))


def go_json(data: bytes) -> object:
    """JSON as Docker's Go loaders read it. Go matches object keys to struct fields
    ignoring case (Unicode folding), so an object with two keys that fold alike is
    refused: Python and Go could pick different ones. UTF-8 only, as Go reads it."""
    return json.loads(data.decode("utf-8"), object_pairs_hook=distinct_keys)


def distinct_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len({key.casefold() for key, _ in pairs}) != len(pairs):
        raise ValueError("keys that differ only in case")
    return dict(pairs)


def go_fields(value: object, *fields: str) -> dict:
    """value as a JSON object decoded into a Go struct with these fields: a key Go would
    match to one of them must be spelled exactly so, or Python would not see what Go
    applies (Go reads "repotags" as RepoTags)."""
    item = typed(value, dict)
    folded = {field.casefold() for field in fields}
    for key in item:
        if key.casefold() in folded and key not in fields:
            raise ValueError(key)
    return item


def normalize_ref(ref: str) -> str:
    """The fully qualified form Docker gives a reference: busybox:1.37 is
    docker.io/library/busybox:1.37, and an untagged name is :latest."""
    name, at, digest = ref.partition("@")
    first, slash, rest = name.partition("/")
    if not slash or (
        not any(c in first for c in ".:") and first != "localhost" and first == first.lower()
    ):
        domain, path = "docker.io", name
    else:
        domain, path = first, rest
    if domain == "index.docker.io":
        domain = "docker.io"
    if domain == "docker.io" and "/" not in path:
        path = f"library/{path}"
    if not at and ":" not in path.rsplit("/", 1)[-1]:
        path += ":latest"
    return f"{domain}/{path}" + (f"@{digest}" if at else "")


# STAGED DATA


def load_staged(dest: Path, crypto: Crypto) -> Staged:
    """Reads back what verify_archive staged (with O_NOFOLLOW), decrypting the metadata.
    Raises VerifyError if any of it is missing or does not match the verification."""
    try:
        verification = Verification.from_json(
            crypto.decrypt_bytes(read_staged(dest, VERIFIED_NAME))
        )
        sums = {m.name: m for m in verification.members}
        raw_manifest = read_staged(dest, MANIFEST_NAME)
        check_sum(raw_manifest, sums.get(MANIFEST_NAME))
        manifest = Manifest.model_validate_json(raw_manifest)
        if [m.name for m in verification.members] != [MANIFEST_NAME, *manifest.members]:
            raise VerifyError(GONE)
        decrypted_members = {}
        for member in manifest.members:
            if member.startswith(("config/", "compose/")):
                data = crypto.decrypt_bytes(read_staged(dest, member))
                check_sum(data, sums[member])
                decrypted_members[member] = data
        images = {}
        for entry in manifest.images:
            if entry.data_member is not None:
                with open_staged(dest, entry.data_member) as handle:
                    staged_image_identity(handle, verification, entry.data_member)
                images[entry.data_member] = dest / entry.data_member
    except OSError, CryptoError, ValueError:
        raise VerifyError(GONE) from None
    config_data = [d for k, d in decrypted_members.items() if k.startswith("config/")]
    if (
        sum(map(len, config_data)) > MAX_STAGED_CONFIG
        or sum(map(json_values, config_data)) > MAX_CONFIG_VALUES
    ):
        raise VerifyError(TOO_MUCH_CONFIG)
    configs = {}
    for member, data in decrypted_members.items():
        if member.startswith("config/"):
            try:
                document = json.loads(data)
            except ValueError:
                document = None
            if not isinstance(document, dict):
                raise VerifyError(f"{member} is not a JSON object.")
            configs[member] = document
    compose = {k: v for k, v in decrypted_members.items() if k.startswith("compose/")}
    return Staged(dest, manifest, configs, compose, images, verification)


def json_values(data: bytes) -> int:
    """An upper bound on the values json.loads builds from data, keys aside: every value
    but the outermost follows a "[", "{" or ",". Strings holding these bytes only raise
    the count."""
    return 1 + data.count(b",") + data.count(b"[") + data.count(b"{")


def check_sum(data: bytes, expected: MemberSum | None) -> None:
    if expected is None or hashlib.sha256(data).hexdigest() != expected.sha256:
        raise VerifyError(GONE)


def open_staged_image(staged: Staged, member: str) -> BinaryIO:
    """The staged docker-save tar of an images/ member, open for docker load. Opened
    without following any symlink, and refused (VerifyError) unless it is still the very
    file pass 1 wrote. Load from this handle, never by path."""
    try:
        handle = open_staged(staged.dest, member)
    except OSError:
        raise VerifyError(GONE) from None
    try:
        staged_image_identity(handle, staged.verification, member)
    except BaseException:
        handle.close()
        raise
    return handle


def staged_image_identity(handle: BinaryIO, verification: Verification, member: str) -> None:
    """Refuses a staged image file that is not the one pass 1 wrote and closed."""
    if FileIdentity.from_fd(handle.fileno()) != verification.staged_images.get(member):
        raise VerifyError(GONE)


def read_staged(dest: Path, member: str) -> bytes:
    with open_staged(dest, member) as handle:
        return handle.read()


def open_staged(dest: Path, member: str) -> BinaryIO:
    """A staged file, opened component by component without following any symlink."""
    parts = member.split("/")
    directory = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(dest, directory)
    try:
        for part in parts[:-1]:
            inner = os.open(part, directory, dir_fd=fd)
            os.close(fd)
            fd = inner
        file_fd = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd
        )
    finally:
        os.close(fd)
    handle = os.fdopen(file_fd, "rb")
    if not stat.S_ISREG(os.fstat(file_fd).st_mode):
        handle.close()
        raise VerifyError(GONE)
    return handle


def secret_values(staged: Staged) -> list[str]:
    """Values to redact from the run log: container env values and env-file values."""
    values: list[str] = []
    for member, config in staged.configs.items():
        if not member.startswith("config/containers/"):
            continue
        settings = config.get("Config")
        env = settings.get("Env") if isinstance(settings, dict) else None
        if isinstance(env, list):
            values += env_values(item for item in env if isinstance(item, str))
    for entry in staged.manifest.compose_files:
        if entry.role != "config_file" and entry.member in staged.compose:
            values += dotenv_values(staged.compose[entry.member])
    return values


# INNER TAR GUARD


@dataclass(frozen=True)
class Header:
    """A ustar header block, read the way Go's archive/tar reads it."""

    kind: bytes
    name: bytes
    linkname: bytes
    mode: int
    uid: int
    gid: int
    size: int
    mtime: int


class InnerTarGuard:
    """Checks a tar stream (a volume, bind or image member) block by block.

    feed() returns the bytes that are safe to forward: regular-file data and zero blocks
    stream through, and a header is released only after its checks pass, together with
    the extension blocks (at most one PAX "x", one GNU "L" and one "K") that precede it.
    The rules:
    - only regular files, directories, symlinks and hard links; never a device node, a
      FIFO, a contiguous file, a global or sparse header, or any other type; non-regular
      entries hold no data;
    - numbers and times Go would refuse (beyond int64, malformed PAX times) are refused;
    - PAX records only from PAX_KEYS or SCHILY.xattr.security.capability (the one xattr
      Docker's archive API emits), each key once and never empty; no empty GNU long name;
    - names (and hard link targets) never empty, absolute or with a ".." component;
      "dir" streams name everything "." or "./..."; in "dir" and "image" streams the root
      is a directory; a "file" stream holds exactly one regular file named file_name;
    - nothing at or under a symlink seen earlier (compared by canonical path, with empty
      and "." components dropped), and no hard link to or through one.
    facts() reports the root's mode and owner and whether any regular file or hard link
    is setuid or setgid, or any entry carries security.capability. capture collects the
    bodies of the named regular files (image metadata), each of which may appear only
    once. rename_to (pass 2, file binds) replaces the one entry's header with one of that
    name, keeping its owner, mode, time and xattr.
    """

    def __init__(
        self,
        kind: GuardKind,
        file_name: str | None = None,
        rename_to: str | None = None,
        capture: Iterable[str] = (),
        *,
        label: str = "The tar stream",
    ) -> None:
        if kind == "file" and not file_name:
            raise ValueError("a file stream needs its file name")
        if rename_to is not None and (
            kind != "file" or rename_to in ("", ".", "..") or "/" in rename_to or "\0" in rename_to
        ):
            raise ValueError("rename_to must be a plain file name, for a file stream")
        self.kind = kind
        self.file_name = file_name
        self.rename_to = rename_to
        self.label = label
        self.captured: dict[str, bytes] = {}
        self._capture = frozenset(capture)
        self._header = bytearray()  # the header block being read
        self._skip = 0  # regular-file data and padding still to stream through
        self._capturing: bytearray | None = None
        self._capture_name = ""
        self._capture_left = 0
        self._held = bytearray()  # extension blocks waiting for their main header
        self._seen_ext: set[bytes] = set()
        self._ext: bytes | None = None  # the extension whose body is being read
        self._ext_body = bytearray()
        self._ext_size = 0
        self._ext_left = 0
        self._pax: dict[str, bytes] | None = None
        self._long_name: bytes | None = None
        self._long_link: bytes | None = None
        self._links: set[bytes] = set()  # digests of canonical symlink paths
        self._ended = False
        self._entries = 0
        self._root: tuple[int, int, int] | None = None
        self._setid = False

    # STREAM

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        view = memoryview(data)
        i = 0
        while i < len(view):
            if self._skip:
                n = min(self._skip, len(view) - i)
                piece = view[i : i + n]
                if self._capturing is not None:
                    take = min(n, self._capture_left)
                    self._capturing += piece[:take]
                    self._capture_left -= take
                    if not self._capture_left:
                        self.captured[self._capture_name] = bytes(self._capturing)
                        self._capturing = None
                out += piece
                self._skip -= n
                i += n
                continue
            if self._ext_left:
                n = min(self._ext_left, len(view) - i)
                piece = view[i : i + n]
                self._held += piece
                want = self._ext_size - len(self._ext_body)
                if want > 0:
                    self._ext_body += piece[:want]
                self._ext_left -= n
                i += n
                if not self._ext_left:
                    self._end_extension()
                continue
            n = min(BLOCK - len(self._header), len(view) - i)
            self._header += view[i : i + n]
            i += n
            if len(self._header) == BLOCK:
                block = bytes(self._header)
                self._header.clear()
                out += self._block(block)
        return bytes(out)

    def close(self) -> bytes:
        """The end checks. Everything safe was already released by feed()."""
        if self._header or self._skip or self._ext is not None or self._held:
            raise VerifyError(f"{self.label} ends in the middle of an entry.")
        if not self._ended:
            raise VerifyError(f"{self.label} has no end-of-archive marker.")
        if self.kind == "file" and self._entries != 1:
            raise VerifyError(f"{self.label} does not hold exactly one file.")
        return b""

    def facts(self) -> MemberFacts:
        mode, uid, gid = self._root if self._root is not None else (None, None, None)
        return MemberFacts(mode, uid, gid, self._setid, self._entries)

    # BLOCKS

    def _fail(self, problem: str) -> VerifyError:
        return VerifyError(f"{self.label} {problem}.")

    def _block(self, block: bytes) -> bytes:
        if block.count(0) == BLOCK:
            if self._held:
                raise self._fail("ends inside an entry")
            self._ended = True
            return block
        if self._ended:
            raise self._fail("holds data after its end-of-archive marker")
        header = self._parse(block)
        if header.kind in (b"x", b"L", b"K"):
            self._start_extension(header)
            self._held += block
            if not self._ext_left:
                self._end_extension()
            return b""
        if header.kind in (b"3", b"4", b"6"):
            raise self._fail("holds a device node or FIFO")
        # Not "7" (contiguous file) either: Docker's extractor refuses it, and containerd's
        # image importer skips it, so it would not be read as the guard reads it.
        if header.kind not in (b"0", b"\0", b"5", b"2", b"1"):
            raise self._fail("holds an unsupported tar entry type")
        return self._main(header, block)

    def _parse(self, block: bytes) -> Header:
        try:
            tarfile.TarInfo.frombuf(block, "utf-8", "surrogateescape")  # checksum, structure
        except tarfile.HeaderError:
            raise self._fail("holds a damaged tar header") from None
        magic = block[257:263]
        if magic == b"ustar\x00" and block[508:512] != b"tar\x00":
            prefix = cstring(block[345:500])
        elif magic == b"ustar " and block[263:265] == b" \x00":
            prefix = b""  # GNU: no prefix field
            # Where atime or ctime does not parse, Go reads bytes 345:500 as a prefix
            # (its pre-1.8 compatibility path), so the name would differ: refuse those.
            # Base-256 times are refused too, since Go fails on some that tar_number reads.
            for field in (block[345:357], block[357:369]):
                try:
                    if field[0] & 0x80:
                        raise ValueError("base-256 time")
                    tar_number(field)
                except ValueError:
                    raise self._fail("holds a tar header in an unsupported format") from None
        else:
            raise self._fail("holds a tar header in an unsupported format")
        name = cstring(block[0:100])
        try:
            return Header(
                kind=block[156:157],
                name=prefix + b"/" + name if prefix else name,
                linkname=cstring(block[157:257]),
                mode=tar_number(block[100:108]),
                uid=tar_number(block[108:116]),
                gid=tar_number(block[116:124]),
                size=tar_number(block[124:136]),
                mtime=tar_number(block[136:148]),
            )
        except ValueError:
            raise self._fail("holds a damaged tar header") from None

    def _start_extension(self, header: Header) -> None:
        if header.kind in self._seen_ext:
            raise self._fail("holds two extended headers of one kind before an entry")
        limit = MAX_PAX_HEADER if header.kind == b"x" else MAX_LONG_NAME
        if header.size > limit:
            raise self._fail("holds an oversized tar extended header")
        self._seen_ext.add(header.kind)
        self._ext = header.kind
        self._ext_body = bytearray()
        self._ext_size = header.size
        self._ext_left = -(-header.size // BLOCK) * BLOCK

    def _end_extension(self) -> None:
        body = bytes(self._ext_body)
        if self._ext == b"x":
            self._pax = self._parse_pax(body)
        else:
            # Go ignores an empty long name and keeps the ustar one, so refuse it rather
            # than check a name Docker does not use.
            long = cstring(body)
            if not long:
                raise self._fail("holds an empty tar long name")
            if self._ext == b"L":
                self._long_name = long
            else:
                self._long_link = long
        self._ext = None
        self._ext_body = bytearray()

    def _parse_pax(self, body: bytes) -> dict[str, bytes]:
        try:
            records = pax_records(body)
        except VerifyError:
            raise self._fail("holds a malformed tar extended header") from None
        found: dict[str, bytes] = {}
        for raw_key, value in records:
            key = raw_key.decode("utf-8", "surrogateescape")
            if key not in PAX_KEYS and key != CAPABILITY_XATTR:
                raise self._fail("holds an unsupported tar extended header record")
            if key in found:
                raise self._fail("holds a tar extended header that repeats a record")
            if not value:
                # Go skips an empty record and keeps the ustar field, so refuse it rather
                # than check a value Docker does not use.
                raise self._fail("holds an empty tar extended header record")
            found[key] = value
        return found

    # ENTRIES

    def _main(self, header: Header, block: bytes) -> bytes:
        pax = self._pax or {}
        if ("path" in pax and self._long_name is not None) or (
            "linkpath" in pax and self._long_link is not None
        ):
            raise self._fail("names an entry twice")
        raw_name = pax.get("path", self._long_name if self._long_name is not None else header.name)
        raw_link = pax.get(
            "linkpath", self._long_link if self._long_link is not None else header.linkname
        )
        size = self._pax_int(pax, "size", header.size)
        uid = self._pax_int(pax, "uid", header.uid)
        gid = self._pax_int(pax, "gid", header.gid)
        # Go refuses the whole header for a time it cannot parse, so check all three.
        for key in ("atime", "ctime", "mtime"):
            if key in pax:
                self._check_pax_time(pax[key])
        mtime: float = float(pax["mtime"].decode()) if "mtime" in pax else header.mtime
        name = raw_name.decode("utf-8", "surrogateescape")
        kind = header.kind
        if kind == b"\0" and name.endswith("/"):
            kind = b"5"  # as Go reads it: a legacy directory
        regular = kind in (b"0", b"\0")
        if size and not regular:
            raise self._fail("holds data in an entry that is not a regular file")
        self._entries += 1
        if self._entries > MAX_INNER_ENTRIES:
            raise self._fail("holds too many entries")
        canonical = self._check_name(name, kind, regular)
        self._check_links(canonical)
        if kind == b"2":
            if not canonical:
                raise self._fail("holds a symbolic link at its root")
            self._links.add(link_key(canonical))
            if len(self._links) > MAX_INNER_LINKS:
                raise self._fail("holds too many symbolic links")
        elif kind == b"1":
            self._check_hard_link(raw_link.decode("utf-8", "surrogateescape"))
        # Docker applies a hard link's mode (and owner) to the inode it links to.
        if (kind in (b"0", b"\0", b"1") and header.mode & 0o6000) or CAPABILITY_XATTR in pax:
            self._setid = True
        if canonical == "" and kind == b"5":
            self._root = (header.mode & 0o7777, uid, gid)
        if canonical in self._capture:
            # Docker's loaders read one of two copies; which one is not for the guard to guess.
            if canonical in self.captured:
                raise self._fail(f"holds {canonical} twice")
            if not regular:
                raise self._fail(f"holds {canonical} as something other than a regular file")
            if size > MAX_IMAGE_META:
                raise self._fail(f"holds an oversized {canonical}")
            self.captured[canonical] = b""
            if size:
                self._capturing = bytearray()
                self._capture_name = canonical
                self._capture_left = size
        if self.rename_to is not None:
            released = self._renamed(size, header.mode, uid, gid, mtime, pax)
        else:
            released = bytes(self._held) + block
        self._held.clear()
        self._seen_ext.clear()
        self._pax = self._long_name = self._long_link = None
        self._skip = -(-size // BLOCK) * BLOCK if regular else 0
        return released

    def _pax_int(self, pax: dict[str, bytes], key: str, default: int) -> int:
        if key not in pax:
            return default
        value = pax[key]
        # Go parses these as int64 and refuses the header beyond that.
        if not value.isdigit() or int(value) >= INT64_LIMIT:
            raise self._fail("holds a malformed tar extended header")
        return int(value)

    def _check_pax_time(self, value: bytes) -> None:
        match = PAX_TIME_RE.fullmatch(value)
        if match is None or int(match[1]) >= INT64_LIMIT:
            raise self._fail("holds a malformed tar extended header")

    def _check_name(self, name: str, kind: bytes, regular: bool) -> str:
        parts = name.split("/")
        if "\0" in name or name.startswith("/") or ".." in parts:
            raise self._fail("holds an entry outside its root")
        canonical = "/".join(p for p in parts if p not in ("", "."))
        if not name:
            raise self._fail("holds an entry with no name")
        if self.kind == "dir" and not (name in (".", "./") or name.startswith("./")):
            raise self._fail("holds an entry outside its root")
        if self.kind != "file" and canonical == "" and kind != b"5":
            raise self._fail("has a root that is not a directory")
        if self.kind == "file":
            if self._entries > 1:
                raise self._fail("holds more than one file")
            if not regular or name != self.file_name:
                raise self._fail(f"does not hold exactly the file {self.file_name}")
        return canonical

    def _check_links(self, canonical: str) -> None:
        """Refuses a path at or under a symlink seen earlier."""
        if not self._links or not canonical:
            return
        # One running hash over the path gives every prefix's key in linear time.
        hasher = hashlib.blake2b(digest_size=16)
        for k, part in enumerate(canonical.split("/")):
            hasher.update(("/" + part if k else part).encode("utf-8", "surrogateescape"))
            if hasher.copy().digest() in self._links:
                raise self._fail("writes through a symbolic link")

    def _check_hard_link(self, target: str) -> None:
        parts = target.split("/")
        if "\0" in target or target.startswith("/") or ".." in parts:
            raise self._fail("holds a hard link outside its root")
        canonical = "/".join(p for p in parts if p not in ("", "."))
        if not canonical:
            raise self._fail("holds a hard link outside its root")
        self._check_links(canonical)

    def _renamed(
        self, size: int, mode: int, uid: int, gid: int, mtime: float, pax: dict[str, bytes]
    ) -> bytes:
        info = tarfile.TarInfo(self.rename_to or "")
        info.type = tarfile.REGTYPE
        info.size = size
        info.mode = mode & 0o7777
        info.uid = uid
        info.gid = gid
        info.mtime = mtime
        info.pax_headers = {
            key: value.decode("utf-8", "surrogateescape")
            for key, value in pax.items()
            if key.startswith(XATTR_PREFIX)
        }
        return info.tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape")


def cstring(field: bytes) -> bytes:
    return field.split(b"\0", 1)[0]


def tar_number(field: bytes) -> int:
    """A numeric header field as Go's archive/tar reads it (NULs and spaces trimmed from
    both ends, where tarfile stops at the first NUL). ValueError where Go fails too, and
    for a negative or unusual base-256 value, which Docker never writes."""
    if field and field[0] & 0x80:
        if field[0] != 0x80:
            raise ValueError("unsupported base-256 number")
        value = int.from_bytes(field[1:], "big")
        if value >= INT64_LIMIT:
            raise ValueError("base-256 number beyond int64")  # Go fails here too
        return value
    digits = field.strip(b" \x00")
    if not digits:
        return 0
    if any(c < 0x30 or c > 0x37 for c in digits):
        raise ValueError("not an octal number")
    return int(digits, 8)


def link_key(canonical: str) -> bytes:
    return hashlib.blake2b(canonical.encode("utf-8", "surrogateescape"), digest_size=16).digest()


# PASS 2


@contextlib.contextmanager
def open_verified(
    storage: StorageBackend,
    staged: Staged,
    crypto: Crypto,
    cancel: threading.Event | None,
    passphrase: str | None = None,
) -> Iterator[ArchiveReader]:
    """The archive pass 1 verified, open for streaming its members. Use it before any
    mutation: it refuses a file whose fstat identity changed since pass 1. passphrase is
    the one pass 1 was given, if any."""
    verification = staged.verification
    handle = storage.open(verification.archive)
    try:
        fd = handle.fileno()
        if FileIdentity.from_fd(fd) != verification.identity:
            raise VerifyError(CHANGED_SINCE)
        opener = fd_opener(fd)
        with contextlib.ExitStack() as stack:
            if verification.encrypted:
                passphrases = candidates(crypto, verification.archive, passphrase)
                # Rotating the keys since pass 1 shifts the indexes, so the recorded one
                # only goes first; a wrong one fails at age's header, before any output.
                index = verification.passphrase_index
                if index is not None and 0 < index < len(passphrases):
                    passphrases.insert(0, passphrases.pop(index))
                stream, _ = stack.enter_context(
                    decrypted(opener, passphrases, require_complete=False)
                )
            else:
                stream = stack.enter_context(opener())
            plain = stack.enter_context(zstd.ZstdFile(TrailerReader(stream), "r"))
            tar = stack.enter_context(tarfile.open(fileobj=HeaderGuard(plain), mode="r|"))  # type: ignore[arg-type]
            yield ArchiveReader(tar, staged, fd, cancel)
    finally:
        handle.close()


@contextlib.contextmanager
def damage_is_change() -> Iterator[None]:
    try:
        yield
    except tarfile.TarError, zstd.ZstdError, EOFError:
        raise VerifyError(CHANGED_SINCE) from None


class ArchiveReader:
    """Streams data members in archive order, re-hashing every member against pass 1."""

    def __init__(
        self,
        tar: tarfile.TarFile,
        staged: Staged,
        fd: int,
        cancel: threading.Event | None,
    ) -> None:
        self._tar = tar
        self._members = iter(tar)
        self._staged = staged
        self._expected = staged.verification.members
        self._positions = {m.name: i for i, m in enumerate(self._expected)}
        self._fd = fd
        self._cancel = cancel
        self._position = -1  # of the last member taken from the archive
        self._current: tarfile.TarInfo | None = None  # advanced to, not yet read
        self._reading = False
        self._broken = False

    def advance_to(self, member: str) -> None:
        """Moves to member, hashing every member skipped on the way. Call it before
        opening the request that will carry the member, so no request idles meanwhile."""
        if self._broken or self._reading:
            raise VerifyError("The archive was not read to the end of a member.")
        target = self._positions.get(member)
        if target is None:
            raise VerifyError(f"{member} is not in the verified archive.")
        if self._current is not None and target == self._position:
            return
        if target <= self._position:
            raise VerifyError(f"{member} was requested out of archive order.")
        with damage_is_change():
            if self._current is not None:
                self._skip(self._current)
                self._current = None
            while True:
                info = next(self._members, None)
                self._position += 1
                if info is None or info.name != self._expected[self._position].name:
                    raise VerifyError(CHANGED_SINCE)
                if self._position == target:
                    self._current = info
                    return
                self._skip(info)

    def _skip(self, info: tarfile.TarInfo) -> None:
        if hash_member(self._tar, info, self._cancel) != self._expected[self._position]:
            raise VerifyError(f"{info.name} changed since it was verified.")

    def data(self, member: str, rename_to: str | None = None) -> Iterator[bytes]:
        """The member's inner tar, checked again by the guard as it streams. advance_to
        (member) must come first. The last piece is held back until the member's sum
        matched pass 1."""
        info = self._current
        if info is None or info.name != member or self._reading or self._broken:
            raise VerifyError(f"{member} was not advanced to before it was read.")
        kind, file_name = self._guard_kind(member)
        guard = InnerTarGuard(kind, file_name=file_name, rename_to=rename_to, label=member)
        self._reading = True
        return self._stream(info, guard)

    def _stream(self, info: tarfile.TarInfo, guard: InnerTarGuard) -> Iterator[bytes]:
        expected = self._expected[self._position]
        held = b""
        done = False
        try:
            with damage_is_change():
                source = pipe(self._tar.extractfile(info))
                hasher = hashlib.sha256()
                size = 0
                while chunk := source.read(CHUNK):
                    if self._cancel is not None and self._cancel.is_set():
                        raise Cancelled("The run was cancelled.")
                    hasher.update(chunk)
                    size += len(chunk)
                    released = guard.feed(chunk)
                    if released:
                        if held:
                            yield held
                        held = released
                held += guard.close()
            if MemberSum(info.name, size, hasher.hexdigest()) != expected:
                raise VerifyError(f"{info.name} changed since it was verified.")
            done = True
        finally:
            self._broken = self._broken or not done
            self._current = None
            self._reading = False
        if held:
            yield held

    def _guard_kind(self, member: str) -> tuple[GuardKind, str | None]:
        return guard_kind(data_entry(self._staged.manifest, member))

    def facts(self, member: str) -> MemberFacts:
        try:
            return self._staged.verification.data[member]
        except KeyError:
            raise VerifyError(f"{member} has no verified data.") from None

    def close(self) -> None:
        """Checks once more that the open file is still the one pass 1 verified."""
        if FileIdentity.from_fd(self._fd) != self._staged.verification.identity:
            raise VerifyError(CHANGED_SINCE)


# LISTING


@dataclass(frozen=True)
class Preview:
    """What an archive's first bytes say, for listing. Unauthenticated: display only."""

    state: Literal["manifest", "encrypted", "unreadable"]
    manifest: Manifest | None = None
    reason: str | None = None


def read_head_manifest(head: bytes) -> Preview:
    if head.startswith(AGE_MAGIC):
        return Preview("encrypted")
    if not head.startswith(ZSTD_MAGIC):
        return Preview("unreadable", reason="not a drydock archive")
    try:
        # Bounded whatever the compression ratio: at most one header and the manifest.
        plain = zstd.ZstdDecompressor().decompress(head, max_length=BLOCK + MAX_MANIFEST_BYTES)
        if len(plain) < BLOCK:
            return Preview("unreadable", reason=TOO_LARGE)
        info = tarfile.TarInfo.frombuf(plain[:BLOCK], "utf-8", "surrogateescape")
        if not info.isreg() or info.name != MANIFEST_NAME or info.size > MAX_MANIFEST_BYTES:
            return Preview("unreadable", reason="manifest.json is not the first member")
        if len(plain) < BLOCK + info.size:
            return Preview("unreadable", reason=TOO_LARGE)
        manifest = Manifest.model_validate_json(plain[BLOCK : BLOCK + info.size])
    except pydantic.ValidationError:
        return Preview("unreadable", reason="not a valid drydock manifest")
    except zstd.ZstdError, tarfile.HeaderError, ValueError:
        return Preview("unreadable", reason="the archive is damaged")
    return Preview("manifest", manifest=manifest)


def preview(storage: StorageBackend, name: str) -> Preview:
    """Reads FIRST_HEAD_BYTES, and HEAD_BYTES only for a manifest that does not fit: a
    listing of remote storage reads every archive's head over the network."""
    for size in (FIRST_HEAD_BYTES, HEAD_BYTES):
        try:
            head = storage.read_head(name, size)
        except StorageError as exc:
            return Preview("unreadable", reason=str(exc))
        except OSError:
            return Preview("unreadable", reason="the archive cannot be read")
        result = read_head_manifest(head)
        if result.reason != TOO_LARGE or len(head) < size:
            return result
    return result
