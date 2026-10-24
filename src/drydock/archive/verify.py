"""Streaming archive verifier. Restore (Phase 3) runs it before touching anything.

One pass over the stream, nothing extracted:
- Tar headers are checked before tarfile reads them: only regular members, each with
  at most one PAX extended header of at most 64 KiB holding only PAX_KEYS records, are
  accepted (no GNU long names, sparse files or global headers, which drydock never
  writes), so a crafted header cannot make tarfile buffer gigabytes.
- manifest.json must be the first member and checksums.json the last.
- Every member is a regular file, appears once, and is exactly the next name the
  manifest lists; anything else is rejected.
- Every member's size and sha256 must match checksums.json, and its HMAC must verify
  with one of the configured keys (any key in the list, so rotation keeps old archives
  signed).
- Sizes are capped from the tar headers, before any data is read: manifest.json at
  4 MiB, checksums.json at 16 MiB, and all members together at 16 TiB
  (MAX_TOTAL_BYTES). There is no compression-ratio rule, so zero-filled data (a
  preallocated database file) stays restorable; a bomb in a data member costs CPU time
  only, which the total cap and cancellation bound.
- After checksums.json only tar padding may follow, the zstd frame (with its content
  checksum) must end cleanly, and the trailing skippable frame must hold the SHA-256 of
  every compressed byte before it. For encrypted archives age also authenticates every
  chunk and must exit cleanly.

Restore hooks into the same pass: read_members calls on_member(manifest, info) for every
member between manifest.json and checksums.json, after the order, duplicate, position and
size checks, and the returned MemberSink receives each chunk as it is hashed (then
close() once the size is checked). Archives are read through an opener, a callable that
returns a fresh handle; restore's opener re-reads one already open file descriptor, so
every read sees the same file whatever happens to its name.

Blocking. Run on a worker thread.
"""

import contextlib
import dataclasses
import hashlib
import json
import subprocess
import tarfile
import threading
from collections.abc import Callable, Iterator, Sequence
from compression import zstd
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol

import pydantic

from drydock.archive.manifest import CHECKSUMS_NAME, MANIFEST_NAME, Manifest
from drydock.archive.writer import (
    CHECKSUMS_VERSION,
    CHUNK,
    MAX_SCRYPT_WORK_FACTOR,
    TRAILER_LEN,
    ArchiveError,
    Cancelled,
    MemberSum,
    pipe,
    signed_payload,
    spawn_age,
    trailer,
)
from drydock.crypto import Crypto

MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 2**40  # every member's declared size, summed
MAX_MEMBERS = 100_000
STDERR_LIMIT = 64 * 1024
MAX_PAX_HEADER = 64 * 1024
# The PAX records accepted, outer and inner: what tarfile and Docker write. tarfile acts
# on others (GNU.sparse.* makes it read a sparse map of any size, hdrcharset changes how
# names decode), so every other key is refused.
PAX_KEYS = frozenset(
    {
        "path",
        "linkpath",
        "size",
        "uid",
        "gid",
        "uname",
        "gname",
        "mtime",
        "atime",
        "ctime",
        "comment",
    }
)
BLOCK = tarfile.BLOCKSIZE
REGULAR_KINDS = (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.CONTTYPE)
AGE_MAGIC = b"age-encryption.org/v1\n"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class VerifyError(Exception):
    """The archive is damaged, tampered with, unsigned or unreadable. Safe to show."""


@dataclass(frozen=True)
class Verified:
    manifest: Manifest
    members: tuple[MemberSum, ...]  # every member except checksums.json, in order
    signed: bool
    encrypted: bool
    passphrase_index: int | None = None  # which candidate decrypted it (encrypted only)
    manifest_bytes: bytes = b""  # manifest.json exactly as the archive holds it


class MemberSink(Protocol):
    """Receives one member's bytes while it is hashed."""

    def write(self, data: bytes) -> None: ...

    def close(self) -> None: ...


OnMember = Callable[[Manifest, tarfile.TarInfo], MemberSink | None]
Opener = Callable[[], BinaryIO]


# PLAIN STREAMS


def verify_stream(
    compressed: BinaryIO,
    crypto: Crypto,
    *,
    require_signed: bool = True,
    cancel: threading.Event | None = None,
    encrypted: bool = False,
    on_member: OnMember | None = None,
) -> Verified:
    """Verifies a .tar.zst stream (already decrypted)."""
    source = TrailerReader(compressed)
    try:
        with zstd.ZstdFile(source, "r") as plain:
            manifest, sums, document, manifest_bytes = read_members(plain, cancel, on_member)
        if source.read(CHUNK):
            raise VerifyError("Unexpected data after the archive.")
    except VerifyError, Cancelled:
        raise
    except pydantic.ValidationError:
        raise VerifyError("manifest.json is not a valid drydock manifest.") from None
    except (tarfile.TarError, zstd.ZstdError, EOFError, OSError, ValueError) as exc:
        raise VerifyError(f"The archive is damaged: {exc}") from None
    if source.tail != trailer(source.sha256.digest()):
        raise VerifyError("The archive is damaged: its integrity trailer does not match.")
    expected = parse_checksums(document)
    if len(expected) != len(sums):
        raise VerifyError("checksums.json does not list exactly the archive's members.")
    for listed, actual in zip(expected, sums, strict=True):
        if listed != actual:
            raise VerifyError(f"Checksum mismatch for {actual.name}.")
    signed = crypto.verify(signed_payload(sums), document["hmac_sha256"])
    if require_signed and not signed:
        raise VerifyError("The archive is not signed by any configured secret key.")
    if (manifest.encryption is not None) != encrypted:
        raise VerifyError("The manifest's encryption setting does not match the archive.")
    return Verified(
        manifest=manifest,
        members=tuple(sums),
        signed=signed,
        encrypted=encrypted,
        manifest_bytes=manifest_bytes,
    )


class TrailerReader:
    """Passes a compressed stream through, hashing all of it except the final trailer."""

    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.sha256 = hashlib.sha256()
        self.tail = b""

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size if size and size > 0 else CHUNK)
        if len(data) >= TRAILER_LEN:
            self.sha256.update(self.tail)
            self.sha256.update(memoryview(data)[:-TRAILER_LEN])
            self.tail = data[-TRAILER_LEN:]
        elif data:
            combined = self.tail + data
            self.sha256.update(combined[:-TRAILER_LEN])
            self.tail = combined[-TRAILER_LEN:]
        return data


def read_members(
    plain: BinaryIO, cancel: threading.Event | None, on_member: OnMember | None = None
) -> tuple[Manifest, list[MemberSum], dict, bytes]:
    """The manifest, every member's sum (checksums.json aside), the checksums document
    and manifest.json's bytes."""
    manifest: Manifest | None = None
    manifest_bytes = b""
    expected: list[str] = []
    sums: list[MemberSum] = []
    document: dict | None = None
    seen: set[str] = set()
    total = 0
    with tarfile.open(fileobj=HeaderGuard(plain), mode="r|") as tar:  # type: ignore[arg-type]
        for info in tar:
            if cancel is not None and cancel.is_set():
                raise Cancelled("The run was cancelled.")
            name = info.name
            if document is not None:
                raise VerifyError(f"{name} follows checksums.json, which must be the last member.")
            if not info.isreg():
                raise VerifyError(f"{name} is not a regular file.")
            if name in seen:
                raise VerifyError(f"{name} appears twice.")
            seen.add(name)
            if len(seen) > MAX_MEMBERS:
                raise VerifyError("The archive has too many members.")
            total += info.size
            if total > MAX_TOTAL_BYTES:
                raise VerifyError("The archive decompresses to more than drydock's limit.")
            if manifest is None:
                if name != MANIFEST_NAME:
                    raise VerifyError("manifest.json is not the first member.")
                data = manifest_bytes = read_small(tar, info, MAX_MANIFEST_BYTES)
                manifest = Manifest.model_validate_json(data)
                expected = list(manifest.members)
                sums.append(MemberSum(name, len(data), hashlib.sha256(data).hexdigest()))
            elif name == CHECKSUMS_NAME:
                document = json.loads(read_small(tar, info))
            else:
                index = len(sums) - 1
                if index >= len(expected) or expected[index] != name:
                    raise VerifyError(f"{name} is not listed in the manifest at this position.")
                sink = on_member(manifest, info) if on_member is not None else None
                sums.append(hash_member(tar, info, cancel, sink))
        if manifest is None:
            raise VerifyError("The archive is empty.")
        if document is None:
            raise VerifyError("checksums.json is missing or not the last member.")
        if len(sums) != len(expected) + 1:
            raise VerifyError("The archive is missing members listed in its manifest.")
        # Only zero padding may follow; reading to the end also checks the zstd checksum.
        rest = pipe(tar.fileobj)
        while chunk := rest.read(CHUNK):
            if chunk.count(0) != len(chunk):
                raise VerifyError("Unexpected data after the last member.")
    return manifest, sums, document, manifest_bytes


class HeaderGuard:
    """Passes a plain tar stream through, checking each header block before tarfile sees it.

    tarfile reads a PAX or GNU extended header's whole body into memory before it yields
    the member, so the limits are enforced here instead. The PAX "size" record of a
    member over 8 GiB is honoured, so the guard stays aligned with the member data. A
    member may have one PAX header only: with two, tarfile applies the first one's size
    and this guard would apply the second's, and the two would read different blocks as
    the next header.
    """

    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self._header = bytearray()
        self._skip = 0  # member data and padding until the next header
        self._pax: bytearray | None = None  # the body of the PAX header being read
        self._pax_left = 0
        self._next_size: int | None = None  # from the last PAX header
        self._pending = False  # a PAX header was read and its member has not come yet

    def read(self, size: int = -1) -> bytes:
        data = self.source.read(size)
        view = memoryview(data)
        i = 0
        while i < len(view):
            if self._skip:
                n = min(self._skip, len(view) - i)
                if self._pax is not None and self._pax_left:
                    take = min(n, self._pax_left)
                    self._pax += view[i : i + take]
                    self._pax_left -= take
                self._skip -= n
                i += n
                if not self._skip and self._pax is not None:
                    self._next_size = pax_size(bytes(self._pax))
                    self._pax = None
                continue
            n = min(BLOCK - len(self._header), len(view) - i)
            self._header += view[i : i + n]
            i += n
            if len(self._header) == BLOCK:
                self._check(bytes(self._header))
                self._header.clear()
        return data

    def _check(self, block: bytes) -> None:
        if block.count(0) == BLOCK:
            return  # end-of-archive marker or padding
        kind = block[156:157]
        size = tarfile.nti(block[124:136])
        if kind == b"x":
            if self._pending:
                raise VerifyError("The archive holds two tar extended headers for one member.")
            if size > MAX_PAX_HEADER:
                raise VerifyError("The archive holds an oversized tar extended header.")
            self._pax, self._pax_left = bytearray(), size
            self._pending = True
        elif kind in REGULAR_KINDS:
            if self._next_size is not None:
                size = self._next_size
            self._next_size = None
            self._pending = False
        else:
            # Every member must be a regular file; refusing the rest here also keeps the
            # guard aligned (and rules out GNU long names and global headers).
            raise VerifyError("The archive holds a member that is not a regular file.")
        self._skip = -(-size // BLOCK) * BLOCK
        if self._pax is not None and not self._skip:
            self._pax = None


def pax_records(body: bytes) -> list[tuple[bytes, bytes]]:
    """The records of a PAX extended header, split by their length prefixes as Go's
    archive/tar and tarfile do (a value may hold a newline)."""
    records = []
    pos = 0
    while pos < len(body):
        space = body.find(b" ", pos, pos + 21)
        digits = body[pos:space] if space > pos else b""
        if not digits.isdigit() or (len(digits) > 1 and digits.startswith(b"0")):
            raise VerifyError("The archive holds a malformed tar extended header.")
        end = pos + int(digits)
        if end > len(body) or end <= space + 1 or body[end - 1] != 0x0A:
            raise VerifyError("The archive holds a malformed tar extended header.")
        key, sep, value = body[space + 1 : end - 1].partition(b"=")
        if not sep or not key:
            raise VerifyError("The archive holds a malformed tar extended header.")
        records.append((key, value))
        pos = end
    return records


def pax_size(body: bytes) -> int | None:
    """The "size" record of an outer PAX extended header, if any. Records outside
    PAX_KEYS, and a record given twice, are refused."""
    found = None
    keys: set[bytes] = set()
    for key, value in pax_records(body):
        if key.decode("utf-8", "surrogateescape") not in PAX_KEYS:
            raise VerifyError("The archive holds an unsupported tar extended header record.")
        if key in keys:
            raise VerifyError("The archive holds a tar extended header that repeats a record.")
        keys.add(key)
        if key == b"size":
            if not value.isdigit():
                raise VerifyError("The archive holds a malformed tar extended header.")
            found = int(value)
    return found


def read_small(
    tar: tarfile.TarFile, info: tarfile.TarInfo, limit: int = MAX_METADATA_BYTES
) -> bytes:
    if info.size > limit:
        raise VerifyError(f"{info.name} is too large.")
    data = pipe(tar.extractfile(info)).read()
    if len(data) != info.size:
        raise VerifyError(f"{info.name} is truncated.")
    return data


def hash_member(
    tar: tarfile.TarFile,
    info: tarfile.TarInfo,
    cancel: threading.Event | None,
    sink: MemberSink | None = None,
) -> MemberSum:
    source = pipe(tar.extractfile(info))
    hasher = hashlib.sha256()
    size = 0
    while chunk := source.read(CHUNK):
        if cancel is not None and cancel.is_set():
            raise Cancelled("The run was cancelled.")
        hasher.update(chunk)
        size += len(chunk)
        if sink is not None:
            sink.write(chunk)
    if size != info.size:
        raise VerifyError(f"{info.name} is truncated.")
    if sink is not None:
        sink.close()
    return MemberSum(info.name, size, hasher.hexdigest())


def parse_checksums(document: object) -> list[MemberSum]:
    try:
        if not isinstance(document, dict) or document.get("version") != CHECKSUMS_VERSION:
            raise TypeError
        if not isinstance(document.get("hmac_sha256"), str):
            raise TypeError
        listing = document["members"]
        return [
            MemberSum(str(item["name"]), int(item["size"]), str(item["sha256"])) for item in listing
        ]
    except TypeError, KeyError, ValueError:
        raise VerifyError("checksums.json is malformed.") from None


# ENCRYPTED ARCHIVES


def check_work_factor(head: bytes) -> None:
    """Refuses an age header whose scrypt work factor is above what drydock writes."""
    lines = head.split(b"\n")
    stanza = lines[1].split() if len(lines) > 1 else []
    if stanza[:2] != [b"->", b"scrypt"]:
        raise VerifyError("The archive is not encrypted with a passphrase.")
    if len(stanza) != 4 or not stanza[3].isdigit() or len(stanza[3]) > 2:
        raise VerifyError("The archive's encryption header is malformed.")
    if int(stanza[3]) > MAX_SCRYPT_WORK_FACTOR:
        raise VerifyError(
            f"The archive's scrypt work factor ({int(stanza[3])}) is above drydock's limit "
            f"of {MAX_SCRYPT_WORK_FACTOR}."
        )


@contextlib.contextmanager
def decrypted(
    opener: Opener, passphrases: Sequence[str], *, require_complete: bool = True
) -> Iterator[tuple[BinaryIO, int]]:
    """Yields the decrypted stream and the index of the passphrase that worked, trying
    each candidate in order (newest key first).

    A wrong passphrase fails at the header, before any output. Once a passphrase works,
    age must still exit 0 after the whole stream was read, or the stream was tampered with.
    With require_complete=False the consumer may stop early (age authenticates every
    chunk before it outputs it), and leaving the context kills age instead of raising.

    Every handle from opener is closed, and the age process that read it has exited,
    before opener is called again: an opener may hand out handles sharing one offset.
    """
    with opener() as source:
        check_work_factor(source.read(256))
    for index, passphrase in enumerate(passphrases):
        with opener() as source:
            try:
                process = spawn_age(["--decrypt"], passphrase, source, subprocess.PIPE)
            except ArchiveError as exc:
                raise VerifyError(str(exc)) from None
        stdout, stderr = pipe(process.stdout), pipe(process.stderr)
        # age must never block on a full stderr pipe; at most 64 KiB of it is kept.
        drain = threading.Thread(target=drain_stderr, args=(stderr,), daemon=True)
        drain.start()
        try:
            first = stdout.read(CHUNK)
            if not first:
                process.wait()
                continue
            yield PrefixedReader(first, stdout), index  # type: ignore[misc]
            if not require_complete:
                return
            # The consumer read to the end; age has authenticated the final chunk.
            if stdout.read(1) or process.wait() != 0:
                raise VerifyError("The encrypted archive is damaged or was tampered with.")
            return
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            stdout.close()
            drain.join(timeout=5)
            stderr.close()
    raise VerifyError("No configured secret key decrypts this archive.")


def drain_stderr(stream: BinaryIO) -> bytes:
    kept = stream.read(STDERR_LIMIT)
    with contextlib.suppress(OSError, ValueError):
        while stream.read(CHUNK):
            pass
    return kept


class PrefixedReader:
    """A readable that returns `first` and then the rest of `rest`."""

    def __init__(self, first: bytes, rest: BinaryIO) -> None:
        self._first = first
        self._rest = rest

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self._first:
            if size is None or size < 0:
                data, self._first = self._first + self._rest.read(), b""
                return data
            data, self._first = self._first[:size], self._first[size:]
            return data
        return self._rest.read(size)

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


# FILES


def verify_file(
    path: Path,
    crypto: Crypto,
    *,
    passphrases: Sequence[str] = (),
    require_signed: bool = True,
    cancel: threading.Event | None = None,
) -> Verified:
    """Verifies an archive file, decrypting it first when it starts with the age header."""
    return verify_source(
        lambda: path.open("rb"),
        crypto,
        passphrases=passphrases,
        require_signed=require_signed,
        cancel=cancel,
    )


def verify_source(
    opener: Opener,
    crypto: Crypto,
    *,
    passphrases: Sequence[str] = (),
    require_signed: bool = True,
    cancel: threading.Event | None = None,
    on_member: OnMember | None = None,
) -> Verified:
    """Verifies the archive opener() reads: one handle to sniff the format, then one for
    a plain archive, or one per decryption attempt (see decrypted)."""
    with opener() as handle:
        head = handle.read(len(AGE_MAGIC))
    if head.startswith(ZSTD_MAGIC):
        with opener() as handle:
            return verify_stream(
                handle, crypto, require_signed=require_signed, cancel=cancel, on_member=on_member
            )
    if head != AGE_MAGIC:
        raise VerifyError("This is not a drydock archive.")
    if not passphrases:
        raise VerifyError("The archive is encrypted and no passphrase is available.")
    with decrypted(opener, passphrases) as (stream, index):
        verified = verify_stream(
            stream,
            crypto,
            require_signed=require_signed,
            cancel=cancel,
            encrypted=True,
            on_member=on_member,
        )
    return dataclasses.replace(verified, passphrase_index=index)
