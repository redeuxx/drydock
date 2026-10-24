"""Archive writer: tar inside zstd, optionally inside age.

Member order is fixed: manifest.json first, then config/ and compose/, then volumes/,
binds/ and images/, and checksums.json last. checksums.json lists the size and sha256 of
every other member in archive order, with an HMAC-SHA256 over that list made with the
newest secret key. The manifest names every member up front, so the writer refuses
anything else and the verifier can reject unknown members.

Large members are staged one at a time: streamed to a file in the staging directory,
appended to the archive (hashed on the way in) and deleted, so peak staging space is the
largest member. The archive itself is written where the caller says (for local storage,
a temporary name in the storage directory). Free space is checked in the staging
directory while staging and next to the archive before each append, so a run fails early
instead of filling either disk.

The zstd frame carries a content checksum, and is followed by a zstd skippable frame
holding the SHA-256 of the compressed bytes before it. Standard tools skip that frame,
so `tar --zstd -xf` still works. Some compressed bytes can change without changing the
content (the window size, or a match offset that copies the same zeros), and the
trailer catches those too: a flipped byte anywhere fails verification.

Encryption pipes the compressed stream through the age CLI (age-plugin-batchpass). The
passphrase reaches age through an inherited pipe, never argv or the environment, and no
shell is involved. The result decrypts with a plain `age -d` and the passphrase.

Blocking. Run on a worker thread.
"""

import contextlib
import errno
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import threading
import uuid
from collections.abc import Iterable, Iterator
from compression import zstd
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from drydock.archive.manifest import (
    CHECKSUMS_NAME,
    MANIFEST_NAME,
    Manifest,
    member_rank,
    valid_member,
)
from drydock.crypto import Crypto

CHUNK = 1024 * 1024
RESERVE = 64 * 1024 * 1024  # never stage into the last 64 MiB of the disk
STAGING = "the staging directory"
OUTPUT = "the storage directory"  # where callers write archives (see jobs.dispatcher)
ZSTD_LEVEL = 3
AGE_DIR = Path("/opt/age")  # age and age-plugin-batchpass, pinned and checksummed in the image
# scrypt log2(N) for new archives. age's default of 18 stretches human passphrases and
# costs 256 MiB of memory; drydock's passphrases are 256-bit HKDF outputs, which need no
# stretching, so 14 (16 MiB) keeps the age process small. Any age decrypts it.
SCRYPT_WORK_FACTOR = 14
# Decryption refuses a higher work factor, so a foreign archive cannot make every
# passphrase attempt cost gigabytes of memory and minutes of CPU.
MAX_SCRYPT_WORK_FACTOR = 14
CHECKSUMS_VERSION = 1
# A zstd skippable frame (magic 0x184D2A5D, 48-byte payload): a tag and a SHA-256.
TRAILER_HEADER = (0x184D2A5D).to_bytes(4, "little") + (48).to_bytes(4, "little")
TRAILER_TAG = b"drydock-sha256v1"
TRAILER_LEN = len(TRAILER_HEADER) + len(TRAILER_TAG) + 32


def trailer(digest: bytes) -> bytes:
    return TRAILER_HEADER + TRAILER_TAG + digest


class ArchiveError(Exception):
    """The archive could not be written. The message is safe to show."""


class InsufficientSpace(ArchiveError):
    pass


class Cancelled(ArchiveError):
    pass


@dataclass(frozen=True)
class MemberSum:
    name: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class ArchiveResult:
    path: Path
    size: int  # of the file on disk (compressed, and encrypted if enabled)
    sha256: str  # of the file on disk
    encrypted: bool
    members: tuple[MemberSum, ...]


# CHECKSUMS


def signed_payload(members: Iterable[MemberSum]) -> bytes:
    """The exact bytes the HMAC covers: the member list as canonical JSON."""
    listing = [m.as_dict() for m in members]
    return json.dumps(listing, sort_keys=True, separators=(",", ":")).encode()


def checksums_document(members: list[MemberSum], crypto: Crypto) -> bytes:
    document = {
        "version": CHECKSUMS_VERSION,
        "members": [m.as_dict() for m in members],
        "hmac_sha256": crypto.sign(signed_payload(members)),
    }
    return json.dumps(document, indent=2).encode()


# DISK SPACE


def ensure_space(path: Path, need: int, label: str) -> None:
    free = shutil.disk_usage(path).free
    if free < need + RESERVE:
        raise InsufficientSpace(
            f"Not enough free space in {label}: {free // 2**20} MiB free, "
            f"{(need + RESERVE) // 2**20} MiB needed."
        )


def create_new(path: Path | str, dir_fd: int | None = None) -> BinaryIO:
    """Opens a file that must not exist yet (no symlink games), mode 0600."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    return os.fdopen(os.open(path, flags, 0o600, dir_fd=dir_fd), "wb")


@contextlib.contextmanager
def disk_full_is_insufficient_space(label: str) -> Iterator[None]:
    try:
        yield
    except OSError as exc:
        if exc.errno in (errno.ENOSPC, errno.EDQUOT):
            raise InsufficientSpace(f"The disk holding {label} is full.") from None
        raise


# OUTPUT PIPELINE


class HashingSink(io.RawIOBase):
    """Writes through to a file and hashes everything written."""

    def __init__(self, target, label: str = OUTPUT) -> None:
        self.target = target
        self.label = label
        self.sha256 = hashlib.sha256()
        self.size = 0

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        with disk_full_is_insufficient_space(self.label):
            self.target.write(data)
        self.sha256.update(data)
        self.size += len(data)
        return len(data)


def spawn_age(args: list[str], passphrase: str, stdin, stdout) -> subprocess.Popen[bytes]:
    """Starts age with the batchpass plugin reading the passphrase from an inherited pipe."""
    age_dir = AGE_DIR
    binary = age_dir / "age"
    if not (binary.is_file() and (age_dir / "age-plugin-batchpass").is_file()):
        raise ArchiveError(f"The age CLI is not installed in {age_dir}.")
    read_fd, write_fd = os.pipe()
    try:
        # Far below the pipe buffer, so this never blocks.
        os.write(write_fd, passphrase.encode())
    finally:
        os.close(write_fd)
    try:
        return subprocess.Popen(  # noqa: S603 (fixed argv, no shell)
            [str(binary), *args, "-j", "batchpass"],
            stdin=stdin,
            stdout=stdout,
            stderr=subprocess.PIPE,
            env={
                "PATH": str(age_dir),
                "AGE_PASSPHRASE_FD": str(read_fd),
                "AGE_PASSPHRASE_WORK_FACTOR": str(SCRYPT_WORK_FACTOR),
                "AGE_PASSPHRASE_MAX_WORK_FACTOR": str(MAX_SCRYPT_WORK_FACTOR),
            },
            pass_fds=(read_fd,),
            close_fds=True,
        )
    finally:
        os.close(read_fd)


def pipe[T](stream: T | None) -> T:
    if stream is None:
        raise ArchiveError("The age process has no pipe.")
    return stream


class AgeEncryptor(io.RawIOBase):
    """A writable stream that encrypts into sink through `age -e`."""

    def __init__(self, passphrase: str, sink: HashingSink) -> None:
        self.process = spawn_age(["--encrypt"], passphrase, subprocess.PIPE, subprocess.PIPE)
        self._stdin = pipe(self.process.stdin)
        self._stdout = pipe(self.process.stdout)
        self._stderr_pipe = pipe(self.process.stderr)
        self._sink = sink
        self._errors: list[BaseException] = []
        self._stderr = b""
        self._threads = [
            threading.Thread(target=self._drain_stdout, daemon=True),
            threading.Thread(target=self._drain_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _drain_stdout(self) -> None:
        try:
            while chunk := self._stdout.read(CHUNK):
                self._sink.write(chunk)
        except BaseException as exc:  # reported by finish()
            self._errors.append(exc)
            self.process.kill()

    def _drain_stderr(self) -> None:
        self._stderr = self._stderr_pipe.read(64 * 1024)
        while self._stderr_pipe.read(CHUNK):
            pass

    def writable(self) -> bool:
        return True

    def write(self, data) -> int:
        try:
            self._stdin.write(data)
        except BrokenPipeError:
            raise ArchiveError(self._failure()) from None
        return len(data)

    def _failure(self) -> str:
        self.process.wait()
        for thread in self._threads:
            thread.join()
        if self._errors:
            return f"Writing the encrypted archive failed: {self._errors[0]}"
        detail = self._stderr.decode(errors="replace").strip()[:500]
        return f"age failed with exit code {self.process.returncode}: {detail}"

    def finish(self) -> None:
        with contextlib.suppress(BrokenPipeError):
            self._stdin.close()
        self.process.wait()
        for thread in self._threads:
            thread.join()
        if self.process.returncode != 0 or self._errors:
            raise ArchiveError(self._failure())

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        for thread in self._threads:
            thread.join(timeout=5)
        for stream in (self._stdin, self._stdout, self._stderr_pipe):
            with contextlib.suppress(OSError):
                stream.close()


class CancellableReader:
    """Reads a staged member, hashing it and checking for cancellation between chunks."""

    def __init__(self, source: BinaryIO, cancel: threading.Event | None) -> None:
        self.source = source
        self.cancel = cancel
        self.sha256 = hashlib.sha256()
        self.size = 0

    def read(self, size: int) -> bytes:
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled("The run was cancelled.")
        data = self.source.read(size)
        self.sha256.update(data)
        self.size += len(data)
        return data


# WRITER


class ArchiveWriter:
    """Writes one archive. Use as a context manager: any exception removes the output."""

    def __init__(
        self,
        path: Path,
        staging_dir: Path,
        crypto: Crypto,
        *,
        mtime: int,
        passphrase: str | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.path = path
        self.staging_dir = staging_dir
        self._crypto = crypto
        self._mtime = mtime
        self._cancel = cancel
        self._sums: list[MemberSum] = []
        self._expected: list[str] | None = None
        self._staged: Path | None = None
        self._closed = False
        staging_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._raw = create_new(path)
        self._sink = HashingSink(self._raw)
        self._age: AgeEncryptor | None = None
        try:
            if passphrase is not None:
                self._age = AgeEncryptor(passphrase, self._sink)
            options = {
                zstd.CompressionParameter.compression_level: ZSTD_LEVEL,
                zstd.CompressionParameter.checksum_flag: 1,
            }
            self._compressed = HashingSink(self._age if self._age is not None else self._sink)
            self._zst = zstd.ZstdFile(self._compressed, "w", options=options)
            self._tar = tarfile.open(  # noqa: SIM115 (closed by close() or abort())
                fileobj=self._zst, mode="w|", format=tarfile.PAX_FORMAT, copybufsize=CHUNK
            )
        except BaseException:
            self.abort()
            raise

    def __enter__(self) -> ArchiveWriter:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None or not self._closed:
            self.abort()

    # MEMBERS

    def add_manifest(self, manifest: Manifest) -> None:
        if self._sums:
            raise ArchiveError("manifest.json must be the first member.")
        self._expected = list(manifest.members)
        self._append_bytes(MANIFEST_NAME, manifest.to_json())

    def add_bytes(self, name: str, data: bytes) -> None:
        self._check_next(name)
        self._append_bytes(name, data)

    def add_stream(self, name: str, chunks: Iterable[bytes]) -> None:
        """Stages chunks to a file, appends it and deletes it."""
        self._check_next(name)
        staged = self._staged = self.staging_dir / f"member-{uuid.uuid4().hex}"
        try:
            size = 0
            with disk_full_is_insufficient_space(STAGING), create_new(staged) as out:
                for chunk in chunks:
                    self._check_cancel()
                    ensure_space(self.staging_dir, len(chunk), STAGING)
                    out.write(chunk)
                    size += len(chunk)
            # Appending can grow the archive by up to the member's size.
            ensure_space(self.path.parent, size, OUTPUT)
            with staged.open("rb") as source:
                reader = CancellableReader(source, self._cancel)
                info = self._info(name, size)
                self._tar.addfile(info, reader)  # type: ignore[arg-type]
            if reader.size != size:
                raise ArchiveError(f"{name} changed while it was being archived.")
            self._sums.append(MemberSum(name, size, reader.sha256.hexdigest()))
        finally:
            staged.unlink(missing_ok=True)
            self._staged = None

    def close(self) -> ArchiveResult:
        """Writes checksums.json and finishes every layer of the stream."""
        if self._expected is None or len(self._sums) != len(self._expected) + 1:
            raise ArchiveError("The archive is missing members named in its manifest.")
        document = checksums_document(self._sums, self._crypto)
        self._tar.addfile(self._info(CHECKSUMS_NAME, len(document)), io.BytesIO(document))
        self._tar.close()
        self._zst.close()
        self._compressed.target.write(trailer(self._compressed.sha256.digest()))
        if self._age is not None:
            self._age.finish()
        self._raw.flush()
        os.fsync(self._raw.fileno())
        self._raw.close()
        self._closed = True
        return ArchiveResult(
            path=self.path,
            size=self._sink.size,
            sha256=self._sink.sha256.hexdigest(),
            encrypted=self._age is not None,
            members=tuple(self._sums),
        )

    def abort(self) -> None:
        """Stops everything and removes the partial output. Never raises."""
        if self._closed:
            return
        self._closed = True
        if self._age is not None:
            self._age.kill()
        # Each close flushes into a file that is deleted below, or into a dead pipe. Both
        # mark themselves closed first, so nothing flushes again at garbage collection.
        for layer in (getattr(self, "_tar", None), getattr(self, "_zst", None)):
            if layer is not None:
                with contextlib.suppress(Exception):  # the output is discarded either way
                    layer.close()
        self._raw.close()
        if self._staged is not None:
            self._staged.unlink(missing_ok=True)
        self.path.unlink(missing_ok=True)

    # INTERNALS

    def _check_cancel(self) -> None:
        if self._cancel is not None and self._cancel.is_set():
            raise Cancelled("The run was cancelled.")

    def _check_next(self, name: str) -> None:
        if self._expected is None:
            raise ArchiveError("manifest.json must be the first member.")
        index = len(self._sums) - 1
        if index >= len(self._expected) or self._expected[index] != name:
            raise ArchiveError(f"{name} is not the next member named in the manifest.")
        if not valid_member(name) or member_rank(name) not in (1, 2):
            raise ArchiveError(f"{name} is not a valid member name.")

    def _info(self, name: str, size: int) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name)
        info.size = size
        info.mode = 0o600
        info.mtime = self._mtime
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    def _append_bytes(self, name: str, data: bytes) -> None:
        self._check_cancel()
        ensure_space(self.path.parent, len(data), OUTPUT)
        self._tar.addfile(self._info(name, len(data)), io.BytesIO(data))
        self._sums.append(MemberSum(name, len(data), hashlib.sha256(data).hexdigest()))
