"""Archive writer and verifier: order, checksums, HMAC, tampering and encryption."""

import errno
import hashlib
import io
import json
import os
import pty
import shutil
import subprocess
import tarfile
import threading
import time
import uuid
from compression import zstd
from datetime import UTC, datetime
from pathlib import Path

import pyrage
import pytest

from drydock.archive import manifest as m
from drydock.archive import verify, writer
from drydock.crypto import Crypto

needs_age = pytest.mark.skipif(
    not (writer.AGE_DIR / "age").is_file(), reason=f"needs the age CLI in {writer.AGE_DIR}"
)
CONTAINER_ID = "a" * 64
IMAGE_HEX = "b" * 64
MEMBERS = [
    f"config/containers/{CONTAINER_ID}.json",
    "config/volumes/data.json",
    "compose/0/compose.yaml",
    "volumes/data.tar",
    "binds/0.tar",
    f"images/{IMAGE_HEX}.tar",
]
CONTENT = {
    MEMBERS[0]: b'{"Config": {"Env": ["SECRET=sentinel"]}}',
    MEMBERS[1]: b'{"Name": "data"}',
    MEMBERS[2]: b"services:\n  web:\n    image: busybox\n",
    MEMBERS[3]: os.urandom(2048),
    MEMBERS[4]: b"bind data " * 100,
    MEMBERS[5]: b"image layers " * 200,
}


def new_crypto(*extra: bytes) -> Crypto:
    return Crypto((os.urandom(32), *extra))


def sample_manifest(*, encrypted: bool = False, members: list[str] = MEMBERS) -> m.Manifest:
    return m.Manifest(
        instance_id="test",
        drydock_version="0.1.0",
        created_at=datetime(2026, 10, 13, tzinfo=UTC),
        source=m.Source(
            host_name="local", arch="amd64", os="linux", api_version="1.52", engine_version="29"
        ),
        job=m.JobInfo(
            uuid=str(uuid.uuid4()),
            name="web",
            scope="all",
            consistency_mode="stop",
            images_reference_only_if_pullable=False,
        ),
        containers=[
            m.ContainerEntry(
                id=CONTAINER_ID,
                name="web",
                image="local/web:1",
                image_id=f"sha256:{IMAGE_HEX}",
                config_member=MEMBERS[0],
            )
        ],
        volumes=[
            m.VolumeEntry(
                name="data",
                driver="local",
                mounts=[m.MountRef(container=CONTAINER_ID, destination="/d", read_only=False)],
                config_member=MEMBERS[1],
                data_member=MEMBERS[3],
            )
        ],
        binds=[m.BindEntry(n=0, source="/srv/web", kind="dir", mounts=[], data_member=MEMBERS[4])],
        images=[
            m.ImageEntry(
                id=f"sha256:{IMAGE_HEX}",
                refs=["local/web:1"],
                repo_digests=[],
                os="linux",
                architecture="amd64",
                saved=True,
                data_member=MEMBERS[5],
            )
        ],
        compose_files=[
            m.ComposeFile(
                n=0,
                role="config_file",
                host_path="/srv/web/compose.yaml",
                member=MEMBERS[2],
                size=len(CONTENT[MEMBERS[2]]),
            )
        ],
        encryption=m.Encryption(method="age-scrypt", derivation="hkdf-job-uuid")
        if encrypted
        else None,
        members=members,
    )


def write_sample(
    path: Path, crypto: Crypto, passphrase: str | None = None, **kwargs
) -> writer.ArchiveResult:
    staging = path.parent / "staging"
    with writer.ArchiveWriter(
        path,
        staging,
        crypto,
        mtime=1_760_000_000,
        passphrase=passphrase,
        **kwargs,
    ) as out:
        out.add_manifest(sample_manifest(encrypted=passphrase is not None))
        for name in MEMBERS:
            if name.startswith(("volumes/", "binds/", "images/")):
                data = CONTENT[name]
                out.add_stream(name, (data[i : i + 65536] for i in range(0, len(data), 65536)))
            else:
                out.add_bytes(name, CONTENT[name])
        return out.close()


def tar_members(path: Path) -> list[tuple[str, bytes]]:
    with zstd.ZstdFile(path) as plain, tarfile.open(fileobj=plain, mode="r|") as tar:
        return [(info.name, tar.extractfile(info).read()) for info in tar]  # type: ignore[union-attr]


def write_raw(
    path: Path,
    members: list[tuple[str, bytes]],
    link: str | None = None,
    pax: dict[str, str] | None = None,
    tar_format: int = tarfile.PAX_FORMAT,
) -> None:
    """A .tar.zst with exactly these members and a valid trailer, as an attacker would
    rebuild one. With link, that member is a symlink instead. pax adds PAX records to
    every member, and a "size" record holds the member's real size."""
    buffer = io.BytesIO()
    options = {zstd.CompressionParameter.checksum_flag: 1}
    with (
        zstd.ZstdFile(buffer, "w", options=options) as plain,
        tarfile.open(fileobj=plain, mode="w|", format=tar_format) as tar,
    ):
        for name, data in members:
            info = tarfile.TarInfo(name)
            if name == link:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
                continue
            info.size = len(data)
            if pax:
                info.pax_headers = {k: str(len(data)) if k == "size" else v for k, v in pax.items()}
            tar.addfile(info, io.BytesIO(data))
    compressed = buffer.getvalue()
    path.write_bytes(compressed + writer.trailer(hashlib.sha256(compressed).digest()))


@pytest.fixture
def crypto() -> Crypto:
    return new_crypto()


@pytest.fixture
def archive(tmp_path: Path, crypto: Crypto) -> Path:
    path = tmp_path / "archive.tar.zst"
    write_sample(path, crypto)
    return path


# ORDER AND CHECKSUMS


def test_round_trip_order_and_hmac(archive: Path, crypto: Crypto, tmp_path: Path) -> None:
    names = [name for name, _ in tar_members(archive)]
    assert names == [m.MANIFEST_NAME, *MEMBERS, m.CHECKSUMS_NAME]
    result = verify.verify_file(archive, crypto)
    assert result.signed and not result.encrypted
    assert [s.name for s in result.members] == [m.MANIFEST_NAME, *MEMBERS]
    for member in result.members[1:]:
        assert member.sha256 == hashlib.sha256(CONTENT[member.name]).hexdigest()
    document = json.loads(dict(tar_members(archive))[m.CHECKSUMS_NAME])
    assert [entry["name"] for entry in document["members"]] == [m.MANIFEST_NAME, *MEMBERS]
    # Staging held one member at a time and is empty afterwards.
    assert list((tmp_path / "staging").iterdir()) == []


def test_result_hash_matches_the_file(tmp_path: Path, crypto: Crypto) -> None:
    path = tmp_path / "a.tar.zst"
    result = write_sample(path, crypto)
    assert result.size == path.stat().st_size
    assert result.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert path.stat().st_mode & 0o777 == 0o600


def test_hmac_verifies_after_key_rotation(tmp_path: Path) -> None:
    old = os.urandom(32)
    path = tmp_path / "a.tar.zst"
    write_sample(path, Crypto((old,)))
    rotated = Crypto((os.urandom(32), old))
    assert verify.verify_file(path, rotated).signed


def test_archive_from_another_key_is_unsigned(archive: Path) -> None:
    stranger = new_crypto()
    with pytest.raises(verify.VerifyError, match="not signed"):
        verify.verify_file(archive, stranger)
    assert not verify.verify_file(archive, stranger, require_signed=False).signed


# TAMPERING


def test_flipping_any_byte_fails(archive: Path, crypto: Crypto, tmp_path: Path) -> None:
    original = archive.read_bytes()
    target = tmp_path / "flipped.tar.zst"
    passed = []
    for offset in range(len(original)):
        damaged = bytearray(original)
        damaged[offset] ^= 0x01
        target.write_bytes(damaged)
        try:
            verify.verify_file(target, crypto)
        except verify.VerifyError:
            continue
        passed.append(offset)
    assert passed == [], f"tampering at offsets {passed[:10]} of {len(original)} went unnoticed"


@pytest.mark.parametrize("name", [m.MANIFEST_NAME, *MEMBERS])
def test_changed_member_fails_even_in_a_rebuilt_archive(
    archive: Path, crypto: Crypto, tmp_path: Path, name: str
) -> None:
    members = tar_members(archive)
    rebuilt = []
    for member, data in members:
        if member == name:
            data = bytearray(data)
            data[len(data) // 2] ^= 0x20
            data = bytes(data)
        rebuilt.append((member, data))
    target = tmp_path / "rebuilt.tar.zst"
    write_raw(target, rebuilt)
    with pytest.raises(verify.VerifyError):
        verify.verify_file(target, crypto)


def test_recomputed_checksums_without_the_key_fail(
    archive: Path, crypto: Crypto, tmp_path: Path
) -> None:
    members = dict(tar_members(archive))
    members[MEMBERS[3]] = b"replaced volume"
    sums = [
        writer.MemberSum(name, len(data), hashlib.sha256(data).hexdigest())
        for name, data in members.items()
        if name != m.CHECKSUMS_NAME
    ]
    forged = writer.checksums_document(sums, new_crypto())  # signed with another key
    members[m.CHECKSUMS_NAME] = forged
    target = tmp_path / "forged.tar.zst"
    write_raw(target, list(members.items()))
    with pytest.raises(verify.VerifyError, match="not signed"):
        verify.verify_file(target, crypto)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda ms: ms[1:2] + ms[:1] + ms[2:], "first member"),
        (lambda ms: ms[:-2] + ms[-1:] + ms[-2:-1], "follows checksums.json"),
        (lambda ms: [*ms[:-1], ("config/volumes/extra.json", b"{}"), ms[-1]], "not listed"),
        (lambda ms: [*ms[:2], ms[1], *ms[2:]], "appears twice"),
        (lambda ms: ms[:3] + ms[4:], "not listed"),
        (lambda ms: ms[:-1], "checksums.json is missing"),
        (lambda ms: ms[:1] + ms[2:3] + ms[1:2] + ms[3:], "not listed"),
    ],
    ids=[
        "manifest-not-first",
        "checksums-not-last",
        "unlisted-member",
        "duplicate",
        "missing-member",
        "no-checksums",
        "reordered",
    ],
)
def test_structure_violations_fail(
    archive: Path, crypto: Crypto, tmp_path: Path, mutate, message: str
) -> None:
    target = tmp_path / "bad.tar.zst"
    write_raw(target, mutate(tar_members(archive)))
    with pytest.raises(verify.VerifyError, match=message):
        verify.verify_file(target, crypto)


def test_trailing_data_after_the_archive_fails(archive: Path, crypto: Crypto) -> None:
    with archive.open("ab") as handle:
        handle.write(zstd.compress(b"\0" * 1024 + b"extra"))
    with pytest.raises(verify.VerifyError):
        verify.verify_file(archive, crypto)


def test_non_regular_member_fails(archive: Path, crypto: Crypto, tmp_path: Path) -> None:
    target = tmp_path / "link.tar.zst"
    write_raw(target, tar_members(archive), link=MEMBERS[0])
    with pytest.raises(verify.VerifyError, match="not a regular file"):
        verify.verify_file(target, crypto)


def test_tar_extended_headers_are_checked_before_tarfile_reads_them(
    archive: Path, crypto: Crypto, tmp_path: Path
) -> None:
    members = tar_members(archive)
    target = tmp_path / "pax.tar.zst"
    # Small PAX headers, including a size record (as for a member over 8 GiB), verify.
    write_raw(target, members, pax={"size": "", "comment": "drydock"})
    assert verify.verify_file(target, crypto).signed
    # An oversized one is refused before tarfile buffers it.
    write_raw(target, members, pax={"comment": "x" * (verify.MAX_PAX_HEADER + 1)})
    with pytest.raises(verify.VerifyError, match="oversized"):
        verify.verify_file(target, crypto)
    # GNU long names (and every other non-regular header) are refused outright.
    long_name = f"config/volumes/{'v' * 120}.json"
    write_raw(target, [*members[:1], (long_name, b"{}")], tar_format=tarfile.GNU_FORMAT)
    with pytest.raises(verify.VerifyError, match="not a regular file"):
        verify.verify_file(target, crypto)


def test_missing_trailer_fails(archive: Path, crypto: Crypto) -> None:
    archive.write_bytes(archive.read_bytes()[: -writer.TRAILER_LEN])
    with pytest.raises(verify.VerifyError, match="integrity trailer"):
        verify.verify_file(archive, crypto)


def test_standard_tools_read_the_archive(archive: Path, tmp_path: Path) -> None:
    """The trailer is a zstd skippable frame, so tar --zstd extracts the archive as is."""
    if shutil.which("zstd") is None:
        plain = zstd.decompress(archive.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
            assert tar.getnames()[0] == m.MANIFEST_NAME
        return
    out = tmp_path / "x"
    out.mkdir()
    subprocess.run(["tar", "--zstd", "-xf", str(archive), "-C", str(out)], check=True)
    assert (out / m.MANIFEST_NAME).is_file()


def test_not_an_archive(tmp_path: Path, crypto: Crypto) -> None:
    target = tmp_path / "x"
    target.write_bytes(b"hello")
    with pytest.raises(verify.VerifyError, match="not a drydock archive"):
        verify.verify_file(target, crypto)


# WRITER RULES


def test_writer_refuses_members_out_of_manifest_order(tmp_path: Path, crypto: Crypto) -> None:
    path = tmp_path / "a.tar.zst"
    with (
        pytest.raises(writer.ArchiveError, match="first member"),
        writer.ArchiveWriter(path, tmp_path / "s", crypto, mtime=0) as out,
    ):
        out.add_bytes(MEMBERS[0], b"{}")
    assert not path.exists()
    with (
        pytest.raises(writer.ArchiveError, match="not the next member"),
        writer.ArchiveWriter(path, tmp_path / "s", crypto, mtime=0) as out,
    ):
        out.add_manifest(sample_manifest())
        out.add_bytes(MEMBERS[1], b"{}")
    assert not path.exists()
    with (
        pytest.raises(writer.ArchiveError, match="missing members"),
        writer.ArchiveWriter(path, tmp_path / "s", crypto, mtime=0) as out,
    ):
        out.add_manifest(sample_manifest())
        out.close()
    assert not path.exists()


def test_manifest_rejects_unsafe_or_unreferenced_members() -> None:
    for bad in (
        [*MEMBERS, "volumes/../../etc.tar"],
        [*MEMBERS, "/abs.json"],
        [MEMBERS[3], *MEMBERS[:3], *MEMBERS[4:]],  # data before config
        [*MEMBERS, MEMBERS[0]],
        MEMBERS[:-1],  # an entry references a member that is not listed
    ):
        with pytest.raises(ValueError):
            sample_manifest(members=bad)


def test_low_disk_space_fails_early(
    tmp_path: Path, crypto: Crypto, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = shutil.disk_usage

    def tight(path):
        return real(path)._replace(free=writer.RESERVE + 10 * 1024)

    monkeypatch.setattr(writer.shutil, "disk_usage", tight)
    path = tmp_path / "a.tar.zst"
    with (
        pytest.raises(writer.InsufficientSpace),
        writer.ArchiveWriter(path, tmp_path / "s", crypto, mtime=0) as out,
    ):
        out.add_manifest(sample_manifest())
        for name in MEMBERS[:3]:
            out.add_bytes(name, CONTENT[name])
        out.add_stream(MEMBERS[3], iter([b"x" * 65536] * 4))
    assert not path.exists()
    assert list((tmp_path / "s").iterdir()) == []


def test_disk_full_while_writing_is_insufficient_space() -> None:
    class FullDisk:
        def write(self, data: bytes) -> int:
            raise OSError(errno.ENOSPC, "No space left on device")

    sink = writer.HashingSink(FullDisk())
    with pytest.raises(writer.InsufficientSpace, match="full"):
        sink.write(b"x")


def test_cancel_stops_between_chunks(tmp_path: Path, crypto: Crypto) -> None:
    cancel = threading.Event()
    path = tmp_path / "a.tar.zst"

    def chunks():
        yield b"x" * 1024
        cancel.set()
        yield b"y" * 1024
        pytest.fail("the writer kept reading after cancel")

    with (
        pytest.raises(writer.Cancelled),
        writer.ArchiveWriter(path, tmp_path / "s", crypto, mtime=0, cancel=cancel) as out,
    ):
        out.add_manifest(sample_manifest())
        for name in MEMBERS[:3]:
            out.add_bytes(name, CONTENT[name])
        out.add_stream(MEMBERS[3], chunks())
    assert not path.exists()
    assert list((tmp_path / "s").iterdir()) == []


# ENCRYPTION


def age_env() -> dict[str, str]:
    return {"PATH": str(writer.AGE_DIR)}


@needs_age
def test_encrypted_archive_needs_the_passphrase(tmp_path: Path, crypto: Crypto) -> None:
    job = uuid.uuid4()
    passphrase = crypto.job_passphrase(job)
    path = tmp_path / "a.tar.zst.age"
    result = write_sample(path, crypto, passphrase)
    assert result.encrypted
    data = path.read_bytes()
    assert data.startswith(verify.AGE_MAGIC)
    for name, content in CONTENT.items():
        assert name.encode() not in data
        assert content[:32] not in data
    assert passphrase.encode() not in data
    with pytest.raises(verify.VerifyError, match="no passphrase"):
        verify.verify_file(path, crypto)
    with pytest.raises(verify.VerifyError, match="No configured secret key"):
        verify.verify_file(path, crypto, passphrases=["wrong passphrase"])
    verified = verify.verify_file(path, crypto, passphrases=["wrong passphrase", passphrase])
    assert verified.encrypted and verified.signed
    assert [s.name for s in verified.members] == [m.MANIFEST_NAME, *MEMBERS]


@needs_age
def test_encrypted_archive_decrypts_with_plain_age(tmp_path: Path, crypto: Crypto) -> None:
    """`age -d` with an interactive passphrase prompt, no plugin: the standard format."""
    passphrase = crypto.job_passphrase(uuid.uuid4())
    path = tmp_path / "a.tar.zst.age"
    write_sample(path, crypto, passphrase)
    out = tmp_path / "plain.tar.zst"
    pid, fd = pty.fork()
    if pid == 0:  # child: age reads the passphrase from its terminal
        os.execve(str(writer.AGE_DIR / "age"), ["age", "-d", "-o", str(out), str(path)], {})  # noqa: S606
    transcript = b""
    try:
        while b"passphrase" not in transcript.lower():
            transcript += os.read(fd, 1024)
        os.write(fd, passphrase.encode() + b"\n")
        while True:
            try:
                chunk = os.read(fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            transcript += chunk
    finally:
        _, status = os.waitpid(pid, 0)
        os.close(fd)
    assert os.waitstatus_to_exitcode(status) == 0, transcript
    with out.open("rb") as stream:
        assert verify.verify_stream(stream, crypto, encrypted=True).signed
    # pyrage (test-only) reads the same scrypt recipient stanza.
    plain = pyrage.passphrase.decrypt(path.read_bytes(), passphrase)
    assert plain == out.read_bytes()


@needs_age
def test_batchpass_decrypts_with_the_passphrase_on_a_descriptor(
    tmp_path: Path, crypto: Crypto
) -> None:
    passphrase = crypto.job_passphrase(uuid.uuid4())
    path = tmp_path / "a.tar.zst.age"
    write_sample(path, crypto, passphrase)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, passphrase.encode())
    os.close(write_fd)
    done = subprocess.run(
        [str(writer.AGE_DIR / "age"), "-d", "-j", "batchpass", str(path)],
        env=age_env() | {"AGE_PASSPHRASE_FD": str(read_fd)},
        pass_fds=(read_fd,),
        capture_output=True,
        check=True,
    )
    os.close(read_fd)
    assert done.stdout.startswith(verify.ZSTD_MAGIC)


@needs_age
def test_tampered_encrypted_archive_fails(tmp_path: Path, crypto: Crypto) -> None:
    passphrase = crypto.job_passphrase(uuid.uuid4())
    path = tmp_path / "a.tar.zst.age"
    write_sample(path, crypto, passphrase)
    original = path.read_bytes()
    header_end = original.index(b"\n---") + 1
    # One flip in the header and a spread of flips through the payload.
    step = max(1, (len(original) - header_end) // 8)
    offsets = [10, header_end + 5, *range(header_end + 60, len(original), step), len(original) - 1]
    for offset in offsets:
        damaged = bytearray(original)
        damaged[offset] ^= 0x01
        path.write_bytes(damaged)
        with pytest.raises(verify.VerifyError):
            verify.verify_file(path, crypto, passphrases=[passphrase])


@needs_age
def test_encrypted_flag_must_match_the_manifest(tmp_path: Path, crypto: Crypto) -> None:
    """An unencrypted archive whose manifest claims encryption is rejected, and vice versa."""
    plain = tmp_path / "a.tar.zst"
    staging = tmp_path / "s"
    with writer.ArchiveWriter(plain, staging, crypto, mtime=0) as out:
        out.add_manifest(sample_manifest(encrypted=True))
        for name in MEMBERS:
            out.add_bytes(name, CONTENT[name])
        out.close()
    with pytest.raises(verify.VerifyError, match="encryption"):
        verify.verify_file(plain, crypto)


def test_missing_age_is_a_clear_error(tmp_path: Path, crypto: Crypto, monkeypatch) -> None:
    monkeypatch.setattr(writer, "AGE_DIR", tmp_path / "none")
    path = tmp_path / "a.tar.zst.age"
    with pytest.raises(writer.ArchiveError, match="age CLI is not installed"):
        writer.ArchiveWriter(path, tmp_path / "s", crypto, mtime=0, passphrase="x")
    assert not path.exists()


@needs_age
def test_a_high_scrypt_work_factor_is_refused_quickly(
    tmp_path: Path, crypto: Crypto, monkeypatch
) -> None:
    """A foreign archive cannot make each passphrase attempt cost a large scrypt."""
    passphrase = crypto.job_passphrase(uuid.uuid4())
    path = tmp_path / "a.tar.zst.age"
    monkeypatch.setattr(writer, "SCRYPT_WORK_FACTOR", writer.MAX_SCRYPT_WORK_FACTOR + 1)
    write_sample(path, crypto, passphrase)
    started = time.monotonic()
    with pytest.raises(verify.VerifyError, match="work factor"):
        verify.verify_file(path, crypto, passphrases=[passphrase] * 3)
    assert time.monotonic() - started < 1
    # age itself refuses it too (AGE_PASSPHRASE_MAX_WORK_FACTOR), whatever the header says.
    with path.open("rb") as source:
        process = writer.spawn_age(["--decrypt"], passphrase, source, subprocess.PIPE)
    output, _ = process.communicate()
    assert process.returncode != 0 and output == b""
