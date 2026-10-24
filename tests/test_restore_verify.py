"""Restore pass 1 and pass 2: one open file, the inner tar guard, staging and previews."""

import dataclasses
import errno
import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import threading
import time
import uuid
from collections.abc import Callable
from compression import zstd
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from drydock.archive import manifest as m
from drydock.archive import verify as archive_verify
from drydock.archive import writer
from drydock.archive.verify import VerifyError
from drydock.config import Settings
from drydock.crypto import Crypto, CryptoError
from drydock.restore import verify as rv
from drydock.restore.verify import InnerTarGuard
from drydock.storage.base import StorageError, archive_name, parse_name
from drydock.storage.local import LocalStorage
from tests.conftest import make_settings
from tests.restore_support import (
    TarEntry,
    build_archive,
    container_inspect,
    image_tar,
    inner_tar,
    network_inspect,
    pax_body,
    root_only_tar,
)
from tests.test_archive import needs_age, new_crypto, tar_members, write_raw

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="local storage needs Linux")

SECRET = "sentinel-env-secret"
DOTENV_SECRET = "sentinel-dotenv-secret"
IMAGE_ID = f"sha256:{'c' * 64}"
CONTAINER_ID = "d" * 64
CAP = "\x01\x00\x00\x02\x00\x20\x00\x00" + "\x00" * 12  # vfs_cap_data: cap_net_raw+p
ROOT = TarEntry("./", tarfile.DIRTYPE, mode=0o755)


@dataclass
class Env:
    settings: Settings
    storage: LocalStorage
    root: Path
    crypto: Crypto

    @property
    def staging(self) -> Path:
        return self.settings.staging_dir


@pytest.fixture
def env(tmp_path: Path) -> Env:
    root = tmp_path / "storage"
    root.mkdir()
    settings = make_settings(tmp_path / "data", DRYDOCK_LOCAL_STORAGE_ROOTS=str(root))
    return Env(settings, LocalStorage(root, settings), root, new_crypto())


def verify(
    env: Env, name: str, crypto: Crypto | None = None, run_id: int = 1, log=None
) -> rv.Staged:
    return rv.verify_archive(
        env.storage,
        7,
        name,
        crypto or env.crypto,
        env.staging,
        run_id,
        cancel=threading.Event(),
        log=log if log is not None else (lambda _: None),
    )


def web_archive(env: Env, crypto: Crypto | None = None, **kwargs) -> tuple[str, m.Manifest]:
    """One container with a network, a volume, a dir bind, an image and compose files."""
    backend = network_inspect("backend", subnet="172.30.0.0/24")
    container = container_inspect(
        "web",
        id=CONTAINER_ID,
        image="busybox:1.37",
        image_id=IMAGE_ID,
        env=[f"TOKEN={SECRET}"],
        mounts=[("data", "/data")],
        binds=["/srv/web:/srv:ro"],
        networks={"backend": {"NetworkID": backend["Id"], "Aliases": ["web"]}},
    )
    volume = inner_tar(
        [
            TarEntry("./", tarfile.DIRTYPE, mode=0o750, uid=999, gid=999),
            TarEntry("./PG_VERSION", data=b"18\n", uid=999, gid=999, mode=0o600),
        ]
    )
    bind = inner_tar([ROOT, TarEntry("./index.html", data=b"<h1>hello</h1>")])
    defaults = {
        "containers": [container],
        "networks": [backend],
        "volumes": {"data": volume},
        "binds": [("/srv/web", "dir", bind)],
        "images": [(IMAGE_ID, ["busybox:1.37"], image_tar(IMAGE_ID, ["busybox:1.37"]), None)],
        "compose": [
            ("config_file", "/srv/web/compose.yaml", b"services:\n  web:\n    image: busybox\n"),
            ("dotenv", "/srv/web/.env", f"DB_PASSWORD={DOTENV_SECRET}\n".encode()),
        ],
    }
    return build_archive(env.root, crypto or env.crypto, **(defaults | kwargs))


def volume_archive(env: Env, data: bytes, **kwargs) -> str:
    return build_archive(
        env.root,
        env.crypto,
        containers=[container_inspect(id=CONTAINER_ID, mounts=[("data", "/data")])],
        volumes={"data": data},
        **kwargs,
    )[0]


def file_bind_archive(env: Env, data: bytes) -> str:
    return build_archive(
        env.root,
        env.crypto,
        containers=[container_inspect(binds=["/srv/app.conf:/etc/app.conf:ro"])],
        binds=[("/srv/app.conf", "file", data)],
    )[0]


def rewrite(env: Env, name: str, mutate: Callable[[list], list]) -> str:
    path = env.root / name
    members = tar_members(path)
    path.unlink()
    write_raw(path, mutate(members))
    return name


def resign(env: Env, name: str, change: Callable[[str, bytes], bytes]) -> str:
    """The archive rebuilt with each member's bytes changed, and signed again with env's
    key (as an archive from another drydock version, or a forged one, would be)."""
    path = env.root / name
    members = [(n, change(n, d)) for n, d in tar_members(path) if n != m.CHECKSUMS_NAME]
    sums = [writer.MemberSum(n, len(d), hashlib.sha256(d).hexdigest()) for n, d in members]
    path.unlink()
    write_raw(path, [*members, (m.CHECKSUMS_NAME, writer.checksums_document(sums, env.crypto))])
    return name


def tree(dest: Path) -> list[Path]:
    return sorted(dest.rglob("*"))


def age_children() -> list[int]:
    """age processes this test process started and has not reaped."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text()
        except OSError:
            continue
        command = text[text.index("(") + 1 : text.rindex(")")]
        parent = int(text[text.rindex(")") + 2 :].split()[1])
        if command == "age" and parent == os.getpid():
            found.append(int(entry.name))
    return found


# PASS 1


def test_verify_stages_metadata_and_images(env: Env) -> None:
    name, manifest = web_archive(env)
    lines: list[str] = []
    staged = verify(env, name, log=lines.append)
    members = dict(tar_members(env.root / name))
    verification = staged.verification
    assert staged.dest == rv.restore_dir(env.staging, 1)
    assert staged.manifest == manifest
    configs = {k for k in members if k.startswith("config/")}
    assert set(staged.configs) == configs
    for member in configs:
        assert staged.configs[member] == json.loads(members[member])
    assert staged.compose == {k: v for k, v in members.items() if k.startswith("compose/")}
    image_member = manifest.images[0].data_member
    assert image_member is not None
    sums = {s.name: s for s in verification.members}
    staged_image = staged.images[image_member]
    assert hashlib.sha256(staged_image.read_bytes()).hexdigest() == sums[image_member].sha256
    # Metadata is at rest as Fernet tokens, never as JSON or plaintext secrets.
    for member in configs | set(staged.compose):
        raw = (staged.dest / member).read_bytes()
        assert raw.startswith(b"gAAAAA")
        assert SECRET.encode() not in raw and DOTENV_SECRET.encode() not in raw
        with pytest.raises(ValueError):
            json.loads(raw)
    assert stat.S_IMODE(staged.dest.stat().st_mode) == 0o700
    for path in tree(staged.dest):
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600), path
    assert SECRET.encode() not in (staged.dest / rv.VERIFIED_NAME).read_bytes()
    # verified.json round-trips, and loading the run's data again gives the same result.
    assert rv.Verification.from_json(verification.to_json()) == verification
    assert set(verification.staged_images) == {image_member}
    assert rv.load_staged(staged.dest, env.crypto) == staged
    assert verification.signed and not verification.encrypted
    assert verification.passphrase_index is None
    assert verification.storage_target_id == 7 and verification.archive == name
    # Image facts: the recorded ID, the config digest from the tar, and the names in it.
    with tarfile.open(fileobj=io.BytesIO(members[image_member])) as tar:
        saved = json.loads(tar.extractfile("manifest.json").read())  # type: ignore[union-attr]
    config_digest = "sha256:" + saved[0]["Config"].rsplit("/", 1)[-1]
    facts = verification.images[image_member]
    assert IMAGE_ID in facts.ids and config_digest in facts.ids
    assert {rv.normalize_ref(n) for n in facts.names} == {"docker.io/library/busybox:1.37"}
    # Data facts: the volume's root owner and mode; nothing setuid.
    volume = verification.data[manifest.volumes[0].data_member or ""]
    assert (volume.root_mode, volume.root_uid, volume.root_gid) == (0o750, 999, 999)
    assert not volume.setid and volume.entries == 2
    assert set(verification.data) == {
        manifest.volumes[0].data_member,
        manifest.binds[0].data_member,
    }
    secrets = rv.secret_values(staged)
    assert SECRET in secrets and DOTENV_SECRET in secrets
    assert lines[0] == f"Verifying {name}."
    assert lines[-1] == f"Verified {len(sums)} members; the archive is signed."


def test_staging_directory_is_created_on_a_fresh_install(env: Env, tmp_path: Path) -> None:
    assert not env.staging.exists()
    name = volume_archive(env, root_only_tar())
    verify(env, name)
    assert stat.S_IMODE(env.staging.stat().st_mode) == 0o700
    rv.remove_restore_dir(env.staging, 1)
    assert list(env.staging.iterdir()) == []
    env.staging.rmdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    env.staging.symlink_to(elsewhere)
    with pytest.raises(VerifyError, match="staging directory is not usable"):
        verify(env, name)
    assert list(elsewhere.iterdir()) == []


def test_manifest_serialized_another_way_still_verifies(env: Env) -> None:
    """The staged manifest.json is the archive's own bytes, whatever their formatting."""
    name, manifest = web_archive(env)

    def compact(member: str, data: bytes) -> bytes:
        return json.dumps(json.loads(data)).encode() if member == m.MANIFEST_NAME else data

    resign(env, name, compact)
    raw = tar_members(env.root / name)[0][1]
    assert raw != manifest.to_json()
    staged = verify(env, name)
    assert staged.verification.signed and staged.manifest == manifest
    assert (staged.dest / m.MANIFEST_NAME).read_bytes() == raw
    assert rv.load_staged(staged.dest, env.crypto) == staged


def test_members_are_checked_as_the_entry_that_references_them(env: Env) -> None:
    """A file bind referencing a volumes/ member (and a volume a binds/ member) would be
    checked by the wrong guard; the manifest is refused instead."""
    name, manifest = build_archive(
        env.root,
        env.crypto,
        containers=[
            container_inspect(
                id=CONTAINER_ID,
                mounts=[("data", "/data")],
                binds=["/srv/app.conf:/etc/app.conf:ro"],
            )
        ],
        binds=[("/srv/app.conf", "file", inner_tar([TarEntry("b0", data=b"x")]))],
    )
    volume, bind = manifest.volumes[0].data_member, manifest.binds[0].data_member

    def swap(member: str, data: bytes) -> bytes:
        if member != m.MANIFEST_NAME:
            return data
        document = json.loads(data)
        document["volumes"][0]["data_member"] = bind
        document["binds"][0]["data_member"] = volume
        m.Manifest.model_validate(document)  # still a valid manifest on its own
        return json.dumps(document).encode()

    resign(env, name, swap)
    with pytest.raises(VerifyError, match="is not described by the manifest"):
        verify(env, name)
    assert not rv.restore_dir(env.staging, 1).exists()


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EACCES])
def test_staging_failures_are_not_blamed_on_the_archive(
    env: Env, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    name, _ = web_archive(env)

    def fail(*_: object) -> Path:
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(rv, "staged_path", fail)
    expected = writer.InsufficientSpace if code == errno.ENOSPC else VerifyError
    with pytest.raises(expected) as caught:
        verify(env, name)
    assert "damaged" not in str(caught.value) and str(env.staging) not in str(caught.value)
    if code == errno.EACCES:
        assert str(caught.value) == rv.UNUSABLE
    assert not rv.restore_dir(env.staging, 1).exists()


def test_unwritable_staging_directory_is_a_verify_error(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = volume_archive(env, root_only_tar())
    real_mkdir = Path.mkdir

    def mkdir(self: Path, *args, **kwargs) -> None:
        if self.name.startswith("restore-"):
            raise PermissionError(errno.EACCES, "Permission denied")
        real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    with pytest.raises(VerifyError, match="staging directory is not usable"):
        verify(env, name)


def test_rotated_out_key_still_verifies_as_signed(env: Env) -> None:
    old, new = os.urandom(32), os.urandom(32)
    name, _ = web_archive(env, Crypto((old,)))
    assert verify(env, name, Crypto((new, old)), run_id=1).verification.signed
    unsigned = verify(env, name, Crypto((new,)), run_id=2)
    assert not unsigned.verification.signed


@needs_age
def test_wrong_passphrase_fails_during_verification(env: Env) -> None:
    key_a, key_b = os.urandom(32), os.urandom(32)
    name, _ = web_archive(env, Crypto((key_a,)), encrypt=True)
    with pytest.raises(VerifyError, match=r"No configured secret key decrypts this archive\."):
        verify(env, name, Crypto((key_b,)))
    assert not rv.restore_dir(env.staging, 1).exists()
    staged = verify(env, name, Crypto((key_b, key_a)), run_id=2)
    assert staged.verification.passphrase_index == 1
    assert staged.verification.encrypted and staged.verification.signed
    assert age_children() == []


def test_tampered_archive_fails_and_leaves_nothing(env: Env) -> None:
    name, manifest = web_archive(env)
    member = manifest.volumes[0].data_member

    def flip(members: list) -> list:
        out = []
        for current, data in members:
            if current == member:
                data = bytearray(data)
                data[data.index(b"18\n")] ^= 0x01
                data = bytes(data)
            out.append((current, data))
        return out

    rewrite(env, name, flip)
    with pytest.raises(VerifyError, match="Checksum mismatch"):
        verify(env, name)
    assert not rv.restore_dir(env.staging, 1).exists()
    # A flipped byte in the file itself fails too.
    path = env.root / web_archive(env, created_at=datetime(2026, 1, 1, tzinfo=UTC))[0]
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(data)
    with pytest.raises(VerifyError):
        verify(env, path.name)
    assert not rv.restore_dir(env.staging, 1).exists()


def test_renamed_archive_is_refused(env: Env) -> None:
    created_at = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
    name, _ = web_archive(env, created_at=created_at)
    other = archive_name(str(uuid.uuid4()), "web", created_at, False)
    (env.root / name).rename(env.root / other)
    with pytest.raises(VerifyError, match="does not match its manifest"):
        verify(env, other)
    assert not rv.restore_dir(env.staging, 1).exists()


@pytest.mark.parametrize("encrypt", [False, pytest.param(True, marks=needs_age)])
def test_verification_binds_to_one_open_file(
    env: Env, monkeypatch: pytest.MonkeyPatch, encrypt: bool
) -> None:
    job = str(uuid.uuid4())
    first = datetime(2026, 10, 14, 1, 0, tzinfo=UTC)
    second = datetime(2026, 10, 14, 2, 0, tzinfo=UTC)
    good, manifest = web_archive(env, job_uuid=job, created_at=first, encrypt=encrypt)
    bad, _ = web_archive(env, job_uuid=job, created_at=second, encrypt=encrypt)
    # bad is a signed archive whose image member was swapped for another (unsigned) one.
    if encrypt:
        (env.root / bad).write_bytes((env.root / bad).read_bytes()[:-1])
    else:
        image = manifest.images[0].data_member
        rewrite(env, bad, lambda ms: [(n, d + b"\0" * 512 if n == image else d) for n, d in ms])
    real_open = LocalStorage.open
    calls: list[str] = []

    def first_bad_then_good(self: LocalStorage, name: str):
        calls.append(name)
        return real_open(self, bad if len(calls) == 1 else good)

    monkeypatch.setattr(LocalStorage, "open", first_bad_then_good)
    with pytest.raises(VerifyError):
        verify(env, bad)
    assert calls == [bad]
    assert not rv.restore_dir(env.staging, 1).exists()

    # Swapping the directory entry right after the open changes nothing either way.
    def open_then_swap(replacement: Path) -> Callable:
        def wrapper(self: LocalStorage, name: str):
            calls.append(name)
            handle = real_open(self, name)
            replacement.replace(env.root / name)
            return handle

        return wrapper

    bad_bytes = (env.root / bad).read_bytes()
    good_copy = env.root / "good-copy"
    good_copy.hardlink_to(env.root / good)
    calls.clear()
    monkeypatch.setattr(LocalStorage, "open", open_then_swap(good_copy))
    with pytest.raises(VerifyError):
        verify(env, bad, run_id=2)
    assert calls == [bad]
    bad_copy = env.root / "bad-copy"
    bad_copy.write_bytes(bad_bytes)
    calls.clear()
    monkeypatch.setattr(LocalStorage, "open", open_then_swap(bad_copy))
    staged = verify(env, good, run_id=3)
    assert calls == [good] and staged.verification.signed
    # Pass 2 opens the name again and sees a different file.
    monkeypatch.setattr(LocalStorage, "open", real_open)
    with (
        pytest.raises(VerifyError, match="changed since it was verified"),
        rv.open_verified(env.storage, staged, env.crypto, threading.Event()),
    ):
        pass


def test_symlinked_archive_is_refused(env: Env) -> None:
    name = volume_archive(env, root_only_tar())
    link = archive_name(str(uuid.uuid4()), "web", datetime(2026, 1, 1, tzinfo=UTC), False)
    (env.root / link).symlink_to(env.root / name)
    with pytest.raises(StorageError):
        env.storage.open(link)
    with pytest.raises(StorageError):
        verify(env, link)
    assert not rv.restore_dir(env.staging, 1).exists()


def test_fifo_archive_is_refused_without_blocking(env: Env) -> None:
    name = archive_name(str(uuid.uuid4()), "web", datetime(2026, 1, 1, tzinfo=UTC), False)
    os.mkfifo(env.root / name)
    errors: list[Exception] = []

    def attempt() -> None:
        for call in (lambda: env.storage.open(name), lambda: verify(env, name)):
            try:
                call()
            except StorageError as exc:
                errors.append(exc)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "opening a FIFO blocked"
    assert [str(e) for e in errors] == [f"{name} is not a regular file."] * 2
    assert not rv.restore_dir(env.staging, 1).exists()


@pytest.mark.parametrize("oci", [True, False])
def test_image_tar_with_unlisted_tag_is_refused(env: Env, oci: bool) -> None:
    tar = image_tar(IMAGE_ID, ["busybox:1.37", "drydock:local"], oci=oci)
    name, _ = web_archive(env, images=[(IMAGE_ID, ["busybox:1.37"], tar, None)])
    with pytest.raises(VerifyError, match="carries names its manifest does not list"):
        verify(env, name)
    assert not rv.restore_dir(env.staging, 1).exists()
    # The same image without the extra tag verifies, in either save format.
    tar = image_tar(IMAGE_ID, ["busybox:1.37"], oci=oci)
    name, manifest = web_archive(
        env,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        images=[(IMAGE_ID, ["docker.io/library/busybox:1.37"], tar, None)],
    )
    facts = verify(env, name).verification.images[manifest.images[0].data_member or ""]
    assert IMAGE_ID in facts.ids and len(facts.ids) == (3 if oci else 2)


def test_image_facts_parse_shapes() -> None:
    entry = m.ImageEntry(
        id=IMAGE_ID, refs=["nginx", "ghcr.io/acme/app:2"], repo_digests=[], os="linux",
        architecture="amd64", saved=True, data_member=f"images/{'c' * 64}.tar",
    )  # fmt: skip
    index = {
        "manifests": [
            {
                "digest": f"sha256:{'e' * 64}",
                "annotations": {
                    "io.containerd.image.name": "docker.io/library/nginx:latest",
                    "org.opencontainers.image.ref.name": "latest",
                },
            },
            {
                "digest": f"sha256:{'f' * 64}",
                "annotations": {"org.opencontainers.image.ref.name": "ghcr.io/acme/app:2"},
            },
        ]
    }
    facts = rv.image_facts({"index.json": json.dumps(index).encode()}, entry)
    assert facts.ids == (IMAGE_ID, f"sha256:{'e' * 64}", f"sha256:{'f' * 64}")
    assert set(facts.names) == {"docker.io/library/nginx:latest", "ghcr.io/acme/app:2"}
    for bad in (b"[]", b'{"manifests": [{"digest": "md5:x"}]}', b"not json"):
        with pytest.raises(VerifyError, match="malformed"):
            rv.image_facts({"index.json": bad}, entry)
    with pytest.raises(VerifyError, match="malformed"):
        rv.image_facts({"manifest.json": b'[{"Config": "../../etc/passwd"}]'}, entry)
    assert rv.normalize_ref("busybox") == "docker.io/library/busybox:latest"
    assert rv.normalize_ref("acme/app:1") == "docker.io/acme/app:1"
    assert rv.normalize_ref("localhost:5000/app") == "localhost:5000/app:latest"
    assert rv.normalize_ref("index.docker.io/library/x:1") == "docker.io/library/x:1"


HIDDEN = f"sha256:{'e' * 64}"


@pytest.mark.parametrize(
    ("member", "document"),
    [
        ("manifest.json", [{"Config": f"{'c' * 64}.json", "repotags": ["drydock:local"]}]),
        ("manifest.json", [{"Config": f"{'c' * 64}.json", "RepoTag\u017f": ["drydock:local"]}]),
        (
            "manifest.json",
            [{"Config": f"{'c' * 64}.json", "RepoTags": [], "REPOTAGS": ["drydock:local"]}],
        ),
        (
            "index.json",
            {
                "manifests": [],
                "Manifests": [
                    {"digest": HIDDEN, "annotations": {"io.containerd.image.name": "drydock:local"}}
                ],
            },
        ),
        (
            "index.json",
            {
                "manifests": [
                    {"digest": HIDDEN, "Annotations": {"io.containerd.image.name": "drydock:local"}}
                ]
            },
        ),
        ("index.json", {"manifests": [{"Digest": HIDDEN}]}),
    ],
    ids=["repotags", "long-s", "two-spellings", "Manifests", "Annotations", "Digest"],
)
def test_image_names_go_matches_ignoring_case_are_refused(member: str, document: object) -> None:
    """Go's encoding/json matches keys to struct fields ignoring case, so a key Python
    would skip still names the image for docker load."""
    entry = m.ImageEntry(
        id=IMAGE_ID, refs=["busybox:1.37"], repo_digests=[], os="linux",
        architecture="amd64", saved=True, data_member=f"images/{'c' * 64}.tar",
    )  # fmt: skip
    with pytest.raises(VerifyError, match="malformed"):
        rv.image_facts({member: json.dumps(document).encode()}, entry)


@pytest.mark.parametrize("scope", ["config", "data", "image", "all"])
def test_built_archives_follow_capture_naming(env: Env, scope: m.Scope) -> None:
    pulled = f"sha256:{'a' * 64}"
    digest = f"busybox@sha256:{'b' * 64}"
    name, manifest = web_archive(
        env,
        scope=scope,
        images=[
            (IMAGE_ID, ["busybox:1.37"], image_tar(IMAGE_ID, ["busybox:1.37"]), None),
            (pulled, ["busybox:latest"], None, digest),
        ],
        binds=[("/srv/web", "dir", b""), ("/srv/app.conf", "file", b"")],
    )
    members = set(manifest.members)
    assert (f"config/containers/{CONTAINER_ID}.json" in members) is (scope in ("config", "all"))
    assert ("volumes/data.tar" in members) is (scope in ("data", "all"))
    assert (f"images/{'c' * 64}.tar" in members) is (scope in ("image", "all"))
    assert f"images/{'a' * 64}.tar" not in members
    assert manifest.images[1].confirmed_digest == digest and not manifest.images[1].saved
    assert [b.kind for b in manifest.binds] == ["dir", "file"]
    staged = verify(env, name)
    assert staged.verification.signed
    assert set(staged.verification.data) == {
        member for member in members if member.startswith(("volumes/", "binds/"))
    }


# FUZZ CORPUS


def outer_insert(member: tuple[str, bytes]) -> Callable[[list], list]:
    return lambda ms: [*ms[:1], member, *ms[1:]]


def stream_archive(path: Path, members: list[tuple[str, bytes | int]]) -> None:
    """A .tar.zst with a valid trailer; an int member is that many zeros, streamed."""
    buffer = io.BytesIO()
    with zstd.ZstdFile(buffer, "w", options={zstd.CompressionParameter.checksum_flag: 1}) as out:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = data if isinstance(data, int) else len(data)
            out.write(info.tobuf(tarfile.PAX_FORMAT))
            if isinstance(data, int):
                for offset in range(0, data, writer.CHUNK):
                    out.write(bytes(min(writer.CHUNK, data - offset)))
            else:
                out.write(data)
            out.write(bytes(-info.size % tarfile.BLOCKSIZE))
        out.write(bytes(2 * tarfile.BLOCKSIZE))
    compressed = buffer.getvalue()
    path.write_bytes(compressed + writer.trailer(hashlib.sha256(compressed).digest()))


def million_members(env: Env, monkeypatch: pytest.MonkeyPatch) -> str:
    name = volume_archive(env, root_only_tar())
    path = env.root / name
    manifest_data = tar_members(path)[0][1]
    block = tarfile.TarInfo("config/volumes/x.json").tobuf(tarfile.USTAR_FORMAT)
    buffer = io.BytesIO()
    with zstd.ZstdFile(buffer, "w", options={zstd.CompressionParameter.checksum_flag: 1}) as out:
        info = tarfile.TarInfo(m.MANIFEST_NAME)
        info.size = len(manifest_data)
        out.write(info.tobuf(tarfile.PAX_FORMAT) + manifest_data)
        out.write(bytes(-info.size % tarfile.BLOCKSIZE))
        batch = block * 10_000
        for _ in range(100):
            out.write(batch)
        out.write(bytes(2 * tarfile.BLOCKSIZE))
    compressed = buffer.getvalue()
    path.write_bytes(compressed + writer.trailer(hashlib.sha256(compressed).digest()))
    return name


def data_bomb(env: Env, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(archive_verify, "MAX_TOTAL_BYTES", 64 * 2**20)
    name = volume_archive(env, root_only_tar())
    path = env.root / name
    members: list[tuple[str, bytes | int]] = [
        (n, 128 * 2**20 if n.startswith("volumes/") else d) for n, d in tar_members(path)
    ]
    stream_archive(path, members)
    return name


def metadata_bomb(env: Env, monkeypatch: pytest.MonkeyPatch) -> str:
    member = f"config/containers/{CONTAINER_ID}.json"
    big = bytes(archive_verify.MAX_METADATA_BYTES + 1)
    return volume_archive(env, root_only_tar(), raw_members={member: big})


def config_bomb(data: bytes, **limits: int) -> Callable[[Env, pytest.MonkeyPatch], str]:
    """The container's config member replaced by data, with rv's limits set to limits."""

    def build(env: Env, monkeypatch: pytest.MonkeyPatch) -> str:
        for limit, value in limits.items():
            monkeypatch.setattr(rv, limit, value)
        member = f"config/containers/{CONTAINER_ID}.json"
        return volume_archive(env, root_only_tar(), raw_members={member: data})

    return build


def big_manifest(env: Env, monkeypatch: pytest.MonkeyPatch) -> str:
    name = volume_archive(env, root_only_tar())
    (env.root / name).unlink()
    write_raw(env.root / name, [(m.MANIFEST_NAME, b" " * (archive_verify.MAX_MANIFEST_BYTES + 1))])
    return name


def inner(*entries: TarEntry, tail: bytes = b"") -> Callable[[Env, pytest.MonkeyPatch], str]:
    return lambda env, _: volume_archive(env, inner_tar([ROOT, *entries]) + tail)


def outer(member: tuple[str, bytes], at: int = 1) -> Callable[[Env, pytest.MonkeyPatch], str]:
    def build(env: Env, _: pytest.MonkeyPatch) -> str:
        name = volume_archive(env, root_only_tar())
        return rewrite(env, name, lambda ms: [*ms[:at], member, *ms[at:]])

    return build


def outer_headers(*records: list[tuple[str, str]]) -> Callable[[Env, pytest.MonkeyPatch], str]:
    """A signed-looking archive with one outer PAX header per records list right before
    manifest.json, written block by block (tarfile would merge or refuse them)."""

    def build(env: Env, _: pytest.MonkeyPatch) -> str:
        name = volume_archive(env, root_only_tar())
        path = env.root / name
        plain = b""
        for body in map(pax_body, records):
            info = tarfile.TarInfo(PAX_HEADER)
            info.type, info.size = tarfile.XHDTYPE, len(body)
            plain += info.tobuf(tarfile.USTAR_FORMAT) + body + bytes(-len(body) % 512)
        for member, data in tar_members(path):
            info = tarfile.TarInfo(member)
            info.size = len(data)
            plain += info.tobuf(tarfile.USTAR_FORMAT) + data + bytes(-len(data) % 512)
        compressed = zstd.compress(
            plain + bytes(1024), options={zstd.CompressionParameter.checksum_flag: 1}
        )
        path.write_bytes(compressed + writer.trailer(hashlib.sha256(compressed).digest()))
        return name

    return build


def duplicate_member(env: Env, _: pytest.MonkeyPatch) -> str:
    name = volume_archive(env, root_only_tar())
    return rewrite(env, name, lambda ms: [*ms[:2], ms[1], *ms[2:]])


SYMLINK = TarEntry("./a", tarfile.SYMTYPE, linkname="/etc")
FILE = TarEntry("./c", data=b"x")
PAX_HEADER = "././@PaxHeader"
LONG_LINK = "././@LongLink"


def gnu_prefix(prefix: bytes) -> Callable[[bytes], bytes]:
    """A header change to GNU magic with prefix in the atime and ctime fields, which Go
    then reads as a ustar prefix (its pre-1.8 compatibility path)."""
    return lambda b: b[:257] + b"ustar  \x00" + b[265:345] + prefix.ljust(155, b"\0") + b[500:]


FUZZ: dict[str, tuple[Callable[[Env, pytest.MonkeyPatch], str], str | None]] = {
    "outer-dotdot": (outer(("../x", b"x")), "not listed"),
    "outer-absolute": (outer(("/etc/passwd", b"x")), "not listed"),
    "inner-dotdot": (inner(TarEntry("./../x", data=b"x")), "outside its root"),
    "inner-absolute": (inner(TarEntry("/abs", data=b"x")), "outside its root"),
    "write-through-symlink": (
        inner(SYMLINK, TarEntry("./a/passwd", data=b"x")),
        "writes through a symbolic link",
    ),
    "canonical-prefix": (
        inner(SYMLINK, TarEntry(".//a/x", data=b"x")),
        "writes through a symbolic link",
    ),
    "file-over-symlink": (inner(SYMLINK, TarEntry("./a", data=b"x")), "symbolic link"),
    "hardlink-dotdot": (
        inner(TarEntry("./h", tarfile.LNKTYPE, linkname="../../etc/shadow")),
        "hard link outside its root",
    ),
    "hardlink-absolute": (
        inner(TarEntry("./h", tarfile.LNKTYPE, linkname="/etc/shadow")),
        "hard link outside its root",
    ),
    "hardlink-through-symlink": (
        inner(SYMLINK, TarEntry("./h", tarfile.LNKTYPE, linkname="./a/shadow")),
        "symbolic link",
    ),
    "chrdev": (inner(TarEntry("./d", tarfile.CHRTYPE)), "device node or FIFO"),
    "blkdev": (inner(TarEntry("./d", tarfile.BLKTYPE)), "device node or FIFO"),
    "fifo": (inner(TarEntry("./d", tarfile.FIFOTYPE)), "device node or FIFO"),
    "pax-gnu-sparse": (
        inner(TarEntry("./a", data=b"x", pax={"GNU.sparse.name": "./b"})),
        "unsupported tar extended header record",
    ),
    "pax-duplicate-key": (
        inner(
            TarEntry(
                PAX_HEADER, tarfile.XHDTYPE, data=pax_body([("path", "./a"), ("path", "./b")])
            ),
            FILE,
        ),
        "repeats a record",
    ),
    "pax-two-headers": (
        inner(
            TarEntry(PAX_HEADER, tarfile.XHDTYPE, data=pax_body([("comment", "a")])),
            TarEntry(PAX_HEADER, tarfile.XHDTYPE, data=pax_body([("path", "./b")])),
            FILE,
        ),
        "two extended headers",
    ),
    "outer-duplicate": (duplicate_member, "appears twice"),
    # tarfile applies the first of two PAX headers and the guard would apply the last, so
    # the two could read different blocks as the next header (an unchecked GNU long name).
    "outer-two-pax-headers": (
        outer_headers([("comment", "a")], [("size", "1048576")]),
        "two tar extended headers",
    ),
    # A GNU sparse 1.0 map is read by tarfile, of any size, before the member is yielded.
    "outer-gnu-sparse-1.0": (
        outer_headers(
            [
                ("GNU.sparse.major", "1"),
                ("GNU.sparse.minor", "0"),
                ("GNU.sparse.name", m.MANIFEST_NAME),
                ("GNU.sparse.realsize", "1"),
            ]
        ),
        "unsupported tar extended header record",
    ),
    "outer-pax-hdrcharset": (
        outer_headers([("hdrcharset", "BINARY")]),
        "unsupported tar extended header record",
    ),
    "outer-pax-duplicate-key": (
        outer_headers([("comment", "a"), ("comment", "b")]),
        "repeats a record",
    ),
    "million-members": (million_members, "is not listed in the manifest"),
    "zstd-bomb-data": (data_bomb, "more than drydock's limit"),
    "zstd-bomb-metadata": (metadata_bomb, "is too large"),
    # load_staged parses every config at once: they are capped by size and by values.
    "config-over-its-cap": (config_bomb(b" " * (rv.MAX_CONFIG_BYTES + 1)), "is too large"),
    "configs-over-their-total": (
        config_bomb(b"{}" + b" " * 100, MAX_STAGED_CONFIG=100),
        "configuration is larger than drydock's limit",
    ),
    "config-value-bomb": (
        config_bomb(b"[" + b"[]," * 1000 + b"[]]", MAX_CONFIG_VALUES=1000),
        "configuration is larger than drydock's limit",
    ),
    "oversized-manifest": (big_manifest, "is too large"),
    "global-header": (
        inner(TarEntry(PAX_HEADER, tarfile.XGLTYPE, data=pax_body([("comment", "x")])), FILE),
        "unsupported tar entry type",
    ),
    "oversized-pax": (
        inner(TarEntry("./a", data=b"x", pax={"comment": "x" * archive_verify.MAX_PAX_HEADER})),
        "oversized tar extended header",
    ),
    "oversized-long-name": (
        inner(
            TarEntry(
                "././@LongLink", tarfile.GNUTYPE_LONGNAME, data=b"./" + b"a" * rv.MAX_LONG_NAME
            ),
            FILE,
        ),
        "oversized tar extended header",
    ),
    "file-bind-two-entries": (
        lambda env, _: file_bind_archive(
            env, inner_tar([TarEntry("b0", data=b"x"), TarEntry("b1", data=b"y")])
        ),
        "more than one file",
    ),
    "file-bind-wrong-name": (
        lambda env, _: file_bind_archive(env, inner_tar([TarEntry("x", data=b"x")])),
        "does not hold exactly the file b0",
    ),
    "pax-acl-xattr": (
        inner(TarEntry("./a", data=b"x", pax={"SCHILY.xattr.system.posix_acl_access": "x"})),
        "unsupported tar extended header record",
    ),
    "empty-long-name": (
        inner(SYMLINK, TarEntry(LONG_LINK, tarfile.GNUTYPE_LONGNAME), TarEntry("./a/x")),
        "empty tar long name",
    ),
    "empty-pax-path": (
        inner(
            SYMLINK,
            TarEntry(PAX_HEADER, tarfile.XHDTYPE, data=pax_body([("path", "")])),
            TarEntry("./a/x"),
        ),
        "empty tar extended header record",
    ),
    "gnu-prefix-fallback": (
        lambda env, _: volume_archive(
            env,
            with_header(
                inner_tar([ROOT, SYMLINK, TarEntry("./x", data=b"x")]), 1024, gnu_prefix(b"a")
            ),
        ),
        "unsupported format",
    ),
    "dir-entry-without-dot-slash": (inner(TarEntry("a", data=b"x")), "outside its root"),
    "contiguous-file": (
        inner(TarEntry("./c", tarfile.CONTTYPE, data=b"x")),
        "unsupported tar entry type",
    ),
    "pax-bad-atime": (inner(TarEntry("./a", data=b"x", pax={"atime": "xyz"})), "malformed"),
    "pax-bad-ctime": (inner(TarEntry("./a", data=b"x", pax={"ctime": "1.2.3"})), "malformed"),
    "pax-mtime-beyond-int64": (
        inner(TarEntry("./a", data=b"x", pax={"mtime": str(2**63)})),
        "malformed",
    ),
    "pax-uid-beyond-int64": (
        inner(TarEntry("./a", data=b"x", pax={"uid": str(2**63)})),
        "malformed",
    ),
    "pax-gid-beyond-int64": (
        inner(TarEntry("./a", data=b"x", pax={"gid": str(2**64)})),
        "malformed",
    ),
    "pax-size-beyond-int64": (
        inner(TarEntry("./a", data=b"x", pax={"size": str(2**63)})),
        "malformed",
    ),
    "data-after-end": (inner(tail=b"\x01" + bytes(511)), "after its end-of-archive marker"),
}


@pytest.mark.parametrize("case", list(FUZZ))
def test_fuzz_corpus_is_rejected(env: Env, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    build, message = FUZZ[case]
    name = build(env, monkeypatch)
    started = time.monotonic()
    with pytest.raises(VerifyError, match=message):
        verify(env, name)
    assert time.monotonic() - started < 30
    assert not rv.restore_dir(env.staging, 1).exists()
    assert list(env.staging.iterdir()) == []


# INNER GUARD


def run_guard(guard: InnerTarGuard, data: bytes, step: int) -> bytes:
    out = b"".join(guard.feed(data[i : i + step]) for i in range(0, len(data), step))
    return out + guard.close()


def docker_style(*extra: TarEntry) -> bytes:
    return inner_tar(
        [
            TarEntry("./", tarfile.DIRTYPE, mode=0o750, uid=999, gid=998),
            TarEntry("./bin/", tarfile.DIRTYPE, mode=0o755),
            TarEntry("./data/", tarfile.DIRTYPE, uid=999, gid=999, mode=0o700),
            TarEntry(
                "./data/file",
                data=b"x" * 1000,
                uid=999,
                gid=999,
                mode=0o600,
                pax={"uname": "postgres", "gname": "postgres"},
            ),
            TarEntry("./data/link", tarfile.SYMTYPE, linkname="file", mode=0o777),
            TarEntry("./data/hard", tarfile.LNKTYPE, linkname="./data/file", mode=0o600),
            TarEntry("./data/" + "n" * 150, data=b"a long name"),
            TarEntry("./" + "d" * 120 + "/", tarfile.DIRTYPE),
            TarEntry("./etc-link", tarfile.SYMTYPE, linkname="/etc"),
            TarEntry("./empty", data=b""),
            *extra,
        ]
    )


def test_inner_guard_accepts_docker_style_tars() -> None:
    capability = TarEntry("./bin/ping", data=b"ping", mode=0o755, pax={rv.CAPABILITY_XATTR: CAP})
    setuid = TarEntry("./bin/su", data=b"su", mode=0o4755)
    for extra, setid in (((), False), ((capability,), True), ((setuid,), True)):
        data = docker_style(*extra)
        for step in (1, 511, 1024 * 1024):
            guard = InnerTarGuard("dir")
            assert run_guard(guard, data, step) == data
            facts = guard.facts()
            assert facts.setid is setid
            assert (facts.root_mode, facts.root_uid, facts.root_gid) == (0o750, 999, 998)
            assert facts.entries == 10 + len(extra)
    # Image tars hold relative names without "./" and expose their metadata.
    image = image_tar(IMAGE_ID, ["busybox:1.37"])
    guard = InnerTarGuard("image", capture=rv.IMAGE_META_FILES)
    assert run_guard(guard, image, 333) == image
    assert set(guard.captured) == {"index.json", "manifest.json"}


def test_inner_guard_holds_back_headers_until_checked() -> None:
    valid = inner_tar([ROOT, TarEntry("./a", data=b"hello")])
    with tarfile.open(fileobj=io.BytesIO(valid)) as tar:
        end = tar.getmembers()[-1].offset_data + tarfile.BLOCKSIZE
    device = inner_tar([TarEntry("./d", tarfile.CHRTYPE)])
    guard = InnerTarGuard("dir")
    out = guard.feed(valid[:end] + device[:300])
    assert out == valid[:end]
    with pytest.raises(VerifyError, match="device node or FIFO"):
        guard.feed(device[300:512])
    # A PAX header waits for its entry's header block, and both are released together.
    long_entry = inner_tar([TarEntry("./" + "n" * 150, data=b"x")])
    guard = InnerTarGuard("dir")
    assert guard.feed(valid[:end]) == valid[:end]
    assert guard.feed(long_entry[: 1024 + 100]) == b""
    released = guard.feed(long_entry[1024 + 100 : 1536])
    assert released == long_entry[:1536]
    with pytest.raises(VerifyError, match="ends in the middle"):
        guard.close()


def test_inner_guard_renames_a_file_bind_member() -> None:
    data = inner_tar(
        [
            TarEntry(
                "b3", data=b"config", uid=1000, gid=1001, mode=0o640, pax={rv.CAPABILITY_XATTR: CAP}
            )
        ]
    )
    guard = InnerTarGuard("file", file_name="b3", rename_to="app.conf")
    out = run_guard(guard, data, 100)
    assert guard.facts().setid
    with tarfile.open(fileobj=io.BytesIO(out)) as tar:
        members = tar.getmembers()
        assert [i.name for i in members] == ["app.conf"]
        info = members[0]
        assert (info.uid, info.gid, info.mode, info.mtime) == (1000, 1001, 0o640, 1_760_000_000)
        assert tar.extractfile(info).read() == b"config"  # type: ignore[union-attr]
        assert info.pax_headers[rv.CAPABILITY_XATTR] == CAP
    # The renamed stream passes the same checks.
    assert run_guard(InnerTarGuard("file", file_name="app.conf"), out, 4096) == out
    with pytest.raises(ValueError):
        InnerTarGuard("dir", rename_to="x")
    with pytest.raises(ValueError):
        InnerTarGuard("file", file_name="b3", rename_to="../x")


def with_header(data: bytes, offset: int, change: Callable[[bytes], bytes]) -> bytes:
    """data with the header block at offset changed and its checksum recomputed."""
    header = bytearray(change(data[offset : offset + 512]))
    header[148:156] = b"        "
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    return data[:offset] + bytes(header) + data[offset + 512 :]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda b: b[:124] + b"\xff" * 12 + b[136:], "damaged"),  # negative base-256
        (lambda b: b[:124] + b"\x80" + (2**63).to_bytes(11) + b[136:], "damaged"),
        (lambda b: b[:124] + b"0000 0000005" + b[136:], "damaged"),  # space in the digits
        (lambda b: b[:257] + bytes(8) + b[265:], "unsupported format"),  # v7 header
        (lambda b: b[:508] + b"tar\x00", "unsupported format"),  # star
    ],
    ids=["negative-size", "size-beyond-int64", "space-in-size", "v7", "star"],
)
def test_inner_guard_refuses_headers_go_reads_differently(change, message: str) -> None:
    data = with_header(inner_tar([ROOT, TarEntry("./a", data=b"hello")]), 512, change)
    with pytest.raises(VerifyError, match=message):
        InnerTarGuard("dir").feed(data)


def test_inner_guard_reads_numbers_as_go_does() -> None:
    """A size field led by a NUL is 0 to tarfile but 5 to Go, which trims NULs and
    spaces; the guard follows Go, so it stays aligned with what Docker extracts."""
    data = inner_tar([ROOT, TarEntry("./a", data=b"hello")])
    nul_led = with_header(data, 512, lambda b: b[:124] + b"\x000000000005\x00" + b[136:])
    assert tarfile.TarInfo.frombuf(nul_led[512:1024], "utf-8", "strict").size == 0
    assert run_guard(InnerTarGuard("dir"), nul_led, 700) == nul_led
    # The same field claiming more data than follows leaves the guard mid-entry.
    long = with_header(data, 512, lambda b: b[:124] + b"\x000000077777\x00" + b[136:])
    guard = InnerTarGuard("dir")
    guard.feed(long)
    with pytest.raises(VerifyError, match="middle of an entry"):
        guard.close()


def test_inner_guard_reads_gnu_headers_as_go_does() -> None:
    """GNU headers have no prefix, unless atime or ctime fails to parse: then Go reads
    those bytes as one. Valid or empty times pass; anything else is refused."""
    data = inner_tar([ROOT, TarEntry("./a", data=b"hello")])
    for times in (b"", b"00000000001\x0000000000002\x00"):
        gnu = with_header(data, 512, gnu_prefix(times))
        assert run_guard(InnerTarGuard("dir"), gnu, 700) == gnu
    for times in (b"a", b"0000000000x\x00", b"\x80" + bytes(10) + b"\x01"):
        with pytest.raises(VerifyError, match="unsupported format"):
            InnerTarGuard("dir").feed(with_header(data, 512, gnu_prefix(times)))


TAGGED_MANIFEST = json.dumps([{"Config": "c.json", "RepoTags": ["drydock:local"]}]).encode()


@pytest.mark.parametrize(
    ("entries", "change", "message"),
    [
        (
            [TarEntry(LONG_LINK, tarfile.GNUTYPE_LONGNAME), TarEntry("manifest.json")],
            None,
            "empty tar long name",
        ),
        (
            [
                TarEntry(PAX_HEADER, tarfile.XHDTYPE, data=pax_body([("path", "")])),
                TarEntry("manifest.json"),
            ],
            None,
            "empty tar extended header record",
        ),
        (
            [TarEntry("x")],
            lambda b: bytes(100) + gnu_prefix(b"manifest.json")(b)[100:],
            "unsupported format",
        ),
        ([TarEntry("")], None, "no name"),
        ([TarEntry(".")], None, "root that is not a directory"),
        ([TarEntry("manifest.json", data=b"[]"), TarEntry("manifest.json")], None, "twice"),
        ([TarEntry("index.json", data=b"{}"), TarEntry("./index.json")], None, "twice"),
        (
            [TarEntry("manifest.json", data=b"[]"), TarEntry("manifest.json", tarfile.CONTTYPE)],
            None,
            "unsupported tar entry type",
        ),
    ],
    ids=[
        "empty-long-name",
        "empty-pax-path",
        "gnu-prefix",
        "empty-name",
        "regular-root",
        "duplicate-manifest",
        "duplicate-index",
        "contiguous-manifest",
    ],
)
def test_inner_guard_refuses_image_names_docker_reads_differently(
    entries: list[TarEntry], change: Callable[[bytes], bytes] | None, message: str
) -> None:
    """Each tar hides a manifest.json (moving a tag) from the guard's capture, if read
    differently from Go; the guard refuses it instead."""
    entries = [*entries[:-1], dataclasses.replace(entries[-1], data=TAGGED_MANIFEST)]
    data = inner_tar(entries)
    if change is not None:
        data = with_header(data, 0, change)
    with pytest.raises(VerifyError, match=message):
        run_guard(InnerTarGuard("image", capture=rv.IMAGE_META_FILES), data, 512)


def test_inner_guard_flags_setid_hard_links() -> None:
    """Docker applies a hard link's mode to the file it links to."""
    for mode, setid in ((0o755, False), (0o4755, True), (0o2755, True)):
        data = inner_tar(
            [
                ROOT,
                TarEntry("./etc/", tarfile.DIRTYPE),
                TarEntry("./etc/passwd", data=b"#!/bin/sh\n", mode=0o755),
                TarEntry("./y", tarfile.LNKTYPE, linkname="etc/passwd", mode=mode),
            ]
        )
        guard = InnerTarGuard("dir")
        run_guard(guard, data, 512)
        assert guard.facts().setid is setid


# PASS 2


def test_pass_two_reader_rehashes_and_detects_changes(env: Env) -> None:
    name, manifest = web_archive(env)
    staged = verify(env, name)
    volume = manifest.volumes[0].data_member or ""
    bind = manifest.binds[0].data_member or ""
    original = dict(tar_members(env.root / name))
    cancel = threading.Event()
    with rv.open_verified(env.storage, staged, env.crypto, cancel) as reader:
        reader.advance_to(volume)
        assert b"".join(reader.data(volume)) == original[volume]
        reader.advance_to(bind)
        assert b"".join(reader.data(bind)) == original[bind]
        assert reader.facts(volume).root_uid == 999
        reader.close()
    # Skipping a member hashes it; going back or reading without advancing is refused.
    with rv.open_verified(env.storage, staged, env.crypto, cancel) as reader:
        with pytest.raises(VerifyError, match="not advanced"):
            reader.data(volume)
        reader.advance_to(bind)
        with pytest.raises(VerifyError, match="out of archive order"):
            reader.advance_to(volume)
    # The staged copy reloaded (as the dispatcher does) reads the same.
    reloaded = rv.load_staged(staged.dest, env.crypto)
    with rv.open_verified(env.storage, reloaded, env.crypto, cancel) as reader:
        reader.advance_to(bind)
        cancel.set()
        with pytest.raises(writer.Cancelled):
            b"".join(reader.data(bind))
    path = env.root / name
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
    with (
        pytest.raises(VerifyError, match="changed since it was verified"),
        rv.open_verified(env.storage, staged, env.crypto, cancel),
    ):
        pass
    staged = verify(env, name, run_id=2)
    path.write_bytes(path.read_bytes())
    with (
        pytest.raises(VerifyError, match="changed since it was verified"),
        rv.open_verified(env.storage, staged, env.crypto, cancel),
    ):
        pass


def with_sums(staged: rv.Staged, changed: set[str]) -> rv.Staged:
    """staged with the pass-1 sums of changed members altered, as if the bytes pass 2
    reads (behind the same fstat identity) differed from the bytes pass 1 verified."""
    members = tuple(
        dataclasses.replace(s, sha256="0" * 64) if s.name in changed else s
        for s in staged.verification.members
    )
    return dataclasses.replace(
        staged, verification=dataclasses.replace(staged.verification, members=members)
    )


def test_pass_two_rehashes_every_member_against_pass_one(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    big = os.urandom(64 * 1024)
    volume_data = inner_tar([ROOT, TarEntry("./big", data=big)])
    name, manifest = web_archive(env, volumes={"data": volume_data})
    staged = verify(env, name)
    volume = manifest.volumes[0].data_member or ""
    bind = manifest.binds[0].data_member or ""
    order = [s.name for s in staged.verification.members]
    assert order.index(volume) < order.index(bind)
    monkeypatch.setattr(rv, "CHUNK", 4096)  # many pieces, so one must be held back
    # A data member whose bytes differ fails at its end, and its last piece (with the
    # end-of-archive marker) is never released.
    with rv.open_verified(env.storage, with_sums(staged, {volume}), env.crypto, None) as reader:
        reader.advance_to(volume)
        released = []
        with pytest.raises(VerifyError, match=f"{volume} changed since it was verified"):
            for piece in reader.data(volume):
                released.append(piece)
        out = b"".join(released)
        assert released and out != volume_data and volume_data.startswith(out)
        assert volume_data[len(out) :].endswith(bytes(1024))
        with pytest.raises(VerifyError, match="not read to the end"):
            reader.advance_to(bind)
    # A member skipped on the way is hashed too.
    with (
        rv.open_verified(env.storage, with_sums(staged, {volume}), env.crypto, None) as reader,
        pytest.raises(VerifyError, match=f"{volume} changed since it was verified"),
    ):
        reader.advance_to(bind)
    # So is the member advanced to and then passed over without being read.
    with rv.open_verified(env.storage, with_sums(staged, {volume}), env.crypto, None) as reader:
        reader.advance_to(volume)
        with pytest.raises(VerifyError, match=f"{volume} changed since it was verified"):
            reader.advance_to(bind)
    # Pass 2 runs the inner guard again: a member that no longer passes it is refused.
    monkeypatch.setattr(rv.ArchiveReader, "_guard_kind", lambda self, member: ("file", "not-there"))
    with rv.open_verified(env.storage, staged, env.crypto, None) as reader:
        reader.advance_to(volume)
        with pytest.raises(VerifyError, match="does not hold exactly the file"):
            b"".join(reader.data(volume))


@needs_age
def test_pass_two_reads_encrypted_archives_with_the_recorded_passphrase(env: Env) -> None:
    key_a, key_b = os.urandom(32), os.urandom(32)
    big = os.urandom(3 * 1024 * 1024)
    volume_data = inner_tar([ROOT, TarEntry("./big", data=big)])
    name, manifest = web_archive(env, Crypto((key_a,)), volumes={"data": volume_data}, encrypt=True)
    crypto = Crypto((key_b, key_a))
    staged = verify(env, name, crypto)
    assert staged.verification.passphrase_index == 1
    volume = manifest.volumes[0].data_member or ""
    with rv.open_verified(env.storage, staged, crypto, threading.Event()) as reader:
        reader.advance_to(volume)
        assert b"".join(reader.data(volume)) == volume_data
        reader.close()
    assert age_children() == []
    with rv.open_verified(env.storage, staged, crypto, threading.Event()) as reader:
        reader.advance_to(volume)
        chunks = reader.data(volume)
        assert next(chunks)
        chunks.close()
    assert age_children() == []
    # A key rotated in after pass 1 shifts the recorded index; pass 2 still finds key A.
    rotated = Crypto((os.urandom(32), key_b, key_a))
    with rv.open_verified(env.storage, staged, rotated, threading.Event()) as reader:
        reader.advance_to(volume)
        assert b"".join(reader.data(volume)) == volume_data
    with (
        pytest.raises(VerifyError, match="No configured secret key decrypts"),
        rv.open_verified(env.storage, staged, Crypto((key_b,)), threading.Event()),
    ):
        pass
    assert age_children() == []


# LISTING


def test_head_preview_reads_the_manifest_without_the_catalog(env: Env) -> None:
    name, manifest = web_archive(env)
    head = (env.root / name).read_bytes()[: rv.HEAD_BYTES]
    assert rv.read_head_manifest(head) == rv.Preview("manifest", manifest=manifest)
    assert rv.preview(env.storage, name) == rv.Preview("manifest", manifest=manifest)
    assert (
        rv.read_head_manifest(archive_verify.AGE_MAGIC + b"-> scrypt x 14\n").state == "encrypted"
    )
    random = rv.read_head_manifest(os.urandom(4096))
    assert random.state == "unreadable" and random.reason == "not a drydock archive"
    missing = rv.preview(
        env.storage, archive_name(str(uuid.uuid4()), "x", datetime.now(UTC), False)
    )
    assert missing.state == "unreadable" and "does not exist" in (missing.reason or "")
    # A bomb: a manifest header claiming the maximum size, then 256 MiB of zeros.
    header = tarfile.TarInfo(m.MANIFEST_NAME)
    header.size = archive_verify.MAX_MANIFEST_BYTES
    bomb = zstd.compress(header.tobuf(tarfile.PAX_FORMAT) + bytes(256 * 2**20))
    assert len(bomb) < rv.HEAD_BYTES
    started = time.monotonic()
    result = rv.read_head_manifest(bomb)
    assert result.state == "unreadable" and time.monotonic() - started < 5
    zeros = rv.read_head_manifest(zstd.compress(bytes(64 * 2**20)))
    assert zeros.state == "unreadable"


def test_parse_name_anchors_the_uuid_before_the_stamp() -> None:
    job, decoy = uuid.uuid4(), uuid.uuid4()
    created = datetime(2026, 10, 14, 12, 0, 1, tzinfo=UTC)
    name = archive_name(str(job), str(decoy), created, True)
    parsed = parse_name(name)
    assert parsed.job_uuid == job and parsed.slug == str(decoy)
    assert parsed.created_at == created and parsed.encrypted
    assert not parse_name(archive_name(str(job), "web", created, False)).encrypted
    for bad in (name + "x", name.replace("20261014", "20261314"), "drydock-web.tar.zst", "../x"):
        with pytest.raises(StorageError, match="Invalid archive name"):
            parse_name(bad)


# CRYPTO


def test_crypto_bytes_round_trip_across_rotation() -> None:
    old, new = os.urandom(32), os.urandom(32)
    token = Crypto((old,)).encrypt_bytes(b"\x00secret\xff")
    rotated = Crypto((new, old))
    assert rotated.decrypt_bytes(token) == b"\x00secret\xff"
    fresh = rotated.encrypt_bytes(b"\x00secret\xff")
    assert Crypto((new,)).decrypt_bytes(fresh) == b"\x00secret\xff"
    with pytest.raises(CryptoError):
        Crypto((new,)).decrypt_bytes(token)
    with pytest.raises(CryptoError):
        rotated.decrypt_bytes(token[:-1] + b"A")


def test_staged_image_that_changed_is_gone(env: Env) -> None:
    name, manifest = web_archive(env)
    staged = verify(env, name)
    member = manifest.images[0].data_member or ""
    path = staged.images[member]
    original = path.read_bytes()
    with rv.open_staged_image(staged, member) as handle:
        assert handle.read() == original
    # Rewritten in place (same bytes, even), or replaced by another file: refused.
    path.write_bytes(original)
    info = path.stat()
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
    with pytest.raises(VerifyError, match="is gone"):
        rv.load_staged(staged.dest, env.crypto)
    with pytest.raises(VerifyError, match="is gone"):
        rv.open_staged_image(staged, member)
    path.unlink()
    path.symlink_to(staged.dest / m.MANIFEST_NAME)
    with pytest.raises(VerifyError, match="is gone"):
        rv.open_staged_image(staged, member)
    with pytest.raises(VerifyError, match="is gone"):
        rv.open_staged_image(staged, "images/" + "0" * 64 + ".tar")


def test_staged_data_that_was_changed_or_removed_is_gone(env: Env) -> None:
    name, manifest = web_archive(env)
    staged = verify(env, name)
    member = manifest.containers[0].config_member or ""
    token = (staged.dest / member).read_bytes()
    (staged.dest / member).unlink()
    with pytest.raises(VerifyError, match="is gone"):
        rv.load_staged(staged.dest, env.crypto)
    # A valid token for other content is refused by its pass-1 sum.
    (staged.dest / member).write_bytes(env.crypto.encrypt_bytes(b"{}"))
    with pytest.raises(VerifyError, match="is gone"):
        rv.load_staged(staged.dest, env.crypto)
    (staged.dest / member).unlink()
    (staged.dest / member).symlink_to(staged.dest / "elsewhere")
    with pytest.raises(VerifyError, match="is gone"):
        rv.load_staged(staged.dest, env.crypto)
    (staged.dest / member).unlink()
    (staged.dest / member).write_bytes(token)
    assert rv.load_staged(staged.dest, env.crypto) == staged
    rv.remove_restore_dir(env.staging, 1)
    assert not staged.dest.exists()
    rv.remove_restore_dir(env.staging, 1)  # already gone: fine
    with pytest.raises(VerifyError, match="is gone"):
        rv.load_staged(staged.dest, env.crypto)
