"""Local storage: root containment, archive names and atomic writes."""

import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from drydock.config import Settings
from drydock.storage import base
from drydock.storage.local import PARTIAL_PREFIX, LocalStorage, validate_root
from tests.conftest import make_settings

NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def roots(tmp_path: Path) -> Path:
    allowed = tmp_path / "backups"
    allowed.mkdir()
    return allowed


@pytest.fixture
def storage_settings(tmp_path: Path, roots: Path) -> Settings:
    return make_settings(tmp_path / "data", DRYDOCK_LOCAL_STORAGE_ROOTS=str(roots))


def local_file(tmp_path: Path, data: bytes = b"archive bytes") -> Path:
    path = tmp_path / f"staged-{uuid.uuid4().hex}"
    path.write_bytes(data)
    return path


# ROOTS


def test_root_inside_the_allowlist(roots: Path, storage_settings: Settings) -> None:
    (roots / "nightly").mkdir()
    assert validate_root(roots / "nightly", storage_settings) == (roots / "nightly").resolve()
    assert validate_root(roots, storage_settings) == roots.resolve()


@pytest.mark.parametrize("where", ["outside", "relative", "missing", "file", "symlink-out"])
def test_root_outside_the_allowlist_is_rejected(
    tmp_path: Path, roots: Path, storage_settings: Settings, where: str
) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    candidates = {
        "outside": outside,
        "relative": Path("backups"),
        "missing": roots / "nope",
        "file": roots / "file",
        "symlink-out": roots / "escape",
    }
    (roots / "file").write_bytes(b"")
    (roots / "escape").symlink_to(outside)
    with pytest.raises(base.StorageError):
        validate_root(candidates[where], storage_settings)
    with pytest.raises(base.StorageError):
        LocalStorage(candidates[where], storage_settings)


def test_empty_allowlist_rejects_everything(tmp_path: Path, roots: Path) -> None:
    settings = make_settings(tmp_path / "data")
    with pytest.raises(base.StorageError, match="DRYDOCK_LOCAL_STORAGE_ROOTS"):
        validate_root(roots, settings)


@pytest.mark.parametrize("which", ["data", "staging", "inside-data", "parent-of-data"])
def test_root_overlapping_drydock_directories_is_rejected(tmp_path: Path, which: str) -> None:
    data = tmp_path / "data"
    staging = data / "staging"
    staging.mkdir(parents=True)
    (data / "sub").mkdir()
    paths = {
        "data": data,
        "staging": staging,
        "inside-data": data / "sub",
        "parent-of-data": tmp_path,
    }
    # Even when an admin lists the directory as a storage root.
    settings = make_settings(data, DRYDOCK_LOCAL_STORAGE_ROOTS=str(tmp_path))
    with pytest.raises(base.StorageError, match="overlaps"):
        validate_root(paths[which], settings)


# NAMES


def test_archive_name_comes_from_ids_and_a_slug() -> None:
    job = str(uuid.uuid4())
    name = base.archive_name(job, "../../x", NOW, encrypted=False)
    assert name == f"drydock-x-{job}-20261013T120000Z.tar.zst"
    assert base.archive_name(job, "Web App/../DB!", NOW, encrypted=True).startswith(
        "drydock-web-app-db-"
    )
    assert base.archive_name(job, "///", NOW, encrypted=True).endswith(".tar.zst.age")
    assert base.archive_name(job, "///", NOW, encrypted=False).startswith("drydock-job-")
    with pytest.raises(ValueError):
        base.archive_name("../../etc", "x", NOW, encrypted=False)


@pytest.mark.parametrize(
    "name", ["../x", "a/b", "/etc/passwd", "", ".hidden", "x\0y", "A" * 300, "..", "a..b"]
)
def test_unsafe_names_are_refused(roots: Path, storage_settings: Settings, name: str) -> None:
    storage = LocalStorage(roots, storage_settings)
    with pytest.raises(base.StorageError):
        storage.read_head(name, 10)
    with pytest.raises(base.StorageError):
        storage.delete(name)


def test_job_named_dot_dot_writes_inside_the_root(
    tmp_path: Path, roots: Path, storage_settings: Settings
) -> None:
    storage = LocalStorage(roots, storage_settings)
    name = base.archive_name(str(uuid.uuid4()), "../../x", NOW, encrypted=False)
    stored = storage.put(local_file(tmp_path), name, None, threading.Event())
    assert stored.name == name
    assert [p.name for p in roots.iterdir()] == [name]
    assert not list(tmp_path.glob("x*"))
    assert (roots / name).stat().st_mode & 0o777 == 0o600


# OPERATIONS


def test_put_list_get_read_head_delete(
    tmp_path: Path, roots: Path, storage_settings: Settings
) -> None:
    storage = LocalStorage(roots, storage_settings)
    storage.test()
    data = os.urandom(20 * 1024 * 1024)
    seen: list[int] = []
    name = base.archive_name(str(uuid.uuid4()), "web", NOW, encrypted=False)
    stored = storage.put(local_file(tmp_path, data), name, seen.append, threading.Event())
    assert stored.size == len(data)
    assert seen[-1] == len(data) and len(seen) == 3  # 8 MiB chunks
    assert [o.name for o in storage.list()] == [name]
    assert storage.list(prefix="drydock-other") == []
    assert storage.read_head(name, 16) == data[:16]
    copy = tmp_path / "copy"
    assert storage.get(name, copy, None, threading.Event()) == len(data)
    assert copy.read_bytes() == data
    with pytest.raises(base.StorageError, match="already exists"):
        storage.put(local_file(tmp_path), name, None, threading.Event())
    storage.delete(name)
    assert storage.list() == []
    with pytest.raises(base.StorageError):
        storage.delete(name)


def test_cancelled_put_leaves_nothing(
    tmp_path: Path, roots: Path, storage_settings: Settings
) -> None:
    storage = LocalStorage(roots, storage_settings)
    cancel = threading.Event()
    name = base.archive_name(str(uuid.uuid4()), "web", NOW, encrypted=False)

    def progress(done: int) -> None:
        cancel.set()

    source = local_file(tmp_path, os.urandom(20 * 1024 * 1024))
    with pytest.raises(base.StorageError, match="cancelled"):
        storage.put(source, name, progress, cancel)
    assert list(roots.iterdir()) == []


def test_list_ignores_partials_symlinks_and_foreign_files(
    tmp_path: Path, roots: Path, storage_settings: Settings
) -> None:
    storage = LocalStorage(roots, storage_settings)
    (roots / f"{PARTIAL_PREFIX}abc").write_bytes(b"x")  # not a name drydock makes
    (roots / f"{PARTIAL_PREFIX}{'d' * 32}").write_bytes(b"x")
    (roots / "Notes.TXT").write_bytes(b"x")
    link = base.archive_name(str(uuid.uuid4()), "link", NOW, encrypted=False)
    (roots / link).symlink_to(tmp_path / "secret")
    (roots / base.archive_name(str(uuid.uuid4()), "dir", NOW, encrypted=False)).mkdir()
    assert storage.list() == []
    with pytest.raises(base.StorageError):
        storage.read_head(link, 10)
    assert storage.remove_partials() == 1
    assert not (roots / f"{PARTIAL_PREFIX}{'d' * 32}").exists()
    assert (roots / f"{PARTIAL_PREFIX}abc").exists()


def test_archive_written_in_place_is_published_without_replacing(
    roots: Path, storage_settings: Settings
) -> None:
    storage = LocalStorage(roots, storage_settings)
    name = base.archive_name(str(uuid.uuid4()), "web", NOW, encrypted=False)
    partial = storage.new_partial()
    assert partial.parent == roots.resolve() and not partial.exists()
    partial.write_bytes(b"first")
    stored = storage.publish(partial, name)
    assert (stored.name, stored.size) == (name, 5)
    assert not partial.exists() and (roots / name).read_bytes() == b"first"
    # A second archive under the same name never replaces the first.
    again = storage.new_partial()
    again.write_bytes(b"second")
    with pytest.raises(base.StorageError, match="already exists"):
        storage.publish(again, name)
    assert (roots / name).read_bytes() == b"first"
    # Only drydock's own temporary names in the root can be published.
    (roots / "Notes.TXT").write_bytes(b"x")
    for bad in (roots / "Notes.TXT", roots.parent / again.name):
        with pytest.raises(base.StorageError, match="temporary name"):
            storage.publish(bad, base.archive_name(str(uuid.uuid4()), "x", NOW, encrypted=False))


def test_root_swapped_for_a_symlink_is_refused(
    tmp_path: Path, roots: Path, storage_settings: Settings
) -> None:
    (roots / "nightly").mkdir()
    storage = LocalStorage(roots / "nightly", storage_settings)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (roots / "nightly").rmdir()
    (roots / "nightly").symlink_to(outside)
    name = base.archive_name(str(uuid.uuid4()), "web", NOW, encrypted=False)
    with pytest.raises(base.StorageError):
        storage.put(local_file(tmp_path), name, None, threading.Event())
    assert list(outside.iterdir()) == []


def test_root_removed_from_allowlist_is_refused_later(
    tmp_path: Path, roots: Path, storage_settings: Settings
) -> None:
    storage = LocalStorage(roots, storage_settings)
    narrowed = make_settings(tmp_path / "data", DRYDOCK_LOCAL_STORAGE_ROOTS=str(tmp_path / "x"))
    storage._settings = narrowed
    with pytest.raises(base.StorageError):
        storage.list()


def test_unwritable_root_fails_the_test(roots: Path, storage_settings: Settings) -> None:
    storage = LocalStorage(roots, storage_settings)
    roots.chmod(0o500)
    try:
        with pytest.raises(base.StorageError, match="not writable"):
            storage.test()
    finally:
        roots.chmod(0o700)
