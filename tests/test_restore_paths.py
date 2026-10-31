"""Restores from a server path (restore.paths, POST /restore/from-path): every refused
path, the check-then-open race, an allowlist no route can change, and the wizard fed from
a path."""

import dataclasses
import os
import re
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from drydock.config import Settings
from drydock.restore import paths, verify
from drydock.restore.paths import PathError, ServerFile, open_checked
from drydock.routes import restore as restore_routes
from tests.conftest import Browser, make_settings, running
from tests.restore_support import build_archive, image_tar
from tests.test_restore_routes import audits, run_status, stored

pytestmark = pytest.mark.anyio

NAME = "drydock-web-0b5e4c38-8c5a-4e43-9a1c-6c0f5a3f6b21-20261030T120000Z.tar.zst"


@pytest.fixture
def inbox(tmp_path: Path) -> Path:
    path = tmp_path / "inbox"
    path.mkdir()
    (path / NAME).write_bytes(b"archive")
    return path


# REFUSED PATHS


def refused(path: str | Path, allowed: tuple[Path, ...], message: str) -> None:
    with pytest.raises(PathError, match=message):
        open_checked(str(path), allowed)


def test_an_allowed_file_opens(inbox: Path) -> None:
    handle, real = open_checked(str(inbox / NAME), (inbox,))
    with handle:
        assert handle.read() == b"archive"
    assert real == inbox / NAME


def test_relative_and_dot_dot_paths_are_refused(inbox: Path, tmp_path: Path) -> None:
    (tmp_path / NAME).write_bytes(b"outside")
    refused(f"../{NAME}", (inbox,), "absolute path")
    refused(NAME, (inbox,), "absolute path")
    refused(f"{inbox}/../{NAME}", (inbox,), "not inside")
    refused(f"{inbox}/sub/../../{NAME}", (inbox,), "not inside")


def test_a_path_outside_the_allowlist_is_refused(inbox: Path, tmp_path: Path) -> None:
    (tmp_path / NAME).write_bytes(b"outside")
    refused(tmp_path / NAME, (inbox,), "not inside")
    refused(inbox, (inbox,), "not inside")  # the allowed directory itself
    refused(f"{inbox}x/{NAME}", (inbox,), "not inside")  # a sibling sharing the prefix


def test_nothing_is_allowed_without_an_allowlist(inbox: Path) -> None:
    refused(inbox / NAME, (), "DRYDOCK_RESTORE_PATHS")


def test_a_symlink_pointing_outside_is_refused(inbox: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / NAME).write_bytes(b"outside")
    (inbox / ("drydock-x" + NAME.removeprefix("drydock-web"))).symlink_to(outside / NAME)
    refused(inbox / ("drydock-x" + NAME.removeprefix("drydock-web")), (inbox,), "not inside")
    (inbox / "linked-dir").symlink_to(outside)
    refused(inbox / "linked-dir" / NAME, (inbox,), "not inside")


def test_a_symlink_swapped_in_after_the_check_is_caught(
    inbox: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """realpath passes on a real directory; it becomes a symlink before the open."""
    sub = inbox / "sub"
    sub.mkdir()
    (sub / NAME).write_bytes(b"inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / NAME).write_bytes(b"outside")
    real_realpath = os.path.realpath

    def realpath_then_swap(path: str) -> str:
        result = real_realpath(path)
        if path == str(sub / NAME):
            (sub / NAME).unlink()
            sub.rmdir()
            sub.symlink_to(outside)
        return result

    monkeypatch.setattr(paths.os.path, "realpath", realpath_then_swap)
    refused(sub / NAME, (inbox,), "changed while it was opened")


def test_the_last_component_swapped_for_a_symlink_is_refused(
    inbox: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "other").write_bytes(b"outside")
    real_realpath = os.path.realpath

    def realpath_then_swap(path: str) -> str:
        result = real_realpath(path)
        if path == str(inbox / NAME):
            (inbox / NAME).unlink()
            (inbox / NAME).symlink_to(tmp_path / "other")
        return result

    monkeypatch.setattr(paths.os.path, "realpath", realpath_then_swap)
    refused(inbox / NAME, (inbox,), "cannot be opened")  # O_NOFOLLOW: ELOOP


def test_a_directory_and_a_fifo_are_refused(inbox: Path) -> None:
    directory = inbox / ("drydock-d" + NAME.removeprefix("drydock-web"))
    directory.mkdir()
    refused(directory, (inbox,), "not a regular file")
    fifo = inbox / ("drydock-f" + NAME.removeprefix("drydock-web"))
    os.mkfifo(fifo)
    refused(fifo, (inbox,), "not a regular file")  # and the open did not block


def test_only_archive_names_are_opened(inbox: Path) -> None:
    (inbox / "passwd").write_bytes(b"x")
    refused(inbox / "passwd", (inbox,), "Only archives")
    refused(inbox / "missing" / NAME, (inbox,), "does not exist")


def test_no_route_can_change_the_allowlist(settings: Settings) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        settings.restore_paths = ()  # type: ignore[misc]
    # Routes only read it, and only the restore routes at that; nothing rebuilds Settings.
    routes = Path(restore_routes.__file__).parent
    for module in routes.glob("*.py"):
        text = module.read_text()
        reads = re.findall(r"settings\.restore_paths\s*(=?)", text)
        assert all(after != "=" for after in reads), module.name
        assert ("settings.restore_paths" in text) == (module.name == "restore.py"), module.name
        assert "state.settings =" not in text and "Settings(" not in text, module.name


# THE WIZARD FROM A PATH


@pytest.fixture
async def with_inbox(tmp_path: Path) -> AsyncIterator[Browser]:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (tmp_path / "storage").mkdir()
    settings = make_settings(tmp_path / "data", DRYDOCK_RESTORE_PATHS=str(inbox))
    async with running(settings) as browser:
        response = await browser.setup()
        assert response.status_code == 303
        yield browser


def image_archive(browser: Browser) -> str:
    image_id = "sha256:" + "a" * 64
    name, _ = build_archive(
        browser.settings.restore_paths[0],
        browser.app.state.crypto,
        scope="image",
        images=[(image_id, ["busybox:1.37"], image_tar(image_id, ["busybox:1.37"]), None)],
    )
    return name


async def test_a_path_feeds_the_wizard(with_inbox: Browser) -> None:
    browser = with_inbox
    inbox = browser.settings.restore_paths[0]
    page = await browser.get("/restore")
    assert 'action="/restore/from-path"' in page.text and str(inbox) in page.text
    name = image_archive(browser)
    response = await browser.post("/restore/from-path", {"path": f" {inbox}/./{name} "})
    assert response.status_code == 303, response.text
    run_id = int(response.headers["location"].split("/")[3])
    await browser.app.state.dispatcher.wait(run_id)
    assert run_status(browser, run_id) == "awaiting_confirmation"
    doc = stored(browser, run_id)
    assert doc["source"] == {"path": str(inbox / name), "archive": name}
    assert doc["signed"] is True
    assert audits(browser, "restore.verify") == ["success"]
    page = await browser.get(f"/restore/runs/{run_id}/plan")
    assert page.status_code == 200 and "busybox:1.37" in page.text

    # Pass 2 reopens the path, and refuses a file that changed since pass 1.
    dispatcher = browser.app.state.dispatcher
    source = dispatcher._load_restore(run_id)
    storage = dispatcher._restore_storage(source, run_id)
    assert isinstance(storage, ServerFile)
    staged = verify.load_staged(
        verify.restore_dir(browser.settings.staging_dir, run_id), browser.app.state.crypto
    )
    with verify.open_verified(storage, staged, browser.app.state.crypto, None):
        pass
    replaced = inbox / f"{name}.new"
    replaced.write_bytes((inbox / name).read_bytes())
    replaced.replace(inbox / name)
    with (
        pytest.raises(verify.VerifyError, match="changed since"),
        verify.open_verified(storage, staged, browser.app.state.crypto, None),
    ):
        pass


async def test_a_refused_path_is_shown_and_audited(with_inbox: Browser, tmp_path: Path) -> None:
    response = await with_inbox.post("/restore/from-path", {"path": str(tmp_path / NAME)})
    assert response.status_code == 422 and "not inside" in response.text
    assert audits(with_inbox, "restore.verify") == ["failure"]
    assert with_inbox.sql("SELECT COUNT(*) FROM runs") == [(0,)]


async def test_without_an_allowlist_the_form_is_hidden_and_the_route_refuses(
    admin: Browser,
) -> None:
    page = await admin.get("/restore")
    assert "/restore/from-path" not in page.text
    response = await admin.post("/restore/from-path", {"path": f"/restore-inbox/{NAME}"})
    assert response.status_code == 422 and "DRYDOCK_RESTORE_PATHS" in response.text
