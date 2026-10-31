"""Archives this drydock did not sign (from another instance) and the database-loss path:
unsigned archives are superadmin only, a passphrase entered for a foreign encrypted
archive is used by both passes and never stored or logged, a wrong one fails during
verification, and after losing drydock.db the same secret key lists, verifies and
decrypts the archives again with no passphrase entered."""

import base64
import shutil
from pathlib import Path

import pytest

from drydock.crypto import Crypto
from drydock.jobs.runlog import log_path
from drydock.restore import verify
from drydock.restore.verify import NOT_DECRYPTED
from drydock.storage.base import parse_name
from tests.conftest import Browser, make_settings, running
from tests.restore_support import build_archive, image_tar
from tests.test_archive import needs_age, new_crypto
from tests.test_jobs import add_storage
from tests.test_restore_routes import login_as, run_status, stored
from tests.test_uploads import put

pytestmark = pytest.mark.anyio

IMAGE_ID = "sha256:" + "a" * 64


def image_archive(root: Path, crypto: Crypto, *, encrypt: bool = False) -> str:
    name, _ = build_archive(
        root,
        crypto,
        scope="image",
        images=[(IMAGE_ID, ["busybox:1.37"], image_tar(IMAGE_ID, ["busybox:1.37"]), None)],
        encrypt=encrypt,
    )
    return name


async def restore(browser: Browser, storage_id: int, name: str, passphrase: str = "") -> int:
    form = {"storage_id": str(storage_id), "name": name, "passphrase": passphrase}
    response = await browser.post("/restore/from-storage", form)
    assert response.status_code == 303, response.text
    run_id = int(response.headers["location"].split("/")[3])
    await browser.app.state.dispatcher.wait(run_id)
    return run_id


def run_error(browser: Browser, run_id: int) -> str:
    return browser.sql("SELECT error FROM runs WHERE id = ?", (run_id,))[0][0] or ""


def pass_two(browser: Browser, run_id: int) -> None:
    """Opens the archive as execute would, with what the dispatcher kept for the run."""
    dispatcher = browser.app.state.dispatcher
    source = dispatcher._load_restore(run_id)
    dest = verify.restore_dir(browser.settings.staging_dir, run_id)
    staged = verify.load_staged(dest, browser.app.state.crypto)
    storage = dispatcher._restore_storage(source, run_id)
    entered = dispatcher._entered.get(run_id)
    with verify.open_verified(storage, staged, browser.app.state.crypto, None, entered):
        pass


# ANOTHER DRYDOCK


async def test_an_unsigned_archive_is_superadmin_only(admin: Browser) -> None:
    storage_id = await add_storage(admin)
    root = admin.settings.local_storage_roots[0]
    name = image_archive(root, new_crypto())  # another instance's secret key
    await login_as(admin, "alice", "admin")
    run_id = await restore(admin, storage_id, name)
    assert run_status(admin, run_id) == "awaiting_confirmation"
    assert stored(admin, run_id)["signed"] is False
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert "Only a superadmin can restore an archive" in page.text
    response = await admin.post(
        f"/restore/runs/{run_id}/plan", {"host_id": "1", "mode": "image-only"}
    )
    assert response.status_code == 403


@needs_age
async def test_a_foreign_encrypted_archive_needs_its_passphrase(admin: Browser) -> None:
    storage_id = await add_storage(admin)
    root = admin.settings.local_storage_roots[0]
    other = new_crypto()
    name = image_archive(root, other, encrypt=True)
    right = other.job_passphrase(parse_name(name).job_uuid)

    page = await admin.get(f"/restore/storage/{storage_id}")
    assert 'name="passphrase"' in page.text and 'type="password"' in page.text

    # None entered: this drydock's own passphrases do not decrypt it.
    run_id = await restore(admin, storage_id, name)
    assert run_status(admin, run_id) == "failed"
    assert "No configured secret key decrypts" in run_error(admin, run_id)

    # A wrong one fails during verification, before anything is staged.
    run_id = await restore(admin, storage_id, name, "not-the-passphrase")
    assert run_status(admin, run_id) == "failed"
    assert run_error(admin, run_id) == NOT_DECRYPTED
    assert not verify.restore_dir(admin.settings.staging_dir, run_id).exists()

    # The right one (pasted with stray whitespace) verifies it, and pass 2 decrypts too.
    run_id = await restore(admin, storage_id, name, f"  {right}\n")
    assert run_status(admin, run_id) == "awaiting_confirmation"
    doc = stored(admin, run_id)
    assert doc["signed"] is False and doc["encrypted"] is True
    pass_two(admin, run_id)

    # Never stored or logged: kept in memory for the run only, gone with its staged data.
    assert admin.app.state.dispatcher._entered == {run_id: right}
    for path in admin.settings.data_dir.glob("drydock.db*"):
        assert right.encode() not in path.read_bytes(), path.name
    for row_id in (run_id - 1, run_id):
        assert right not in log_path(admin.settings.data_dir, row_id).read_text()
    details = admin.sql("SELECT details FROM audit_events WHERE action = 'restore.verify'")
    assert all(right not in d for (d,) in details)
    assert '"entered_phrase": true' in details[-1][0]
    assert await admin.app.state.dispatcher.discard_restore(run_id)
    assert admin.app.state.dispatcher._entered == {}


@pytest.mark.parametrize("passphrase", ["x" * 7, "x" * 1025])
async def test_a_passphrase_of_the_wrong_length_is_refused(admin: Browser, passphrase: str) -> None:
    storage_id = await add_storage(admin)
    name = image_archive(admin.settings.local_storage_roots[0], admin.app.state.crypto)
    form = {"storage_id": str(storage_id), "name": name, "passphrase": passphrase}
    response = await admin.post("/restore/from-storage", form)
    assert response.status_code == 422 and "8 to 1024 characters" in response.text
    assert admin.sql("SELECT COUNT(*) FROM runs") == [(0,)]


@needs_age
async def test_a_wrong_passphrase_costs_no_upload(admin: Browser, tmp_path: Path) -> None:
    """A restore uses its upload up, so the passphrase is checked before it starts."""
    other = new_crypto()
    built = tmp_path / "built"
    built.mkdir()
    name = image_archive(built, other, encrypt=True)
    right = other.job_passphrase(parse_name(name).job_uuid)
    response = await put(admin, (built / name).read_bytes(), name=name)
    upload_id = response.json()["id"]

    for passphrase, message in (("", "enter its passphrase"), ("wrong-one", NOT_DECRYPTED)):
        response = await admin.post(f"/restore/from-upload/{upload_id}", {"passphrase": passphrase})
        assert response.status_code == 422 and message in response.text, passphrase
        assert admin.sql("SELECT id FROM uploads") == [(upload_id,)]
    assert admin.sql("SELECT COUNT(*) FROM runs") == [(0,)]

    response = await admin.post(f"/restore/from-upload/{upload_id}", {"passphrase": right})
    assert response.status_code == 303, response.text
    run_id = int(response.headers["location"].split("/")[3])
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "awaiting_confirmation"
    pass_two(admin, run_id)
    assert admin.sql("SELECT COUNT(*) FROM uploads") == [(0,)]


# LOSING THE DATABASE


@needs_age
async def test_after_losing_the_database_the_secret_key_restores_everything(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "storage"
    storage.mkdir()
    first = make_settings(tmp_path / "first", DRYDOCK_LOCAL_STORAGE_ROOTS=str(storage))
    key = base64.urlsafe_b64encode(first.secret_keys[0]).decode()
    crypto = Crypto(first.secret_keys)
    plain = image_archive(storage, crypto)
    encrypted = image_archive(storage, crypto, encrypt=True)
    foreign = image_archive(storage, new_crypto(), encrypt=True)

    # drydock.db is gone: a new data directory, the same secret key, the wizard again.
    shutil.rmtree(tmp_path / "first", ignore_errors=True)
    settings = make_settings(
        tmp_path / "second", DRYDOCK_SECRET_KEY=key, DRYDOCK_LOCAL_STORAGE_ROOTS=str(storage)
    )
    async with running(settings) as browser:
        assert (await browser.setup()).status_code == 303
        storage_id = await add_storage(browser)
        page = await browser.get(f"/restore/storage/{storage_id}")
        assert plain in page.text and encrypted in page.text and foreign in page.text

        run_id = await restore(browser, storage_id, plain)
        assert run_status(browser, run_id) == "awaiting_confirmation"
        assert stored(browser, run_id)["signed"] is True
        pass_two(browser, run_id)

        # Its passphrase is re-derived from the key and the job UUID in the name.
        run_id = await restore(browser, storage_id, encrypted)
        assert run_status(browser, run_id) == "awaiting_confirmation"
        doc = stored(browser, run_id)
        assert doc["signed"] is True and doc["encrypted"] is True
        pass_two(browser, run_id)

        # Another instance's archive still needs its passphrase entered.
        run_id = await restore(browser, storage_id, foreign)
        assert run_status(browser, run_id) == "failed"
