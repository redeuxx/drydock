"""Archive uploads (restore.uploads, PUT /restore/uploads): the checks made before the body
is read, partial files removed on every failure, roles and CSRF, expiry and startup
cleanup, and a 5 GiB upload's memory use in a uvicorn process of its own."""

import base64
import hashlib
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import httpx
import pytest

from drydock.archive.writer import RESERVE
from drydock.config import Settings
from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs.dispatcher import DispatchError
from drydock.restore import uploads, verify
from drydock.storage.rclone import Reserved
from tests.conftest import CLIENT_IP, PASSWORD, Browser, form_token
from tests.restore_support import build_archive, image_tar
from tests.test_restore_routes import audits as audit_outcomes
from tests.test_restore_routes import login_as, run_status, stored

pytestmark = pytest.mark.anyio

MiB = 2**20
NAME = "drydock-web-0b5e4c38-8c5a-4e43-9a1c-6c0f5a3f6b21-20261030T120000Z.tar.zst"


async def put(
    browser: Browser,
    content: Any = b"",
    *,
    name: str = NAME,
    headers: dict[str, str] | None = None,
    csrf: bool = True,
) -> httpx.Response:
    sent = browser.origin_headers | {"Content-Type": "application/octet-stream"}
    if csrf:
        sent["X-CSRF-Token"] = await browser.csrf_token()
    return await browser.client.put(
        "/restore/uploads", params={"name": name}, content=content, headers=sent | (headers or {})
    )


async def raw_put(browser: Browser, declared: int, messages: list[dict]) -> int:
    """Calls the app with these receive messages, then http.disconnect for good, and
    returns the status: what httpx cannot send (a client that disconnects or stalls)."""
    cookie = "; ".join(f"{c.name}={c.value}" for c in browser.client.cookies.jar)
    headers = [
        (b"host", b"drydock.test"),
        (b"cookie", cookie.encode()),
        (b"x-csrf-token", (await browser.csrf_token()).encode()),
        (b"origin", browser.settings.base_url.encode()),
        (b"content-type", b"application/octet-stream"),
        (b"content-length", str(declared).encode()),
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "PUT",
        "scheme": "https",
        "path": "/restore/uploads",
        "raw_path": b"/restore/uploads",
        "query_string": f"name={NAME}".encode(),
        "root_path": "",
        "headers": headers,
        "client": (CLIENT_IP, 50000),
        "server": ("drydock.test", 443),
    }
    pending = list(messages)
    statuses: list[int] = []

    async def receive() -> dict:
        if pending:
            message = pending.pop(0)
            return await message() if callable(message) else message
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    await browser.app(scope, receive, send)
    return statuses[0]


def body(data: bytes, more: bool = True) -> dict:
    return {"type": "http.request", "body": data, "more_body": more}


def rows(browser: Browser) -> list[tuple]:
    return browser.sql("SELECT id, name, declared_size, received, status, path FROM uploads")


def files(settings: Settings) -> list[str]:
    folder = uploads.uploads_dir(settings)
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


def audits(browser: Browser) -> list[tuple]:
    return browser.sql(
        "SELECT outcome, details FROM audit_events WHERE action = 'restore.upload' ORDER BY id"
    )


def nothing_left(browser: Browser) -> bool:
    return rows(browser) == [] and files(browser.settings) == [] and Reserved.total == 0


class Untouched:
    """A body that records whether anything read it."""

    def __init__(self) -> None:
        self.read = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.read = True
        yield b"x"


def free_space(monkeypatch: pytest.MonkeyPatch, free: int) -> None:
    real = shutil.disk_usage
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=free) if "uploads" in str(path) else real(path),
    )


# COMPLETE UPLOADS


async def test_an_upload_is_stored_whole(admin: Browser) -> None:
    data = os.urandom(3 * MiB + 12345)  # several write chunks and a short last one
    response = await put(admin, data)
    assert response.status_code == 201, response.text
    upload_id = response.json()["id"]
    assert response.json() == {"id": upload_id, "name": NAME, "size": len(data)}
    ((row_id, name, declared, received, status, path),) = rows(admin)
    assert (row_id, name, declared, received, status) == (
        upload_id,
        NAME,
        len(data),
        len(data),
        "complete",
    )
    stored = Path(path)
    assert stored.parent == uploads.uploads_dir(admin.settings)
    assert re.fullmatch(r"upload-[0-9a-f]{32}", stored.name)
    assert hashlib.sha256(stored.read_bytes()).digest() == hashlib.sha256(data).digest()
    assert stored.stat().st_mode & 0o777 == 0o600
    assert stored.parent.stat().st_mode & 0o777 == 0o700
    ((outcome, details),) = audits(admin)
    assert outcome == "success" and f'"declared_size": {len(data)}' in details
    assert Reserved.total == 0


# REFUSED BEFORE THE BODY


@pytest.mark.parametrize(
    ("headers", "status", "message"),
    [
        ({"Content-Length": str(50 * 10**9 + 1)}, 413, "at most 50 GB"),
        ({"Content-Length": "0"}, 400, "empty"),
        ({"Content-Length": "12x"}, 400, "not valid"),
        ({"Content-Length": "1", "Content-Type": "text/plain"}, 415, "octet-stream"),
    ],
)
async def test_bad_headers_are_refused_unread(
    admin: Browser, headers: dict[str, str], status: int, message: str
) -> None:
    content = Untouched()
    response = await put(admin, content, headers=headers)
    assert response.status_code == status and message in response.text
    assert not content.read
    assert nothing_left(admin)
    assert [outcome for outcome, _ in audits(admin)] == ["failure"]


async def test_a_missing_content_length_is_411(admin: Browser) -> None:
    content = Untouched()  # streamed with chunked encoding: no Content-Length
    response = await put(admin, content)
    assert response.status_code == 411
    assert not content.read and nothing_left(admin)


async def test_a_name_drydock_did_not_write_is_refused(admin: Browser) -> None:
    for name in ("", "backup.tar.zst", "../" + NAME, NAME + ".exe"):
        content = Untouched()
        response = await put(admin, content, name=name, headers={"Content-Length": "1"})
        assert response.status_code == 422, name
        assert not content.read
    assert nothing_left(admin)


async def test_more_than_the_free_space_is_507_unread(
    admin: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    free_space(monkeypatch, RESERVE + 10 * MiB)
    content = Untouched()
    response = await put(admin, content, headers={"Content-Length": str(10 * MiB + 1)})
    assert response.status_code == 507 and "Not enough free space" in response.text
    assert not content.read and nothing_left(admin)


async def test_uploads_in_flight_count_against_the_free_space(
    admin: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    free_space(monkeypatch, RESERVE + 10 * MiB)
    release = anyio.Event()

    async def rest() -> dict:
        await release.wait()
        return body(b"b" * (6 * MiB - 1), more=False)

    async with anyio.create_task_group() as tg:
        first: list[int] = []

        async def first_upload() -> None:
            first.append(await raw_put(admin, 6 * MiB, [body(b"a"), rest]))

        tg.start_soon(first_upload)
        while Reserved.total == 0:
            await anyio.sleep(0.01)
        # 5 MiB fits the disk alone, not next to the 6 MiB in flight.
        response = await put(admin, Untouched(), headers={"Content-Length": str(5 * MiB)})
        assert response.status_code == 507
        release.set()
    assert first == [201]
    assert [r[4] for r in rows(admin)] == ["complete"]
    assert Reserved.total == 0


# FAILURES WHILE RECEIVING


async def test_a_body_past_its_content_length_is_413_and_removed(admin: Browser) -> None:
    response = await put(admin, b"x" * (2 * MiB), headers={"Content-Length": str(MiB)})
    assert response.status_code == 413 and "larger than its Content-Length" in response.text
    assert nothing_left(admin)
    ((outcome, details),) = audits(admin)
    assert outcome == "failure" and "larger than" in details


async def test_a_disconnect_removes_the_partial_file(admin: Browser) -> None:
    seen: list[list[str]] = []

    async def disconnect() -> dict:
        seen.append(files(admin.settings))  # the partial file exists until now
        return {"type": "http.disconnect"}

    status = await raw_put(admin, 4 * MiB, [body(b"x" * (2 * MiB)), disconnect])
    assert status == 400
    assert len(seen[0]) == 1
    assert nothing_left(admin)
    assert "interrupted" in audits(admin)[0][1]


async def test_a_body_that_ends_short_is_removed(admin: Browser) -> None:
    status = await raw_put(admin, 4 * MiB, [body(b"x" * MiB, more=False)])
    assert status == 400
    assert nothing_left(admin)


async def test_a_stalled_upload_is_dropped(admin: Browser, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uploads, "IDLE_TIMEOUT", 0.2)

    async def stall() -> dict:
        await anyio.sleep_forever()
        raise AssertionError

    status = await raw_put(admin, 4 * MiB, [body(b"x"), stall])
    assert status == 408
    assert nothing_left(admin)


async def test_a_folder_it_cannot_write_is_an_audited_500(admin: Browser) -> None:
    folder = uploads.uploads_dir(admin.settings)
    folder.mkdir(mode=0o500, parents=True)
    try:
        response = await put(admin, b"data")
    finally:
        folder.chmod(0o700)
    assert response.status_code == 500 and "could not be written" in response.text
    assert nothing_left(admin)
    ((outcome, details),) = audits(admin)
    assert outcome == "failure" and '"content_length": "4"' in details


# ROLES AND CSRF


@pytest.mark.parametrize("role", ["viewer", "operator"])
async def test_viewers_and_operators_get_403(admin: Browser, role: str) -> None:
    await login_as(admin, "someone", role)
    content = Untouched()
    response = await put(admin, content, headers={"Content-Length": "1"})
    assert response.status_code == 403
    assert not content.read and nothing_left(admin)


async def test_a_missing_csrf_header_gets_403(admin: Browser) -> None:
    content = Untouched()
    response = await put(admin, content, csrf=False, headers={"Content-Length": "1"})
    assert response.status_code == 403
    assert not content.read and nothing_left(admin)


async def test_other_types_keep_the_body_limit(admin: Browser) -> None:
    """Only octet-stream bodies skip the 64 KiB limit: the CSRF check would parse a form."""
    response = await admin.client.put(
        "/restore/uploads",
        params={"name": NAME},
        content=b"csrf_token=" + b"x" * (100 * 1024),
        headers=admin.origin_headers | {"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413
    assert nothing_left(admin)


# RESTORING AN UPLOAD


def image_archive(browser: Browser, folder: Path) -> tuple[str, bytes]:
    folder.mkdir(exist_ok=True)
    image_id = "sha256:" + "a" * 64
    name, _ = build_archive(
        folder,
        browser.app.state.crypto,
        scope="image",
        images=[(image_id, ["busybox:1.37"], image_tar(image_id, ["busybox:1.37"]), None)],
    )
    return name, (folder / name).read_bytes()


async def test_an_upload_feeds_the_wizard_and_is_used_up(admin: Browser, tmp_path: Path) -> None:
    name, data = image_archive(admin, tmp_path / "built")
    upload_id = (await put(admin, data, name=name)).json()["id"]
    upload_path = Path(admin.sql("SELECT path FROM uploads")[0][0])
    page = await admin.get("/restore")
    assert f'action="/restore/from-upload/{upload_id}"' in page.text and name in page.text
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    assert response.status_code == 303, response.text
    run_id = int(response.headers["location"].split("/")[3])
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "awaiting_confirmation"
    doc = stored(admin, run_id)
    assert doc["source"] == {"upload_id": upload_id, "archive": name, "file": str(upload_path)}
    assert doc["signed"] is True
    assert audit_outcomes(admin, "restore.verify") == ["success"]

    # The restore took the upload: the row is gone and the file moved into the run.
    staging = admin.settings.staging_dir
    copy = verify.restore_dir(staging, run_id) / verify.DOWNLOAD_DIR / name
    assert copy.read_bytes() == data
    assert rows(admin) == [] and not upload_path.exists()
    page = await admin.get("/restore")
    assert f"/restore/from-upload/{upload_id}" not in page.text
    uploads.expire(admin.app.state.sessionmaker, admin.settings)  # nothing left to touch
    assert copy.exists()

    # Pass 2 reads the moved copy.
    dispatcher = admin.app.state.dispatcher
    source = dispatcher._load_restore(run_id)
    staged = verify.load_staged(verify.restore_dir(staging, run_id), admin.app.state.crypto)
    storage = dispatcher._restore_storage(source, run_id)
    with verify.open_verified(storage, staged, admin.app.state.crypto, None):
        pass

    # A second restore of it is refused before any run starts.
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    assert response.status_code == 404 and "Upload the archive again" in response.text
    assert audit_outcomes(admin, "restore.verify") == ["success", "failure"]


async def test_an_expired_upload_is_not_taken(admin: Browser) -> None:
    """Past expires_at but not swept yet: refused, as expire is about to delete it."""
    upload_id = (await put(admin, b"data")).json()["id"]
    admin.sql("UPDATE uploads SET expires_at = '2026-01-01 00:00:00'")
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    assert response.status_code == 404
    with pytest.raises(DispatchError, match="Upload the archive again"):
        await admin.app.state.dispatcher.submit_restore_from({"upload_id": upload_id}, NAME, "x")
    assert [r[0] for r in rows(admin)] == [upload_id]


async def test_a_restore_failing_before_the_move_deletes_the_taken_file(
    admin: Browser, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name, data = image_archive(admin, tmp_path / "built")
    upload_id = (await put(admin, data, name=name)).json()["id"]
    dispatcher = admin.app.state.dispatcher

    def fail(self, archive: str) -> list[str]:
        raise DispatchError("no passphrases today")

    monkeypatch.setattr(type(dispatcher), "_passphrases", fail)
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    run_id = int(response.headers["location"].split("/")[3])
    await dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "failed"
    assert rows(admin) == [] and files(admin.settings) == []


async def test_too_many_pending_restores_keep_the_upload(
    admin: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload_id = (await put(admin, b"data")).json()["id"]
    monkeypatch.setattr(dispatcher_module, "MAX_AWAITING", 0)
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    assert response.status_code == 409 and "Too many restores" in response.text
    assert [r[0] for r in rows(admin)] == [upload_id]
    assert len(files(admin.settings)) == 1


async def test_an_upload_gone_before_verification_fails_the_run(
    admin: Browser, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name, data = image_archive(admin, tmp_path / "built")
    upload_id = (await put(admin, data, name=name)).json()["id"]
    upload_path = Path(admin.sql("SELECT path FROM uploads")[0][0])
    dispatcher = admin.app.state.dispatcher
    real_load = type(dispatcher)._load_restore

    def load_then_expire(self, run_id: int):
        source = real_load(self, run_id)
        upload_path.unlink()  # expired between loading the row and linking
        return source

    monkeypatch.setattr(type(dispatcher), "_load_restore", load_then_expire)
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    run_id = int(response.headers["location"].split("/")[3])
    await dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "failed"
    error = admin.sql("SELECT error FROM runs WHERE id = ?", (run_id,))[0][0]
    assert "Upload the archive again" in error
    assert not verify.restore_dir(admin.settings.staging_dir, run_id).exists()


async def test_viewers_and_operators_cannot_restore_an_upload(admin: Browser) -> None:
    upload_id = (await put(admin, b"data")).json()["id"]
    await login_as(admin, "op", "operator")
    response = await admin.post(f"/restore/from-upload/{upload_id}")
    assert response.status_code == 403
    assert admin.sql("SELECT COUNT(*) FROM runs") == [(0,)]


# EXPIRY AND STARTUP


async def test_complete_uploads_expire_after_24_hours(admin: Browser) -> None:
    old = (await put(admin, b"old")).json()["id"]
    new = (await put(admin, b"new")).json()["id"]
    old_path = Path(admin.sql("SELECT path FROM uploads WHERE id = ?", (old,))[0][0])
    created = admin.sql("SELECT created_at, expires_at FROM uploads WHERE id = ?", (new,))[0]
    assert created[1] > created[0]  # 24 hours later; sqlite_ts strings compare in order
    admin.sql("UPDATE uploads SET expires_at = '2026-01-01 00:00:00' WHERE id = ?", (old,))
    uploads.expire(admin.app.state.sessionmaker, admin.settings)
    assert [r[0] for r in rows(admin)] == [new]
    assert not old_path.exists()
    assert len(files(admin.settings)) == 1
    details = admin.sql("SELECT details FROM audit_events WHERE action = 'restore.upload_expire'")
    assert details == [(f'{{"uploads": [{old}]}}',)]


async def test_startup_removes_uploads_a_stop_cut_short(admin: Browser) -> None:
    done = (await put(admin, b"done")).json()["id"]
    partial = uploads.uploads_dir(admin.settings) / "upload-cut"
    partial.write_bytes(b"part")
    admin.sql(
        "INSERT INTO uploads (name, declared_size, received, path, status, created_at,"
        " expires_at) VALUES (?, 10, 0, ?, 'receiving', '2026-10-30 00:00:00',"
        " '2026-10-31 00:00:00')",
        (NAME, str(partial)),
    )
    taken = uploads.uploads_dir(admin.settings) / ("upload-" + "c" * 32)
    taken.write_bytes(b"a restore took it, then drydock stopped")
    uploads.recover(admin.app.state.sessionmaker, admin.settings)
    assert [r[0] for r in rows(admin)] == [done]
    assert not partial.exists() and not taken.exists()
    assert len(files(admin.settings)) == 1


async def test_expiry_sweeps_old_files_no_upload_names(admin: Browser) -> None:
    named = Path(
        admin.sql(
            "SELECT path FROM uploads WHERE id = ?", ((await put(admin, b"x")).json()["id"],)
        )[0][0]
    )
    folder = named.parent
    old_orphan = folder / ("upload-" + "a" * 32)
    new_orphan = folder / ("upload-" + "b" * 32)
    other = folder / "notes.txt"
    for path in (old_orphan, new_orphan, other):
        path.write_bytes(b"x")
    old = time.time() - uploads.ORPHAN_AGE.total_seconds() - 60
    for path in (old_orphan, other, named):
        os.utime(path, (old, old))
    uploads.expire(admin.app.state.sessionmaker, admin.settings)
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        [named.name, new_orphan.name, other.name]
    )


# 5 GiB IN A UVICORN PROCESS (EXIT CRITERION)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def peak_rss(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) * 1024
    raise AssertionError("no VmHWM")


def cookie_of(response: httpx.Response) -> str:
    """name=value of the response's cookie. httpx keeps Secure cookies to https URLs."""
    return response.headers["set-cookie"].split(";", 1)[0]


@pytest.mark.slow
def test_a_5_gib_upload_streams(settings: Settings, tmp_path: Path) -> None:
    """Measures a fresh drydock process (uvicorn, as in the image), so the result does not
    depend on what the test process loaded before. Its TMPDIR must stay empty: the body is
    never spooled."""
    port = free_port()
    base_url = f"http://127.0.0.1:{port}"
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    keys = "\n".join(base64.urlsafe_b64encode(k).decode() for k in settings.secret_keys)
    env = os.environ | {
        "DRYDOCK_SECRET_KEY": keys,
        "DRYDOCK_DATA_DIR": str(settings.data_dir),
        "DRYDOCK_RUN_DIR": str(settings.run_dir),
        "DRYDOCK_STAGING_DIR": str(settings.staging_dir),
        "DRYDOCK_BASE_URL": base_url,
        "TMPDIR": str(tmpdir),
    }
    output = tmp_path / "drydock.out"
    with output.open("wb") as log:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "drydock.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--workers",
                "1",
                "--log-level",
                "warning",
            ],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=Path(__file__).parent.parent,
        )
    size = 5 * 1024 * MiB
    digest = hashlib.sha256()
    try:
        with httpx.Client(base_url=base_url, timeout=60) as client:
            deadline = time.monotonic() + 60
            while True:
                assert proc.poll() is None, output.read_text()
                try:
                    if client.get("/healthz").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                assert time.monotonic() < deadline, "drydock did not start"
                time.sleep(0.2)
            origin = {"Origin": base_url, "Sec-Fetch-Site": "same-origin"}
            page = client.get("/setup")
            form = {"csrf_token": form_token(page.text), "username": "admin"}
            form |= {"password": PASSWORD, "password_confirm": PASSWORD}
            done = client.post("/setup", data=form, headers=origin | {"Cookie": cookie_of(page)})
            assert done.status_code == 303, done.text
            session = {"Cookie": cookie_of(done)}
            token = form_token(client.get("/account", headers=session).text)
            baseline = peak_rss(proc.pid)
            block = os.urandom(MiB)

            def chunks():
                for i in range(5 * 1024):
                    chunk = block[i % 256 :] + block[: i % 256]  # every MiB differs
                    digest.update(chunk)
                    yield chunk

            started = time.monotonic()
            response = client.put(
                "/restore/uploads",
                params={"name": NAME},
                content=chunks(),
                headers=origin
                | session
                | {
                    "X-CSRF-Token": token,
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(size),
                },
                timeout=900,
            )
            elapsed = time.monotonic() - started
            assert response.status_code == 201, response.text
            peak = peak_rss(proc.pid)
    finally:
        proc.terminate()
        proc.wait(timeout=90)
    print(
        f"\n5 GiB UPLOAD: {elapsed:.1f} s, drydock peak RSS before {baseline / MiB:.0f} MiB, "
        f"after {peak / MiB:.0f} MiB"
    )
    assert peak < 300 * MiB
    assert list(tmpdir.iterdir()) == []
    (stored,) = (uploads.uploads_dir(settings)).iterdir()
    assert stored.stat().st_size == size
    stored_digest = hashlib.sha256()
    with stored.open("rb") as handle:
        while chunk := handle.read(8 * MiB):
            stored_digest.update(chunk)
    assert stored_digest.hexdigest() == digest.hexdigest()
