"""The backups page: filters and downloads."""

import uuid

import pytest

from drydock.models import utcnow
from tests.conftest import Browser, add_user, sqlite_ts
from tests.test_jobs import add_job, add_storage

pytestmark = pytest.mark.anyio


def archive_name(slug: str) -> str:
    return f"drydock-{slug}-{uuid.uuid4()}-20261118T030000Z.tar.zst"


def catalog(admin: Browser, storage_id: int, job_id: int | None, name: str, size: int) -> int:
    return admin.sql(
        "INSERT INTO backups (job_id, storage_target_id, name, size, sha256, signed, encrypted,"
        " created_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?) RETURNING id",
        (job_id, storage_id, name, size, "0" * 64, sqlite_ts(utcnow())),
    )[0][0]


async def test_the_catalog_filters_by_job_storage_and_name(admin: Browser) -> None:
    storage = await add_storage(admin, "nas")
    other = await add_storage(admin, "cloud")
    web = await add_job(admin, "web nightly", storage_id=str(storage))
    db = await add_job(admin, "db hourly", storage_id=str(storage))
    web_archive, db_archive = archive_name("web-nightly"), archive_name("db-hourly")
    catalog(admin, storage, web, web_archive, 10)
    catalog(admin, other, db, db_archive, 10)

    async def shown(**query: str) -> set[str]:
        page = (await admin.get("/backups", params=query)).text
        return {name for name in (web_archive, db_archive) if name in page}

    assert await shown() == {web_archive, db_archive}
    assert await shown(job=str(web)) == {web_archive}
    assert await shown(storage=str(other)) == {db_archive}
    assert await shown(job="", storage="", q="web") == {web_archive}, "the All options"
    assert await shown(job=str(db), storage="") == {db_archive}
    assert await shown(job="x", storage="-1") == {web_archive, db_archive}, "ignored"
    assert await shown(q="DB HOUR") == {db_archive}, "a job's name"
    assert await shown(q=web_archive[:20]) == {web_archive}, "an archive's name"
    assert await shown(q="%") == set(), "LIKE wildcards are literal"
    page = (await admin.get("/backups", params={"q": "nothing"})).text
    assert "No backup matches the filters." in page


async def test_admins_download_an_archive_and_each_download_is_audited(admin: Browser) -> None:
    storage = await add_storage(admin)
    name = archive_name("web")
    data = uuid.uuid4().bytes * 1000
    (admin.settings.local_storage_roots[0] / name).write_bytes(data)
    backup = catalog(admin, storage, None, name, len(data))
    page = (await admin.get("/backups")).text
    assert f'action="/backups/{backup}/download"' in page

    admin.sql("UPDATE sessions SET reauth_at = NULL")
    stale = await admin.post(f"/backups/{backup}/download")
    assert stale.status_code == 403 and "Re-enter your password" in stale.text
    await admin.login("admin")

    response = await admin.post(f"/backups/{backup}/download")
    assert response.status_code == 200 and response.content == data
    assert response.headers["content-disposition"] == f'attachment; filename="{name}"'
    assert response.headers["cache-control"] == "no-store"

    gone = catalog(admin, storage, None, archive_name("gone"), 1)
    missing = await admin.post(f"/backups/{gone}/download")
    assert missing.status_code == 502 and "Cannot download" in missing.text
    assert admin.sql(
        "SELECT target, outcome FROM audit_events WHERE action = 'backup.download' ORDER BY id"
    ) == [(f"backup:{backup}", "success"), (f"backup:{gone}", "failure")]
    assert (await admin.post("/backups/999999/download")).status_code == 404

    for role in ("viewer", "operator"):
        await add_user(admin, role, role)
    for role in ("viewer", "operator"):
        await admin.login(role)
        assert "/download" not in (await admin.get("/backups")).text
        assert (await admin.post(f"/backups/{backup}/download")).status_code == 403
