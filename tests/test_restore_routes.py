"""The restore wizard's routes: listing without the catalog, the role, signature, flag,
typed-name and recent-auth rules, the verify page, discard, the partial-data warning, and
stacks and compose output directories.

Archives are real (tests.restore_support.build_archive). The target state, apply and
rollback are faked as in tests/test_restore_dispatch.py; restore.apply has its own tests.
"""

import functools
import hashlib
import json
import re
import secrets
import sys
import tarfile
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from drydock.archive.verify import AGE_MAGIC
from drydock.crypto import Crypto
from drydock.engine import capture
from drydock.hosts import client as docker_client
from drydock.hosts.manager import HostManager
from drydock.models import Run
from drydock.restore import apply as restore_apply
from drydock.restore import plan as p
from drydock.restore import verify as rv
from drydock.routes import restore as restore_routes
from tests.conftest import PASSWORD, Browser, add_user
from tests.restore_support import (
    TarEntry,
    build_archive,
    container_inspect,
    image_tar,
    inner_tar,
    volume_inspect,
)
from tests.test_jobs import add_host, add_storage, run_status
from tests.test_restore_dispatch import IMAGE_ID, WEB_ID, Fakes, target_info
from tests.test_routes import snapshot

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(sys.platform != "linux", reason="local storage needs Linux"),
]

STAMP = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
REAUTH_FORM = 'action="/reauth"'
DIGEST_RE = re.compile(r'name="plan_digest" value="([0-9a-f]{64})"')
WARNING_RE = re.compile(r'<div role="alert" class="alert alert-warning[^"]*"><span>([^<]*)</span>')


# FAKES


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> Fakes:
    """The target the plan sees, and recording stand-ins for apply and rollback."""
    fakes = Fakes()
    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", fakes.open_client)
    monkeypatch.setattr(restore_apply, "inspect_target", fakes.inspect_target)
    monkeypatch.setattr(restore_apply, "apply", fakes.apply)
    monkeypatch.setattr(restore_apply, "rollback", fakes.rollback)
    return fakes


# HELPERS


def web_archive(
    browser: Browser,
    *,
    crypto: Crypto | None = None,
    host_config: dict[str, Any] | None = None,
    binds: tuple[str, ...] = (),
    bind_data: tuple[tuple[str, str, bytes], ...] = (),
    job_name: str = "web",
    created_at: datetime | None = None,
) -> tuple[str, Any]:
    """Container web (ID WEB_ID) with volume data in "data" and a saved image."""
    container = container_inspect(
        "web",
        id=WEB_ID,
        image_id=IMAGE_ID,
        mounts=[("data", "/data")],
        binds=binds,
        host_config=host_config,
    )
    volume = inner_tar(
        [TarEntry("./", tarfile.DIRTYPE, mode=0o755), TarEntry("./index.html", data=b"hello\n")]
    )
    return build_archive(
        browser.settings.local_storage_roots[0],
        crypto or browser.app.state.crypto,
        job_name=job_name,
        created_at=created_at,
        containers=[container],
        volumes={"data": volume},
        binds=bind_data,
        images=[(IMAGE_ID, ["busybox:1.37"], image_tar(IMAGE_ID, ["busybox:1.37"]), None)],
    )


async def ready(browser: Browser, fakes: Fakes, **target: Any) -> tuple[int, int]:
    """A local host whose fake state the plan sees, and a storage target."""
    host_id = add_host(browser, "local")
    fakes.target = target_info(host_id, **target)
    return host_id, await add_storage(browser)


async def start(browser: Browser, storage_id: int, name: str) -> int:
    response = await browser.post(
        "/restore/from-storage", {"storage_id": str(storage_id), "name": name}
    )
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    run_id = int(location.split("/")[3])
    assert location == f"/restore/runs/{run_id}/plan"
    return run_id


async def verified(browser: Browser, storage_id: int, name: str) -> int:
    run_id = await start(browser, storage_id, name)
    await browser.app.state.dispatcher.wait(run_id)
    assert run_status(browser, run_id) == "awaiting_confirmation"
    return run_id


async def plan(browser: Browser, run_id: int, host_id: int, mode: str, **fields: str):
    form = {"host_id": str(host_id), "mode": mode} | fields
    return await browser.post(f"/restore/runs/{run_id}/plan", form)


async def seen_digest(browser: Browser, run_id: int) -> str:
    """The plan digest the confirm form carries, as a browser would submit it."""
    page = await browser.get(f"/restore/runs/{run_id}/plan")
    match = DIGEST_RE.search(page.text)
    return match.group(1) if match else ""


async def execute(browser: Browser, run_id: int, **fields: Any) -> httpx.Response:
    """Submits the confirm form as the plan page currently shows it, unless the test passes
    its own plan_digest."""
    if "plan_digest" not in fields:
        fields["plan_digest"] = await seen_digest(browser, run_id)
    return await browser.post(f"/restore/runs/{run_id}/execute", fields)


def stored(browser: Browser, run_id: int) -> dict[str, Any]:
    return json.loads(browser.sql("SELECT plan FROM runs WHERE id = ?", (run_id,))[0][0])


def flag_keys(browser: Browser, run_id: int) -> list[str]:
    return [flag["key"] for flag in stored(browser, run_id)["summary"]["risk"]]


def audits(browser: Browser, action: str) -> list[str]:
    rows = browser.sql("SELECT outcome FROM audit_events WHERE action = ? ORDER BY id", (action,))
    return [outcome for (outcome,) in rows]


def stale_auth(browser: Browser) -> None:
    browser.sql("UPDATE sessions SET reauth_at = NULL")


async def reauth(browser: Browser) -> None:
    response = await browser.post("/reauth", {"password": PASSWORD, "next": "/"})
    assert response.status_code == 303, response.text


async def login_as(browser: Browser, username: str, role: str) -> None:
    await add_user(browser, username, role)
    response = await browser.login(username)
    assert response.status_code == 303, response.text


def bind_number(manifest: Any, source: str) -> int:
    return next(b.n for b in manifest.binds if b.source == source)


# LISTING


async def test_listing_does_not_need_the_catalog(admin: Browser, fakes: Fakes) -> None:
    _, storage_id = await ready(admin, fakes)
    root = admin.settings.local_storage_roots[0]
    web, _ = web_archive(admin, job_name="web backup", created_at=STAMP)
    db_container = container_inspect("db", image_id=IMAGE_ID)
    other, _ = build_archive(
        root,
        admin.app.state.crypto,
        job_name="db backup",
        created_at=STAMP + timedelta(days=1),
        containers=[db_container],
        scope="config",
    )
    encrypted = f"drydock-secret-{uuid.uuid4()}-20261003T000000Z.tar.zst.age"
    (root / encrypted).write_bytes(AGE_MAGIC + secrets.token_bytes(64))
    (root / "notes.txt").write_text("not an archive")
    admin.sql("DELETE FROM backups")
    before = snapshot(admin)

    response = await admin.get(f"/restore/storage/{storage_id}")
    assert response.status_code == 200, response.text
    text = response.text
    for expected in (web, other, encrypted, "web backup", "db backup", ">encrypted<"):
        assert expected in text, expected
    assert "unverified preview" in text
    assert "notes.txt" not in text
    # Newest first: the encrypted archive (October 3), then db, then web.
    assert text.index(encrypted) < text.index(other) < text.index(web)
    assert text.count('action="/restore/from-storage"') == 3
    assert snapshot(admin) == before


async def test_listing_pages_reach_every_archive(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Archives past the first page stay reachable, newest first, each on one page."""
    monkeypatch.setattr(restore_routes, "LISTING_LIMIT", 2)
    _, storage_id = await ready(admin, fakes)
    root = admin.settings.local_storage_roots[0]
    names = [f"drydock-old-{uuid.uuid4()}-2026100{day}T000000Z.tar.zst" for day in range(1, 6)]
    for name in names:
        (root / name).write_bytes(b"not an archive")
    newest_first = names[::-1]
    pages = []
    for page in (1, 2, 3):
        response = await admin.get(f"/restore/storage/{storage_id}?page={page}")
        assert response.status_code == 200, response.text
        pages.append(response.text)
        shown = [name for name in newest_first if name in response.text]
        assert shown == newest_first[(page - 1) * 2 : page * 2], page
    assert "Showing archives 1 to 2 of 5" in pages[0]
    assert "Showing archives 5 to 5 of 5" in pages[2]
    assert f'href="/restore/storage/{storage_id}?page=2">Older archives' in pages[0]
    assert "Newer archives" not in pages[0]
    assert f'href="/restore/storage/{storage_id}?page=1">Newer archives' in pages[1]
    assert "Older archives" not in pages[2]
    response = await admin.get(f"/restore/storage/{storage_id}?page=0")
    assert response.status_code == 422


async def test_archive_strings_are_escaped(admin: Browser, fakes: Fakes) -> None:
    """An unsigned archive's job name and bind source are anyone's text: the listing and
    the plan page (before and after a plan) show them escaped only."""
    host_id, storage_id = await ready(admin, fakes)
    job = '<script>alert("job")</script>'
    source = "/srv/x<img src=x onerror=alert(1)>"
    name, _ = web_archive(
        admin,
        crypto=Crypto((secrets.token_bytes(32),)),  # unsigned here
        job_name=job,
        binds=(f"{source}:/srv/x",),
    )
    escaped = (
        "&lt;script&gt;alert(&#34;job&#34;)&lt;/script&gt;",
        "/srv/x&lt;img src=x onerror=alert(1)&gt;",
    )

    def assert_escaped(text: str, expected: tuple[str, ...]) -> None:
        assert job not in text and "<img" not in text
        for value in expected:
            assert value in text, value

    listing = await admin.get(f"/restore/storage/{storage_id}")
    assert_escaped(listing.text, escaped[:1])
    run_id = await verified(admin, storage_id, name)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert_escaped(page.text, escaped)
    shown = page.text.count(escaped[1])
    response = await plan(admin, run_id, host_id, "overwrite")
    assert response.status_code == 303, response.text
    assert any(source in item["label"] for item in stored(admin, run_id)["summary"]["data"])
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert "4. Confirm" in page.text
    assert_escaped(page.text, escaped)
    assert page.text.count(escaped[1]) > shown  # the summary's data write names it too


# SIGNATURE, FLAGS AND RECENT AUTH


async def test_unsigned_risky_archive_needs_superadmin_acknowledgement_and_reauth(
    admin: Browser, fakes: Fakes
) -> None:
    host_id, storage_id = await ready(admin, fakes)
    risky = {"Privileged": True, "CapAdd": ["SYS_ADMIN"], "PidMode": "host"}
    name, manifest = web_archive(
        admin,
        crypto=Crypto((secrets.token_bytes(32),)),  # a foreign drydock: unsigned here
        host_config=risky,
        binds=("/:/host", "/var/run/docker.sock:/var/run/docker.sock"),
    )
    run_id = await verified(admin, storage_id, name)
    assert stored(admin, run_id)["signed"] is False
    root_bind = bind_number(manifest, "/")
    socket_bind = bind_number(manifest, "/var/run/docker.sock")

    # An admin may neither plan nor execute it.
    await login_as(admin, "alice", "admin")
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert "Only a superadmin can restore an archive" in page.text
    response = await plan(admin, run_id, host_id, "overwrite")
    assert response.status_code == 403
    assert audits(admin, "restore.plan") == ["denied"]
    response = await execute(admin, run_id, confirm_name="web")
    assert response.status_code == 403  # not 409: no plan is stored, but that comes later
    assert audits(admin, "restore.execute") == ["denied"]

    # A superadmin: the denylisted binds are refused for every role.
    await admin.login("admin")
    response = await plan(admin, run_id, host_id, "overwrite")
    assert response.status_code == 422, response.text
    assert "Binding / is refused" in response.text
    assert "Binding /var/run/docker.sock is refused" in response.text
    assert "summary" not in stored(admin, run_id)
    remaps = {f"remap_{root_bind}": "/srv/a", f"remap_{socket_bind}": "/srv/b"}
    response = await plan(admin, run_id, host_id, "overwrite", **remaps)
    assert response.status_code == 303, response.text
    keys = flag_keys(admin, run_id)
    assert {"web:Privileged", "web:CapAdd", "web:PidMode"} <= set(keys)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    for key in keys:
        assert f'name="ack" value="{key}"' in page.text

    response = await execute(admin, run_id, confirm_name="web")
    assert response.status_code == 422
    for field in ("Privileged", "CapAdd", "PidMode"):
        assert field in response.text
    stale_auth(admin)
    response = await execute(admin, run_id, confirm_name="web", ack=keys)
    assert response.status_code == 403
    assert REAUTH_FORM in response.text
    assert fakes.applied == []
    await reauth(admin)
    response = await execute(admin, run_id, confirm_name="web", ack=keys)
    assert response.status_code == 303, response.text
    assert response.headers["location"] == f"/runs/{run_id}"
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "done"
    assert len(fakes.applied) == 1
    assert {f.key for f in fakes.applied[0].risk} == set(keys)
    assert audits(admin, "restore.execute") == ["denied", "failure", "success"]
    details = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'restore.execute' AND outcome = 'success'"
    )[0][0]
    assert json.loads(details)["acknowledged"] == sorted(keys)


async def test_signed_flagged_archive_still_needs_superadmin(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, _ = web_archive(admin, host_config={"Privileged": True})
    run_id = await verified(admin, storage_id, name)
    assert stored(admin, run_id)["signed"] is True

    await login_as(admin, "alice", "admin")
    response = await plan(admin, run_id, host_id, "new-name", new_name="web-copy")
    assert response.status_code == 303, response.text
    keys = flag_keys(admin, run_id)
    assert "web-copy:Privileged" in keys
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert "Flagged fields need a superadmin." in page.text
    assert "web-copy" in page.text and "Privileged" in page.text
    assert f'action="/restore/runs/{run_id}/execute"' not in page.text
    response = await execute(admin, run_id, ack=keys)
    assert response.status_code == 403
    assert audits(admin, "restore.execute") == ["denied"]

    # A superadmin still acknowledges every flagged field and needs recent auth, although
    # the archive is signed and new-name mode needs neither otherwise.
    await admin.login("admin")
    response = await execute(admin, run_id)
    assert response.status_code == 422
    assert "Acknowledge every flagged field first: web-copy Privileged." in response.text
    stale_auth(admin)
    response = await execute(admin, run_id, ack=keys)
    assert response.status_code == 403
    assert REAUTH_FORM in response.text
    assert fakes.applied == []
    await reauth(admin)
    response = await execute(admin, run_id, ack=keys)
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "done"
    assert len(fakes.applied) == 1
    assert audits(admin, "restore.execute") == ["denied", "failure", "success"]


async def test_bind_remap_onto_etc_or_root_is_rejected_for_superadmin(
    admin: Browser, fakes: Fakes
) -> None:
    host_id, storage_id = await ready(admin, fakes)
    data = inner_tar([TarEntry("./", tarfile.DIRTYPE), TarEntry("./a.txt", data=b"a")])
    name, manifest = web_archive(
        admin, binds=("/srv/data:/srv/data",), bind_data=(("/srv/data", "dir", data),)
    )
    run_id = await verified(admin, storage_id, name)
    n = bind_number(manifest, "/srv/data")
    for target in ("/etc/x", "/root"):
        response = await plan(admin, run_id, host_id, "overwrite", **{f"remap_{n}": target})
        assert response.status_code == 422, (target, response.text)
        assert f"Drydock never writes to {target}." in response.text
    assert "summary" not in stored(admin, run_id)
    assert audits(admin, "restore.plan") == ["failure", "failure"]


async def test_overwrite_needs_typed_name_and_recent_auth(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, _ = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    response = await plan(admin, run_id, host_id, "overwrite")
    assert response.status_code == 303, response.text
    assert flag_keys(admin, run_id) == []
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'name="confirm_name"' in page.text
    assert 'maxlength="255"' in page.text  # plan.OBJECT_NAME_RE allows 255 characters

    response = await execute(admin, run_id, confirm_name="web2")
    assert response.status_code == 422
    assert "Type the container name to confirm." in response.text
    assert audits(admin, "restore.execute") == ["failure"]
    stale_auth(admin)
    response = await execute(admin, run_id, confirm_name="web")
    assert response.status_code == 403
    assert REAUTH_FORM in response.text
    await reauth(admin)
    response = await execute(admin, run_id, confirm_name=" web ")
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "done"
    assert [step.name for step in fakes.applied[0].containers] == ["web"]


async def test_data_only_needs_recent_auth(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = await ready(admin, fakes, volumes={"target": volume_inspect("target")})
    name, _ = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    response = await plan(admin, run_id, host_id, "data-only", volmap_0="target")
    assert response.status_code == 303, response.text
    assert stored(admin, run_id)["choice"]["volume_map"] == {"data": "target"}
    stale_auth(admin)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert "asks for your password" in page.text
    response = await execute(admin, run_id)
    assert response.status_code == 403
    assert REAUTH_FORM in response.text
    await reauth(admin)
    response = await execute(admin, run_id)
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert [step.label for step in fakes.applied[0].data] == ["volume target"]


async def test_operator_cannot_restore_or_cancel_restores(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, _ = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    await login_as(admin, "olga", "operator")
    for path in ("/restore", f"/restore/storage/{storage_id}", f"/restore/runs/{run_id}/plan"):
        assert (await admin.get(path)).status_code == 403, path
    posts = {
        "/restore/from-storage": {"storage_id": str(storage_id), "name": name},
        f"/restore/runs/{run_id}/plan": {"host_id": str(host_id), "mode": "overwrite"},
        f"/restore/runs/{run_id}/execute": {"confirm_name": "web"},
    }
    for path, form in posts.items():
        assert (await admin.post(path, form)).status_code == 403, path
    response = await admin.post(f"/runs/{run_id}/cancel")
    assert response.status_code == 403
    assert audits(admin, "run.cancel") == ["denied"]
    assert run_status(admin, run_id) == "awaiting_confirmation"
    assert rv.restore_dir(admin.settings.staging_dir, run_id).is_dir()
    page = await admin.get(f"/runs/{run_id}")
    assert 'action="/runs/' not in page.text  # no Discard button for an operator
    # Nor links to the plan page, which would answer 403.
    assert "/restore/runs/" not in page.text
    page = await admin.get("/runs")
    assert name in page.text and "/restore/runs/" not in page.text


async def test_restore_routes_refuse_other_runs(admin: Browser, fakes: Fakes) -> None:
    """A backup run's ID, or no run's, is not a restore: 404, and nothing is recorded."""
    host_id, _ = await ready(admin, fakes)
    with admin.app.state.sessionmaker() as db, db.begin():
        backup = Run(job_id=None, status="done", triggered_by="admin", archive_name="a", plan="{}")
        db.add(backup)
        db.flush()
        backup_id = backup.id
    before = snapshot(admin)
    for run_id in (backup_id, backup_id + 100):
        assert (await admin.get(f"/restore/runs/{run_id}/plan")).status_code == 404
        response = await plan(admin, run_id, host_id, "image-only")
        assert response.status_code == 404, run_id
        response = await execute(admin, run_id, plan_digest="0" * 64)
        assert response.status_code == 404, run_id
    assert snapshot(admin) == before
    assert fakes.applied == []


# VERIFY, DISCARD AND WARNINGS


async def test_verify_page_polls_then_shows_the_plan(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, storage_id = await ready(admin, fakes)
    gate = threading.Event()
    verify_archive = rv.verify_archive

    def held(*args: Any, **kwargs: Any) -> rv.Staged:
        assert gate.wait(30)
        return verify_archive(*args, **kwargs)

    monkeypatch.setattr(rv, "verify_archive", held)
    name, _ = web_archive(admin)
    run_id = await start(admin, storage_id, name)
    try:
        assert run_status(admin, run_id) == "verifying"
        page = await admin.get(f"/restore/runs/{run_id}/plan")
        assert page.status_code == 200
        assert 'id="run-log"' in page.text and 'role="log"' in page.text
        assert 'id="log-poller"' in page.text
        assert f'action="/restore/runs/{run_id}/plan"' not in page.text
    finally:
        gate.set()
    await admin.app.state.dispatcher.wait(run_id)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'id="log-poller"' not in page.text
    assert f'action="/restore/runs/{run_id}/plan"' in page.text
    assert ">signed<" in page.text
    response = await admin.get(f"/runs/{run_id}/log", headers={"HX-Request": "true"})
    assert response.status_code == 204 and response.headers["HX-Refresh"] == "true"


async def test_discard_via_cancel_removes_staging(admin: Browser, fakes: Fakes) -> None:
    _, storage_id = await ready(admin, fakes)
    name, _ = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    staged = rv.restore_dir(admin.settings.staging_dir, run_id)
    assert staged.is_dir()
    page = await admin.get(f"/runs/{run_id}")
    assert 'hx-confirm="Discard this restore?' in page.text
    assert f'href="/restore/runs/{run_id}/plan"' in page.text
    response = await admin.post(f"/runs/{run_id}/cancel")
    assert response.status_code == 303, response.text
    assert run_status(admin, run_id) == "cancelled"
    assert not staged.exists()
    assert audits(admin, "run.cancel") == ["success"]
    response = await admin.post(f"/runs/{run_id}/cancel")
    assert response.status_code == 409
    assert audits(admin, "run.cancel") == ["success", "failure"]


def add_restore_run(
    browser: Browser, status: str, journal: dict[str, Any], plan: dict[str, Any] | None = None
) -> int:
    with browser.app.state.sessionmaker() as db, db.begin():
        run = Run(
            job_id=None,
            kind="restore",
            status=status,
            triggered_by="admin",
            archive_name=f"drydock-web-{uuid.uuid4()}-20261001T120000Z.tar.zst",
            plan=json.dumps(plan or {}),
            restore_originals_json=json.dumps(journal),
        )
        db.add(run)
        db.flush()
        return run.id


async def test_partial_data_warning_is_shown(admin: Browser) -> None:
    original = {"id": WEB_ID, "name": "web", "old_name": "web-drydock-old", "running": True}
    overwrite = {
        "host_id": 1,
        "mode": "overwrite",
        "originals": [original],
        "wipe_started": True,
        "data_started": False,
        "committed": False,
        "volumes": ["data"],
        "binds": [],
    }
    cases = [
        (
            "interrupted",
            overwrite | {"rolled_back": True},
            ["may be partial", "volume data", "renamed back"],
            ["pending or failed"],
        ),
        (
            "interrupted",
            overwrite | {"rolled_back": False},
            ["may be partial", "volume data", "pending or failed"],
            ["renamed back"],
        ),
        (
            "failed",
            {
                "mode": "new-name",
                "originals": [],
                "data_started": True,
                "volumes": ["copy-data"],
                "binds": ["/srv/copy"],
                "rolled_back": True,
            },
            ["may be partial", "volume copy-data", "bind mount /srv/copy"],
            ["renamed back", "pending or failed"],
        ),
        (
            "done",
            {"mode": "overwrite", "committed": True, "leftover": ["web-drydock-old"]},
            ["Remove web-drydock-old by hand; drydock could not."],
            ["may be partial"],
        ),
    ]
    committed = {"mode": "overwrite", "committed": True, "originals": [original]}
    cases += [
        (
            "failed",
            committed | {"rolled_back": False},
            ["removing the originals is still pending or failed"],
            ["may be partial"],
        ),
        (
            "interrupted",
            committed | {"rolled_back": True},
            ["drydock finished removing the originals at startup"],
            ["pending or failed"],
        ),
    ]
    for status, journal, present, absent in cases:
        run_id = add_restore_run(admin, status, journal)
        page = await admin.get(f"/runs/{run_id}")
        assert page.status_code == 200
        warning = WARNING_RE.search(page.text)
        assert warning is not None, (status, journal)
        for text in present:
            assert text in warning.group(1), (status, journal, text)
        for text in absent:
            assert text not in page.text, (status, journal, text)
    quiet = add_restore_run(admin, "failed", {"wipe_started": False, "data_started": False})
    page = await admin.get(f"/runs/{quiet}")
    assert "may be partial" not in page.text and "by hand" not in page.text
    # A healthy run removing its originals (journal committed, rollback not done) is no
    # cause for a warning while it is still going.
    for status in ("queued", "running", "done"):
        live = add_restore_run(admin, status, committed | {"rolled_back": False})
        page = await admin.get(f"/runs/{live}")
        assert WARNING_RE.search(page.text) is None, status


async def test_compose_files_warning_is_shown(admin: Browser) -> None:
    """The compose files are written after the commit, best effort: a run that is done
    still warns when they failed, or may not have been written, and names the directory
    from the confirmed summary, never the error text."""
    plan = {"summary": {"mode": "new-name", "compose": {"dir": "/srv/copy", "files": []}}}
    committed = {"mode": "new-name", "committed": True, "originals": []}
    problem = "Could not write the compose files to /srv/copy: secret detail."
    cases = [
        ("done", committed | {"compose_problem": problem}, "were not written to /srv/copy"),
        ("interrupted", committed, "may not have been written to /srv/copy"),
        ("done", committed, "may not have been written to /srv/copy"),
    ]
    for status, journal, text in cases:
        run_id = add_restore_run(admin, status, journal, plan)
        page = await admin.get(f"/runs/{run_id}")
        warning = WARNING_RE.search(page.text)
        assert warning is not None, (status, journal)
        assert text in warning.group(1), (status, journal)
        assert "secret detail" not in warning.group(1)
    quiet = [
        ("done", committed | {"compose_written": True}, plan),
        ("running", committed, plan),
        ("done", committed, {}),  # the plan wrote no compose files
        ("failed", {"mode": "new-name", "committed": False, "originals": []}, plan),
    ]
    for status, journal, quiet_plan in quiet:
        run_id = add_restore_run(admin, status, journal, quiet_plan)
        page = await admin.get(f"/runs/{run_id}")
        assert WARNING_RE.search(page.text) is None, (status, journal)


async def test_plan_form_errors_and_stored_choice(admin: Browser, fakes: Fakes) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, _ = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    response = await plan(admin, run_id, host_id + 100, "overwrite")
    assert response.status_code == 422
    assert "Choose an enabled host." in response.text
    response = await plan(admin, run_id, host_id, "sideways")
    assert response.status_code == 422
    assert "Choose a restore mode this archive supports." in response.text
    response = await plan(admin, run_id, host_id, "new-name", new_name="-bad")
    assert response.status_code == 422
    assert "The new name must start with a letter or digit" in response.text
    assert audits(admin, "restore.plan") == ["failure", "failure", "failure"]
    assert fakes.applied == []

    response = await plan(admin, run_id, host_id, "new-name", new_name="web-copy", volmap_0="x")
    assert response.status_code == 303, response.text
    doc = stored(admin, run_id)
    choice = p.Choice.from_dict(doc["choice"])
    # Fields of other modes stay out of the stored choice.
    assert choice == p.Choice(host_id, "new-name", new_name="web-copy")
    assert doc["summary"]["containers"] == ["web-copy"]
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'value="web-copy"' in page.text
    assert "4. Confirm" in page.text
    details = admin.sql(
        "SELECT details FROM audit_events WHERE action = 'restore.plan' AND outcome = 'success'"
    )[0][0]
    assert json.loads(details) == {
        "mode": "new-name",
        "host_id": host_id,
        "flags": [],
        "signed": True,
    }

    # Executing twice: the second one finds the run no longer awaiting confirmation.
    response = await execute(admin, run_id)
    assert response.status_code == 303, response.text
    response = await execute(admin, run_id)
    assert response.status_code == 409
    await admin.app.state.dispatcher.wait(run_id)
    response = await plan(admin, run_id, host_id, "new-name", new_name="web-copy")
    assert response.status_code == 409
    assert len(fakes.applied) == 1
    assert fakes.applied[0].mode == "new-name"


async def test_execute_refuses_a_plan_replaced_after_it_was_shown(
    admin: Browser, fakes: Fakes
) -> None:
    """A superadmin confirms what the page showed. An admin may re-plan a signed archive
    meanwhile; the flag keys and the typed name stay the same on another host, so only
    the digest tells the two plans apart."""
    staging, storage_id = await ready(admin, fakes)
    production = add_host(admin, "production")
    name, _ = web_archive(admin, host_config={"Privileged": True})
    run_id = await verified(admin, storage_id, name)
    response = await plan(admin, run_id, staging, "overwrite")
    assert response.status_code == 303, response.text
    keys = flag_keys(admin, run_id)
    assert "web:Privileged" in keys
    shown = await seen_digest(admin, run_id)
    assert shown

    await login_as(admin, "alice", "admin")
    response = await plan(admin, run_id, production, "overwrite")
    assert response.status_code == 303, response.text
    assert flag_keys(admin, run_id) == keys
    assert stored(admin, run_id)["summary"]["host_id"] == production

    await admin.login("admin")
    response = await execute(admin, run_id, confirm_name="web", ack=keys, plan_digest=shown)
    assert response.status_code == 409
    assert "The plan changed since you viewed it." in response.text
    response = await execute(admin, run_id, confirm_name="web", ack=keys, plan_digest="")
    assert response.status_code == 409
    assert run_status(admin, run_id) == "awaiting_confirmation"
    assert fakes.applied == []
    assert audits(admin, "restore.execute") == ["failure", "failure"]

    # Reviewing the page again shows the production plan; confirming that one runs it.
    response = await execute(admin, run_id, confirm_name="web", ack=keys)
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "done"
    assert len(fakes.applied) == 1
    assert fakes.applied[0].host_id == production


async def test_non_ascii_digit_ids_are_refused(admin: Browser, fakes: Fakes) -> None:
    """str.isdigit() accepts superscript digits that int() rejects: no 500."""
    _, storage_id = await ready(admin, fakes)
    name, _ = web_archive(admin)
    response = await admin.post("/restore/from-storage", {"storage_id": "²", "name": name})
    assert response.status_code == 422
    assert audits(admin, "restore.verify") == ["failure"]
    run_id = await verified(admin, storage_id, name)
    form = {"host_id": "²", "mode": "image-only"}
    response = await admin.post(f"/restore/runs/{run_id}/plan", form)
    assert response.status_code == 422
    assert "Choose an enabled host." in response.text
    assert audits(admin, "restore.plan") == ["failure"]


# STACKS AND COMPOSE FILES

PROJECT = "com.docker.compose.project"
COMPOSE = (("config_file", "/srv/app/compose.yaml", b"services: {}\n"),)


def stack_member(service: str, depends: str = "") -> dict[str, Any]:
    """A container of Compose project app, as Docker inspects it."""
    labels = {
        PROJECT: "app",
        "com.docker.compose.service": service,
        "com.docker.compose.container-number": "1",
        "com.docker.compose.project.working_dir": "/srv/app",
    }
    if depends:
        labels["com.docker.compose.depends_on"] = depends
    return container_inspect(
        f"app-{service}-1",
        id=hashlib.sha256(service.encode()).hexdigest(),
        image_id=IMAGE_ID,
        labels=labels,
    )


def compose_archive(
    browser: Browser, monkeypatch: pytest.MonkeyPatch, *, stack: bool
) -> tuple[str, Any]:
    """A stack job's archive of project app (web depends on db), or a container job's
    archive of app-web-1 alone, both with the project's compose file."""
    if stack:
        containers = [stack_member("web", "db:service_started:false"), stack_member("db")]
    else:
        containers = [stack_member("web")]
    with monkeypatch.context() as patched:
        if stack:
            job = functools.partial(capture.CaptureJob, target_type="stack", project="app")
            patched.setattr(capture, "CaptureJob", job)
        return build_archive(
            browser.settings.local_storage_roots[0],
            browser.app.state.crypto,
            job_name="app",
            containers=containers,
            compose=COMPOSE,
            images=[(IMAGE_ID, ["busybox:1.37"], image_tar(IMAGE_ID, ["busybox:1.37"]), None)],
        )


def audit_details(browser: Browser, action: str) -> list[dict[str, Any]]:
    rows = browser.sql(
        "SELECT details FROM audit_events WHERE action = ? AND outcome = 'success' ORDER BY id",
        (action,),
    )
    return [json.loads(details) for (details,) in rows]


async def test_stack_restores_under_a_new_project_with_its_compose_files(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, manifest = compose_archive(admin, monkeypatch, stack=True)
    assert manifest.job.target_type == "stack" and manifest.job.project == "app"
    run_id = await verified(admin, storage_id, name)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'Compose project <span class="font-mono">app</span>, 2 containers' in page.text
    assert "New project name (new-name mode)" in page.text
    assert "Containers become &lt;name&gt;-&lt;service&gt;-&lt;number&gt;" in page.text
    assert 'name="compose_dir"' in page.text
    assert "/srv/app/compose.yaml" in page.text

    response = await plan(admin, run_id, host_id, "new-name", new_name="Copy")
    assert response.status_code == 422
    assert "The new project name must hold 1 to 63 lowercase letters" in response.text
    response = await plan(
        admin, run_id, host_id, "new-name", new_name="copy", compose_dir="/srv/copy"
    )
    assert response.status_code == 303, response.text
    doc = stored(admin, run_id)
    assert doc["choice"]["compose_dir"] == "/srv/copy"
    summary = doc["summary"]
    assert summary["project"] == "copy"
    assert summary["containers"] == ["copy-db-1", "copy-web-1"]
    assert summary["compose"] == {"dir": "/srv/copy", "files": ["compose.yaml"]}
    assert summary["risk"] == []
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert '<dd class="font-mono break-all">copy</dd>' in page.text
    assert "(created and started in this order)" in page.text
    assert 'Written to <span class="font-mono">/srv/copy</span>' in page.text
    assert audit_details(admin, "restore.plan")[-1] == {
        "mode": "new-name",
        "host_id": host_id,
        "flags": [],
        "signed": True,
        "project": "copy",
        "compose_dir": "/srv/copy",
    }

    # A compose directory needs no recent auth by itself.
    stale_auth(admin)
    response = await execute(admin, run_id)
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "done"
    (applied,) = fakes.applied
    assert applied.project == "copy" and applied.projects == ("copy",)
    assert applied.compose is not None and applied.compose.dir == "/srv/copy"
    assert audit_details(admin, "restore.execute")[-1]["project"] == "copy"


async def test_stack_overwrite_needs_the_project_name_and_recent_auth(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, _ = compose_archive(admin, monkeypatch, stack=True)
    run_id = await verified(admin, storage_id, name)
    response = await plan(admin, run_id, host_id, "overwrite")
    assert response.status_code == 303, response.text
    summary = stored(admin, run_id)["summary"]
    assert summary["project"] == "app" and "compose" not in summary
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'Type <span class="font-mono">app</span> to confirm' in page.text

    response = await execute(admin, run_id, confirm_name="app-db-1")
    assert response.status_code == 422
    assert "Type the project name to confirm." in response.text
    stale_auth(admin)
    response = await execute(admin, run_id, confirm_name="app")
    assert response.status_code == 403
    assert REAUTH_FORM in response.text
    await reauth(admin)
    response = await execute(admin, run_id, confirm_name="app")
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert run_status(admin, run_id) == "done"
    (applied,) = fakes.applied
    assert [step.name for step in applied.containers] == ["app-db-1", "app-web-1"]
    assert applied.project == "app"


async def test_single_container_archive_can_write_its_compose_files(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, manifest = compose_archive(admin, monkeypatch, stack=False)
    assert manifest.job.target_type == "container"
    run_id = await verified(admin, storage_id, name)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'name="compose_dir"' in page.text and "New name (new-name mode)" in page.text
    assert "New project name" not in page.text

    for mode, fields in (("new-name", {"new_name": "web-copy"}), ("overwrite", {})):
        response = await plan(admin, run_id, host_id, mode, compose_dir="/srv/copy", **fields)
        assert response.status_code == 303, response.text
        summary = stored(admin, run_id)["summary"]
        assert summary["compose"] == {"dir": "/srv/copy", "files": ["compose.yaml"]}
        assert "project" not in summary
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'Type <span class="font-mono">app-web-1</span> to confirm' in page.text
    response = await execute(admin, run_id, confirm_name="app-web-1")
    assert response.status_code == 303, response.text
    await admin.app.state.dispatcher.wait(run_id)
    assert fakes.applied[0].compose is not None

    # The field is shown only for archives with compose files; a stale value is refused.
    name, _ = web_archive(admin)
    run_id = await verified(admin, storage_id, name)
    page = await admin.get(f"/restore/runs/{run_id}/plan")
    assert 'name="compose_dir"' not in page.text
    response = await plan(admin, run_id, host_id, "overwrite", compose_dir="/srv/copy")
    assert response.status_code == 422
    assert "This archive holds no compose files." in response.text
    # Other modes ignore it.
    response = await plan(admin, run_id, host_id, "image-only", compose_dir="/srv/copy")
    assert response.status_code == 303, response.text
    assert stored(admin, run_id)["choice"]["compose_dir"] == ""


async def test_compose_dir_under_etc_is_rejected_for_superadmin(
    admin: Browser, fakes: Fakes, monkeypatch: pytest.MonkeyPatch
) -> None:
    host_id, storage_id = await ready(admin, fakes)
    name, _ = compose_archive(admin, monkeypatch, stack=True)
    run_id = await verified(admin, storage_id, name)
    for directory in ("/etc/stack", "/etc"):
        response = await plan(admin, run_id, host_id, "overwrite", compose_dir=directory)
        assert response.status_code == 422, (directory, response.text)
        assert f"Drydock never writes to {directory}." in response.text
    response = await plan(admin, run_id, host_id, "overwrite", compose_dir="/var/stack")
    assert response.status_code == 422
    assert "Drydock cannot create a directory in /var" in response.text
    assert "summary" not in stored(admin, run_id)
    assert audits(admin, "restore.plan") == ["failure"] * 3
