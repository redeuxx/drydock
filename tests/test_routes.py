"""Route inventory: every route is classified, guarded and audited."""

import dataclasses
import inspect
import re
import secrets

import asyncssh
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, RouteContext, iter_route_contexts
from starlette.routing import Mount

from drydock import notify
from drydock.archive.writer import Cancelled
from drydock.crypto import Crypto
from drydock.hosts import client as docker_client
from drydock.hosts import ssh
from drydock.hosts.manager import HostManager
from drydock.jobs.dispatcher import Dispatcher, Target
from drydock.jobs.runlog import RunLog, log_path
from drydock.models import Backup, Run
from drydock.notify import Notifier
from drydock.restore import apply as restore_apply
from drydock.restore import plan as restore_plan
from drydock.routes import auth as auth_routes
from drydock.security import csrf
from drydock.security.rbac import Role, authenticated
from drydock.storage import certs, gdrive_oauth
from tests.conftest import PASSWORD, Browser, add_user
from tests.rclone_support import certificate
from tests.restore_support import build_archive, container_inspect, image_tar

pytestmark = pytest.mark.anyio

NEW_PASSWORD = "another long passphrase"
SSH_HOST_FORM = {
    "kind": "ssh",
    "name": "remote",
    "address": "203.0.113.9",
    "port": "22",
    "username": "backup",
    "remote_socket_path": "/var/run/docker.sock",
    "key_source": "generate",
    "enabled": "1",
}
FAKE_HOST_KEY = ssh.public_key_line(asyncssh.generate_private_key("ssh-ed25519"))
FAKE_FINGERPRINT = "SHA256:" + "A" * 43
DRIVE_FORM = {
    "name": "gdrive",
    "kind": "drive",
    "enabled": "1",
    "opt_client_id": "1234-abc.apps.googleusercontent.com",
    "opt_client_secret": "secret",
}

# Reachable without a session. Everything else requires one.
PUBLIC = {"/setup", "/login", "/healthz"}
# GET routes allowed to write something other than sessions.last_seen_at, with their guard.
GET_WRITE_EXEMPTIONS: dict[str, str] = {
    "/storage/oauth/callback": "the single-use, user-bound OAuth state (storage.gdrive_oauth)",
}
# (methods, path pattern, minimum role); the first match wins.
EXPECTED_MIN_ROLE = [
    ({"GET", "POST"}, re.compile(r"^/users"), Role.superadmin),
    ({"GET"}, re.compile(r"^/hosts/[^/]+/containers$"), Role.viewer),  # "view inventory"
    ({"GET", "POST"}, re.compile(r"^/hosts"), Role.admin),
    ({"GET", "POST"}, re.compile(r"^/audit"), Role.admin),
    ({"GET", "POST"}, re.compile(r"^/storage"), Role.admin),
    ({"GET"}, re.compile(r"^/notifications/new$"), Role.superadmin),
    ({"POST"}, re.compile(r"^/notifications"), Role.superadmin),
    ({"GET"}, re.compile(r"^/notifications"), Role.admin),
    ({"POST"}, re.compile(r"^/jobs/[^/]+/passphrase$"), Role.superadmin),
    ({"POST"}, re.compile(r"^/jobs/[^/]+/run$"), Role.operator),
    ({"POST"}, re.compile(r"^/runs/[^/]+/cancel$"), Role.operator),
    ({"GET", "POST", "PUT"}, re.compile(r"^/restore"), Role.admin),
    ({"GET"}, re.compile(r"^/hooks/new$"), Role.superadmin),
    ({"POST"}, re.compile(r"^/hooks"), Role.superadmin),
    ({"GET"}, re.compile(r"^/hooks"), Role.admin),
    ({"GET"}, re.compile(r"^/jobs/new$"), Role.admin),
    ({"GET"}, re.compile(r"^/jobs/cron-preview$"), Role.admin),
    ({"POST"}, re.compile(r"^/jobs"), Role.admin),
    ({"GET", "POST"}, re.compile(r".*"), Role.viewer),
]
# Every route the app serves. A new route fails this test until it is added here,
# which forces a decision about its role, CSRF and audit coverage.
INVENTORY = {
    ("GET", "/"),
    ("GET", "/account"),
    ("GET", "/account/password"),
    ("POST", "/account/password"),
    ("GET", "/audit"),
    ("GET", "/healthz"),
    ("GET", "/hosts"),
    ("POST", "/hosts"),
    ("GET", "/hosts/new"),
    ("GET", "/hosts/{host_id}"),
    ("POST", "/hosts/{host_id}"),
    ("GET", "/hosts/{host_id}/containers"),
    ("POST", "/hosts/{host_id}/delete"),
    ("POST", "/hosts/{host_id}/key"),
    ("POST", "/hosts/{host_id}/scan-hostkey"),
    ("POST", "/hosts/{host_id}/test"),
    ("POST", "/hosts/{host_id}/trust-hostkey"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("POST", "/logout"),
    ("GET", "/reauth"),
    ("POST", "/reauth"),
    ("GET", "/setup"),
    ("POST", "/setup"),
    ("GET", "/users"),
    ("POST", "/users"),
    ("GET", "/users/new"),
    ("GET", "/users/{user_id}"),
    ("POST", "/users/{user_id}/delete"),
    ("POST", "/users/{user_id}/disabled"),
    ("POST", "/users/{user_id}/password"),
    ("POST", "/users/{user_id}/role"),
    ("POST", "/users/{user_id}/sessions/revoke"),
    ("GET", "/storage"),
    ("POST", "/storage"),
    ("GET", "/storage/new"),
    ("GET", "/storage/{storage_id}"),
    ("POST", "/storage/{storage_id}"),
    ("POST", "/storage/{storage_id}/delete"),
    ("POST", "/storage/{storage_id}/test"),
    ("POST", "/storage/host-key"),
    ("POST", "/storage/certificate"),
    ("GET", "/storage/oauth/guide"),
    ("GET", "/storage/oauth/callback"),
    ("POST", "/storage/{storage_id}/oauth/start"),
    ("POST", "/storage/{storage_id}/oauth/paste"),
    ("GET", "/notifications"),
    ("POST", "/notifications"),
    ("GET", "/notifications/new"),
    ("GET", "/notifications/{target_id}"),
    ("POST", "/notifications/{target_id}"),
    ("POST", "/notifications/{target_id}/delete"),
    ("POST", "/notifications/{target_id}/test"),
    ("GET", "/jobs"),
    ("POST", "/jobs"),
    ("GET", "/jobs/new"),
    ("GET", "/jobs/cron-preview"),
    ("GET", "/jobs/{job_id}"),
    ("POST", "/jobs/{job_id}"),
    ("POST", "/jobs/{job_id}/delete"),
    ("POST", "/jobs/{job_id}/passphrase"),
    ("POST", "/jobs/{job_id}/run"),
    ("GET", "/hooks"),
    ("POST", "/hooks"),
    ("GET", "/hooks/new"),
    ("GET", "/hooks/{hook_id}"),
    ("POST", "/hooks/{hook_id}"),
    ("POST", "/hooks/{hook_id}/delete"),
    ("GET", "/runs"),
    ("GET", "/runs/{run_id}"),
    ("GET", "/runs/{run_id}/log"),
    ("POST", "/runs/{run_id}/cancel"),
    ("GET", "/backups"),
    ("GET", "/restore"),
    ("GET", "/restore/storage/{storage_id}"),
    ("POST", "/restore/from-storage"),
    ("PUT", "/restore/uploads"),
    ("POST", "/restore/from-upload/{upload_id}"),
    ("POST", "/restore/from-path"),
    ("GET", "/restore/runs/{restore_id}/plan"),
    ("POST", "/restore/runs/{restore_id}/plan"),
    ("POST", "/restore/runs/{restore_id}/execute"),
}
CROSS_SITE = [
    {"Origin": "https://evil.example"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Origin": "null"},
]


def api_routes(app: FastAPI) -> list[tuple[str, str, RouteContext]]:
    """Flattens included routers; app.routes alone only lists the router wrappers."""
    return [
        (method, ctx.path, ctx)
        for ctx in iter_route_contexts(app.routes)
        if isinstance(ctx.original_route, APIRoute)
        for method in sorted(ctx.methods)
    ]


def dependency_calls(route: RouteContext) -> list:
    calls, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        calls.append(dep.call)
        stack.extend(dep.dependencies)
    return calls


def declared_roles(route: RouteContext) -> list[Role]:
    return [c.required_role for c in dependency_calls(route) if hasattr(c, "required_role")]


def fill(path: str, user_id: int, **ids: int) -> str:
    """Replaces {user_id} and any other {name} placeholder (default: user_id)."""
    for name in (
        "host_id",
        "storage_id",
        "job_id",
        "hook_id",
        "run_id",
        "restore_id",
        "target_id",
        "upload_id",
    ):
        path = path.replace("{" + name + "}", str(ids.get(name, user_id)))
    return path.replace("{user_id}", str(user_id))


async def add_hosts(browser: Browser) -> tuple[int, int]:
    """A local host on an unreachable proxy and an SSH host that is not trusted yet."""
    local = await browser.post(
        "/hosts",
        {"kind": "local", "name": "local", "docker_url": "tcp://127.0.0.1:9", "enabled": "1"},
    )
    remote = await browser.post("/hosts", SSH_HOST_FORM)
    assert local.status_code == remote.status_code == 303, (local.text, remote.text)
    return tuple(int(r.headers["location"].rsplit("/", 1)[1]) for r in (local, remote))


async def test_every_route_is_classified(admin: Browser) -> None:
    app = admin.app
    mounts = [r.path for r in app.routes if isinstance(r, Mount)]
    assert mounts == ["/static"]
    assert {(method, path) for method, path, _ in api_routes(app)} == INVENTORY
    for method, path, route in api_routes(app):
        calls = dependency_calls(route)
        roles = declared_roles(route)
        source = inspect.getsource(route.endpoint)
        if path in PUBLIC:
            assert not roles, path
            if method != "GET":
                assert csrf.verify_presession in calls, path
                assert "audit.record(" in source, path
            continue
        assert len(roles) == 1, f"{method} {path} has no role check"
        assert authenticated in calls, path
        expected = next(
            role
            for methods, pattern, role in EXPECTED_MIN_ROLE
            if method in methods and pattern.match(path)
        )
        assert roles[0] == expected, f"{method} {path} requires {roles[0]!r}, not {expected!r}"
        if method != "GET":
            assert "audit.record(" in source, f"{method} {path} is not audited"


async def test_every_private_route_requires_a_session(admin: Browser) -> None:
    admin.client.cookies.clear()
    for method, path, _route in api_routes(admin.app):
        if path in PUBLIC:
            continue
        response = await admin.client.request(method, fill(path, 1), headers=admin.origin_headers)
        assert response.status_code == 303, f"{method} {path}"
        assert response.headers["location"] == "/login"


async def test_every_unsafe_route_rejects_missing_csrf_and_cross_site(admin: Browser) -> None:
    victim = await add_user(admin, "victim", "viewer")
    token = await admin.csrf_token()
    before = snapshot(admin)
    for method, path, _route in api_routes(admin.app):
        if method == "GET" or path in PUBLIC:
            continue
        url = fill(path, victim)
        response = await admin.client.request(method, url, headers=admin.origin_headers)
        assert response.status_code == 403, f"{method} {path} without token"
        for headers in CROSS_SITE:
            response = await admin.client.request(
                method, url, headers={"X-CSRF-Token": token, **headers}
            )
            assert response.status_code == 403, f"{method} {path} with {headers}"
    assert snapshot(admin) == before


def snapshot(browser: Browser) -> dict[str, list[tuple]]:
    with browser.db() as conn:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        result = {}
        for table in tables:
            columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
            if table == "sessions":
                columns.remove("last_seen_at")
            result[table] = conn.execute(
                f"SELECT {', '.join(columns)} FROM {table} ORDER BY 1"  # noqa: S608
            ).fetchall()
    return result


async def add_backup_objects(browser: Browser, host_id: int) -> dict[str, int]:
    """A storage target holding one archive, a hook, a job on host_id that runs it, a
    finished run with a catalogued backup, and a finished restore run. browser is a
    superadmin with recent auth."""
    root = browser.settings.local_storage_roots[0]
    storage = await browser.post("/storage", {"name": "backups", "path": str(root), "enabled": "1"})
    assert storage.status_code == 303, storage.text
    storage_id = int(storage.headers["location"].rsplit("/", 1)[1])
    hook = await browser.post("/hooks", hook_form(host_id))
    assert hook.status_code == 303, hook.text
    hook_id = int(hook.headers["location"].rsplit("/", 1)[1])
    target = await browser.post(
        "/notifications",
        # Nothing listens there: a run of this job never reaches a real service.
        {
            "name": "ops",
            "kind": "ntfy",
            "ntfy_server": "http://127.0.0.1:9",
            "ntfy_topic": "backups",
            "enabled": "1",
        },
    )
    assert target.status_code == 303, target.text
    target_id = int(target.headers["location"].rsplit("/", 1)[1])
    job = await browser.post(
        "/jobs",
        job_form(
            host_id,
            storage_id,
            pre_hooks="dump",
            notifications="1",
            notify_failure=str(target_id),
        ),
    )
    assert job.status_code == 303, job.text
    job_id = int(job.headers["location"].rsplit("/", 1)[1])
    archive, _ = build_archive(
        root, browser.app.state.crypto, containers=[container_inspect("web")], scope="config"
    )
    with browser.app.state.sessionmaker() as db, db.begin():
        run = Run(job_id=job_id, status="done", triggered_by="admin", archive_name="a", size=1)
        restore = Run(
            job_id=None,
            kind="restore",
            status="done",
            triggered_by="admin",
            archive_name=archive,
            plan="{}",
        )
        db.add_all([run, restore])
        db.add(Backup(job_id=job_id, storage_target_id=storage_id, name="a", size=1, sha256="0"))
        db.flush()
        run_id, restore_id = run.id, restore.id
    RunLog(log_path(browser.settings.data_dir, run_id))("A line.")
    return {
        "storage_id": storage_id,
        "job_id": job_id,
        "hook_id": hook_id,
        "run_id": run_id,
        "restore_id": restore_id,
        "target_id": target_id,
    }


def job_form(
    host_id: int | str, storage_id: int | str, name: str = "web backup", **fields: str
) -> dict:
    return {
        "name": name,
        "host_id": str(host_id),
        "target": "web",
        "storage_target_id": str(storage_id),
        "scope": "config",
        "encrypted": "1",
        "enabled": "1",
    } | fields


def hook_form(host_id: int | str, name: str = "dump", **fields: str) -> dict:
    """A container hook for the container job_form backs up."""
    return {
        "name": name,
        "host_id": str(host_id),
        "container": "web",
        "argv": '["pg_dump", "-f", "/srv/dump.sql"]',
        "timeout_s": "300",
    } | fields


async def test_get_routes_write_nothing_but_last_seen(admin: Browser) -> None:
    victim = await add_user(admin, "victim", "operator")
    hosts = await add_hosts(admin)
    ids = await add_backup_objects(admin, hosts[0])
    before = snapshot(admin)
    for host_id in hosts:
        for method, path, _route in api_routes(admin.app):
            if method != "GET" or path in GET_WRITE_EXEMPTIONS:
                continue
            response = await admin.get(fill(path, victim, host_id=host_id, **ids))
            assert response.status_code in (200, 404), f"GET {path}: {response.status_code}"
            if "{" in path:
                assert response.status_code == 200, f"GET {path}"
    response = await admin.get(f"/runs/{ids['run_id']}/log", headers={"HX-Request": "true"})
    assert response.status_code == 204 and response.headers["HX-Refresh"] == "true"
    assert snapshot(admin) == before


async def test_restore_plan_page_writes_nothing_in_any_state(
    admin: Browser, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan page while verifying, and while awaiting confirmation without and with a
    stored plan (load_staged, the digest and the recent-auth check), writes nothing. The
    archive is unsigned here, so the stored plan needs recent auth."""
    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", lambda url, timeout=60: FakeDocker())
    monkeypatch.setattr(restore_apply, "inspect_target", empty_target)
    hosts = await add_hosts(admin)
    ids = await add_backup_objects(admin, hosts[0])
    image_id = "sha256:" + "a" * 64
    archive, _ = build_archive(
        admin.settings.local_storage_roots[0],
        Crypto((secrets.token_bytes(32),)),  # a foreign drydock: unsigned here
        scope="image",
        images=[(image_id, ["busybox:1.37"], image_tar(image_id, ["busybox:1.37"]), None)],
    )
    with admin.app.state.sessionmaker() as db, db.begin():
        verifying = Run(
            job_id=None,
            kind="restore",
            status="verifying",
            triggered_by="admin",
            archive_name=archive,
            plan="{}",
        )
        db.add(verifying)
        db.flush()
        verifying_id = verifying.id
    form = {"storage_id": str(ids["storage_id"]), "name": archive}
    response = await admin.post("/restore/from-storage", form)
    assert response.status_code == 303, response.text
    awaiting_id = int(response.headers["location"].split("/")[3])
    await admin.app.state.dispatcher.wait(awaiting_id)
    statuses = admin.sql(
        "SELECT id, status FROM runs WHERE id IN (?, ?)", (verifying_id, awaiting_id)
    )
    assert dict(statuses) == {verifying_id: "verifying", awaiting_id: "awaiting_confirmation"}

    before = snapshot(admin)
    page = await admin.get(f"/restore/runs/{verifying_id}/plan")
    assert page.status_code == 200 and 'id="log-poller"' in page.text
    page = await admin.get(f"/restore/runs/{awaiting_id}/plan")
    assert page.status_code == 200 and f'action="/restore/runs/{awaiting_id}/plan"' in page.text
    assert 'name="plan_digest"' not in page.text
    assert snapshot(admin) == before

    form = {"host_id": str(hosts[0]), "mode": "image-only"}
    response = await admin.post(f"/restore/runs/{awaiting_id}/plan", form)
    assert response.status_code == 303, response.text
    for stale in (False, True):
        if stale:
            admin.sql("UPDATE sessions SET reauth_at = NULL")
        before = snapshot(admin)
        page = await admin.get(f"/restore/runs/{awaiting_id}/plan")
        assert page.status_code == 200 and 'name="plan_digest"' in page.text
        assert ("asks for your password" in page.text) is stale
        assert snapshot(admin) == before


VIEWER_PAGES = {"/", "/account", "/jobs", "/runs", "/backups"}
ADMIN_PAGES = {"/audit", "/hosts", "/storage", "/notifications", "/jobs/new", "/restore", "/hooks"}
# Pages whose section is open to a role that cannot open them.
NARROWER = {"/jobs/new", "/hooks/new"}


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        ("viewer", VIEWER_PAGES),
        ("operator", VIEWER_PAGES),
        ("admin", VIEWER_PAGES | ADMIN_PAGES),
        ("superadmin", VIEWER_PAGES | ADMIN_PAGES | {"/users", "/hooks/new"}),
    ],
)
async def test_role_matrix(admin: Browser, role: str, allowed: set[str]) -> None:
    local, _ = await add_hosts(admin)
    ids = await add_backup_objects(admin, local)
    await add_user(admin, f"user-{role}", role)
    await admin.login(f"user-{role}")
    pages = ("/", "/account", "/audit", "/users", "/users/new", "/users/1", "/hosts")
    host_pages = ("/hosts/new", f"/hosts/{local}", f"/hosts/{local}/containers")
    storage_pages = ("/storage", "/storage/new", f"/storage/{ids['storage_id']}")
    job_pages = ("/jobs", "/jobs/new", f"/jobs/{ids['job_id']}")
    hook_pages = ("/hooks", "/hooks/new", f"/hooks/{ids['hook_id']}")
    run_pages = ("/runs", f"/runs/{ids['run_id']}", f"/runs/{ids['run_id']}/log", "/backups")
    restore_pages = (
        "/restore",
        f"/restore/storage/{ids['storage_id']}",
        f"/restore/runs/{ids['restore_id']}/plan",
    )
    paths = pages + host_pages + storage_pages + job_pages + hook_pages + run_pages
    for path in paths + restore_pages:
        response = await admin.get(path)
        section = path.split("/")[1]
        section_allowed = path in allowed or (
            path not in NARROWER and section in {p.split("/")[1] for p in allowed}
        )
        expected = 200 if section_allowed or path.endswith("/containers") else 403
        assert response.status_code == expected, f"{role} GET {path}"
        if path == f"/jobs/{ids['job_id']}":
            # Run now for operators, editing for admins, the passphrase for superadmins.
            assert ('/run"' in response.text) == (role != "viewer"), role
            assert ("Edit job" in response.text) == (role in ("admin", "superadmin")), role
            assert ('/passphrase"' in response.text) == (role == "superadmin"), role
            # Every role sees the hook's name; only admins get a link to its page.
            assert "dump" in response.text, role
            hook_link = f'href="/hooks/{ids["hook_id"]}"' in response.text
            assert hook_link == (role in ("admin", "superadmin")), role
        if path == f"/hooks/{ids['hook_id']}":
            assert ("Edit hook" in response.text) == (role == "superadmin"), role


async def test_every_route_refuses_every_role_below_its_minimum(admin: Browser) -> None:
    """The role the inventory reads is the one enforced: every method on every route
    answers 403 to each lower role, with a valid CSRF token, and changes nothing."""
    minimums = [
        (method, path, roles[0])
        for method, path, route in api_routes(admin.app)
        if (roles := declared_roles(route))
    ]
    lower = (Role.viewer, Role.operator, Role.admin)
    for role in lower:
        await add_user(admin, f"user-{role.name}", role.name)
    tested = set()
    for role in lower:
        await admin.login(f"user-{role.name}")
        headers = admin.origin_headers | {"X-CSRF-Token": await admin.csrf_token()}
        before = snapshot(admin)
        for method, path, minimum in minimums:
            if role >= minimum:
                continue
            response = await admin.client.request(method, fill(path, 1), headers=headers)
            assert response.status_code == 403, f"{role.name} {method} {path}"
            assert "Your role does not allow this." in response.text, f"{method} {path}"
            tested.add(minimum)
        assert snapshot(admin) == before, role.name
    assert tested == {Role.operator, Role.admin, Role.superadmin}


@pytest.mark.parametrize(
    "path",
    [
        "/docs",
        "/redoc",
        "/openapi.json",
        # The package's own modules sit one level above the static folder.
        "/static/%2e%2e/main.py",
        "/static/%252e%252e/main.py",
        "/static/css/%2e%2e/%2e%2e/config.py",
    ],
)
async def test_nothing_is_served_outside_the_inventory(admin: Browser, path: str) -> None:
    response = await admin.get(path)
    assert response.status_code == 404, path
    assert "import" not in response.text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/users/3", "/users/3"),
        ("/restore?x=1", "/restore?x=1"),
        (None, "/"),
        ("", "/"),
        ("users", "/"),
        ("//evil.example/x", "/"),
        ("/\\evil.example", "/"),
        ("\\\\evil.example", "/"),
        ("https://evil.example/", "/"),
        ("javascript:alert(1)", "/"),
        ("/\tevil", "/"),
        ("/ok\r\nSet-Cookie: x=1", "/"),
        ("/ x", "/"),
        ("/x\x7f", "/"),
        ("/\u20ac", "/"),
        ("/x\u2028y", "/"),
        ("/x\u00a0y", "/"),
    ],
)
def test_redirect_targets_stay_on_drydock(value: str | None, expected: str) -> None:
    assert auth_routes.safe_next(value) == expected


# Every unsafe route, in an order that works on one fresh install, with a valid request,
# the audit action its success must record and the status it answers with. {user_id} is
# the user created by POST /users, {host_id} the host created by POST /hosts, and so on;
# placeholders in form values are filled the same way ({storage_root} is the allowed root).
AUDITED_SUCCESS = [
    ("/setup", None, "setup.complete", 303),
    ("/users", {"username": "victim", "password": PASSWORD, "role": "viewer"}, "user.create", 303),
    ("/users/{user_id}/role", {"role": "operator"}, "user.role", 303),
    ("/users/{user_id}/disabled", {"disabled": "1"}, "user.disable", 303),
    ("/users/{user_id}/password", {"password": NEW_PASSWORD}, "user.password_reset", 303),
    ("/users/{user_id}/sessions/revoke", {}, "user.sessions_revoke", 303),
    ("/users/{user_id}/delete", {}, "user.delete", 303),
    ("/hosts", SSH_HOST_FORM, "host.create", 303),
    ("/hosts/{host_id}", SSH_HOST_FORM | {"name": "remote-2"}, "host.update", 303),
    ("/hosts/{host_id}/key", {"key_source": "generate"}, "host.key", 303),
    ("/hosts/{host_id}/scan-hostkey", {}, "host.hostkey_scan", 200),
    (
        "/hosts/{host_id}/trust-hostkey",
        {"fingerprint": FAKE_FINGERPRINT},
        "host.hostkey_trust",
        303,
    ),
    ("/hosts/{host_id}/test", {}, "host.test", 200),
    (
        "/storage",
        {"name": "backups", "path": "{storage_root}", "enabled": "1"},
        "storage.create",
        303,
    ),
    (
        "/storage/{storage_id}",
        {"name": "backups-2", "path": "{storage_root}", "enabled": "1"},
        "storage.update",
        303,
    ),
    ("/storage/{storage_id}/test", {}, "storage.test", 200),
    (
        "/storage/host-key",
        {"kind": "sftp", "name": "nas", "opt_host": "203.0.113.9", "opt_port": "22"},
        "storage.hostkey_fetch",
        200,
    ),
    (
        "/storage/certificate",
        {"kind": "webdav", "name": "dav", "opt_url": "https://203.0.113.9"},
        "storage.cert_fetch",
        200,
    ),
    # On a Google Drive target of its own (DRIVE_FORM), Google faked.
    ("/storage/{storage_id}/oauth/start", {"mode": "paste"}, "storage.oauth_start", 200),
    (
        "/storage/{storage_id}/oauth/paste",
        {"url": "http://127.0.0.1:50000/?state=" + "s" * 43 + "&code=4/c"},
        "storage.oauth_connect",
        303,
    ),
    (
        "/notifications",
        {
            "name": "ops",
            "kind": "ntfy",
            "ntfy_server": "http://127.0.0.1:9",
            "ntfy_topic": "backups",
            "enabled": "1",
        },
        "notification.create",
        303,
    ),
    (
        "/notifications/{target_id}",
        {"name": "ops-2", "kind": "ntfy", "enabled": "1"},
        "notification.update",
        303,
    ),
    ("/notifications/{target_id}/test", {}, "notification.test", 200),
    ("/notifications/{target_id}/delete", {}, "notification.delete", 303),
    (
        "/restore/from-storage",
        {"storage_id": "{storage_id}", "name": "{archive}"},
        "restore.verify",
        303,
    ),
    ("/restore/uploads", None, "restore.upload", 201),  # a PUT of the archive itself
    (
        "/restore/runs/{restore_id}/plan",
        {"host_id": "{host_id}", "mode": "image-only"},
        "restore.plan",
        303,
    ),
    (
        "/restore/runs/{restore_id}/execute",
        {"plan_digest": "{plan_digest}"},
        "restore.execute",
        303,
    ),
    ("/restore/from-upload/{upload_id}", {}, "restore.verify", 303),
    ("/restore/from-path", {"path": "{storage_root}/{archive}"}, "restore.verify", 303),
    ("/hooks", hook_form("{host_id}"), "hook.create", 303),
    ("/hooks/{hook_id}", hook_form("{host_id}", timeout_s="60"), "hook.update", 303),
    ("/jobs", job_form("{host_id}", "{storage_id}", pre_hooks="dump"), "job.create", 303),
    (
        "/jobs/{job_id}",
        job_form("{host_id}", "{storage_id}", "renamed", post_hooks="dump"),
        "job.update",
        303,
    ),
    ("/jobs/{job_id}/run", {}, "job.run", 303),
    ("/runs/{run_id}/cancel", {}, "run.cancel", 303),
    ("/jobs/{job_id}/passphrase", {}, "job.passphrase_reveal", 200),
    ("/jobs/{job_id}/delete", {}, "job.delete", 303),
    ("/hooks/{hook_id}/delete", {}, "hook.delete", 303),
    ("/storage/{storage_id}/delete", {}, "storage.delete", 303),
    ("/hosts/{host_id}/delete", {}, "host.delete", 303),
    ("/reauth", {"password": PASSWORD, "next": "/"}, "auth.reauth", 303),
    (
        "/account/password",
        {
            "current_password": PASSWORD,
            "new_password": NEW_PASSWORD,
            "new_password_confirm": NEW_PASSWORD,
        },
        "account.password",
        303,
    ),
    ("/logout", {}, "auth.logout", 303),
    ("/login", None, "auth.login", 303),
]


def successes(browser: Browser, action: str) -> int:
    rows = browser.sql(
        "SELECT COUNT(*) FROM audit_events WHERE action = ? AND outcome = 'success'", (action,)
    )
    return rows[0][0]


class FakeDocker:
    """Stands in for a reachable daemon in the connection test."""

    engine_version, api_version, arch, os = "29.9.0", "1.53", "amd64", "linux"

    def __init__(self) -> None:
        self.client = self
        self.api = self  # tests replace whatever else would call the Docker API

    def info(self) -> dict:
        """GET /info without a daemon ID: name locks are scoped by the host entry."""
        return {}

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        pass

    def __enter__(self) -> FakeDocker:
        return self

    def __exit__(self, *exc: object) -> None:
        pass


def empty_target(
    handle, lookup, *, host_id: int, host_name: str, helper_image: str
) -> restore_plan.TargetInfo:
    """A host with nothing on it, amd64 like the archive's image: it loads, no tag moves."""
    return restore_plan.TargetInfo(
        host_id=host_id, host_name=host_name, api_version="1.53", arch="amd64"
    )


def wait_for_cancel(self, plan, handle, targets, cancel, run_log) -> None:
    """Stands in for the backup itself: runs until the run is cancelled."""
    assert cancel.wait(30)
    raise Cancelled("The run was cancelled.")


async def test_every_unsafe_route_audits_its_success(fresh: Browser, monkeypatch) -> None:
    async def fake_scan(address: str, port: int) -> tuple[str, str]:
        return f"{address} {FAKE_HOST_KEY}", FAKE_FINGERPRINT

    monkeypatch.setattr(ssh, "scan_host_key", fake_scan)
    cert, _ = certificate("dav", ["203.0.113.9"])
    monkeypatch.setattr(certs, "fetch", lambda host, port: (cert, False))
    flow = gdrive_oauth.Flow(
        "v" * 64,
        1,
        0,
        "http://127.0.0.1:50000/",
        float("inf"),
        DRIVE_FORM["opt_client_id"],
        "drive.file",
    )
    monkeypatch.setattr(
        gdrive_oauth.Flows, "take", lambda self, state, user_id, storage_id=None: flow
    )
    monkeypatch.setattr(gdrive_oauth, "exchange", lambda code, flow, cid, secret: "{}")
    monkeypatch.setattr(HostManager, "docker_url", lambda self, host: "unix:///nonexistent")
    monkeypatch.setattr(docker_client, "open_client", lambda url, timeout=60: FakeDocker())
    monkeypatch.setattr(
        Dispatcher,
        "_resolve",
        lambda self, handle, plan, refs, log: [Target("c" * 64, "web", False)],
    )
    monkeypatch.setattr(Dispatcher, "_backup", wait_for_cancel)
    monkeypatch.setattr(restore_apply, "inspect_target", empty_target)
    monkeypatch.setattr(restore_apply, "apply", lambda *args, **kwargs: None)
    # The storage root doubles as the allowed restore path.
    root_path = fresh.settings.local_storage_roots[0]
    allowed = dataclasses.replace(fresh.settings, restore_paths=(root_path,))
    monkeypatch.setattr(fresh.app.state, "settings", allowed)
    monkeypatch.setattr(fresh.app.state.dispatcher, "settings", allowed)
    monkeypatch.setattr(
        Notifier, "test", lambda self, name, url_enc: notify.Outcome(name, True, "ntfy: success")
    )

    unsafe = {path for method, path, _ in api_routes(fresh.app) if method != "GET"}
    assert {path for path, _, _, _ in AUDITED_SUCCESS} == unsafe
    ids = {"user_id": 0}
    names = {
        "/users": "user_id",
        "/hosts": "host_id",
        "/storage": "storage_id",
        "/notifications": "target_id",
        "/jobs": "job_id",
        "/hooks": "hook_id",
    }
    root = str(root_path)
    image_id = "sha256:" + "a" * 64
    archive, _ = build_archive(
        fresh.settings.local_storage_roots[0],
        fresh.app.state.crypto,
        scope="image",
        images=[(image_id, ["busybox:1.37"], image_tar(image_id, ["busybox:1.37"]), None)],
    )
    for path, data, action, status in AUDITED_SUCCESS:
        before = successes(fresh, action)
        if path == "/setup":
            response = await fresh.setup()
        elif path == "/login":
            response = await fresh.login("admin", NEW_PASSWORD)
        elif path == "/restore/uploads":
            response = await fresh.client.put(
                path,
                params={"name": archive},
                content=(root_path / archive).read_bytes(),
                headers=fresh.origin_headers
                | {
                    "X-CSRF-Token": await fresh.csrf_token(),
                    "Content-Type": "application/octet-stream",
                },
            )
        else:
            if "/oauth/" in path:  # a Google Drive target's routes
                if "drive_id" not in ids:
                    created = await fresh.post("/storage", DRIVE_FORM)
                    ids["drive_id"] = int(created.headers["location"].rsplit("/", 1)[1])
                path = path.replace("{storage_id}", str(ids["drive_id"]))
            if path == "/jobs/{job_id}/delete":
                await fresh.app.state.dispatcher.wait(ids["run_id"])
            if path == "/restore/runs/{restore_id}/plan":
                await fresh.app.state.dispatcher.wait(ids["restore_id"])  # verified
            digest = ""
            if path == "/restore/runs/{restore_id}/execute":
                page = await fresh.get(fill("/restore/runs/{restore_id}/plan", **ids))
                digest = page.text.split('name="plan_digest" value="', 1)[1][:64]
            form = {
                k: fill(v, **ids)
                .replace("{storage_root}", root)
                .replace("{archive}", archive)
                .replace("{plan_digest}", digest)
                for k, v in (data or {}).items()
            }
            response = await fresh.post(fill(path, **ids), form)
        assert response.status_code == status, f"POST {path}: {response.status_code}"
        if path in names:
            ids[names[path]] = int(response.headers["location"].rsplit("/", 1)[1])
        if path == "/jobs/{job_id}/run":
            ids["run_id"] = int(response.headers["location"].rsplit("/", 1)[1])
        if path == "/restore/from-storage":
            ids["restore_id"] = int(response.headers["location"].split("/")[3])
        if path == "/restore/runs/{restore_id}/execute":
            await fresh.app.state.dispatcher.wait(ids["restore_id"])
        if path == "/restore/uploads":
            ids["upload_id"] = response.json()["id"]
        if path in ("/restore/from-upload/{upload_id}", "/restore/from-path"):
            await fresh.app.state.dispatcher.wait(int(response.headers["location"].split("/")[3]))
        assert successes(fresh, action) == before + 1, f"POST {path} did not audit {action}"
    statuses = fresh.sql("SELECT kind, status FROM runs ORDER BY id")
    awaiting = ("restore", "awaiting_confirmation")
    assert statuses == [("restore", "done"), awaiting, awaiting, ("backup", "cancelled")]
