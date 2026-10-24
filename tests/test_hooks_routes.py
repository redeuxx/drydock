"""The hook library routes and hooks on the job form: superadmin-only edits with recent
auth, audit before and after values, the binding of hooks to a host and a target on every
job save and every hook edit, and what viewers see."""

import json
import re

import pytest

from drydock.engine import stacks
from drydock.jobs import hooks
from drydock.routes import jobs as job_routes
from tests.conftest import PASSWORD, Browser, add_user
from tests.test_jobs import add_host, add_job, add_storage
from tests.test_routes import hook_form, job_form, snapshot

pytestmark = pytest.mark.anyio

JOB_COLUMNS = "name, host_id, target_type, target, consistency_mode, pre_hooks, post_hooks"


def new_id(response) -> int:
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


async def add_hook(browser: Browser, host_id: int, name: str = "dump", **fields: str) -> int:
    return new_id(await browser.post("/hooks", hook_form(host_id, name, **fields)))


def job_row(browser: Browser, job_id: int) -> tuple:
    return browser.sql(f"SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?", (job_id,))[0]  # noqa: S608


def hook_row(browser: Browser, hook_id: int) -> tuple:
    return browser.sql("SELECT * FROM hooks WHERE id = ?", (hook_id,))[0]


def audit_details(browser: Browser, action: str) -> list[dict]:
    rows = browser.sql(
        "SELECT details FROM audit_events WHERE action = ? AND outcome = 'success' ORDER BY id",
        (action,),
    )
    return [json.loads(r[0]) for r in rows]


def test_project_res_and_container_res_agree() -> None:
    assert hooks.PROJECT_RE.pattern == stacks.PROJECT_RE.pattern
    assert hooks.CONTAINER_RE.pattern == job_routes.CONTAINER_RE.pattern


async def test_hook_edits_need_superadmin_and_recent_auth(admin: Browser) -> None:
    host_id = add_host(admin)
    hook_id = await add_hook(admin, host_id)
    edit = hook_form(host_id, timeout_s="60")
    requests = (
        ("/hooks", hook_form(host_id, "other")),
        (f"/hooks/{hook_id}", edit),
        (f"/hooks/{hook_id}/delete", {}),
    )
    for role in ("operator", "admin"):
        await add_user(admin, f"user-{role}", role)
        await admin.login(f"user-{role}")
        before = snapshot(admin)
        for path, data in requests:
            response = await admin.post(path, data)
            assert response.status_code == 403, (role, path)
        assert snapshot(admin) == before, role
        page = await admin.get(f"/hooks/{hook_id}")
        assert page.status_code == (200 if role == "admin" else 403), role
        await admin.login("admin")  # the superadmin, so the next add_user works

    admin.sql("UPDATE sessions SET reauth_at = NULL")
    before = snapshot(admin)
    for path, data in requests:
        response = await admin.post(path, data)
        assert response.status_code == 403 and "Re-enter your password" in response.text, path
    assert snapshot(admin) == before

    response = await admin.post("/reauth", {"password": PASSWORD, "next": "/"})
    assert response.status_code == 303
    new_id(await admin.post(*requests[0]))
    assert (await admin.post(*requests[1])).status_code == 303
    assert admin.sql("SELECT timeout_s FROM hooks WHERE id = ?", (hook_id,)) == [(60,)]
    assert (await admin.post(*requests[2])).status_code == 303
    assert admin.sql("SELECT name FROM hooks") == [("other",)]


async def test_hook_update_is_audited_with_before_and_after(admin: Browser) -> None:
    host_id = add_host(admin)
    hook_id = await add_hook(admin, host_id)
    created = audit_details(admin, "hook.create")
    assert created == [
        {
            "name": "dump",
            "host_id": host_id,
            "project": None,
            "container": "web",
            "argv": ["pg_dump", "-f", "/srv/dump.sql"],
            "user": "",
            "workdir": "",
            "timeout_s": 300,
            "log_output": False,
        }
    ]
    changed = hook_form(host_id, argv='["pg_dump", "-f", "/srv/other.sql"]', timeout_s="60")
    assert (await admin.post(f"/hooks/{hook_id}", changed)).status_code == 303
    assert audit_details(admin, "hook.update") == [
        {
            "argv": {
                "from": ["pg_dump", "-f", "/srv/dump.sql"],
                "to": ["pg_dump", "-f", "/srv/other.sql"],
            },
            "timeout_s": {"from": 300, "to": 60},
        }
    ]
    logged = changed | {"log_output": "1"}
    assert (await admin.post(f"/hooks/{hook_id}", logged)).status_code == 303
    assert audit_details(admin, "hook.update")[1] == {"log_output": {"from": False, "to": True}}
    stored = admin.sql("SELECT argv_json, timeout_s, log_output FROM hooks")
    assert stored == [('["pg_dump","-f","/srv/other.sql"]', 60, 1)]
    page = await admin.get("/hooks")
    assert "output logged" in page.text and "unused" in page.text


async def test_attaching_a_hook_outside_the_job_is_rejected(admin: Browser) -> None:
    host_a, host_b = add_host(admin, "a"), add_host(admin, "b")
    storage_id = await add_storage(admin)
    await add_hook(admin, host_a, "db-hook", container="db")
    await add_hook(admin, host_b, "web-b")
    await add_hook(admin, host_a, "app-proj", project="app")
    await add_hook(admin, host_a, "web-a")
    web = await add_job(admin, "web job", host_id=str(host_a), storage_id=str(storage_id))
    before = job_row(admin, web)
    for hook, message in (
        ("db-hook", "Hook db-hook runs in db, which this job does not back up."),
        ("web-b", "Hook web-b is bound to another host, so this job cannot run it."),
        ("app-proj", "Hook app-proj is for Compose project app;"),
    ):
        form = job_form(host_a, storage_id, "web job", pre_hooks=hook)
        response = await admin.post(f"/jobs/{web}", form)
        assert response.status_code == 422 and message in response.text, hook
        assert job_row(admin, web) == before, hook

    stack = {"target_type": "stack", "target": "app"}
    response = await admin.post(
        "/jobs", job_form(host_a, storage_id, "app job", post_hooks="web-a", **stack)
    )
    assert response.status_code == 422
    assert "Hook web-a is for container web;" in response.text
    app_id = new_id(
        await admin.post(
            "/jobs", job_form(host_a, storage_id, "app job", post_hooks="APP-PROJ", **stack)
        )
    )
    proj_id = admin.sql("SELECT id FROM hooks WHERE name = 'app-proj'")[0][0]
    assert job_row(admin, app_id)[2:] == ("stack", "app", "stop", "[]", f"[{proj_id}]")
    other = {"target_type": "stack", "target": "other"}
    response = await admin.post(
        "/jobs", job_form(host_a, storage_id, "other job", pre_hooks="app-proj", **other)
    )
    assert response.status_code == 422
    assert "Hook app-proj is for Compose project app, which this job does not back up." in (
        response.text
    )
    assert admin.sql("SELECT COUNT(*) FROM jobs") == [(2,)]


async def test_moving_a_job_to_another_host_or_target_detaches_nothing_silently(
    admin: Browser,
) -> None:
    host_a, host_b = add_host(admin, "a"), add_host(admin, "b")
    storage_id = await add_storage(admin)
    hook_id = await add_hook(admin, host_a, "web-a")
    job_id = new_id(await admin.post("/jobs", job_form(host_a, storage_id, pre_hooks="web-a")))
    before = job_row(admin, job_id)
    assert before[5] == f"[{hook_id}]"
    for change in (
        {"host_id": str(host_b)},
        {"target": "api"},
        {"target_type": "stack", "target": "web"},
    ):
        form = job_form(host_a, storage_id, pre_hooks="web-a") | change
        response = await admin.post(f"/jobs/{job_id}", form)
        assert response.status_code == 422 and "Hook web-a" in response.text, change
        assert job_row(admin, job_id) == before, change
    response = await admin.post(f"/jobs/{job_id}", job_form(host_b, storage_id, pre_hooks=""))
    assert response.status_code == 303
    assert job_row(admin, job_id)[1] == host_b and job_row(admin, job_id)[5] == "[]"
    changes = audit_details(admin, "job.update")[-1]
    assert changes["pre_hooks"] == {"from": ["web-a"], "to": []}
    assert changes["host_id"] == {"from": host_a, "to": host_b}


async def test_job_targeted_by_id_attaches_a_hook_with_that_id(admin: Browser) -> None:
    host_id, storage_id = add_host(admin), await add_storage(admin)
    container_id = "3f2a9c1b7d0e"
    await add_hook(admin, host_id, "by-id", container=container_id)
    await add_hook(admin, host_id, "by-name")
    by_id = job_form(host_id, storage_id, target=container_id)
    response = await admin.post("/jobs", by_id | {"pre_hooks": "by-name"})
    assert response.status_code == 422 and "Hook by-name runs in web" in response.text
    job_id = new_id(await admin.post("/jobs", by_id | {"pre_hooks": "by-id"}))
    page = await admin.get(f"/jobs/{job_id}")
    # The job page lists only the hooks it can attach as it is.
    assert 'by-id</span> <span class="opacity-70">in 3f2a9c1b7d0e' in page.text
    assert "by-name</span>" not in page.text


async def test_hook_rebinding_is_checked_against_attached_jobs(admin: Browser) -> None:
    host_a, host_b = add_host(admin, "a"), add_host(admin, "b")
    storage_id = await add_storage(admin)
    hook_id = await add_hook(admin, host_a, "web-a")
    await admin.post("/jobs", job_form(host_a, storage_id, "web job", pre_hooks="web-a"))
    before = hook_row(admin, hook_id)
    for change in ({"host_id": str(host_b)}, {"project": "app"}, {"container": "api"}):
        response = await admin.post(f"/hooks/{hook_id}", hook_form(host_a, "web-a") | change)
        assert response.status_code == 422, change
        assert "Jobs web job would no longer match this hook." in response.text, change
        assert hook_row(admin, hook_id) == before, change
    assert audit_details(admin, "hook.update") == []
    response = await admin.post(f"/hooks/{hook_id}", hook_form(host_a, "web-a", argv='["true"]'))
    assert response.status_code == 303
    assert admin.sql("SELECT argv_json FROM hooks") == [('["true"]',)]


async def test_admin_can_attach_existing_hooks_and_the_diff_is_audited(admin: Browser) -> None:
    host_id, storage_id = add_host(admin), await add_storage(admin)
    first = await add_hook(admin, host_id, "h1")
    second = await add_hook(admin, host_id, "h2")
    await add_user(admin, "other-admin", "admin")
    await admin.login("other-admin")
    job_id = new_id(await admin.post("/jobs", job_form(host_id, storage_id)))
    form = job_form(host_id, storage_id, pre_hooks="h2\nh1\n", post_hooks="h1")
    assert (await admin.post(f"/jobs/{job_id}", form)).status_code == 303
    assert job_row(admin, job_id)[5:] == (f"[{second}, {first}]", f"[{first}]")
    assert audit_details(admin, "job.update") == [
        {
            "pre_hooks": {"from": [], "to": ["h2", "h1"]},
            "post_hooks": {"from": [], "to": ["h1"]},
        }
    ]
    page = await admin.get(f"/jobs/{job_id}")
    assert f'href="/hooks/{second}"' in page.text and "h2\nh1</textarea>" in page.text


async def test_unknown_duplicate_and_too_many_hooks_are_refused(admin: Browser) -> None:
    host_id, storage_id = add_host(admin), await add_storage(admin)
    await add_hook(admin, host_id, "h1")
    for phase in ("pre_hooks", "post_hooks"):
        for text, message in (
            ("h1\nmissing", "There is no hook named missing."),
            ("h1\nH1", "Hook H1 is listed twice."),
            ("h1\n" * 11, "A job can run at most 10 hooks before and 10 after."),
        ):
            response = await admin.post("/jobs", job_form(host_id, storage_id, **{phase: text}))
            assert response.status_code == 422 and message in response.text, (phase, text)
    assert admin.sql("SELECT COUNT(*) FROM jobs") == [(0,)]
    # Blank lines and surrounding spaces are ignored.
    job_id = new_id(
        await admin.post("/jobs", job_form(host_id, storage_id, pre_hooks="\n  h1 \n\n"))
    )
    assert job_row(admin, job_id)[5] != "[]"


async def test_hook_names_split_only_on_line_feeds(admin: Browser) -> None:
    # str.splitlines() would cut these names at U+0085, U+2028 and U+2029.
    host_id, storage_id = add_host(admin), await add_storage(admin)
    names = ["a\u2028b", "c\u0085d", "e\u2029f"]
    hook_ids = [await add_hook(admin, host_id, name) for name in names]
    for part in ("a", "b", "c", "d", "e", "f"):
        await add_hook(admin, host_id, part)
    form = job_form(host_id, storage_id, pre_hooks="\r\n".join(names), post_hooks="a\rb")
    job_id = new_id(await admin.post("/jobs", form))
    assert json.loads(job_row(admin, job_id)[5]) == hook_ids
    # The edit form carries the names back, so saving it unchanged keeps them.
    page = await admin.get(f"/jobs/{job_id}")
    assert "a\u2028b" in page.text
    response = await admin.post(
        f"/jobs/{job_id}", job_form(host_id, storage_id, pre_hooks="\n".join(names))
    )
    assert response.status_code == 303, response.text
    assert json.loads(job_row(admin, job_id)[5]) == hook_ids


async def test_hook_form_refuses_non_ascii_digits_as_host(admin: Browser) -> None:
    # "\u00b2".isdigit() is true but int() refuses it: a 422, never a 500.
    host_id = add_host(admin)
    hook_id = await add_hook(admin, host_id)
    for path in ("/hooks", f"/hooks/{hook_id}"):
        response = await admin.post(path, hook_form("\u00b2", "other"))
        assert response.status_code == 422 and "Choose a host." in response.text, path
    assert admin.sql("SELECT name, host_id FROM hooks") == [("dump", host_id)]


async def test_hook_in_use_cannot_be_deleted(admin: Browser) -> None:
    host_id, storage_id = add_host(admin), await add_storage(admin)
    hook_id = await add_hook(admin, host_id)
    job_id = new_id(await admin.post("/jobs", job_form(host_id, storage_id, post_hooks="dump")))
    response = await admin.post(f"/hooks/{hook_id}/delete")
    assert response.status_code == 409
    assert "Hook dump is attached to jobs web backup. Detach it first." in response.text
    failures = admin.sql(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'hook.delete' AND outcome = 'failure'"
    )
    assert failures == [(1,)]
    assert admin.sql("SELECT COUNT(*) FROM hooks") == [(1,)]
    page = await admin.get(f"/hooks/{hook_id}")
    assert f'href="/jobs/{job_id}"' in page.text and "after the backup" in page.text
    assert (await admin.post(f"/jobs/{job_id}", job_form(host_id, storage_id))).status_code == 303
    assert (await admin.post(f"/hooks/{hook_id}/delete")).status_code == 303
    assert admin.sql("SELECT COUNT(*) FROM hooks") == [(0,)]
    assert audit_details(admin, "hook.delete")[0]["name"] == "dump"


async def test_host_with_hooks_cannot_be_deleted(admin: Browser) -> None:
    host_id, storage_id = add_host(admin), await add_storage(admin)
    hook_id = await add_hook(admin, host_id)
    job_id = await add_job(admin, host_id=str(host_id), storage_id=str(storage_id))
    response = await admin.post(f"/hosts/{host_id}/delete")
    assert response.status_code == 409 and "web backup" in response.text
    assert (await admin.post(f"/jobs/{job_id}/delete")).status_code == 303
    response = await admin.post(f"/hosts/{host_id}/delete")
    assert response.status_code == 409
    assert "Hooks are bound to this host: dump. A superadmin must delete them" in response.text
    assert admin.sql("SELECT COUNT(*) FROM hosts") == [(1,)]
    assert (await admin.post(f"/hooks/{hook_id}/delete")).status_code == 303
    assert (await admin.post(f"/hosts/{host_id}/delete")).status_code == 303
    assert admin.sql("SELECT COUNT(*) FROM hosts") == [(0,)]


async def test_viewers_see_hook_names_but_never_argv(admin: Browser) -> None:
    host_id, storage_id = add_host(admin), await add_storage(admin)
    argv = '["sh", "-c", "argv-marker-text"]'
    hook_id = await add_hook(
        admin, host_id, "dbdump", project="app", container="pgservice", argv=argv
    )
    stack = {"target_type": "stack", "target": "app", "pre_hooks": "dbdump"}
    job_id = new_id(await admin.post("/jobs", job_form(host_id, storage_id, **stack)))
    page = await admin.get(f"/jobs/{job_id}")
    assert "pgservice" in page.text  # admins see where an attachable hook runs
    await add_user(admin, "viewer", "viewer")
    await admin.login("viewer")
    for path in (f"/jobs/{job_id}", "/jobs"):
        page = await admin.get(path)
        assert page.status_code == 200
        assert "argv-marker-text" not in page.text and "pgservice" not in page.text, path
    page = await admin.get(f"/jobs/{job_id}")
    assert "dbdump" in page.text and f'href="/hooks/{hook_id}"' not in page.text
    assert (await admin.get(f"/hooks/{hook_id}")).status_code == 403
    assert (await admin.get("/hooks")).status_code == 403


async def test_hook_argv_is_shown_escaped(admin: Browser) -> None:
    host_id = add_host(admin)
    hook_id = await add_hook(admin, host_id, argv='["echo", "<script>x</script>"]')
    page = await admin.get(f"/hooks/{hook_id}")
    assert page.status_code == 200
    assert "<script>x</script>" not in page.text
    assert "&lt;script&gt;x&lt;/script&gt;" in page.text
    assert "default-src" in page.headers["content-security-policy"]


async def test_hook_form_hints_warn_about_output(admin: Browser) -> None:
    add_host(admin)
    page = await admin.get("/hooks/new")
    assert page.status_code == 200
    assert "visible to every role that can see runs" in page.text
    assert '"pg_dump"' in page.text and '"-f"' in page.text
    assert "Log the hook" in page.text and 'name="log_output"' in page.text
    page = await admin.get("/jobs/new")
    assert "safe to run when the pre-hooks did not all finish" in page.text


async def test_live_mode_warning_on_form_and_detail(admin: Browser) -> None:
    alert = re.compile(r'role="alert"[^>]*>\s*<span>' + re.escape(job_routes.LIVE_WARNING))
    assert "crash-consistent at best" in job_routes.LIVE_WARNING
    page = await admin.get("/jobs/new")
    assert job_routes.LIVE_WARNING in page.text and not alert.search(page.text)
    host_id, storage_id = str(add_host(admin)), str(await add_storage(admin))
    live = await add_job(
        admin, "live", consistency_mode="live", host_id=host_id, storage_id=storage_id
    )
    stop = await add_job(admin, "stop", host_id=host_id, storage_id=storage_id)
    page = await admin.get(f"/jobs/{live}")
    assert alert.search(page.text)
    page = await admin.get(f"/jobs/{stop}")
    assert not alert.search(page.text)
    assert job_routes.LIVE_WARNING in page.text  # the form's note, always shown

    # frontend/app.ts focuses the first role="alert" in #main after a swap, so on a live
    # job's page the standing warning must not take focus from what a submit produced.
    def first_alert(html: str) -> str:
        found = re.search(r'role="alert"[^>]*>(.*?)</div>', html.split('id="main"', 1)[1], re.S)
        return found.group(1) if found else ""

    form = job_form(host_id, storage_id, "live", consistency_mode="live", pre_hooks="nope")
    response = await admin.post(f"/jobs/{live}", form)
    assert response.status_code == 422
    assert "There is no hook named nope." in first_alert(response.text)
    response = await admin.post(f"/jobs/{live}/passphrase")
    assert response.status_code == 200 and "data-focus-result" in response.text
    assert first_alert(response.text) == ""
    assert job_routes.LIVE_WARNING in response.text
