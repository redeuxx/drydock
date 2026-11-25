"""Update policies: the pages, their checks, the scheduler, the backup first and the
notifications of the runs they start."""

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from drydock.jobs import dispatcher as dispatcher_module
from drydock.jobs import scheduler as scheduler_module
from drydock.jobs.dispatcher import DispatchError
from drydock.jobs.runlog import RunLog
from drydock.models import NotificationTarget, Run, UpdatePolicy
from drydock.updates.check import HostChecks
from tests.conftest import Browser, add_user
from tests.test_jobs import add_host, add_job

pytestmark = pytest.mark.anyio


def policy_form(host: int, **fields: str) -> dict[str, str]:
    return {
        "name": "nightly web",
        "host_id": str(host),
        "target_type": "container",
        "target": "web",
        "cron_preset": "custom",
        "cron": "0 4 * * 0",
        "stop_on_failed_backup": "1",
        "enabled": "1",
    } | fields


async def test_policies_need_their_roles_and_are_audited(admin: Browser) -> None:
    host_id = add_host(admin, "web-host")
    created = await admin.post("/updates", policy_form(host_id))
    assert created.status_code == 303 and created.headers["location"] == "/updates"
    ((policy_id,),) = admin.sql("SELECT id FROM update_policies")
    assert admin.sql(
        "SELECT action, target FROM audit_events WHERE action LIKE 'update_policy.%'"
    ) == [("update_policy.create", f"update_policy:{policy_id}")]
    page = (await admin.get("/updates")).text
    assert ("nightly web" in page and "Every Sunday" in page) or "0 4 * * 0" in page
    assert admin.app.state.scheduler.next_update_time(policy_id) is not None, "scheduled"

    await add_user(admin, "runner", "operator")
    await add_user(admin, "watcher", "viewer")
    await admin.login("watcher")
    assert (await admin.get("/updates")).status_code == 403
    await admin.login("runner")
    page = (await admin.get("/updates")).text
    assert "Run now" in page and "New update policy" not in page
    for path in ("/updates/new", f"/updates/{policy_id}"):
        assert (await admin.get(path)).status_code == 403, path
    assert (await admin.post("/updates", policy_form(host_id, name="x"))).status_code == 403
    assert (await admin.post(f"/updates/{policy_id}/delete", {})).status_code == 403

    await admin.login("admin")
    edited = await admin.post(f"/updates/{policy_id}", policy_form(host_id, enabled=""))
    assert edited.status_code == 303
    assert admin.app.state.scheduler.next_update_time(policy_id) is None, "disabled: off"
    assert (await admin.post(f"/updates/{policy_id}/delete", {})).status_code == 303
    assert admin.sql("SELECT count(*) FROM update_policies") == [(0,)]
    assert [
        a
        for (a,) in admin.sql(
            "SELECT action FROM audit_events WHERE action LIKE 'update_policy.%' ORDER BY id"
        )
    ] == ["update_policy.create", "update_policy.update", "update_policy.delete"]


async def test_the_form_refuses_what_cannot_work(admin: Browser) -> None:
    host_id = add_host(admin, "web-host")
    other = add_host(admin, "other-host")
    job_id = await add_job(admin, "web nightly", host_id=str(host_id))
    elsewhere = await add_job(admin, "other nightly", host_id=str(other))
    assert (await admin.post("/updates", policy_form(host_id))).status_code == 303
    for fields, message in [
        ({"name": "nightly web"}, "An update policy with that name exists."),
        ({"name": "a", "host_id": "999"}, "Choose a host."),
        ({"name": "b", "target": "../x"}, "Enter a container name"),
        ({"name": "c", "target_type": "stack", "target": "Bad Name"}, "Compose project"),
        ({"name": "d", "cron": "61 * * * *"}, ""),
        ({"name": "e", "cron": ""}, "Add a schedule."),
        ({"name": "f", "backup_job_id": str(elsewhere)}, "must back up this container"),
        ({"name": "g", "backup_job_id": "999"}, "Choose an existing job"),
        ({"name": "h", "notify_target_id": "999"}, "Choose an existing notification target."),
        ({"name": "i", "timezone": "Mars/Base"}, ""),
    ]:
        refused = await admin.post("/updates", policy_form(host_id, **fields))
        assert refused.status_code == 422, fields
        assert message in refused.text, (fields, message)
    ok = await admin.post("/updates", policy_form(host_id, name="j", backup_job_id=str(job_id)))
    assert ok.status_code == 303
    assert admin.sql("SELECT backup_job_id FROM update_policies WHERE name = 'j'") == [(job_id,)]


async def test_run_now_is_for_operators_and_audited(admin: Browser, monkeypatch) -> None:
    host_id = add_host(admin, "web-host")
    await admin.post("/updates", policy_form(host_id))
    ((policy_id,),) = admin.sql("SELECT id FROM update_policies")

    async def no_docker(active, by) -> None:
        pass

    # The real submit_policy, which writes the run row in its own transaction: the route
    # must not hold the write lock meanwhile (it did after a rollback reloaded auth.user).
    monkeypatch.setattr(admin.app.state.dispatcher, "_execute_update", no_docker)
    await add_user(admin, "runner", "operator")
    await admin.login("runner")
    done = await admin.post(f"/updates/{policy_id}/run", {})
    ((run_id, by),) = admin.sql("SELECT id, triggered_by FROM runs WHERE kind = 'update'")
    assert done.status_code == 303 and done.headers["location"] == f"/runs/{run_id}"
    assert by == "runner"
    assert admin.sql(
        "SELECT actor, outcome, details FROM audit_events WHERE action = 'update_policy.run'"
    ) == [("runner", "success", json.dumps({"name": "nightly web", "run_id": run_id}))]
    assert (await admin.post("/updates/999/run", {})).status_code == 404


async def test_a_policy_run_records_its_target_and_backup(admin: Browser) -> None:
    host_id = add_host(admin, "web-host")
    job_id = await add_job(admin, "web nightly", host_id=str(host_id))
    await admin.post("/updates", policy_form(host_id, backup_job_id=str(job_id)))
    await admin.post(
        "/updates", policy_form(host_id, name="stack", target_type="stack", target="app")
    )
    rows = admin.sql("SELECT id, name FROM update_policies ORDER BY id")
    dispatcher = admin.app.state.dispatcher
    first = dispatcher._create_policy_run(rows[0][0], "the schedule")
    second = dispatcher._create_policy_run(rows[1][0], "the schedule")
    plans = {
        run_id: json.loads(plan)["update"]
        for run_id, plan in admin.sql("SELECT id, plan FROM runs WHERE kind = 'update'")
    }
    assert plans[first] == {
        "host_id": host_id,
        "containers": [],
        "policy_id": rows[0][0],
        "stop_on_failed_backup": True,
        "name": "web",
        "backup_job_id": job_id,
    }
    assert plans[second]["project"] == "app" and "backup_job_id" not in plans[second]
    assert admin.sql("SELECT target_label FROM runs WHERE id = ?", (second,)) == [("stack app",)]
    with admin.app.state.sessionmaker() as db, db.begin():
        db.get(UpdatePolicy, rows[1][0]).enabled = False
    with pytest.raises(DispatchError, match="gone or disabled"):
        dispatcher._create_policy_run(rows[1][0], "the schedule")


class Backups:
    """The dispatcher's side of a backup first: the job's runs end as given."""

    def __init__(self, statuses: list[str], refuse: bool = False) -> None:
        self.statuses = statuses
        self.refuse = refuse
        self.waited: list[int] = []

    async def submit(self, job_id: int, by: str) -> int:
        if self.refuse:
            raise DispatchError("This job already has a run in progress.")
        return 10

    async def wait(self, run_id: int) -> None:
        self.waited.append(run_id)

    def statuses_of(self, first: int) -> list[tuple[int, str]]:
        return [(first + i, s) for i, s in enumerate(self.statuses)]


async def test_the_backup_first_must_succeed_unless_told_otherwise(
    admin: Browser, monkeypatch, tmp_path
) -> None:
    dispatcher = admin.app.state.dispatcher
    log = RunLog(tmp_path / "x.log")

    async def run(doc: dict[str, Any], backups: Backups) -> None:
        monkeypatch.setattr(dispatcher, "submit", backups.submit)
        monkeypatch.setattr(dispatcher, "wait", backups.wait)
        monkeypatch.setattr(dispatcher, "_job_run_statuses", backups.statuses_of)
        await dispatcher._backup_first(doc, "web", log)

    await run({}, Backups(["failed"]))  # no backup job: nothing to do
    good = Backups(["done", "done"])
    await run({"backup_job_id": 3}, good)
    assert good.waited == [10, 11], "every target's run"
    with pytest.raises(DispatchError, match=r"did not succeed \(#11 failed\)"):
        await run({"backup_job_id": 3}, Backups(["done", "failed"]))
    with pytest.raises(DispatchError, match="did not start"):
        await run({"backup_job_id": 3}, Backups([], refuse=True))
    await run({"backup_job_id": 3, "stop_on_failed_backup": False}, Backups(["failed"]))
    assert "updating anyway" in (tmp_path / "x.log").read_text()


async def test_policy_runs_tell_their_target(admin: Browser) -> None:
    host_id = add_host(admin, "web-host")
    with admin.app.state.sessionmaker() as db, db.begin():
        target = NotificationTarget(
            name="ops", kind="ntfy", url_enc=admin.app.state.crypto.encrypt("ntfy://x/y")
        )
        db.add(target)
        db.flush()
        policy = UpdatePolicy(
            name="p",
            host_id=host_id,
            target_type="container",
            target="web",
            cron="0 4 * * 0",
            notify_target_id=target.id,
        )
        db.add(policy)
        db.flush()
        runs = {}
        for key, status, error in (
            ("done", "done", None),
            ("failed", "failed", "boom"),
            ("partial", "done", "The registry could not be asked about db"),
        ):
            run = Run(
                job_id=None,
                kind="update",
                status=status,
                target_label="web",
                plan=json.dumps({"update": {"policy_id": policy.id}}),
                error=error,
            )
            db.add(run)
            db.flush()
            runs[key] = run.id
        policy_id = policy.id
    notifier = admin.app.state.notifier
    assert notifier._load(runs["done"]) == [], "success is told only when asked"
    ((name, url, title, body, failure),) = notifier._load(runs["failed"])
    assert (name, url, failure) == ("ops", "ntfy://x/y", True)
    assert title == "drydock: update of web failed" and "Error: boom" in body
    # Updated only in part: told like a failure.
    ((_, _, title, body, failure),) = notifier._load(runs["partial"])
    assert title == "drydock: update of web succeeded in part" and failure
    assert "Error: The registry could not be asked about db" in body
    with admin.app.state.sessionmaker() as db, db.begin():
        db.get(UpdatePolicy, policy_id).notify_success = True
    assert notifier._load(runs["done"])[0][2] == "drydock: update of web succeeded"


async def test_a_missed_policy_fire_is_audited_and_rung(admin: Browser) -> None:
    host_id = add_host(admin, "web-host")
    with admin.app.state.sessionmaker() as db, db.begin():
        policy = UpdatePolicy(
            name="weekly",
            host_id=host_id,
            target_type="container",
            target="web",
            cron="0 4 * * *",
        )
        db.add(policy)
        db.flush()
        policy_id = policy.id
    sched = admin.app.state.scheduler
    # Noon: hours past the 04:00 fire, so it is a miss whatever the time of the test run.
    now = datetime.now(UTC).replace(hour=12, minute=0)
    spec = scheduler_module.Spec(policy_id, "0 4 * * *", "UTC", now - timedelta(days=3), "update")
    await sched._catch_up(spec, now)
    assert admin.sql(
        "SELECT action, target FROM audit_events WHERE action = 'update.schedule_missed'"
    ) == [("update.schedule_missed", f"update_policy:{policy_id}")]
    bell = (await admin.get("/feed")).text
    assert "A scheduled update of policy" in bell and f'href="/updates/{policy_id}"' in bell


async def test_the_containers_page_shows_what_updates_a_container(
    admin: Browser, monkeypatch
) -> None:
    from tests.test_status import a_host_with_containers

    _, host_id = await a_host_with_containers(admin, monkeypatch)
    assert (await admin.post("/updates", policy_form(host_id))).status_code == 303
    assert (
        await admin.post(
            "/updates", policy_form(host_id, name="app stack", target_type="stack", target="app")
        )
    ).status_code == 303
    page = (await admin.get(f"/containers?host={host_id}")).text
    # Each container's dialog names the policies that update it.
    assert re.search(r"<dd>nightly web, next \d{4}-\d\d-\d\d \d\d:\d\d [^<]+</dd>", page)
    assert page.count("<dd>app stack, next ") == 2, "db and cache"
    job_id = await add_job(
        admin, "web nightly", host_id=str(host_id), schedule="1", cron_preset="0 3 * * *"
    )
    home = (await admin.get("/")).text
    assert 'href="/updates">Update: nightly web</a>' in home
    assert f'href="/jobs/{job_id}">Backup: web nightly</a>' in home


async def test_hosts_and_backup_jobs_in_use_are_not_deleted(admin: Browser) -> None:
    host_id = add_host(admin, "web-host")
    job_id = await add_job(admin, "web nightly", host_id=str(host_id))
    form = policy_form(host_id, backup_job_id=str(job_id), cron_preset="0 3 * * *", cron="x")
    assert (await admin.post("/updates", form)).status_code == 303
    assert admin.sql("SELECT cron FROM update_policies") == [("0 3 * * *",)], "the preset wins"
    refused = await admin.post(f"/jobs/{job_id}/delete", {})
    assert refused.status_code == 409 and "back up with this job first: nightly web" in refused.text
    lone = add_host(admin, "policy-only")
    assert (await admin.post("/updates", policy_form(lone, name="lone"))).status_code == 303
    gone = await admin.post(f"/hosts/{lone}/delete", {})
    assert gone.status_code == 409 and "Update policies still use this host: lone" in gone.text
    by_id = await admin.post("/updates", policy_form(host_id, name="x", target="3f2a9c1b7d0e"))
    assert by_id.status_code == 422 and "not its ID" in by_id.text


async def test_one_run_per_policy_at_a_time(admin: Browser, monkeypatch) -> None:
    host_id = add_host(admin, "web-host")
    await admin.post("/updates", policy_form(host_id))
    ((policy_id,),) = admin.sql("SELECT id FROM update_policies")
    dispatcher = admin.app.state.dispatcher
    gate = __import__("asyncio").Event()

    async def held(active, by) -> None:
        await gate.wait()

    monkeypatch.setattr(dispatcher, "_execute_update", held)
    await dispatcher.submit_policy(policy_id, "a")
    with pytest.raises(DispatchError, match="already has a run in progress"):
        await dispatcher.submit_policy(policy_id, "b")
    gate.set()
    await __import__("asyncio").sleep(0.05)
    await dispatcher.submit_policy(policy_id, "c")
    gate.set()


async def test_the_host_is_checked_again_after_a_policy_run(admin: Browser, monkeypatch) -> None:
    host_id = add_host(admin, "web-host")
    assert (await admin.post("/updates", policy_form(host_id))).status_code == 303
    ((policy_id,),) = admin.sql("SELECT id FROM update_policies")
    dispatcher, checker = admin.app.state.dispatcher, admin.app.state.updates
    assert checker.running
    checked = anyio.Event()
    hosts: list[int] = []

    async def check_host(host) -> None:
        hosts.append(host.id)
        checked.set()

    async def ran(active, by) -> None:
        pass

    monkeypatch.setattr(checker, "check_host", check_host)
    monkeypatch.setattr(dispatcher, "_execute_update", ran)
    await dispatcher.submit_policy(policy_id, "the schedule")
    with anyio.fail_after(5):
        await checked.wait()
    assert hosts == [host_id]


async def test_a_check_under_way_when_the_run_ends_is_followed_by_another(
    admin: Browser, monkeypatch
) -> None:
    """A check that began before the run ended read the host before the update: the
    post-run check waits it out and checks again, rather than joining it."""
    host_id = add_host(admin, "web-host")
    assert (await admin.post("/updates", policy_form(host_id))).status_code == 303
    ((policy_id,),) = admin.sql("SELECT id FROM update_policies")
    checker = admin.app.state.updates
    gate, second = anyio.Event(), anyio.Event()
    calls: list[int] = []

    async def fake_check(host, paced: bool = True) -> HostChecks:
        calls.append(host.id)
        if len(calls) == 1:
            await gate.wait()
        else:
            second.set()
        return HostChecks(datetime.now(UTC))

    monkeypatch.setattr(checker, "_check", fake_check)
    host = SimpleNamespace(id=host_id)
    first = asyncio.create_task(checker.check_host(host))
    await anyio.sleep(0.05)
    checker.policy_ran(policy_id)
    await anyio.sleep(0.05)
    assert calls == [host_id], "waits for the check under way"
    gate.set()
    with anyio.fail_after(5):
        await second.wait()
    await first
    assert calls == [host_id, host_id]


async def test_a_policy_for_every_stack(admin: Browser, monkeypatch, tmp_path) -> None:
    """* updates each stack with something to update in a run of its own, one after
    another; the policy's run fails when any of them does. It cannot back up first."""
    host_id = add_host(admin, "web-host")
    job_id = await add_job(admin, "web nightly", host_id=str(host_id))
    every = policy_form(host_id, name="every", target_type="stack", target="*")
    refused = await admin.post("/updates", every | {"backup_job_id": str(job_id)})
    assert refused.status_code == 422 and "cannot back up first" in refused.text
    assert (await admin.post("/updates", every)).status_code == 303
    ((policy_id,),) = admin.sql("SELECT id FROM update_policies")
    assert "Every stack" in (await admin.get("/updates")).text

    dispatcher = admin.app.state.dispatcher
    parent = dispatcher._create_policy_run(policy_id, "the schedule")
    assert admin.sql("SELECT target_label FROM runs WHERE id = ?", (parent,)) == [("every stack",)]
    names = lambda api, own: list("abcd")  # noqa: E731
    monkeypatch.setattr(dispatcher_module.update_apply, "stack_names", names)
    monkeypatch.setattr(
        dispatcher_module.update_apply,
        "plan_stack",
        lambda api, host, name, *rest, **kw: SimpleNamespace(
            plan=None if name in "bd" else object(),
            unchecked=("d-web-1",) if name == "d" else (),
        ),
    )
    children: list[str] = []

    async def submit_update(host, ids, by, label, *, project=None) -> int:
        children.append(project)
        with admin.app.state.sessionmaker() as db, db.begin():
            run = Run(
                kind="update",
                status="failed" if project == "c" else "done",
                error="in part" if project == "a" else None,
                triggered_by=by,
                target_label=label,
            )
            db.add(run)
            db.flush()
            return run.id

    async def wait(run_id: int) -> None:
        pass

    monkeypatch.setattr(dispatcher, "submit_update", submit_update)
    monkeypatch.setattr(dispatcher, "wait", wait)
    active = dispatcher_module.ActiveRun(parent, None)
    handle = SimpleNamespace(client=SimpleNamespace(api=None), api_version="1.47")
    host = SimpleNamespace(id=host_id, name="web-host")
    failed = r"Not every stack was updated: a \(#\d+ in part\), c \(#\d+ failed\), d \(registry"
    with pytest.raises(DispatchError, match=failed):
        await dispatcher._update_every_stack(
            active, handle, host, frozenset(), "the schedule", RunLog(tmp_path / "run.log")
        )
    assert children == ["a", "c"], "b has nothing to update: no run"
    log = (tmp_path / "run.log").read_text()
    assert "Stacks on web-host: a, b, c, d." in log and "Stack b: nothing to update." in log
    assert "Stack d: The registry could not be asked about d-web-1" in log


async def test_the_runs_pages_show_what_an_update_moved(admin: Browser) -> None:
    digest = "sha256:" + "ab" * 32
    changes = [
        {
            "name": "web",
            "old": "sha256:" + "12" * 32,
            "new": digest,
            "old_ref": "nginx:1.27",
            "new_ref": "nginx:1.27",
            "old_version": "1.27.2",
            "new_version": "<b>1.27.3</b>",
        },
        {
            "name": "db",
            "old": "",
            "new": digest,
            "old_ref": "postgres:16",
            "new_ref": "postgres:17",
            "old_version": "",
            "new_version": "",
        },
        "junk",
    ]
    with admin.app.state.sessionmaker() as db, db.begin():
        run = Run(
            kind="update",
            status="done",
            target_label="stack app",
            plan=json.dumps({"update": {}, "changes": changes}),
        )
        db.add(run)
        db.flush()
        run_id = run.id
    for page in ((await admin.get("/runs")).text, (await admin.get(f"/runs/{run_id}")).text):
        assert "web: 1.27.2 → &lt;b&gt;1.27.3&lt;/b&gt;" in page
        assert "db: 16 unknown → 17 abababababab" in page
    with admin.app.state.sessionmaker() as db, db.begin():
        db.get(Run, run_id).status = "failed"
    page = (await admin.get(f"/runs/{run_id}")).text
    assert "Planned" in page and "1.27.2 \u2192 &lt;b&gt;1.27.3&lt;/b&gt; (not applied)" in page
