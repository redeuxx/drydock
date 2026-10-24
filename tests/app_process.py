"""Runs drydock under uvicorn, as the image does, and starts one run at startup.

test_runs_docker.py and test_restore_docker.py start this as a separate process so they can
SIGKILL it, or SIGTERM it the way `docker compose stop` does, in the middle of a run.
Settings come from the environment. Usage:

    python -m tests.app_process <job_id>
        Queues one run of the job.
    python -m tests.app_process restore <storage_id> <archive> <choice-json> <summary-json-path>
        Verifies the archive, plans it with the choice against the host, stores the choice
        and the summary as POST /restore/runs/{id}/plan does (the summary is also written
        to summary-json-path) and executes it. Verification and planning happen in this
        process because startup recovery in a new one interrupts any restore awaiting
        confirmation.

Each mode prints {"run_id": <id>} once its run has started.
"""

import contextlib
import json
import sys
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI

from drydock.config import load_settings
from drydock.hosts import client as docker_client
from drydock.jobs.dispatcher import archive_facts, json_object
from drydock.main import create_app
from drydock.models import Host, Run
from drydock.restore import apply as restore_apply
from drydock.restore import plan as restore_plan
from drydock.restore import verify as restore_verify

AWAITING = "awaiting_confirmation"


# JOB RUNS


def job_main(job_id: int) -> None:
    app = create_app(load_settings())
    inner = app.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(target):
        async with inner(target):
            run_id = await target.state.dispatcher.submit(job_id, "app_process")
            print(json.dumps({"run_id": run_id}), flush=True)
            yield

    app.router.lifespan_context = lifespan
    uvicorn.run(app, host="127.0.0.1", port=0, log_level="warning", timeout_graceful_shutdown=30)


# RESTORE


def plan_summary(app: FastAPI, run_id: int, choice: restore_plan.Choice) -> dict[str, Any]:
    """The summary POST plan would store: the plan against the host's current state."""
    state = app.state
    staged = restore_verify.load_staged(
        restore_verify.restore_dir(state.settings.staging_dir, run_id), state.crypto
    )
    with state.sessionmaker() as db:
        host = db.get(Host, choice.host_id)
        if host is None:
            raise restore_plan.PlanError("The host does not exist.")
        db.expunge(host)
    lookup = restore_plan.lookups(staged.manifest, staged.configs, choice)
    with docker_client.open_client(state.hosts.docker_url(host)) as handle:
        target = restore_apply.inspect_target(
            handle,
            lookup,
            host_id=host.id,
            host_name=host.name,
            helper_image=state.settings.helper_image,
        )
    plan = restore_plan.build_plan(
        staged.manifest, staged.configs, target, choice, archive_facts(staged)
    )
    return restore_plan.summary(plan, host.name)


def store_plan(
    app: FastAPI, run_id: int, choice: restore_plan.Choice, summary: dict[str, Any]
) -> None:
    """Stores the choice and the summary, compare-and-set on the status like POST plan."""
    with app.state.sessionmaker() as db, db.begin():
        run = db.get(Run, run_id)
        if run is None or run.status != AWAITING:
            raise RuntimeError(f"Restore run {run_id} is no longer awaiting confirmation.")
        doc = json_object(run.plan)
        doc["choice"] = choice.to_dict()
        doc["summary"] = summary
        run.plan = json.dumps(doc)


def run_state(app: FastAPI, run_id: int) -> tuple[str, str | None]:
    with app.state.sessionmaker() as db:
        run = db.get(Run, run_id)
        assert run is not None
        return run.status, run.error


async def start_restore(
    app: FastAPI,
    storage_id: int,
    archive: str,
    choice: restore_plan.Choice,
    summary_path: Path,
) -> int:
    dispatcher = app.state.dispatcher
    run_id = await dispatcher.submit_restore(storage_id, archive, "app_process")
    await dispatcher.wait(run_id)
    status, error = await docker_client.run_blocking(run_state, app, run_id)
    if status != AWAITING:
        raise RuntimeError(f"Restore run {run_id} is {status}: {error}")
    summary = await docker_client.run_blocking(plan_summary, app, run_id, choice)
    summary_path.write_text(json.dumps(summary))
    await docker_client.run_blocking(store_plan, app, run_id, choice, summary)
    await dispatcher.execute_restore(run_id, choice, "app_process")
    return run_id


def restore_main(argv: list[str]) -> None:
    storage_id, archive = int(argv[0]), argv[1]
    choice = restore_plan.Choice.from_dict(json.loads(argv[2]))
    summary_path = Path(argv[3])
    app = create_app(load_settings())
    inner = app.router.lifespan_context
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=0, log_level="warning", timeout_graceful_shutdown=30
        )
    )
    failed = False

    @contextlib.asynccontextmanager
    async def lifespan(target):
        nonlocal failed
        async with inner(target):
            try:
                run_id = await start_restore(target, storage_id, archive, choice, summary_path)
            except Exception as exc:
                print(f"The restore did not start: {exc}", flush=True)
                failed = True
                server.should_exit = True
            else:
                print(json.dumps({"run_id": run_id}), flush=True)
            yield

    app.router.lifespan_context = lifespan
    server.run()
    if failed:
        sys.exit(1)


def main() -> None:
    if sys.argv[1] == "restore":
        restore_main(sys.argv[2:])
    else:
        job_main(int(sys.argv[1]))


if __name__ == "__main__":
    main()
