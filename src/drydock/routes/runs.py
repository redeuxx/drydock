"""Runs: list (filtered by status), detail with a live log, and cancel.

The run page polls GET /runs/{id}/log?offset=N every two seconds while the run is queued
or running. An answer with new complete lines holds them and a fresh poller for the next
offset; with nothing new it is 204, which htmx does not swap, so the poller keeps its
offset. Once the run has ended the answer is HX-Refresh, so the page reloads once and
shows the final state without a poller. A finished run's page shows the end of its log.
Logs are redacted when written (jobs.runlog).

A run that ended can be dismissed from the dashboard (operators and up).

Restore runs (kind "restore") are cancelled by admins only; one awaiting confirmation is
discarded through the same route. Their page warns, from the restore journal, about data
a failed restore may have left partial, about anything drydock could not remove and about
compose files it did not, or may not, have written.
"""

from typing import Annotated, Any
from urllib.parse import urlencode

import anyio.from_thread
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.jobs.dispatcher import (
    ACTIVE_STATUSES,
    JOURNALED_KINDS,
    OPEN_STATUSES,
    journal_entries,
    json_object,
)
from drydock.jobs.runlog import log_path, read_log, read_tail
from drydock.models import RUN_STATUSES, Job, Run, utcnow
from drydock.routes.auth import client_ip
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other

router = APIRouter(prefix="/runs")

Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
Operator = Annotated[Auth, Depends(require_role(Role.operator))]

PAGE_SIZE = 100
PAGE_LOG_LIMIT = 1024 * 1024  # the run page shows at most this much; polling continues after
UNFINISHED = ("failed", "cancelled", "interrupted")  # ended without finishing the restore


def get_run(db: Session, run_id: int) -> Run:
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404)
    return run


def strings(doc: dict[str, Any], key: str) -> list[str]:
    value = doc.get(key)
    items = value if isinstance(value, list) else []
    return list(dict.fromkeys(item for item in items if isinstance(item, str) and item))


def restore_warning(run: Run) -> str | None:
    """What a restore left behind, from its journal: data that may be partial, originals
    not started again, and objects drydock could not remove."""
    if run.kind not in JOURNALED_KINDS:
        return None
    doc = json_object(run.restore_originals_json)
    sentences = []
    originals = journal_entries(doc, "originals")
    if doc.get("committed"):
        if run.status in UNFINISHED and originals:
            sentences.append(
                "The restored containers were created; drydock finished removing the "
                "originals at startup."
                if doc.get("rolled_back") is True
                else "The restored containers were created; removing the originals is still "
                "pending or failed; see the log."
            )
    elif run.status in UNFINISHED and (doc.get("wipe_started") or doc.get("data_started")):
        items = [f"volume {v}" for v in strings(doc, "volumes")]
        items += [f"bind mount {b}" for b in strings(doc, "binds")]
        sentences.append(
            f"The restore did not finish. The data in {', '.join(items)} may be partial."
            if items
            else "The restore did not finish. Its data may be partial."
        )
        if originals and doc.get("rolled_back") is True:
            sentences.append("The original containers were renamed back and left stopped.")
        elif originals:
            sentences.append(
                "Rolling back the original containers is still pending or failed; see the log."
            )
    elif run.status in UNFINISHED and doc.get("rollback_incomplete") is True:
        sentences.append("The rollback did not undo everything; see the log.")
    if not_renamed := strings(doc, "not_renamed"):
        sentences.append(
            f"Drydock could not give {', '.join(not_renamed)} its original name back; see the log."
        )
    if tags_left := strings(doc, "tags_left"):
        sentences.append(
            f"The image tags {', '.join(tags_left)} may still name the restored images; "
            "see the log."
        )
    if leftover := strings(doc, "leftover"):
        sentences.append(f"Remove {', '.join(leftover)} by hand; drydock could not.")
    if sentence := compose_warning(run, doc):
        sentences.append(sentence)
    return " ".join(sentences) or None


def compose_warning(run: Run, doc: dict[str, Any]) -> str | None:
    """Whether the compose files the plan named may be missing. They are written after the
    commit, best effort: the journal holds compose_problem when that failed and
    compose_written once it worked. A committed run that ended with neither (a crash
    between the commit and the write) may not have written them. The directory comes from
    the confirmed summary, never from the error text."""
    summary = json_object(run.plan).get("summary")
    compose = summary.get("compose") if isinstance(summary, dict) else None
    directory = compose.get("dir") if isinstance(compose, dict) else None
    where = f" to {directory}" if isinstance(directory, str) and directory else ""
    problem = doc.get("compose_problem")
    if isinstance(problem, str) and problem:
        return f"The compose files were not written{where}; see the log."
    if (
        where
        and doc.get("committed")
        and doc.get("compose_written") is not True
        and run.status not in ACTIVE_STATUSES
    ):
        return f"The compose files may not have been written{where}; see the log."
    return None


def job_names(db: Session, runs: list[Run]) -> dict[int, str]:
    ids = {r.job_id for r in runs if r.job_id is not None}
    return dict(db.execute(select(Job.id, Job.name).where(Job.id.in_(ids))).all())


@router.get("")
def list_runs(
    request: Request,
    auth: Viewer,
    before: int | None = Query(default=None, ge=1),
    status: list[str] = Query(default=[]),
    db: Session = Depends(get_db),
) -> Response:
    """Newest first, optionally only some statuses (?status=failed&status=interrupted)."""
    chosen = [s for s in RUN_STATUSES if s in status]
    query = select(Run).order_by(Run.id.desc()).limit(PAGE_SIZE)
    if before is not None:
        query = query.where(Run.id < before)
    if chosen:
        query = query.where(Run.status.in_(chosen))
    runs = list(db.scalars(query))
    next_before = runs[-1].id if len(runs) == PAGE_SIZE else None
    return render(
        request,
        "runs/list.html",
        auth=auth,
        runs=runs,
        jobs=job_names(db, runs),
        next_before=next_before,
        statuses=RUN_STATUSES,
        chosen=chosen,
        filter_query=urlencode([("status", s) for s in chosen]),
    )


def run_page(
    request: Request,
    db: Session,
    auth: Auth,
    run: Run,
    status_code: int = 200,
    error: str | None = None,
) -> Response:
    path = log_path(request.app.state.settings.data_dir, run.id)
    active = run.status in ACTIVE_STATUSES
    if active:
        # The first part; the poller fetches the rest.
        text, offset = read_log(path, 0, PAGE_LOG_LIMIT)
        truncated = False
    else:
        # The end, where the outcome is.
        (text, truncated), offset = read_tail(path, PAGE_LOG_LIMIT), 0
    return render(
        request,
        "runs/detail.html",
        status_code=status_code,
        auth=auth,
        run=run,
        job=db.get(Job, run.job_id) if run.job_id is not None else None,
        restore_doc=json_object(run.plan) if run.kind == "restore" else None,
        restore_warning=restore_warning(run),
        siblings=list(
            db.scalars(select(Run).where(Run.first_run_id == run.first_run_id).order_by(Run.id))
        )
        if run.first_run_id is not None
        else [],
        log_text=text,
        offset=offset,
        active=active,
        truncated=truncated,
        errors=[error] if error else [],
    )


@router.get("/{run_id}")
def view_run(
    request: Request, run_id: int, auth: Viewer, db: Session = Depends(get_db)
) -> Response:
    return run_page(request, db, auth, get_run(db, run_id))


@router.get("/{run_id}/log")
def run_log(
    request: Request,
    run_id: int,
    auth: Viewer,
    offset: int = Query(default=0, ge=0, le=2**40),
    db: Session = Depends(get_db),
) -> Response:
    """New log lines after offset, and a poller for the next ones while the run is active."""
    run = get_run(db, run_id)
    active = run.status in ACTIVE_STATUSES
    if not active and is_htmx(request):
        return Response(status_code=204, headers={"HX-Refresh": "true"})
    text, next_offset = read_log(log_path(request.app.state.settings.data_dir, run.id), offset)
    if not text and is_htmx(request):
        return Response(status_code=204)  # nothing new: no swap, the poller keeps its offset
    return render(
        request,
        "runs/log.html",
        auth=auth,
        run=run,
        log_text=text,
        offset=next_offset,
        active=active,
    )


@router.post("/{run_id}/cancel")
def cancel_run(
    request: Request, run_id: int, auth: Operator, db: Session = Depends(get_db)
) -> Response:
    """Cancels a queued or running run. A restore awaiting confirmation is discarded,
    which removes its verified data. Restores are admin only."""
    run = get_run(db, run_id)
    details = {"job_id": run.job_id, "kind": run.kind, "status": run.status}
    if run.kind == "restore" and auth.user.role < Role.admin:
        audit.record(
            db,
            actor=auth.user.username,
            action="run.cancel",
            target=f"run:{run.id}",
            outcome="denied",
            ip=client_ip(request),
            details=details,
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Only an admin can cancel a restore.")
    dispatcher = request.app.state.dispatcher
    cancelled = anyio.from_thread.run_sync(dispatcher.cancel, run.id)
    if not cancelled and run.status == "awaiting_confirmation":
        # The dispatcher writes the run in its own transaction: release the write lock.
        db.expunge(run)
        db.rollback()
        cancelled = anyio.from_thread.run(dispatcher.discard_restore, run.id)
        run = get_run(db, run_id)
    audit.record(
        db,
        actor=auth.user.username,
        action="run.cancel",
        target=f"run:{run.id}",
        outcome="success" if cancelled else "failure",
        ip=client_ip(request),
        details=details,
    )
    db.commit()
    if not cancelled:
        db.refresh(run)
        return run_page(request, db, auth, run, 409, error="This run is not in progress.")
    return see_other(request, f"/runs/{run.id}")


@router.post("/{run_id}/dismiss")
def dismiss_run(
    request: Request, run_id: int, auth: Operator, db: Session = Depends(get_db)
) -> Response:
    """Takes an ended run off the dashboard's "Needs attention". The run and its log stay."""
    run = get_run(db, run_id)
    if run.status in OPEN_STATUSES:
        raise HTTPException(status_code=409, detail="This run has not ended.")
    if run.dismissed_at is None:
        run.dismissed_at = utcnow()
    audit.record(
        db,
        actor=auth.user.username,
        action="run.dismiss",
        target=f"run:{run.id}",
        ip=client_ip(request),
        details={"job_id": run.job_id, "status": run.status},
    )
    db.commit()
    return see_other(request, "/")
