"""Dashboard, notifications, about page, audit log and health check."""

import importlib.metadata
import json
import platform
import re
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from drydock import audit, feed
from drydock.archive.writer import AGE_DIR
from drydock.db import get_db
from drydock.models import AuditEvent, Backup, Host, Job, Run, StorageTarget, User, utcnow
from drydock.routes.auth import client_ip, safe_next
from drydock.security.rbac import Role, require_role
from drydock.security.sessions import Auth
from drydock.storage.rclone_rc import RCLONE_BINARY
from drydock.templating import render, see_other

router = APIRouter()

AUDIT_PAGE_SIZE = 100
Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]
RECENT = 8
NEXT_RUNS = 5
FAILURE_DAYS = 7

# DASHBOARD


@router.get("/")
def home(request: Request, auth: Viewer, db: Session = Depends(get_db)) -> Response:
    """What needs attention, what ran and what runs next. Reads only."""
    since = utcnow() - timedelta(days=FAILURE_DAYS)
    jobs = db.scalars(select(Job).order_by(Job.name)).all()
    names = {j.id: j.name for j in jobs}
    recent = db.scalars(
        select(Run).where(Run.kind == "backup").order_by(Run.id.desc()).limit(RECENT)
    ).all()
    failed = db.scalars(
        select(Run)
        .where(Run.kind == "backup", Run.status.in_(("failed", "interrupted")))
        .where(Run.created_at >= since)
        .order_by(Run.id.desc())
        .limit(RECENT)
    ).all()
    failed_count = db.scalar(
        select(func.count())
        .select_from(Run)
        .where(Run.kind == "backup", Run.status.in_(("failed", "interrupted")))
        .where(Run.created_at >= since)
    )
    active = db.scalar(
        select(func.count()).select_from(Run).where(Run.status.in_(("queued", "running")))
    )
    scheduler = request.app.state.scheduler
    upcoming = sorted(
        (
            (when, job)
            for job in jobs
            if job.enabled and job.cron and (when := scheduler.next_run_time(job.id)) is not None
        ),
        key=lambda pair: pair[0],
    )[:NEXT_RUNS]
    backups = db.execute(select(func.count(), func.coalesce(func.sum(Backup.size), 0))).one()
    context: dict[str, Any] = {
        "jobs": jobs,
        "enabled": sum(1 for j in jobs if j.enabled),
        "names": names,
        "recent": recent,
        "failed": failed,
        "failure_days": FAILURE_DAYS,
        "failed_count": failed_count or 0,
        "active": active or 0,
        "upcoming": upcoming,
        "backup_count": backups[0],
        "backup_bytes": backups[1],
        "hosts": [],
        "storage": [],
    }
    if auth.user.role >= Role.admin:  # the pages these link to are admins' too
        manager = request.app.state.hosts
        context["hosts"] = [
            (host, manager.status(host)) for host in db.scalars(select(Host).order_by(Host.name))
        ]
        context["storage"] = db.scalars(select(StorageTarget).order_by(StorageTarget.name)).all()
    return render(request, "home.html", auth=auth, **context)


# NOTIFICATIONS (THE BELL)


@router.get("/feed")
def feed_page(request: Request, auth: Viewer, db: Session = Depends(get_db)) -> Response:
    user = db.get(User, auth.user.id)
    entries = feed.items(db, user, feed.PAGE) if user is not None else []
    return render(request, "feed.html", auth=auth, entries=entries)


@router.post("/feed/read")
def feed_read(
    request: Request,
    auth: Viewer,
    next_path: Annotated[str, Form(alias="next")] = "/",
    db: Session = Depends(get_db),
) -> Response:
    """Marks every notification read for this user."""
    user = db.get(User, auth.user.id)
    if user is not None:
        user.feed_read_at = utcnow()
    audit.record(
        db, actor=auth.user.username, action="feed.read", ip=client_ip(request), details={}
    )
    db.commit()
    return see_other(request, safe_next(next_path))


# ABOUT

PROJECT_URL = "https://github.com/redeuxx/drydock"
# Python packages: (distribution, what it does here). Linked to their PyPI release.
PYTHON_PACKAGES = (
    ("fastapi", "web framework"),
    ("starlette", "ASGI toolkit under FastAPI"),
    ("uvicorn", "ASGI server"),
    ("jinja2", "HTML templates"),
    ("pydantic", "data validation"),
    ("sqlalchemy", "database toolkit (SQLite)"),
    ("alembic", "database migrations"),
    ("apscheduler", "job schedules"),
    ("docker", "Docker Engine API client"),
    ("asyncssh", "SSH tunnels to remote hosts"),
    ("cryptography", "secret encryption and signatures"),
    ("argon2-cffi", "password hashing"),
    ("apprise", "notifications"),
    ("httpx", "HTTP client"),
)
# Pinned in the Dockerfile and checked by SHA-256 at build time; asked for their versions.
BINARIES = (
    (
        "rclone",
        RCLONE_BINARY,
        ["version"],
        "remote storage",
        "https://github.com/rclone/rclone/releases/tag/v{v}",
    ),
    (
        "age",
        AGE_DIR / "age",
        ["--version"],
        "archive encryption",
        "https://github.com/FiloSottile/age/releases/tag/v{v}",
    ),
)
VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")
# The browser side: versions the image build writes (tools/vendor.ts).
FRONTEND = (
    (
        "htmx.org",
        "htmx",
        "page updates",
        "https://github.com/bigskysoftware/htmx/releases/tag/v{v}",
    ),
    (
        "tailwindcss",
        "Tailwind CSS",
        "styles",
        "https://github.com/tailwindlabs/tailwindcss/releases/tag/v{v}",
    ),
    ("daisyui", "daisyUI", "components", "https://github.com/saadeghi/daisyui/releases/tag/v{v}"),
)
FRONTEND_VERSIONS = Path(__file__).resolve().parent.parent / "static" / "vendor" / "versions.json"


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def short_version(full: str | None) -> str:
    """The release line drydock shows: 0.1.0 is 0.1."""
    parts = (full or "").split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else (full or "unknown")


def binary_version(binary: Path, args: list[str]) -> str | None:
    """What a pinned binary says its version is, or None. No shell, no environment."""
    try:
        done = subprocess.run(  # noqa: S603 (a fixed path and fixed arguments)
            [str(binary), *args], capture_output=True, text=True, timeout=5, env={}, check=False
        )
    except OSError, subprocess.SubprocessError:
        return None
    match = VERSION_RE.search(done.stdout.splitlines()[0] if done.stdout else "")
    return match.group(1) if match else None


def frontend_versions() -> dict[str, str]:
    try:
        data = json.loads(FRONTEND_VERSIONS.read_text())
    except OSError, ValueError:
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


@router.get("/about")
def about(request: Request, auth: Viewer) -> Response:
    python = platform.python_version()
    built = frontend_versions()
    components: list[dict[str, str | None]] = [
        {
            "name": "Python",
            "role": "runtime",
            "version": python,
            "url": f"https://www.python.org/downloads/release/python-{python.replace('.', '')}/",
        }
    ]
    for name, role in PYTHON_PACKAGES:
        version = package_version(name)
        components.append(
            {
                "name": name,
                "role": role,
                "version": version,
                "url": f"https://pypi.org/project/{name}/{version}/" if version else None,
            }
        )
    for name, binary, args, role, url in BINARIES:
        version = binary_version(binary, args)
        components.append(
            {
                "name": name,
                "role": role,
                "version": version,
                "url": url.format(v=version) if version else None,
            }
        )
    for key, name, role, url in FRONTEND:
        version = built.get(key)
        components.append(
            {
                "name": name,
                "role": role,
                "version": version,
                "url": url.format(v=version) if version else None,
            }
        )
    return render(
        request,
        "about.html",
        auth=auth,
        version=short_version(package_version("drydock")),
        project_url=PROJECT_URL,
        components=components,
        helper_image=request.app.state.settings.helper_image,
    )


# AUDIT LOG


@router.get("/audit")
def audit_log(
    request: Request,
    before: int | None = Query(default=None, ge=1),
    auth: Auth = Depends(require_role(Role.admin)),
    db: Session = Depends(get_db),
) -> Response:
    query = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(AUDIT_PAGE_SIZE)
    if before is not None:
        query = query.where(AuditEvent.id < before)
    events = db.scalars(query).all()
    rows = [(e, json.loads(e.details)) for e in events]
    next_before = events[-1].id if len(events) == AUDIT_PAGE_SIZE else None
    return render(request, "audit.html", auth=auth, rows=rows, next_before=next_before)


@router.get("/healthz")
def healthz() -> Response:
    return JSONResponse({"status": "ok"})
