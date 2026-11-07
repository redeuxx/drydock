"""App factory and lifespan. Uvicorn imports drydock.main:app."""

import fcntl
import functools
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import anyio
import anyio.to_thread
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from drydock import db
from drydock.config import DEFAULT_PROXIES, ConfigError, Settings, load_settings
from drydock.crypto import Crypto
from drydock.hosts import alerts as host_alerts
from drydock.hosts import logs as container_logs
from drydock.hosts.client import run_blocking
from drydock.hosts.events import EventCollector
from drydock.hosts.manager import HostManager, load_instance_id
from drydock.hosts.status import StatusCollector
from drydock.jobs.dispatcher import Dispatcher
from drydock.jobs.scheduler import Scheduler
from drydock.models import User
from drydock.notify import Notifier
from drydock.restore import uploads
from drydock.routes import (
    account,
    activity,
    admin_settings,
    auth,
    backups,
    containers,
    hooks,
    hosts,
    images,
    jobs,
    logs,
    notifications,
    restore,
    runs,
    stacks,
    storage,
    system,
    updates,
    users,
)
from drydock.security.headers import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from drydock.security.ratelimit import LoginRateLimiter
from drydock.security.rbac import RecentAuthRequired, Role
from drydock.security.sessions import Auth, LoginRequired, clear_cookie
from drydock.storage import gdrive_oauth
from drydock.storage.rclone_rc import RcloneDaemon
from drydock.templating import is_htmx, render, set_zone
from drydock.updates.check import UpdateChecker

log = logging.getLogger("drydock")

STATIC_DIR = Path(__file__).parent / "static"
SETUP_EXEMPT_PATHS = ("/setup", "/healthz")


# STARTUP HOOKS


def run_startup_hooks(app: FastAPI) -> None:
    """Runs only in the process holding the flock: crash recovery and staging cleanup. The
    scheduler starts later in the lifespan, once the dispatcher has started."""
    log.info("Running startup hooks")
    app.state.dispatcher.recover()
    uploads.recover(app.state.sessionmaker, app.state.settings)


def acquire_lock(path: Path) -> int | None:
    """Returns the locked fd, or None when another process already holds the lock."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    return fd


def count_superadmins(sessionmaker) -> int:
    with sessionmaker() as session:
        return session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.role == Role.superadmin, User.disabled.is_(False))
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    os.umask(0o077)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    # The image sets TMPDIR=/data/tmp because the root filesystem is read-only.
    (settings.data_dir / "tmp").mkdir(mode=0o700, exist_ok=True)
    lock_fd = acquire_lock(settings.data_dir / "drydock.lock")
    app.state.primary = lock_fd is not None
    if not app.state.primary:
        log.critical(
            "ANOTHER DRYDOCK PROCESS HOLDS %s. This process will not run migrations, recovery "
            "or the scheduler. Point each drydock instance at its own data directory.",
            settings.data_dir / "drydock.lock",
        )
    engine = db.make_engine(settings.data_dir / "drydock.db")
    host_manager: HostManager | None = None
    status: StatusCollector | None = None
    events: EventCollector | None = None
    updates: UpdateChecker | None = None
    dispatcher: Dispatcher | None = None
    scheduler: Scheduler | None = None
    notifier: Notifier | None = None
    rclone = app.state.rclone = RcloneDaemon(settings.run_dir)
    try:
        if app.state.primary:
            db.migrate(engine)
        app.state.sessionmaker = db.make_sessionmaker(engine)
        host_manager = app.state.hosts = HostManager(
            settings,
            app.state.sessionmaker,
            app.state.crypto,
            load_instance_id(app.state.sessionmaker),
        )
        status = app.state.status = StatusCollector(app.state.sessionmaker, host_manager)
        events = app.state.events = EventCollector(app.state.sessionmaker, host_manager)
        updates = app.state.updates = UpdateChecker(app.state.sessionmaker, host_manager)
        # Log reads wait on slow hosts on threads of their own, never the routes' pool.
        app.state.log_limiter = anyio.CapacityLimiter(container_logs.THREADS)
        notifier = app.state.notifier = Notifier(settings, app.state.sessionmaker, app.state.crypto)
        app.state.oauth_flows = gdrive_oauth.Flows()  # Google Drive connections under way
        # A drive target Google refused: marked, and its jobs' failure targets told once.
        app.state.mark_reconnect = functools.partial(
            gdrive_oauth.mark_reconnect,
            app.state.sessionmaker,
            app.state.crypto,
            notifier.storage_reconnect,
        )
        dispatcher = app.state.dispatcher = Dispatcher(
            settings,
            app.state.sessionmaker,
            app.state.crypto,
            host_manager,
            enabled=app.state.primary,
            on_end=notifier.run_ended,
            rclone=rclone,
            on_reconnect=app.state.mark_reconnect,
        )
        # Alerts leave out containers a run holds, and are told to the bell and targets.
        events.use(
            dispatcher.holds,
            functools.partial(host_alerts.deliver, app.state.sessionmaker, notifier),
        )
        scheduler = app.state.scheduler = Scheduler(
            settings, app.state.sessionmaker, dispatcher, host_manager
        )
        if not settings.cookie_secure:
            log.warning(
                "DRYDOCK_BASE_URL %s is plain HTTP on a non-loopback address. Session cookies "
                "are sent without the Secure flag and can be stolen on the network. Use HTTPS "
                "through a reverse proxy (docs/configuration.md).",
                settings.base_url,
            )
        if settings.public_https and settings.forwarded_allow_ips == (DEFAULT_PROXIES,):
            log.warning(
                "DRYDOCK_BASE_URL %s looks like a reverse proxy deployment, but "
                "FORWARDED_ALLOW_IPS is still %s. A proxy reaches the container from a Docker "
                "network address, so every client then shares that address: the login limiter "
                "blocks all users together and the audit log records only the proxy. Set "
                "FORWARDED_ALLOW_IPS to the proxy's address as seen from the container.",
                settings.base_url,
                DEFAULT_PROXIES,
            )
        if count_superadmins(app.state.sessionmaker) == 0:
            log.warning(
                "NO SUPERADMIN EXISTS. Anyone who can reach this port can open /setup and take "
                "control of drydock, which is root-equivalent on every host it manages. "
                "Complete setup now."
            )
        if app.state.primary:
            run_startup_hooks(app)
            # One rcd on one socket path: a second process never starts its own.
            await rclone.start()
            # SSH tunnels and the helper reaper run only under the flock. A second process
            # must not reap helpers that the primary is using, and never opens a tunnel.
            await host_manager.start()
            # Container status reads through the tunnels: only here, like them.
            status.start()
            # Events stream through the tunnels too, and only one process stores them.
            events.start()
            updates.start()  # asks registries, through the hosts' daemons
            await dispatcher.start()
            # Only under the flock: a second process never runs scheduled jobs.
            await scheduler.start()
        yield
    finally:
        # Before the dispatcher stops, so no fire submits into a closing dispatcher.
        if scheduler is not None:
            await scheduler.shutdown()
        # Runs first: restarting containers on SSH hosts needs their tunnels.
        if dispatcher is not None:
            await dispatcher.shutdown()
        if events is not None:  # before the notifier: alerts it judged are still told
            await events.close()
            events = None
        if notifier is not None:  # after the dispatcher: the runs it ended still notify
            await run_blocking(notifier.close)
        await rclone.close()  # after the dispatcher: its runs upload through rclone
        if status is not None:  # before the tunnels it reads through close
            await status.close()
        if events is not None:  # likewise; stores what it has left
            await events.close()
        if updates is not None:
            await updates.close()
        if host_manager is not None:
            await host_manager.close()
        engine.dispose()
        if lock_fd is not None:
            os.close(lock_fd)


# REQUEST GUARDS


class SetupGateMiddleware:
    """While no user exists, every route except setup, healthz and static redirects to /setup."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] == "http"
            and path not in SETUP_EXEMPT_PATHS
            and not path.startswith("/static/")
        ):
            state = scope["app"].state
            if not state.setup_complete:
                state.setup_complete = await anyio.to_thread.run_sync(any_users, state)
            if not state.setup_complete:
                await RedirectResponse("/setup", status_code=303)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def any_users(state) -> bool:
    with state.sessionmaker() as session:
        return auth.users_exist(session)


# ERROR HANDLERS


def current_auth(request: Request) -> Auth | None:
    """The session load_auth validated for this request, so error pages keep the header."""
    return getattr(request.state, "auth", None)


async def login_required(request: Request, _exc: LoginRequired) -> Response:
    if is_htmx(request):
        response: Response = PlainTextResponse("Login required", status_code=401)
    else:
        response = RedirectResponse("/login", status_code=303)
    clear_cookie(response, request.app.state.settings)
    return response


async def recent_auth_required(request: Request, exc: RecentAuthRequired) -> Response:
    # Return to the page the form was on; the user resubmits after re-entering the password.
    referer = urlsplit(request.headers.get("referer", ""))
    same_host = referer.netloc == request.headers.get("host")
    next_path = auth.safe_next(referer.path) if same_host else "/"
    return render(
        request,
        "reauth.html",
        403,
        auth=exc.auth,
        next=next_path,
        error="Re-enter your password to continue.",
    )


async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
    message = exc.detail if isinstance(exc.detail, str) else "Request failed."
    response = render(
        request, "error.html", exc.status_code, auth=current_auth(request), message=message
    )
    for name, value in (exc.headers or {}).items():
        response.headers[name] = value
    return response


async def validation_error(request: Request, _exc: RequestValidationError) -> Response:
    message = "The submitted data is invalid."
    return render(request, "error.html", 422, auth=current_auth(request), message=message)


# APP FACTORY


def create_app(settings: Settings) -> FastAPI:
    set_zone(settings.tz)  # pages show times in drydock's zone
    app = FastAPI(
        title="Drydock",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        middleware=[
            Middleware(SecurityHeadersMiddleware, hsts=settings.public_https),
            Middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts)),
            Middleware(ProxyHeadersMiddleware, trusted_hosts=list(settings.forwarded_allow_ips)),
            Middleware(BodySizeLimitMiddleware),
            Middleware(SetupGateMiddleware),
        ],
    )
    app.state.settings = settings
    app.state.crypto = Crypto(settings.secret_keys)
    app.state.login_limiter = LoginRateLimiter()
    app.state.setup_complete = False
    app.add_exception_handler(LoginRequired, login_required)
    app.add_exception_handler(RecentAuthRequired, recent_auth_required)
    app.add_exception_handler(StarletteHTTPException, http_error)
    app.add_exception_handler(RequestValidationError, validation_error)
    routers = (
        auth,
        account,
        users,
        hosts,
        storage,
        notifications,
        jobs,
        hooks,
        runs,
        backups,
        restore,
        system,
        containers,
        stacks,
        images,
        logs,
        activity,
        updates,
        admin_settings,
    )
    for module in routers:
        app.include_router(module.router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR, check_dir=False), name="static")
    return app


def __getattr__(name: str) -> FastAPI:
    """Builds the app on first access, so importing this module has no side effects."""
    if name != "app":
        raise AttributeError(name)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # asyncssh logs every forwarded channel (one per Docker request) at INFO.
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    # httpx logs every rclone rc call (transfers poll job/status) at INFO.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"drydock: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    app = create_app(settings)
    globals()["app"] = app
    return app
