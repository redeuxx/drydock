import base64
import re
import secrets
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from drydock.config import Settings, load_settings
from drydock.main import create_app

PASSWORD = "correct horse battery staple"
CLIENT_IP = "203.0.113.5"
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
NONCE_RE = re.compile(r'nonce="[^"]*"')


def new_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def make_settings(data_dir: Path, **env: str) -> Settings:
    base = {
        "DRYDOCK_SECRET_KEY": new_key(),
        "DRYDOCK_DATA_DIR": str(data_dir),
        "DRYDOCK_RUN_DIR": str(data_dir.parent / "run"),
        "DRYDOCK_STAGING_DIR": str(data_dir / "staging"),
        "DRYDOCK_BASE_URL": "https://drydock.test",
    }
    return load_settings(base | env)


def without_nonces(html: str) -> str:
    """The CSP nonce differs on every response; blank it to compare page bodies."""
    return NONCE_RE.sub('nonce=""', html)


def form_token(html: str) -> str:
    match = TOKEN_RE.search(html)
    assert match, "no csrf_token field in page"
    return match.group(1)


@dataclass
class Browser:
    """An httpx client that behaves like a same-origin browser tab."""

    app: FastAPI
    client: httpx.AsyncClient
    settings: Settings

    @property
    def origin_headers(self) -> dict[str, str]:
        return {"Origin": self.settings.base_url, "Sec-Fetch-Site": "same-origin"}

    async def get(self, path: str, **kwargs) -> httpx.Response:
        return await self.client.get(path, **kwargs)

    async def post(
        self,
        path: str,
        data: dict | None = None,
        *,
        csrf: bool = True,
        headers: dict | None = None,
        **kwargs,
    ) -> httpx.Response:
        data = dict(data or {})
        if csrf and "csrf_token" not in data:
            data["csrf_token"] = await self.csrf_token()
        merged = self.origin_headers | (headers or {})
        return await self.client.post(path, data=data, headers=merged, **kwargs)

    async def csrf_token(self) -> str:
        return form_token((await self.client.get("/account")).text)

    async def setup(self, username: str = "admin", password: str = PASSWORD) -> httpx.Response:
        token = form_token((await self.client.get("/setup")).text)
        data = {
            "csrf_token": token,
            "username": username,
            "password": password,
            "password_confirm": password,
        }
        return await self.client.post("/setup", data=data, headers=self.origin_headers)

    async def login(self, username: str, password: str = PASSWORD) -> httpx.Response:
        token = form_token((await self.client.get("/login")).text)
        data = {"csrf_token": token, "username": username, "password": password}
        return await self.client.post("/login", data=data, headers=self.origin_headers)

    def db(self) -> sqlite3.Connection:
        return sqlite3.connect(self.settings.data_dir / "drydock.db")

    def sql(self, statement: str, params: tuple = ()) -> list[tuple]:
        with closing(self.db()) as conn:
            rows = conn.execute(statement, params).fetchall()
            conn.commit()
            return rows


@asynccontextmanager
async def running(settings: Settings, client_ip: str = CLIENT_IP) -> AsyncIterator[Browser]:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=(client_ip, 50000))
        async with httpx.AsyncClient(transport=transport, base_url=settings.base_url) as client:
            yield Browser(app=app, client=client, settings=settings)


async def add_user(browser: Browser, username: str, role: str, password: str = PASSWORD) -> int:
    response = await browser.post(
        "/users", {"username": username, "password": password, "role": role}
    )
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def sqlite_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(tzinfo=None).isoformat(sep=" ")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings with one allowed local storage root, tmp_path / "storage"."""
    (tmp_path / "storage").mkdir()
    return make_settings(tmp_path / "data", DRYDOCK_LOCAL_STORAGE_ROOTS=str(tmp_path / "storage"))


@pytest.fixture
async def fresh(settings: Settings) -> AsyncIterator[Browser]:
    """A running app with no users yet."""
    async with running(settings) as browser:
        yield browser


@pytest.fixture
async def admin(fresh: Browser) -> Browser:
    """A running app where 'admin' completed setup and is logged in as superadmin."""
    response = await fresh.setup()
    assert response.status_code == 303, response.text
    return fresh
