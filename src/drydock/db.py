"""SQLite engine, per-request sessions and migrations."""

import os
from collections.abc import Iterator
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

BUSY_TIMEOUT_MS = 5000


def make_engine(path: Path) -> Engine:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    os.close(fd)
    path.chmod(0o600)
    # hide_parameters keeps password hashes and CSRF tokens out of logged exceptions.
    engine = create_engine(
        f"sqlite:///{path}", connect_args={"check_same_thread": False}, hide_parameters=True
    )

    @event.listens_for(engine, "connect")
    def on_connect(dbapi_connection, _record) -> None:
        # Take transaction control away from the sqlite3 module so "begin" below decides.
        dbapi_connection.isolation_level = None
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA trusted_schema=OFF")
        cursor.close()

    @event.listens_for(engine, "begin")
    def on_begin(connection) -> None:
        # Every transaction takes the write lock up front. A deferred transaction that
        # reads and then writes can fail with SQLITE_BUSY without waiting, and setup
        # relies on this to create exactly one superadmin under concurrency.
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


def migrate(engine: Engine) -> None:
    cfg = Config()
    cfg.set_main_option("script_location", "drydock:migrations")
    with engine.connect() as connection:
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
        connection.commit()
