"""Alembic environment. Drydock passes its own connection; the CLI builds one from the URL.

On SQLite, foreign keys are off while migrations run: a batch rebuild drops the parent
table, which with foreign keys on would fire ON DELETE SET NULL on every child link (runs
and backups lose their job). The PRAGMA is a no-op inside a transaction, so it goes to the
raw sqlite3 connection before anything begins. Every pending revision then runs in one
transaction (transactional_ddl), and PRAGMA foreign_key_check runs inside it, so a revision
that would leave a dangling link is rolled back with every other one instead of committed.
"""

from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, make_url

from drydock.db import make_engine
from drydock.models import Base

config = context.config


def run(connection) -> None:
    sqlite = connection.dialect.name == "sqlite"
    if sqlite:
        raw = connection.connection.driver_connection  # the sqlite3 connection, no autobegin
        if connection.in_transaction():
            raise RuntimeError("Migrations must start outside a transaction.")
        raw.execute("PRAGMA foreign_keys=OFF")  # a no-op inside a transaction
    try:
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
            render_as_batch=True,  # SQLite cannot ALTER most columns
            transactional_ddl=True,  # one transaction around every pending revision
        )
        with context.begin_transaction():
            migration = context.get_context()
            before = migration.get_current_heads()
            context.run_migrations()
            if sqlite and migration.get_current_heads() != before:
                broken = connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
                if broken:
                    raise RuntimeError(f"Migration left broken foreign keys: {broken[:5]}")
    finally:
        if sqlite:
            raw.execute("PRAGMA foreign_keys=ON")
            if raw.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                # Still inside a transaction: never return this connection to the pool.
                connection.invalidate()
                raise RuntimeError("Foreign keys could not be turned back on after migrating.")


connection = config.attributes.get("connection")
if connection is not None:
    run(connection)
else:
    url = make_url(config.get_main_option("sqlalchemy.url"))
    # drydock's own engine on SQLite: no implicit commits around DDL, BEGIN IMMEDIATE.
    if url.get_backend_name() == "sqlite" and url.database:
        engine = make_engine(Path(url.database))
    else:
        engine = create_engine(url)
    try:
        with engine.connect() as cli_connection:
            run(cli_connection)
    finally:
        engine.dispose()
