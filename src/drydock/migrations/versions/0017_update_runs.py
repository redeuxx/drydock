"""Update runs: run kind 'update' (updates/apply.py).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-05
"""

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

KINDS_0016 = "kind IN ('backup', 'restore')"
KINDS_0017 = "kind IN ('backup', 'restore', 'update')"


def saved_sequence(conn: sa.Connection) -> int | None:
    return conn.execute(sa.text("SELECT seq FROM sqlite_sequence WHERE name = 'runs'")).scalar()


def restore_sequence(conn: sa.Connection, saved: int | None) -> None:
    """The batch copy leaves the sequence at max(id); run IDs name log files, so the
    highest deleted one must never come back."""
    if saved is None:
        return
    updated = conn.execute(
        sa.text("UPDATE sqlite_sequence SET seq = MAX(seq, :saved) WHERE name = 'runs'"),
        {"saved": saved},
    )
    if updated.rowcount == 0:
        conn.execute(
            sa.text("INSERT INTO sqlite_sequence (name, seq) VALUES ('runs', :saved)"),
            {"saved": saved},
        )


def recreate(kinds: str) -> None:
    """runs rebuilt from its own reflected definition (columns, indexes, foreign key, the
    other check), with the kind check replaced."""
    bind = op.get_bind()
    saved = saved_sequence(bind)
    runs = sa.Table("runs", sa.MetaData(), autoload_with=bind)
    with op.batch_alter_table(
        "runs",
        recreate="always",
        copy_from=runs,
        table_kwargs={"sqlite_autoincrement": True},
    ) as batch:
        batch.drop_constraint("ck_runs_kind", type_="check")
        batch.create_check_constraint("ck_runs_kind", kinds)
    restore_sequence(bind, saved)


def upgrade() -> None:
    recreate(KINDS_0017)


def downgrade() -> None:
    op.execute("DELETE FROM runs WHERE kind = 'update'")
    recreate(KINDS_0016)
