"""Restore runs: run kind 'restore', the verify and confirm statuses, plan and journal.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-14
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

KINDS_0003 = "kind IN ('backup')"
KINDS_0004 = "kind IN ('backup', 'restore')"
STATUSES_0003 = "status IN ('queued', 'running', 'done', 'failed', 'cancelled', 'interrupted')"
STATUSES_0004 = (
    "status IN ('queued', 'verifying', 'awaiting_confirmation', 'running', 'done', 'failed',"
    " 'cancelled', 'interrupted')"
)


def runs_columns(status_length: int) -> list[sa.Column]:
    return [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(status_length), nullable=False),
        sa.Column("triggered_by", sa.String(64), nullable=True),
        sa.Column("stopped_containers_json", sa.Text(), nullable=False),
        sa.Column("archive_name", sa.String(255), nullable=True),
        sa.Column("size", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    ]


def runs_0003(metadata: sa.MetaData) -> sa.Table:
    """The runs table exactly as 0003 created it, for the batch copy."""
    return sa.Table(
        "runs",
        metadata,
        *runs_columns(16),
        sa.CheckConstraint(KINDS_0003, name="ck_runs_kind"),
        sa.CheckConstraint(STATUSES_0003, name="ck_runs_status"),
        sa.Index("ix_runs_job_id", "job_id"),
        sa.Index("ix_runs_status", "status"),
        sqlite_autoincrement=True,
    )


def runs_0004(metadata: sa.MetaData) -> sa.Table:
    """The runs table as this revision leaves it, for the downgrade copy."""
    return sa.Table(
        "runs",
        metadata,
        *runs_columns(32),
        sa.Column("plan", sa.Text(), nullable=True),
        sa.Column("restore_originals_json", sa.Text(), nullable=False, server_default="{}"),
        sa.CheckConstraint(KINDS_0004, name="ck_runs_kind"),
        sa.CheckConstraint(STATUSES_0004, name="ck_runs_status"),
        sa.Index("ix_runs_job_id", "job_id"),
        sa.Index("ix_runs_status", "status"),
        sqlite_autoincrement=True,
    )


# AUTOINCREMENT ACROSS THE REBUILD
# The batch copies rows with INSERT ... SELECT, which leaves the new table's sequence at
# max(id), and dropping the old table drops its sequence row. Without this the highest
# deleted run ID would be handed out again, and run IDs name log files opened O_APPEND.


def saved_sequence(conn: sa.Connection) -> int | None:
    return conn.execute(sa.text("SELECT seq FROM sqlite_sequence WHERE name = 'runs'")).scalar()


def restore_sequence(conn: sa.Connection, saved: int | None) -> None:
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


def upgrade() -> None:
    saved = saved_sequence(op.get_bind())
    with op.batch_alter_table(
        "runs", recreate="always", copy_from=runs_0003(sa.MetaData())
    ) as batch:
        batch.drop_constraint("ck_runs_kind", type_="check")
        batch.create_check_constraint("ck_runs_kind", KINDS_0004)
        batch.drop_constraint("ck_runs_status", type_="check")
        batch.create_check_constraint("ck_runs_status", STATUSES_0004)
        batch.alter_column(
            "status",
            existing_type=sa.String(16),
            type_=sa.String(32),
            existing_nullable=False,
        )
        batch.add_column(sa.Column("plan", sa.Text(), nullable=True))
        batch.add_column(
            sa.Column("restore_originals_json", sa.Text(), nullable=False, server_default="{}")
        )
    restore_sequence(op.get_bind(), saved)


def downgrade() -> None:
    saved = saved_sequence(op.get_bind())
    op.execute("DELETE FROM runs WHERE kind = 'restore'")
    op.execute(
        "UPDATE runs SET status = 'interrupted'"
        " WHERE status IN ('verifying', 'awaiting_confirmation')"
    )
    with op.batch_alter_table(
        "runs", recreate="always", copy_from=runs_0004(sa.MetaData())
    ) as batch:
        batch.drop_column("restore_originals_json")
        batch.drop_column("plan")
        batch.alter_column(
            "status",
            existing_type=sa.String(32),
            type_=sa.String(16),
            existing_nullable=False,
        )
        batch.drop_constraint("ck_runs_kind", type_="check")
        batch.create_check_constraint("ck_runs_kind", KINDS_0003)
        batch.drop_constraint("ck_runs_status", type_="check")
        batch.create_check_constraint("ck_runs_status", STATUSES_0003)
    restore_sequence(op.get_bind(), saved)
