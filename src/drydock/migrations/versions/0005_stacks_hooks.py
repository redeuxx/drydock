"""Stacks, consistency modes and hooks: jobs target stacks and run in stop, pause or live mode
with hook ID lists, a hooks table, and runs.paused_containers_json.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-15
"""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

TARGET_0004 = "target_type IN ('container')"
TARGET_0005 = "target_type IN ('container', 'stack')"
MODES_0004 = "consistency_mode IN ('stop')"
MODES_0005 = "consistency_mode IN ('stop', 'pause', 'live')"
SCOPES = "scope IN ('config', 'data', 'image', 'all')"
RUN_KINDS = "kind IN ('backup', 'restore')"
RUN_STATUSES = (
    "status IN ('queued', 'verifying', 'awaiting_confirmation', 'running', 'done', 'failed',"
    " 'cancelled', 'interrupted')"
)


# TABLES AS THEY WERE, FOR THE BATCH COPIES


def jobs_columns() -> list[sa.Column]:
    """The jobs columns exactly as 0003 created them."""
    return [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("uuid", sa.String(36), nullable=False, unique=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column(
            "host_id",
            sa.Integer(),
            sa.ForeignKey("hosts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "storage_target_id",
            sa.Integer(),
            sa.ForeignKey("storage_targets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("consistency_mode", sa.String(16), nullable=False),
        sa.Column("images_reference_only_if_pullable", sa.Boolean(), nullable=False),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    ]


def jobs_0004(metadata: sa.MetaData) -> sa.Table:
    """The jobs table as 0003 created it and 0004 left it."""
    return sa.Table(
        "jobs",
        metadata,
        *jobs_columns(),
        sa.CheckConstraint(TARGET_0004, name="ck_jobs_target_type"),
        sa.CheckConstraint(SCOPES, name="ck_jobs_scope"),
        sa.CheckConstraint(MODES_0004, name="ck_jobs_consistency"),
        sa.Index("ix_jobs_host_id", "host_id"),
        sa.Index("ix_jobs_storage_target_id", "storage_target_id"),
        sqlite_autoincrement=True,
    )


def jobs_0005(metadata: sa.MetaData) -> sa.Table:
    """The jobs table as this revision leaves it, for the downgrade copy."""
    return sa.Table(
        "jobs",
        metadata,
        *jobs_columns(),
        sa.Column("pre_hooks", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("post_hooks", sa.Text(), nullable=False, server_default="[]"),
        sa.CheckConstraint(TARGET_0005, name="ck_jobs_target_type"),
        sa.CheckConstraint(SCOPES, name="ck_jobs_scope"),
        sa.CheckConstraint(MODES_0005, name="ck_jobs_consistency"),
        sa.Index("ix_jobs_host_id", "host_id"),
        sa.Index("ix_jobs_storage_target_id", "storage_target_id"),
        sqlite_autoincrement=True,
    )


def runs_0005(metadata: sa.MetaData) -> sa.Table:
    """The runs table as this revision leaves it (0004's plus paused_containers_json)."""
    return sa.Table(
        "runs",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("triggered_by", sa.String(64), nullable=True),
        sa.Column("stopped_containers_json", sa.Text(), nullable=False),
        sa.Column("archive_name", sa.String(255), nullable=True),
        sa.Column("size", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("plan", sa.Text(), nullable=True),
        sa.Column("restore_originals_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("paused_containers_json", sa.Text(), nullable=False, server_default="[]"),
        sa.CheckConstraint(RUN_KINDS, name="ck_runs_kind"),
        sa.CheckConstraint(RUN_STATUSES, name="ck_runs_status"),
        sa.Index("ix_runs_job_id", "job_id"),
        sa.Index("ix_runs_status", "status"),
        sqlite_autoincrement=True,
    )


# AUTOINCREMENT ACROSS THE REBUILD
# The batch copies rows with INSERT ... SELECT, which leaves the new table's sequence at
# max(id), and dropping the old table drops its sequence row. Job IDs name audit targets
# 'job:<id>' and runs and backups keep pointing at them, and run IDs name log files, so a
# deleted row's ID must never be handed out again.


def saved_sequence(conn: sa.Connection, table: str) -> int | None:
    return conn.execute(
        sa.text("SELECT seq FROM sqlite_sequence WHERE name = :table"), {"table": table}
    ).scalar()


def restore_sequence(conn: sa.Connection, table: str, saved: int | None) -> None:
    if saved is None:
        return
    params = {"table": table, "saved": saved}
    updated = conn.execute(
        sa.text("UPDATE sqlite_sequence SET seq = MAX(seq, :saved) WHERE name = :table"),
        params,
    )
    if updated.rowcount == 0:
        conn.execute(
            sa.text("INSERT INTO sqlite_sequence (name, seq) VALUES (:table, :saved)"), params
        )


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "hooks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column(
            "host_id",
            sa.Integer(),
            sa.ForeignKey("hosts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("project", sa.String(63), nullable=True),
        sa.Column("container", sa.String(128), nullable=False),
        sa.Column("argv_json", sa.Text(), nullable=False),
        sa.Column("user", sa.String(65), nullable=False),
        sa.Column("workdir", sa.String(1024), nullable=False),
        sa.Column("timeout_s", sa.Integer(), nullable=False),
        sa.Column("log_output", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("timeout_s BETWEEN 1 AND 3600", name="ck_hooks_timeout"),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_hooks_host_id", "hooks", ["host_id"])

    saved = saved_sequence(bind, "jobs")
    with op.batch_alter_table(
        "jobs", recreate="always", copy_from=jobs_0004(sa.MetaData())
    ) as batch:
        batch.drop_constraint("ck_jobs_target_type", type_="check")
        batch.create_check_constraint("ck_jobs_target_type", TARGET_0005)
        batch.drop_constraint("ck_jobs_consistency", type_="check")
        batch.create_check_constraint("ck_jobs_consistency", MODES_0005)
        batch.add_column(sa.Column("pre_hooks", sa.Text(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("post_hooks", sa.Text(), nullable=False, server_default="[]"))
    restore_sequence(bind, "jobs", saved)

    # A native ADD COLUMN: runs is not rebuilt, so its links and sequence stay as they are.
    op.add_column(
        "runs",
        sa.Column("paused_containers_json", sa.Text(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    # paused_containers_json is the only record of what an unfinished run froze, and 0004's
    # recovery only restarts what it stopped. Dropping it would leave those containers
    # paused with nothing to say drydock paused them.
    frozen = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM runs WHERE status IN"
            " ('queued', 'verifying', 'awaiting_confirmation', 'running')"
            " AND paused_containers_json != '[]'"
        )
    ).scalar()
    if frozen:
        raise RuntimeError(
            f"{frozen} unfinished run(s) still list paused containers. Start drydock at"
            " revision 0005 once so recovery unpauses them, then downgrade."
        )

    saved = saved_sequence(bind, "runs")
    with op.batch_alter_table(
        "runs", recreate="always", copy_from=runs_0005(sa.MetaData())
    ) as batch:
        batch.drop_column("paused_containers_json")
    restore_sequence(bind, "runs", saved)

    # Stack jobs cannot exist at 0004. Foreign keys are off here, so the SET NULL on their
    # runs and backups has to be explicit or the foreign key check aborts the downgrade.
    op.execute(
        "UPDATE runs SET job_id = NULL"
        " WHERE job_id IN (SELECT id FROM jobs WHERE target_type = 'stack')"
    )
    op.execute(
        "UPDATE backups SET job_id = NULL"
        " WHERE job_id IN (SELECT id FROM jobs WHERE target_type = 'stack')"
    )
    op.execute("DELETE FROM jobs WHERE target_type = 'stack'")
    op.execute("UPDATE jobs SET consistency_mode = 'stop' WHERE consistency_mode != 'stop'")

    saved = saved_sequence(bind, "jobs")
    with op.batch_alter_table(
        "jobs", recreate="always", copy_from=jobs_0005(sa.MetaData())
    ) as batch:
        batch.drop_column("post_hooks")
        batch.drop_column("pre_hooks")
        batch.drop_constraint("ck_jobs_target_type", type_="check")
        batch.create_check_constraint("ck_jobs_target_type", TARGET_0004)
        batch.drop_constraint("ck_jobs_consistency", type_="check")
        batch.create_check_constraint("ck_jobs_consistency", MODES_0004)
    restore_sequence(bind, "jobs", saved)

    op.drop_table("hooks")
