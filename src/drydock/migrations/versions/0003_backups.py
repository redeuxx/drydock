"""Storage targets, jobs, runs and the backup catalog.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "storage_targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("config_enc", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("kind IN ('local')", name="ck_storage_targets_kind"),
        sqlite_autoincrement=True,
    )
    op.create_table(
        "jobs",
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
        sa.CheckConstraint("target_type IN ('container')", name="ck_jobs_target_type"),
        sa.CheckConstraint("scope IN ('config', 'data', 'image', 'all')", name="ck_jobs_scope"),
        sa.CheckConstraint("consistency_mode IN ('stop')", name="ck_jobs_consistency"),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_jobs_host_id", "jobs", ["host_id"])
    op.create_index("ix_jobs_storage_target_id", "jobs", ["storage_target_id"])
    op.create_table(
        "runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("triggered_by", sa.String(64), nullable=True),
        sa.Column("stopped_containers_json", sa.Text(), nullable=False),
        sa.Column("archive_name", sa.String(255), nullable=True),
        sa.Column("size", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.CheckConstraint("kind IN ('backup')", name="ck_runs_kind"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'done', 'failed', 'cancelled', 'interrupted')",
            name="ck_runs_status",
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_runs_job_id", "runs", ["job_id"])
    op.create_index("ix_runs_status", "runs", ["status"])
    op.create_table(
        "backups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "storage_target_id",
            sa.Integer(),
            sa.ForeignKey("storage_targets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("signed", sa.Boolean(), nullable=False),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("storage_target_id", "name", name="uq_backups_name"),
    )
    op.create_index("ix_backups_job_id", "backups", ["job_id"])
    op.create_index("ix_backups_storage_target_id", "backups", ["storage_target_id"])


def downgrade() -> None:
    op.drop_table("backups")
    op.drop_table("runs")
    op.drop_table("jobs")
    op.drop_table("storage_targets")
