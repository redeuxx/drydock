"""Update policies: scheduled updates of a container or a Compose stack.

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-05
"""

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "update_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column(
            "host_id",
            sa.Integer(),
            sa.ForeignKey("hosts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("cron", sa.String(100), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=True),
        sa.Column(
            "backup_job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("stop_on_failed_backup", sa.Boolean(), nullable=False),
        sa.Column(
            "notify_target_id",
            sa.Integer(),
            sa.ForeignKey("notification_targets.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("notify_success", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_fired_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "target_type IN ('container', 'stack')", name="ck_update_policies_target_type"
        ),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_update_policies_host_id", "update_policies", ["host_id"])


def downgrade() -> None:
    op.drop_index("ix_update_policies_host_id", "update_policies")
    op.drop_table("update_policies")
