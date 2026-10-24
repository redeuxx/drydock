"""Notifications: notification_targets (encrypted Apprise URLs) and job_notifications.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

KINDS = "kind IN ('webhook', 'email', 'ntfy', 'gotify', 'url')"


def upgrade() -> None:
    op.create_table(
        "notification_targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("url_enc", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(KINDS, name="ck_notification_targets_kind"),
        sqlite_autoincrement=True,
    )
    op.create_table(
        "job_notifications",
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "target_id",
            sa.Integer(),
            sa.ForeignKey("notification_targets.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("on_success", sa.Boolean(), nullable=False),
        sa.Column("on_failure", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_job_notifications_target_id", "job_notifications", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_job_notifications_target_id", table_name="job_notifications")
    op.drop_table("job_notifications")
    op.drop_table("notification_targets")
