"""Uploads: archives uploaded in the browser for a restore (restore.uploads).

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-30
"""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

STATUSES = "status IN ('receiving', 'complete')"


def upgrade() -> None:
    op.create_table(
        "uploads",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("declared_size", sa.Integer(), nullable=False),
        sa.Column("received", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(STATUSES, name="ck_uploads_status"),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_uploads_user_id", "uploads", ["user_id"])


def downgrade() -> None:
    # The files stay in the staging directory's uploads/ folder; remove them by hand.
    op.drop_index("ix_uploads_user_id", table_name="uploads")
    op.drop_table("uploads")
