"""Skipped mounts: jobs gain a list of mounts whose data they leave out, such as a cache.

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: jobs is not rebuilt, so its links and sequence stay.
    op.add_column("jobs", sa.Column("skip_mounts", sa.Text(), nullable=False, server_default="[]"))


def downgrade() -> None:
    op.execute("ALTER TABLE jobs DROP COLUMN skip_mounts")
