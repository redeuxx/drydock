"""Retention: jobs gain a retention policy (JSON), keep last 7 by default.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

DEFAULT = '{"keep_last": 7, "mode": "last"}'  # retention.DEFAULT_JSON, frozen here


def upgrade() -> None:
    # Native ADD and DROP COLUMN: jobs is not rebuilt, so its links and sequence stay.
    op.add_column("jobs", sa.Column("retention", sa.Text(), nullable=False, server_default=DEFAULT))


def downgrade() -> None:
    op.execute("ALTER TABLE jobs DROP COLUMN retention")
