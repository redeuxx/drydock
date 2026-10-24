"""Schedules: jobs gain a cron expression, a time zone and the time of their last fire.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

COLUMNS = ("last_fired_at", "timezone", "cron")


def upgrade() -> None:
    # Native ADD and DROP COLUMN: jobs is not rebuilt, so its links and sequence stay.
    op.add_column("jobs", sa.Column("cron", sa.String(100), nullable=True))
    op.add_column("jobs", sa.Column("timezone", sa.String(64), nullable=True))
    op.add_column("jobs", sa.Column("last_fired_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    for column in COLUMNS:
        op.execute(f"ALTER TABLE jobs DROP COLUMN {column}")
