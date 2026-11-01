"""The bell: each user's notifications are read up to a point in time.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: users is not rebuilt, so its links and sequence stay.
    op.add_column("users", sa.Column("feed_read_at", sa.DateTime(), nullable=True))
    # Accounts that exist now start with nothing unread, not with every run so far.
    op.execute("UPDATE users SET feed_read_at = strftime('%Y-%m-%d %H:%M:%f', 'now')")
    op.create_index("ix_runs_finished_at", "runs", ["finished_at"])
    op.create_index("ix_audit_events_action_ts", "audit_events", ["action", "ts"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_action_ts", "audit_events")
    op.drop_index("ix_runs_finished_at", "runs")
    op.execute("ALTER TABLE users DROP COLUMN feed_read_at")
