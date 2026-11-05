"""Host alerts: whether a host's container and connection changes are alerted, and to
which notification target.

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-05
"""

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: hosts is not rebuilt, so its links and sequence stay.
    op.add_column(
        "hosts",
        sa.Column("alerts_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # No foreign key: SQLite adds one only by rebuilding hosts, which half the schema
    # points at. Deleting a notification target clears it here (routes/notifications.py),
    # and target IDs are never reused (AUTOINCREMENT).
    op.add_column("hosts", sa.Column("alert_target_id", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.execute("ALTER TABLE hosts DROP COLUMN alert_target_id")
    op.execute("ALTER TABLE hosts DROP COLUMN alerts_enabled")
