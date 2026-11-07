"""Settings: how often drydock checks the hosts for newer images, in hours (0: never by
itself), on the installation's single row.

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-07
"""

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "installation",
        sa.Column("update_check_hours", sa.Integer(), nullable=False, server_default="6"),
    )


def downgrade() -> None:
    op.execute("ALTER TABLE installation DROP COLUMN update_check_hours")
