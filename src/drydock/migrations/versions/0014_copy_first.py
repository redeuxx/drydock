"""Copy on the host first: a job can copy its data on the host and let the containers run.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: jobs is not rebuilt, so its links and sequence stay.
    op.add_column(
        "jobs", sa.Column("copy_first", sa.Boolean(), nullable=False, server_default=sa.false())
    )


def downgrade() -> None:
    op.execute("ALTER TABLE jobs DROP COLUMN copy_first")
