"""Update policies: the tag a container or a stack's main service switches to, and that
main service.

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-07
"""

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: update_policies is not rebuilt, so its links and sequence stay.
    op.add_column("update_policies", sa.Column("tag", sa.String(128), nullable=True))
    op.add_column("update_policies", sa.Column("main_service", sa.String(255), nullable=True))


def downgrade() -> None:
    op.execute("ALTER TABLE update_policies DROP COLUMN main_service")
    op.execute("ALTER TABLE update_policies DROP COLUMN tag")
