"""User preference: whether the dashboard's Hosts section starts collapsed. Health
acknowledgements: an exited container someone has seen was unhealthy.

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-05
"""

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: users is not rebuilt, so its links and sequence stay.
    op.add_column(
        "users",
        sa.Column("hosts_collapsed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "health_acks",
        sa.Column(
            "host_id",
            sa.Integer(),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("container_id", sa.String(64), primary_key=True),
        sa.Column("acked_at", sa.DateTime(), nullable=False),
        sa.Column("acked_by", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("health_acks")
    op.execute("ALTER TABLE users DROP COLUMN hosts_collapsed")
