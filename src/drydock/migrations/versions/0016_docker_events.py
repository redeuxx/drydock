"""Docker events: container events from every host, for the activity page and the cards.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-04
"""

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "docker_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "host_id",
            sa.Integer(),
            sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("time_ns", sa.BigInteger(), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("container_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("image", sa.String(255), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("health", sa.String(16), nullable=True),
        sa.UniqueConstraint(
            "host_id", "time_ns", "container_id", "action", name="uq_docker_events_event"
        ),
    )
    op.create_index("ix_docker_events_time", "docker_events", ["time_ns", "id"])


def downgrade() -> None:
    op.drop_index("ix_docker_events_time", "docker_events")
    op.drop_table("docker_events")
