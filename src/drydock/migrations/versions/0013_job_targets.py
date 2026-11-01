"""More targets per job: a job's second and later containers or Compose projects, each with
an ID of its own for its archive names; runs record which target they backed up.

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "job_targets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "job_id",
            sa.Integer(),
            sa.ForeignKey("jobs.id", name="fk_job_targets_job_id_jobs", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("uuid", sa.String(36), nullable=False),
        sa.CheckConstraint(
            "target_type IN ('container', 'stack')", name="ck_job_targets_target_type"
        ),
        sa.UniqueConstraint("uuid", name="uq_job_targets_uuid"),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_job_targets_job_id", "job_targets", ["job_id"])
    # Native ADD COLUMN: runs is not rebuilt, so its links and sequence stay.
    op.add_column("runs", sa.Column("target_uuid", sa.String(36), nullable=True))
    op.add_column("runs", sa.Column("target_label", sa.String(300), nullable=True))


def downgrade() -> None:
    op.execute("ALTER TABLE runs DROP COLUMN target_label")
    op.execute("ALTER TABLE runs DROP COLUMN target_uuid")
    op.drop_index("ix_job_targets_job_id", "job_targets")
    op.drop_table("job_targets")
