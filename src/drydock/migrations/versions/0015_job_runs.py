"""Job runs: a job's target runs share first_run_id, and a run can be dismissed from the
dashboard's "Needs attention".

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-02
"""

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Native ADD COLUMN: runs is not rebuilt, so its links and sequence stay.
    op.add_column("runs", sa.Column("dismissed_at", sa.DateTime(), nullable=True))
    op.add_column("runs", sa.Column("first_run_id", sa.Integer(), nullable=True))
    # A job's runs were created together, its own target first (target_uuid NULL), so a
    # backup's first run is the newest run of the job's own target at or before it. Runs
    # of deleted jobs lost their job_id and stay on their own.
    op.execute(
        "UPDATE runs SET first_run_id = (SELECT max(p.id) FROM runs p"
        " WHERE p.job_id = runs.job_id AND p.kind = 'backup' AND p.target_uuid IS NULL"
        " AND p.id <= runs.id) WHERE kind = 'backup' AND job_id IS NOT NULL"
    )
    op.create_index("ix_runs_first_run_id", "runs", ["first_run_id"])


def downgrade() -> None:
    op.drop_index("ix_runs_first_run_id", "runs")
    op.execute("ALTER TABLE runs DROP COLUMN first_run_id")
    op.execute("ALTER TABLE runs DROP COLUMN dismissed_at")
