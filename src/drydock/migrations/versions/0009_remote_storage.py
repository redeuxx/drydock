"""Remote storage kinds: storage_targets.kind admits sftp, smb, webdav and drive.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-22
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

KINDS_0008 = "kind IN ('local')"
KINDS_0009 = "kind IN ('local', 'sftp', 'smb', 'webdav', 'drive')"


def storage_targets(metadata: sa.MetaData, kinds: str) -> sa.Table:
    """storage_targets as 0003 created it, with the given kind CHECK."""
    return sa.Table(
        "storage_targets",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("config_enc", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(kinds, name="ck_storage_targets_kind"),
        sqlite_autoincrement=True,
    )


def saved_sequence(conn: sa.Connection, table: str) -> int | None:
    return conn.execute(
        sa.text("SELECT seq FROM sqlite_sequence WHERE name = :table"), {"table": table}
    ).scalar()


def restore_sequence(conn: sa.Connection, table: str, saved: int | None) -> None:
    if saved is None:
        return
    params = {"table": table, "saved": saved}
    updated = conn.execute(
        sa.text("UPDATE sqlite_sequence SET seq = MAX(seq, :saved) WHERE name = :table"),
        params,
    )
    if updated.rowcount == 0:
        conn.execute(
            sa.text("INSERT INTO sqlite_sequence (name, seq) VALUES (:table, :saved)"), params
        )


def recreate(kinds_from: str, kinds_to: str) -> None:
    bind = op.get_bind()
    saved = saved_sequence(bind, "storage_targets")
    with op.batch_alter_table(
        "storage_targets",
        recreate="always",
        copy_from=storage_targets(sa.MetaData(), kinds_from),
    ) as batch:
        batch.drop_constraint("ck_storage_targets_kind", type_="check")
        batch.create_check_constraint("ck_storage_targets_kind", kinds_to)
    restore_sequence(bind, "storage_targets", saved)


def upgrade() -> None:
    recreate(KINDS_0008, KINDS_0009)


def downgrade() -> None:
    bind = op.get_bind()
    used = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM jobs WHERE storage_target_id IN"
            " (SELECT id FROM storage_targets WHERE kind != 'local')"
        )
    ).scalar()
    if used:
        raise RuntimeError(
            f"{used} job(s) use remote storage, which revision 0008 cannot hold. Move them to"
            " local storage or delete them, then downgrade."
        )
    # Foreign keys are off here, so the catalog rows go first or the foreign key check
    # aborts the downgrade. The archives themselves stay where they are.
    op.execute(
        "DELETE FROM backups WHERE storage_target_id IN"
        " (SELECT id FROM storage_targets WHERE kind != 'local')"
    )
    op.execute("DELETE FROM storage_targets WHERE kind != 'local'")
    recreate(KINDS_0009, KINDS_0008)
