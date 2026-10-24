"""Docker hosts, and the installation ID that labels helper containers.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-13
"""

import uuid

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64, collation="NOCASE"), nullable=False, unique=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("docker_url", sa.String(255), nullable=True),
        sa.Column("address", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("ssh_key_enc", sa.Text(), nullable=True),
        sa.Column("ssh_public_key", sa.Text(), nullable=True),
        sa.Column("key_passphrase_enc", sa.Text(), nullable=True),
        sa.Column("known_host_line", sa.Text(), nullable=True),
        sa.Column("host_key_fingerprint", sa.String(128), nullable=True),
        sa.Column("remote_socket_path", sa.String(255), nullable=True),
        sa.Column("api_version", sa.String(16), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.CheckConstraint("kind IN ('local', 'ssh')", name="ck_hosts_kind"),
        sa.CheckConstraint("port IS NULL OR port BETWEEN 1 AND 65535", name="ck_hosts_port"),
        sqlite_autoincrement=True,
    )
    installation = op.create_table(
        "installation",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("instance_id", sa.String(32), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_installation_single_row"),
    )
    op.bulk_insert(installation, [{"id": 1, "instance_id": uuid.uuid4().hex}])


def downgrade() -> None:
    op.drop_table("installation")
    op.drop_table("hosts")
