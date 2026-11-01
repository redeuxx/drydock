"""ORM models. The migrations create the same schema; a test keeps them in sync."""

from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Stores naive UTC in SQLite and hands back aware UTC datetimes."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not allowed")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN (10, 20, 30, 40)", name="ck_users_role"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64, collation="NOCASE"), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[int]
    disabled: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    # The bell's notifications up to here are read (drydock.feed).
    feed_read_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)


class UserSession(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    reauth_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditEvent(Base):
    """Append-only: SQLite triggers reject UPDATE and DELETE."""

    __tablename__ = "audit_events"
    # The bell reads a few actions, newest first (drydock.feed).
    __table_args__ = (Index("ix_audit_events_action_ts", "action", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    actor: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(255))
    outcome: Mapped[str] = mapped_column(String(16))
    details: Mapped[str] = mapped_column(Text, default="{}")


class Host(Base):
    """A Docker host. Admins add every host explicitly, including the local one.

    kind "local" talks to docker_url (normally the socket proxy). kind "ssh" forwards a
    unix socket over SSH to remote_socket_path. Key material is stored only encrypted
    through drydock.crypto, and the host key is pinned by known_host_line.
    """

    __tablename__ = "hosts"
    __table_args__ = (
        CheckConstraint("kind IN ('local', 'ssh')", name="ck_hosts_kind"),
        CheckConstraint("port IS NULL OR port BETWEEN 1 AND 65535", name="ck_hosts_port"),
        # Ids name socket paths and audit targets, so a deleted host's id is never reused.
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64, collation="NOCASE"), unique=True)
    kind: Mapped[str] = mapped_column(String(8))
    docker_url: Mapped[str | None] = mapped_column(String(255))
    address: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int | None] = mapped_column(Integer)
    username: Mapped[str | None] = mapped_column(String(64))
    ssh_key_enc: Mapped[str | None] = mapped_column(Text)
    ssh_public_key: Mapped[str | None] = mapped_column(Text)  # shown to admins; not secret
    # Always NULL: pasted keys are stored decrypted inside the Fernet token (ssh.save_key).
    key_passphrase_enc: Mapped[str | None] = mapped_column(Text)
    known_host_line: Mapped[str | None] = mapped_column(Text)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    remote_socket_path: Mapped[str | None] = mapped_column(String(255))
    api_version: Mapped[str | None] = mapped_column(String(16))
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    enabled: Mapped[bool] = mapped_column(default=True)


class Installation(Base):
    """A single row made by migration 0002: the ID that labels this installation's helpers."""

    __tablename__ = "installation"
    __table_args__ = (CheckConstraint("id = 1", name="ck_installation_single_row"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[str] = mapped_column(String(32))


# BACKUPS

SCOPES = ("config", "data", "image", "all")
# The order is part of the schema: migration 0005 hardcodes the CHECKs in_list() makes.
TARGET_TYPES = ("container", "stack")
CONSISTENCY_MODES = ("stop", "pause", "live")
RUN_KINDS = ("backup", "restore")
# The order is part of the schema: migration 0009 hardcodes the CHECK that in_list() makes.
STORAGE_KINDS = ("local", "sftp", "smb", "webdav", "drive")
# The order is part of the schema: migration 0008 hardcodes the CHECK that in_list() makes.
NOTIFICATION_KINDS = ("webhook", "email", "ntfy", "gotify", "url")
# The order is part of the schema: migration 0004 hardcodes the CHECK that in_list() makes.
RUN_STATUSES = (
    "queued",
    "verifying",
    "awaiting_confirmation",
    "running",
    "done",
    "failed",
    "cancelled",
    "interrupted",
)


def in_list(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class StorageTarget(Base):
    """Where archives go. config_enc is a Fernet token over the backend's JSON config."""

    __tablename__ = "storage_targets"
    __table_args__ = (
        CheckConstraint(in_list("kind", STORAGE_KINDS), name="ck_storage_targets_kind"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64, collation="NOCASE"), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    config_enc: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Job(Base):
    """A backup of one container or one Compose project (target_type 'stack', target is the
    project name).

    uuid is random and goes into every archive name: the job passphrase is derived from it
    and the secret key, so encrypted archives stay readable after losing the database.
    """

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(in_list("target_type", TARGET_TYPES), name="ck_jobs_target_type"),
        CheckConstraint(in_list("scope", SCOPES), name="ck_jobs_scope"),
        CheckConstraint(in_list("consistency_mode", CONSISTENCY_MODES), name="ck_jobs_consistency"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True)
    name: Mapped[str] = mapped_column(String(64, collation="NOCASE"), unique=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="RESTRICT"), index=True)
    storage_target_id: Mapped[int] = mapped_column(
        ForeignKey("storage_targets.id", ondelete="RESTRICT"), index=True
    )
    target_type: Mapped[str] = mapped_column(String(16), default="container")
    target: Mapped[str] = mapped_column(String(255))  # container ref or Compose project
    scope: Mapped[str] = mapped_column(String(16))
    consistency_mode: Mapped[str] = mapped_column(String(16), default="stop")
    images_reference_only_if_pullable: Mapped[bool] = mapped_column(default=False)
    encrypted: Mapped[bool] = mapped_column(default=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    # JSON lists of hooks.id in run order. Admins attach hooks; only superadmins edit them.
    pre_hooks: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")
    post_hooks: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")
    # JSON list of mounts whose data the job leaves out: "bind:<host path>" or
    # "volume:<name>" (jobs.mounts). The containers still mount them on restore.
    skip_mounts: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")
    # JSON policy, see jobs.retention. Applied after each successful backup.
    retention: Mapped[str] = mapped_column(
        Text,
        default='{"keep_last": 7, "mode": "last"}',
        server_default='{"keep_last": 7, "mode": "last"}',
    )
    # Five-field crontab (jobs.scheduler), NULL: started by hand only. timezone NULL: TZ.
    cron: Mapped[str | None] = mapped_column(String(100), default=None)
    timezone: Mapped[str | None] = mapped_column(String(64), default=None)
    # Set by each scheduled fire, and when startup finds a fire missed too long ago.
    last_fired_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class JobTarget(Base):
    """A job's second and later containers or Compose projects (drydock.jobs.targets), each
    with a UUID of its own for its archive names. The first is the job's own target."""

    __tablename__ = "job_targets"
    __table_args__ = (
        CheckConstraint(in_list("target_type", TARGET_TYPES), name="ck_job_targets_target_type"),
        UniqueConstraint("uuid", name="uq_job_targets_uuid"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)
    target_type: Mapped[str] = mapped_column(String(16))
    target: Mapped[str] = mapped_column(String(255))
    uuid: Mapped[str] = mapped_column(String(36))


class NotificationTarget(Base):
    """One Apprise URL (notify.py), stored only encrypted and never decrypted for display."""

    __tablename__ = "notification_targets"
    __table_args__ = (
        CheckConstraint(in_list("kind", NOTIFICATION_KINDS), name="ck_notification_targets_kind"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64, collation="NOCASE"), unique=True)
    kind: Mapped[str] = mapped_column(String(16))
    url_enc: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class JobNotification(Base):
    """A target a job tells when its runs succeed and, or, fail."""

    __tablename__ = "job_notifications"

    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("notification_targets.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    on_success: Mapped[bool] = mapped_column(default=False)
    on_failure: Mapped[bool] = mapped_column(default=True)


class Hook(Base):
    """Runs argv through exec in one container of a job's targets.

    Only superadmins create, edit or delete hooks (Decision 2). A hook is bound to one host
    entry and, through project, to a container job (NULL: container is the job's container
    ref) or to the stack job of one Compose project (container is a service or container
    name of that project).
    """

    __tablename__ = "hooks"
    __table_args__ = (
        CheckConstraint("timeout_s BETWEEN 1 AND 3600", name="ck_hooks_timeout"),
        # Ids name audit targets 'hook:<id>' and sit in jobs' hook lists, so never reused.
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64, collation="NOCASE"), unique=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="RESTRICT"), index=True)
    project: Mapped[str | None] = mapped_column(String(63), default=None)
    container: Mapped[str] = mapped_column(String(128))
    argv_json: Mapped[str] = mapped_column(Text)  # JSON array of strings, never a shell line
    user: Mapped[str] = mapped_column(String(65), default="")
    workdir: Mapped[str] = mapped_column(String(1024), default="")
    timeout_s: Mapped[int] = mapped_column(Integer, default=300)
    # Superadmin opt-in: log up to 64 KiB of output. Off: byte counts, plus a stderr tail
    # when the hook fails.
    log_output: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Run(Base):
    """One execution of a job, or a restore (job_id NULL, kind "restore").

    Log files are named from the run ID only, so IDs are never reused.
    """

    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint(in_list("kind", RUN_KINDS), name="ck_runs_kind"),
        CheckConstraint(in_list("status", RUN_STATUSES), name="ck_runs_status"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16), default="backup")
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    triggered_by: Mapped[str | None] = mapped_column(String(64))
    # Written before anything is stopped, so recovery can restart them after a crash.
    stopped_containers_json: Mapped[str] = mapped_column(Text, default="[]")
    # Written before anything is paused, so recovery can unpause them after a crash.
    paused_containers_json: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")
    archive_name: Mapped[str | None] = mapped_column(String(255))
    size: Mapped[int | None] = mapped_column(Integer)
    sha256: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    # JSON: the restore source, choices and summary. Never create bodies, env values or
    # compose file contents.
    plan: Mapped[str | None] = mapped_column(Text)
    # The restore journal: what to roll back or finish after a failure or crash.
    restore_originals_json: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    # Which of its job's targets a backup ran for (drydock.jobs.targets): None for the job's
    # own; the label stays readable after the target is removed.
    target_uuid: Mapped[str | None] = mapped_column(String(36), default=None)
    target_label: Mapped[str | None] = mapped_column(String(300), default=None)


UPLOAD_STATUSES = ("receiving", "complete")


class Upload(Base):
    """An archive uploaded in the browser for a restore (restore.uploads). A failed upload
    leaves no row and no file; a complete one is deleted at expires_at."""

    __tablename__ = "uploads"
    __table_args__ = (
        CheckConstraint(in_list("status", UPLOAD_STATUSES), name="ck_uploads_status"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))  # the archive name, as check_name allows
    declared_size: Mapped[int] = mapped_column(Integer)
    received: Mapped[int] = mapped_column(Integer, default=0)
    path: Mapped[str] = mapped_column(String(1024))  # server-named, in <staging>/uploads
    status: Mapped[str] = mapped_column(String(16), default="receiving")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class Backup(Base):
    """Catalog of archives in storage. Restore can also list storage without it."""

    __tablename__ = "backups"
    __table_args__ = (UniqueConstraint("storage_target_id", "name", name="uq_backups_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), index=True
    )
    storage_target_id: Mapped[int] = mapped_column(
        ForeignKey("storage_targets.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    signed: Mapped[bool] = mapped_column(default=True)
    encrypted: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
