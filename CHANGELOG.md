# Changelog

Notable changes to drydock. Versions follow [semantic versioning](https://semver.org/); release images are tagged `X.Y.Z` and `X.Y` (see [docs/development.md](docs/development.md#releases)).

## 0.1.0 (unreleased)

The first release.

### Backups
- Back up a single container or a whole Compose project on the local host (through a filtering socket proxy) or on remote hosts over SSH with pinned host keys. Drydock installs its own SSH key with the user's password, used once and never stored.
- Scopes: configuration (inspect output, compose files and `.env` files), data (volumes and bind mounts), images, or everything. Images still served by their registry can be stored by reference.
- A job can back up several containers and Compose projects one after another, each into its own archive; each target runs again before the next is touched.
- Skip chosen volumes and bind mounts, such as caches; the containers still mount them, and a restore creates a missing one empty, with its recorded owner and mode.
- Stop, pause or live consistency modes. Stacks stop and start in dependency order and wait for `service_healthy` dependencies.
- Pre- and post-hooks run with `docker exec`, from a library only a superadmin edits.
- Archives are tar in zstd, with per-member SHA-256 checksums and an HMAC signature, and are encrypted with age by default. The passphrase is derived from the secret key, so archives survive losing the database.
- Cron schedules per job, in the job's time zone, with missed-fire handling.
- Retention by count, by age, or daily, weekly, monthly and yearly.
- Notifications by webhook, email, ntfy, Gotify and a list of Apprise services.

### Storage
- Local directories, plus SFTP, SMB, WebDAV and Google Drive (with your own OAuth client) through an embedded rclone.

### Restore
- Restore from storage, a browser upload of up to 50 GB, a file on the server, or an archive from another drydock (superadmin only).
- New name, overwrite, data only or images only, onto any managed host. Every archive is fully verified before any host is contacted, the plan is shown and confirmed, and a failed restore rolls back what it created.
- Host-path denylist, flagged risky container settings that need a superadmin, and startup recovery for interrupted restores.

### Interface
- A dashboard with failed backups, recent runs, the next scheduled runs, hosts and storage.
- A notification bell with unread markers for finished runs and, for admins, missed schedules, host key mismatches and storage that needs reconnecting.
- An About page with the version and the stack's components, each linked to its release.
- Job pages show the summary and recent runs; editing has a page of its own.
- Times show in drydock's time zone (`TZ`), with UTC beside them.

### Security
- Roles (viewer, operator, admin, superadmin), Argon2id passwords, sessions with idle and absolute limits, re-authentication for sensitive actions, CSRF protection, a strict CSP and an audit log.
- Secrets in the database are encrypted with the secret key, which supports rotation.
- The container runs as uid 10001 with a read-only root filesystem, no capabilities and `no-new-privileges`.
- [Threat model](docs/threat-model.md) with each threat linked to the tests that cover it.
- Images for amd64 and arm64 with an SBOM and provenance, scanned in CI with dated exceptions in `.trivyignore.yaml`. Tested on Python 3.14 and 3.15.
