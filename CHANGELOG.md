# Changelog

Notable changes to drydock. Versions follow [semantic versioning](https://semver.org/); release images are tagged `X.Y.Z` and `X.Y` (see [docs/development.md](docs/development.md#releases)).

## Unreleased

**Upgrading:** pull the new `compose.yaml` before `docker compose up -d`. Its socket proxy allows container logs (`ALLOW_LOGS=1`), which the logs page needs.

### Dashboard
- Live container status: a card per host, for every role, with its containers by state, unhealthy containers by name, CPU and memory, images, volumes, networks and Compose stacks. Cards refresh every 10 seconds from what drydock last read, and drydock reads a host only while a page shows the cards, so pages never call Docker. It replaces the admins' list of hosts.
- Containers page: one host's containers with state, health, uptime, restarts, CPU, memory, network and disk I/O, addresses, published ports (linked), Compose stack and the backup jobs that cover each one. Search, filter by state or stack, and sort by any column; it refreshes every 10 seconds and the address keeps the view. The dashboard's counters and unhealthy list open it filtered. Every role sees it; label values are searched for admins only.
- The status cards show memory as used of total.
- Container actions on the containers page: operators start, stop, restart, pause and unpause one container or the selected ones (stop and restart ask first), each audited. Drydock refuses its own containers and helpers, and containers a backup or restore is using. Admins can inspect a container, with environment values and secret-looking labels hidden.
- Logs page (admins only): one container's log, live, from its last 100 to 5,000 lines, with stderr marked, pause and clear. Pick the container from a filterable list with favourites. Escape sequences are removed and reads are capped, so a chatty container cannot exhaust drydock's memory.
- Pages that poll in the background (the status cards, a run's live log) no longer count as activity: a tab left open cannot keep a session past its 1 hour idle timeout, and polls skip their turn while the tab is hidden.
- Dismiss a failed or interrupted run from "Needs attention" (operators and up). The run, its log and the failure count stay.
- Filter the run list by status. The "Failed" and "Running or queued" tiles open the list filtered to their runs.
- A job's runs, one per target, are one entry in the notifications and in "Recent backups": how many targets ended how, total size, how long it took, who started it and the first error. "Recent backups" lists the targets, and a run's page lists the other targets of its job run.

### Interface
- A logo: in the header, on the login, setup and About pages, and as the favicon.
- The run list and the audit log fit the window: rows keep one line and long values are cut short, with the full text on hover. Clicking an audit event opens every field, details included.
- Custom schedules read like the presets in the job list ("Every Monday to Friday at 02:15").
- The job list shows "encrypted" beside the job's status and a stack target's badge on its own line.
- Adding a user explains what each role can do.
- The About page shows when the image was built and links the commit it was built from (`DRYDOCK_COMMIT`).

## 0.2.0 (2026-11-01)

### Backups
- Copy the data on the host first: in stop and pause mode the containers are down only while their data is copied on their own host, not while it travels to drydock, and a job's next target starts during the upload. The run fails before stopping anything when the copy would not fit.

## 0.1.0 (2026-11-01)

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

### Fixed during release validation
- Backups over SSH no longer buffer without bound when the link is faster than drydock writes (asyncssh's channel window ignored buffered data); a 100 GB run now stays at about 155 MiB.
- A new-name restore onto another host than the original's keeps published ports and writes bind mount data.
- Run logs no longer mask values that are part of names drydock shows anyway, such as `POSTGRES_DB=<project>`.

### Security
- Roles (viewer, operator, admin, superadmin), Argon2id passwords, sessions with idle and absolute limits, re-authentication for sensitive actions, CSRF protection, a strict CSP and an audit log.
- Secrets in the database are encrypted with the secret key, which supports rotation.
- The container runs as uid 10001 with a read-only root filesystem, no capabilities and `no-new-privileges`.
- [Threat model](docs/threat-model.md) with each threat linked to the tests that cover it.
- Images for amd64 and arm64 with an SBOM and provenance, scanned in CI with dated exceptions in `.trivyignore.yaml`. Tested on Python 3.14 and 3.15.
