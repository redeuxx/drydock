# Changelog

Notable changes to drydock. Versions follow [semantic versioning](https://semver.org/); release images are tagged `X.Y.Z` and `X.Y` (see [docs/development.md](docs/development.md#releases)).

## Unreleased

**Upgrading:** this version adds a column to the users table and a table of health acknowledgements, so copy the `drydock-data` volume first ([Upgrading](docs/operations.md#upgrading)).

- Stacks page under Docker: each Compose stack on a host with its running containers, newer images and backup jobs. Operators update, start, stop and restart a whole stack; admins remove one (containers only, volumes and networks kept). It lists each stack's update policies, and admins schedule automatic updates of a stack from there.
- Images page under Docker: a host's images with the containers that use each one. Admins remove unused images.
- Admins can remove containers from the containers page (stopped first, volumes kept). Removing containers, stacks and images asks for the password again.
- The dashboard's Environments section is now Hosts, and it folds away; whether it starts folded is a preference on the Account page.
- The logs page's container list folds away, and stays as it was left in this browser.
- Adding a host asks for the password again before the form, not after it is filled in.
- A container that exited while unhealthy stays unhealthy until an operator acknowledges it on the containers page; it counts again once it has started since. On daemons before API 1.52, an exited container's health now comes from its last inspect.
- The activity page lists backup runs among the container events, with a Backup run filter.
- Update policies can update every Compose stack on a host (target `*`), each stack in its own run, and the Stacks page lists and schedules them.
- Containers, Stacks and Images share a Docker menu in the navigation bar, and the Manage menu is now Backups.
- Starting an update of a container or a stack no longer fails with HTTP 500 ("database is locked") after 5 seconds.
- The containers table gives every column a width and scrolls sideways when they do not fit, so headers no longer overlap and the actions column is never cut off.

## 0.3.0 (2026-11-05)

**Upgrading:** this version changes the database (new tables and columns, a new run kind), so copy the `drydock-data` volume first ([Upgrading](docs/operations.md#upgrading)). Pull the new `compose.yaml` before `docker compose up -d`: its socket proxy allows container logs (`ALLOW_LOGS=1`) for the logs page and events (`EVENTS=1`) for the activity record.

### Dashboard
- Live container status: a card per host, for every role, with its containers by state, unhealthy containers by name, CPU and memory, images, volumes, networks and Compose stacks. Cards refresh every 10 seconds from what drydock last read, and drydock reads a host only while a page shows the cards, so pages never call Docker. It replaces the admins' list of hosts.
- Containers page: one host's containers with state, health, uptime, restarts, CPU, memory, network and disk I/O, addresses, published ports (linked), Compose stack and the backup jobs that cover each one. Search, filter by state or stack, and sort by any column; it refreshes every 10 seconds and the address keeps the view. The dashboard's counters and unhealthy list open it filtered. Every role sees it; label values are searched for admins only.
- The status cards show memory as used of total.
- Container actions on the containers page: operators start, stop, restart, pause and unpause one container or the selected ones (stop and restart ask first), each audited. Drydock refuses its own containers and helpers, and containers a backup or restore is using. Admins can inspect a container, with environment values and secret-looking labels hidden.
- Logs page (admins only): container logs, live, from their last 100 to 5,000 lines, with stderr marked, pause and clear. One container, or up to 10 merged by time or side by side, or a whole Compose stack. Hide timestamps, unwrap lines, change the text size, search, copy or download. Pick containers from a filterable list with favourites. Escape sequences are removed and reads are capped, so a chatty container cannot exhaust drydock's memory.
- Container events from every host are recorded (created, started, died with its exit code, health results and more), always on, with nothing lost across short drops. Only a few fields are kept, never labels or exec commands; 30 days and at most 200,000 events. Each host's card counts them, and the Activity page lists them for every role, filtered by container, action, host and time range, refreshing every 5 seconds. Admins can clear it (audited, password asked again).
- Newer images: drydock checks every 6 hours whether the registry has a newer image for each container's tag (without pulling) and marks those containers on the containers page and the dashboard. Operators can check a host at once. Pinned and locally built images are skipped.
- Update a container to the newest image of its tag from the containers page (operators): drydock pulls it, makes the container again with the same configuration, and puts the old one back if the new one does not stay up or become healthy. Its own containers and helpers are never updated. Or update a whole Compose stack in dependency order, all or nothing. See [docs/updates.md](docs/updates.md).
- Scheduled updates: update policies (Manage > Updates) update a container or a stack on a cron schedule, optionally after a backup by one of the jobs (stopping when it fails), and tell a notification target. Missed fires are audited like a job's. The containers page shows each container's policy and next run, and the dashboard's next runs include them.
- Sparklines of the latest CPU and memory readings on the dashboard cards and the containers page (in memory, about 10 minutes).
- Alerts per host (admins turn them on, with a notification target): a container that becomes unhealthy, exits with an error nobody asked for, or keeps restarting, and a host unreachable for 5 minutes, each told once and again when it recovers, in the bell and to the target. Containers a backup, restore or update is working on are left out.
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
