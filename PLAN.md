# Drydock implementation plan

Phases 0 and 1 build the security core and retire the main technical risks: SSH streaming, the socket proxy, file ownership on round trips, and age streaming. Phases 2 and 3 back up and restore a real container from end to end. The remaining features follow that working path.

## Stack (pinned versions)

| Component | Pin | Status / note |
|---|---|---|
| Python | `python:3.15-slim` if the Phase 0 wheel check passes, otherwise `python:3.14-slim` (3.14.8). Either way it is pinned by digest. | The spec says "latest". pydantic-core, SQLAlchemy, cryptography and argon2-cffi-bindings already ship cp315 wheels, and pyrage ships abi3 wheels. Only uvloop, httptools and watchfiles (from `uvicorn[standard]`) still need checking. Using 3.14 would be a deliberate deviation that you approve (open decision 7). |
| zstd | stdlib `compression.zstd`, tarfile `w\|zst` / `r\|zst` | `zstandard` is not used. |
| FastAPI | `~=0.143.0` | Still 0.x. |
| Starlette | 1.7.0 (comes with FastAPI) | Sessions use an opaque token stored in the DB. No SessionMiddleware or itsdangerous. |
| Uvicorn | `uvicorn[standard]==0.54.0` | Still 0.x. Always runs with `--workers 1` and an exec-form CMD. |
| SQLAlchemy / Alembic | 2.1.4 / 1.20.0 | Alembic uses `render_as_batch=True` because SQLite cannot ALTER most columns. |
| Pydantic | 2.14.1 | |
| Jinja2 | 3.1.6 | Autoescape on. |
| python-multipart | `>=0.0.32` | Used only for small forms. Older versions had DoS CVEs. |
| argon2-cffi | 25.1.0 | Used directly. No pwdlib. |
| cryptography | 50.0.2 | MultiFernet, HKDF, HMAC. |
| docker (docker-py) | 7.2.0 | Always pass an explicit `base_url` and an explicitly negotiated `version`. Never call `from_env()`. |
| Docker Engine API | 1.44 to 1.56 | Drydock negotiates `min(server_max, 1.56)`, so it never sends request bodies to an untested newer API version. The floor is 1.44 because container create first accepts multiple networks at that version. |
| asyncssh | 2.24.1 | Only appears in the research baseline, so re-check it at Phase 1. No paramiko or `docker[ssh]`. |
| APScheduler | `>=3.11.3,<4` | **4.0.0a6 is an alpha pre-release with a different API. Do not use it.** |
| Apprise | 2.0.1 | New major version. `notify()` now returns `AppriseResult`. |
| pyrage | 1.4.0 | Streaming support is unverified. Phase 1 has a spike for it. |
| rclone | v1.75.2, checked against SHA256SUMS | Needs 1.74+ for rc auth and 1.75+ for the security fixes. It is 3 days old, the same age as Python 3.15. |
| htmx | `htmx.org@4.0.0`, exact pin, vendored | **Stable on GitHub, but npm `latest` still points to 2.0.11. Version 4.0.0 is only on the `next` tag.** |
| Tailwind CSS / daisyUI | `tailwindcss@4.3.3` and `@tailwindcss/cli@4.3.3` / `daisyui@5.7.48`, exact pins | Replaces Pico.css, which is no longer maintained. Compiled in the Node build stage into one static stylesheet, `/static/css/app.css`. daisyUI components that embed `data:` URLs (loading, mask, chat, mockup, tooltip, and the noise texture) are excluded, so the CSP needs no `img-src data:`. |
| Alpine.js | Not used | If it turns out to be needed, use `@alpinejs/csp` 3.17.4. |
| uv / ruff / pytest | 0.13.0 / 0.17.0 / 9.1.1 | uv and ruff are 0.x. pytest uses the anyio plugin and httpx. |
| Pinned in Phase 0 | Node `24.21.0-slim` (LTS) by digest, TypeScript `7.0.2`, Playwright `1.64.0` with `mcr.microsoft.com/playwright:v1.64.0-noble` by digest, httpx `0.28.1`, ruamel.yaml `0.19.1` (test-only YAML parser), pip-audit `2.10.1` (CI) | pydantic-settings is not used. |
| Not covered by the research | linuxserver/socket-proxy, helper image (busybox or alpine) | Pin each by exact version or digest when locking. |

## Phase 0: Foundation and security core

**Goal:** A deployable image and a dev loop that works on Windows. Auth, CSRF, roles, secret encryption and audit logging all exist before any code touches a Docker socket.

**Deliverables**

Python version check, done first:
- Check that uvloop, httptools and watchfiles have cp315 wheels.
- If they all do, target 3.15.
- If any is missing, use 3.14 and record it as a deviation for you to approve.

Python version check result (2026-10-12): **target 3.15.** PyPI has manylinux x86_64 and aarch64 wheels for all three latest releases: uvloop 0.23.0 and httptools 0.9.0 ship `cp315` wheels, and watchfiles 1.3.0 ships `cp310-abi3` wheels, which install on 3.15. The base image is `python:3.15.0-slim@sha256:ea4f1f290e071bf7d28199cfb3e09f5dbad31b50e9c32fd58f2f2d7be915f3ae` (multi-arch index digest). No deviation is needed.

Repo files:
- `pyproject.toml` (`requires-python >=3.14`; the base image pins the interpreter) and `uv.lock`.
- `package.json` and `package-lock.json` (htmx 4.0.0, Tailwind CSS 4 and daisyUI 5, TypeScript, Playwright for the smoke test).
- `.gitattributes` (`* text=auto eol=lf`), `.dockerignore`, `.editorconfig`.
- Alembic `0001`.

`Dockerfile`, multi-stage:
- Node stage: `npm ci`, `tsc`, the Tailwind CLI build of `frontend/app.css`, and a copy of the htmx and hx-csp dist files.
- uv stage: `uv sync --locked --no-dev`.
- Runtime stage: the Python slim image chosen above, pinned by digest.
  - Runs as uid 10001 and works with a read-only rootfs.
  - `TMPDIR=/data/tmp`. Has a `HEALTHCHECK`.
  - Exec-form CMD, so uvicorn is PID 1 and receives SIGTERM: `CMD ["uvicorn", "drydock.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--timeout-graceful-shutdown", "30"]`.
  - Trusted proxies come from uvicorn's own `FORWARDED_ALLOW_IPS` environment variable, not from a CLI argument.

Compose files:
- `compose.yaml`:
  - Publishes `127.0.0.1:8000:8000` only.
  - Named volume at `/data`.
  - `tmpfs: /run/drydock` (uid 10001, mode 0700).
  - The secret key comes from a Docker secret `drydock_secret_key`. Outside swarm this is a plain bind mount and `uid`/`mode` are ignored, so the README tells users to run `chown 10001` and `chmod 0400` on the file. Otherwise startup fails.
  - `stop_grace_period: 90s`, so Docker's 10 s default does not SIGKILL drydock while containers it stopped are still down.
  - `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true`.
- `compose.dev.yaml`: source bind-mounted, uvicorn `--reload`, and `WATCHFILES_FORCE_POLLING=true`. The repo sits on NTFS, and inotify events do not reach the Linux container.
- `compose.test.yaml`: a pytest runner plus a headless Chromium. The app and integration tests always run in Linux containers, because they need `fcntl` and unix sockets.

Modules:
- `config.py`:
  - Reads `DRYDOCK_SECRET_KEY(_FILE)`, `_BASE_URL`, `_ALLOWED_HOSTS`, `_LOCAL_DOCKER_URL`, `_RESTORE_PATHS`, `_LOCAL_STORAGE_ROOTS`, `_STAGING_DIR` (default `/data/staging`), `FORWARDED_ALLOW_IPS` and `TZ`.
  - Refuses to start if the key is missing, malformed or unreadable.
- `db.py`:
  - A connect event sets WAL, `busy_timeout` and `foreign_keys=ON`.
  - The database file `/data/drydock.db` has mode 0600.
- `main.py`:
  - App factory.
  - The lifespan takes an exclusive `flock` on `/data/drydock.lock`. If the lock is held, the startup hooks (recovery, and the scheduler from Phase 5) never run and the app logs loudly.
  - While no superadmin exists, a prominent warning is logged at every start.
  - Lifespan shutdown cancels active runs and restores the state of containers drydock stopped. Phase 2 adds the run logic for this.
- `crypto.py`:
  - MultiFernet with a key list, newest first, so keys can be rotated.
  - HKDF derives separate subkeys for `secrets`, `manifest-hmac` and `job-passphrase`.
  - Per-job passphrase = HKDF(secret key, info=`job-passphrase` + job UUID). Job UUIDs are random and written into the archive name, so after losing the DB drydock re-derives the passphrase from the secret key alone. Decryption tries every key in the list, so rotation keeps old archives readable.
  - HMAC signing uses the newest key. Verification tries the subkey of every key in the list, so a rotation does not turn old archives "unsigned".
  - A secret is re-encrypted with the newest key whenever it is written.
- `security/passwords.py`: Argon2 `PasswordHasher` with `check_needs_rehash`. Unknown usernames are checked against a dummy hash so timing doesn't reveal which accounts exist. Minimum password length is 12.
- `security/sessions.py`:
  - Opaque 32-byte token. Only its sha256 is stored.
  - Rotated on login.
  - Idle timeout 1h, absolute timeout 12h.
  - Revoked when the password or role changes, or the user is disabled.
  - Cookie `__Host-drydock_session`: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. Browsers treat `http://localhost` as a secure context, so this works over the SSH tunnel.
  - The `Secure` flag and the `__Host-` prefix are dropped only when `BASE_URL` is plain HTTP on a non-loopback address. A warning is logged at every start when that happens.
- `security/csrf.py`:
  - After login: a synchronizer token sent in the `X-CSRF-Token` header or a form field.
  - Before login (`/setup` and `/login`): a double-submit cookie (`__Host-drydock_precsrf`) that must match a form field.
  - Both also check `Origin` and `Sec-Fetch-Site`.
- `security/rbac.py`: `Role` IntEnum, `require_role()`, and `require_recent_auth()` (password re-entered within the last 10 minutes).
- `security/headers.py`:
  - Strict CSP: `default-src 'self'; script-src 'nonce-<per response>'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types htmx`. The nonce and Trusted Types serve the hx-csp extension (see the frontend result below).
  - `TrustedHostMiddleware`, which blocks DNS rebinding against the setup wizard.
  - `nosniff` and `Referrer-Policy`.
- `security/ratelimit.py`: in memory, keyed on username plus IP.
- `audit.py`: `record(actor, action, target, outcome, details)` with secret redaction. Completing setup records the source IP.

Tables:
- `users`: username unique NOCASE, password_hash, role, disabled.
- `sessions`: token_sha256, user_id, csrf_token, last_seen_at, expires_at, reauth_at.
- `audit_events`: append-only, enforced by SQLite triggers that block UPDATE and DELETE.

Endpoints:
- `GET/POST /setup`, `GET/POST /login`, `POST /logout`, `POST /reauth`
- `/account`, `/account/password`
- `/users` CRUD, including `POST /users/{id}/sessions/revoke`
- `/audit`
- `/healthz`

Templates and client code:
- `base.html`:
  - `<body hx-headers:inherited='{"X-CSRF-Token": "..."}'>`
  - `<meta name="htmx-config">` with an extension allowlist
  - navigation that changes by role
- `static/app.ts`:
  - `htmx:error` handler and a redirect to login on 401
  - no inline scripts and no `hx-on`
- Error responses are 422 fragments that are safe to swap in, or are routed with `hx-status`. This matters because htmx 4 swaps 4xx and 5xx responses by default.

Frontend result (2026-10-12), checked against the htmx 4.0.0 package source and the smoke test:
- Styling is Tailwind CSS 4 with daisyUI 5 (light and dark themes, chosen by `prefers-color-scheme`). Pico.css is dropped because it is unmaintained.
- The `hx-csp` extension is loaded. It gates htmx on a CSP nonce: every element with an `hx-` attribute (including `<body>`) carries `hx-nonce`, and hx-csp strips htmx attributes from any element without the page nonce. Injected markup therefore cannot send htmx requests that inherit the CSRF header. The CSP gains a per-response nonce (`script-src 'nonce-...'`, replacing `'self'`) and Trusted Types (`require-trusted-types-for 'script'; trusted-types htmx`).
- The extension allowlist is `{"extensions": "hx-csp", "includeIndicatorCSS": false}`. An empty `extensions` value would allow every extension.
- htmx 4 adds its indicator CSS as a constructed stylesheet (`adoptedStyleSheets`). Chromium 156 does not treat that as a `style-src` violation, but drydock turns it off and ships the indicator rules in `app.css`, so the result does not depend on browser behaviour.
- Logged-in pages inherit `hx-target="#main"`, `hx-select="#main"` and `hx-swap="outerHTML"` from `<body>`. Every HTML response, including error pages, has a `#main`, so 4xx responses swap safely without separate fragment templates and without `hx-status`. `app.ts` stops the swap for 401 (and navigates to `/login`) and for non-HTML errors such as 413 and 500.
- Successful htmx POSTs get `204` with `HX-Redirect`, which htmx 4 turns into a full navigation. Plain form posts still get `303`. Error event names in 4.0.0: `htmx:error` (network and client errors) and `htmx:response:error` (HTTP 4xx and 5xx).

Route inventory tests run over `app.routes`:
- Every non-GET route has auth, a role check, CSRF and an audit call, unless it is on an explicit exemption list.
- Every route except `/setup`, `/login`, `/healthz` and `/static` requires a session.
- No GET route writes to the DB except `last_seen`. Any exception goes on an explicit list with the guard named. The first entry is the OAuth callback in Phase 6.

Also in this phase:
- CI: ruff, unit tests, image build, dependency scan, and the CSP smoke test.
- README stub:
  - The setup wizard warning.
  - How to reach the UI through an SSH tunnel (`ssh -L 8000:127.0.0.1:8000`).
  - Secret key file ownership and mode.

Default role matrix (enforced on the server for every route):

| Capability | viewer | operator | admin | superadmin |
|---|---|---|---|---|
| View jobs, runs, logs, backups, inventory | yes | yes | yes | yes |
| Run now, cancel | | yes | yes | yes |
| Edit hosts, storage, jobs, notifications, retention | | | yes | yes |
| Restore a signed archive (new name or overwrite) | | | yes | yes |
| Upload an archive, restore from a server path | | | yes | yes |
| View the audit log | | | yes | yes |
| Edit hooks, manage users, restore an unsigned archive | | | | yes |

**Exit criteria**
- With no secret key, or a malformed or unreadable one, the container exits non-zero with a clear message.
- While no users exist:
  - Every route except setup, healthz and static redirects to `/setup`.
  - The startup log contains the no-superadmin warning.
  - 20 concurrent `POST /setup` requests, each with a valid pre-session CSRF token and using `BEGIN IMMEDIATE`, create exactly one superadmin. `/setup` returns 404 afterwards.
  - The audit row for setup holds the source IP.
- `POST /setup` and `POST /login` get 403 when the pre-session token is missing or doesn't match, or when `Origin` or `Sec-Fetch-Site` is cross-site.
- A request with `Host: attacker.example` gets 400 on every route, including `/setup`.
- Login:
  - A wrong username and a wrong password give identical status and body.
  - Both paths run an Argon2 verify (checked with a spy).
  - The 11th failure in 15 minutes returns 429.
  - `X-Forwarded-For` is ignored unless the request comes from an address in `FORWARDED_ALLOW_IPS`.
- Cookie attribute tests:
  - With a loopback or HTTPS `BASE_URL`, the cookie is `__Host-` and Secure.
  - With HTTP on a LAN IP, the cookie is not Secure and a warning is logged.
- Route inventory tests pass:
  - A missing CSRF token, or a cross-site `Origin` or `Sec-Fetch-Site`, gets 403.
  - GET routes write nothing to the DB except `last_seen` and the listed exemptions.
- The last superadmin cannot be demoted or disabled. Role changes require recent auth.
- Crypto:
  - A DB dump contains no raw session token.
  - A sentinel secret encrypted through `crypto` never appears in plaintext.
  - A wrong key raises an error rather than returning garbage.
  - A value encrypted under an old key still decrypts.
  - An HMAC made under an old key still verifies after rotation.
- Templates and CSP:
  - A username like `<script>` renders escaped.
  - The CSP has no `unsafe-inline` or `unsafe-eval`.
  - A headless Chromium smoke test loads every page with htmx 4 running and records zero `securitypolicyviolation` events. If htmx injects inline styles, add the `hx-csp` extension or ship the indicator CSS, and record which. (Done: both. See the frontend result above.)
- UPDATE and DELETE on `audit_events` fail. Setup, logins, user changes and role changes are all audited.
- A second process pointed at the same `/data` fails to take the flock, logs loudly, and skips the startup hooks. This tests the guard itself. Phase 5 re-checks that the scheduler doesn't start.
- A test parses `compose.yaml` and confirms:
  - the port binds only to `127.0.0.1`
  - `/run/drydock` is a tmpfs
  - `stop_grace_period` is at least 90 s
- Templates contain no external script or style URLs.
- The Dockerfile CMD is exec form, and PID 1 in the container is uvicorn.
- On Windows, `docker compose -f compose.dev.yaml up` serves the app and reloads when code changes, using polling.

**Risks**
- htmx 4.0.0 is six weeks old, and most examples online are for 2.x. Check `hx-headers:inherited`, `HX-Redirect` and indicator style injection against 4.0.
- SameSite has to be Lax because the OAuth callback in Phase 6 is a cross-site navigation. CSRF tokens and Origin checks cover the gap.

## Phase 1: Docker connectivity and risk spikes

**Goal:** Prove the riskiest assumptions before building on them:
- Drydock can reach the local Docker host through the socket proxy.
- It can reach remote hosts through an asyncssh unix-socket forward, with the private key only in memory and the host key pinned.
- Volume data survives a round trip with ownership intact, at acceptable speed.
- Archive encryption can be streamed.

**Deliverables**

Compose:
- `compose.yaml` adds `linuxserver/socket-proxy`, pinned by digest.
  - Flags set to 1: `CONTAINERS IMAGES VOLUMES NETWORKS EXEC POST ALLOW_START ALLOW_STOP ALLOW_RESTARTS ALLOW_PAUSE ALLOW_UNPAUSE ALLOW_ARCHIVE INFO VERSION PING`. Everything else is 0, including `DISTRIBUTION`.
  - The proxy runs with `read_only`, tmpfs `/run` and the socket mounted `:ro`.
  - The proxy and drydock share an `internal: true` network. Drydock alone has a separate egress network.
  - The drydock container never mounts `docker.sock`.
- `compose.test.yaml` adds a `docker:29-dind` container running sshd, which stands in for a remote host.

Table `hosts` (Alembic `0002`): id, name, kind (local or ssh), docker_url, address, port, username, ssh_key_enc, key_passphrase_enc, known_host_line, host_key_fingerprint, remote_socket_path, api_version, last_seen, enabled.

Drydock never registers the local Docker host automatically. An admin adds it explicitly after setup.

Modules:
- `hosts/client.py`:
  - Reads the daemon's `/version`, then builds `DockerClient(base_url=..., version=min(server_max, '1.56'))`.
  - Refuses daemons below API 1.44.
  - `run_blocking()` runs every docker-py call on a worker thread.
- `hosts/ssh.py`:
  - One long-lived asyncssh connection per host, opened with `import_private_key` and `import_known_hosts`, both read from the DB.
  - `forward_local_path('/run/drydock/hosts/<id>.sock', remote_socket_path)`. The directory is 0700 and each socket is 0600.
  - Keepalive, plus reconnect with exponential backoff capped at 60 s.
  - The remote socket path is set per host, so rootless Docker works.
  - Drydock can generate an ed25519 key pair and show the public key, or the user can paste an existing key.
- `hosts/helper.py`:
  - The helper image is pinned by the digest of a multi-arch index and pulled on demand. The image ref can be configured for air-gapped hosts.
  - Each helper has NetworkMode `none`, a read-only rootfs, `CapDrop=ALL`, `no-new-privileges` and the label `drydock.helper=1`.
  - Helpers are removed in a `finally` block.
  - A reaper runs at startup. Phase 5 adds a schedule for it.
- `hosts/inventory.py`: lists containers grouped by `com.docker.compose.project`, with their mounts, networks and images.

Endpoints:
- `/hosts` CRUD (admin).
- `POST /hosts/{id}/scan-hostkey` shows the host key's SHA256 fingerprint.
- `POST /hosts/{id}/trust-hostkey` requires recent auth and writes an audit row.
- `POST /hosts/{id}/test` shows the engine version, the negotiated API version and the architecture.
- `GET /hosts/{id}/containers` returns the inventory fragment.

Spikes, used only by tests:
- `engine/stream_probe.py`: runs `get_archive` to a staging file, then `put_archive` into a new volume, and times both directions.
- Encryption spike: encrypt and decrypt a 10 GB stream with pyrage and check that memory stays flat.
  - Decision order: age passphrase through pyrage, then the `age` binary driven through pipes, then chunked AES-GCM (only drydock could decrypt).
  - Record the decision in the README.

**Exit criteria**
- A 1 GB volume round trip passes both through the local proxy and over SSH. The volume holds files owned by uid 999 with mode 0600, an absolute symlink and an empty directory. Afterwards sha256, uid/gid and mode all match.
- `put_archive` and `exec` with `stream=True` both work through the proxy and through the SSH forward.
- When a host key changes:
  - The connection is refused.
  - No Docker call is made.
  - The UI shows a mismatch error.
  - An audit row is written.
- A test confirms no code path uses `known_hosts=None` or automatic host key acceptance.
- After connecting, a scan of `/data`, `/tmp` and `/run` finds no PEM or OpenSSH key material. The host edit page never contains key material.
- `/healthz` answers in under 200 ms while a 1 GB transfer runs.
- SSH throughput gate:
  - Throughput is recorded for the local and SSH paths.
  - Pass: SSH reaches at least 30% of local after tuning the asyncssh window and packet size.
  - If it doesn't, try parallel channels. If it is still below 30%, record it in the README as a known limit and continue.
- Killing sshd shows the host as disconnected. It reconnects within 60 s of sshd coming back.
- Inspecting a helper confirms its hardening settings. The startup reaper removes an orphaned helper.
- A daemon below API 1.44 is refused with a clear message. A daemon above 1.56 is driven at 1.56 (checked with a mocked `/version`).
- After setup on a fresh install, the `hosts` table is empty.
- The encryption decision is recorded.

**Risks**
- asyncssh single-channel throughput is unknown.
- Hosts on another architecture, such as ARM, need the multi-arch helper digest.
- Busybox `find -delete` support is unverified. The fallback is an alpine digest.
- The remote SSH user needs Docker access, which is root-equivalent. Document this.

## Phase 2: Single-container backup to local storage

**Goal:** "Run now" on a container on any host produces a signed, verifiable `.tar.zst` in local storage, with a live log and recovery after a crash.

**Deliverables**

Archive:
- `archive/manifest.py`: a pydantic model with `schema_version: 1`. It records:
  - instance id and drydock version
  - source host name, architecture and API version
  - job, scope and consistency mode
  - containers, volumes, binds and images (ref, ID, RepoDigests, and whether each image was saved or only referenced)
  - compose files
  - skipped tmpfs mounts
  - encryption info
- `archive/writer.py` writes with `tarfile` `w|zst` in this order:
  1. `manifest.json` (always first)
  2. `config/containers|networks|volumes|images/*.json` and `compose/<n>/`
  3. `volumes/<name>.tar`, `binds/<n>.tar`, `images/<id>.tar`
  4. `checksums.json` (always last): size and sha256 of every member, plus an HMAC-SHA256 over that list, signed with the newest key
- Each inner member is staged, hashed, appended and then deleted, so peak staging space during a backup is about the size of the largest member. The writer checks `disk_usage` and fails early if space is short.
- Optional per-job encryption, using the method chosen in Phase 1, produces `.tar.zst.age`.

Capture (`engine/capture.py`, `engine/compose_files.py`):
- Config scope:
  - Inspect output for the container, its image, each non-default network and each named volume.
  - For any container with `com.docker.compose.project`, also the files named by `config_files`, `environment_file`, `working_dir/.env` and `env_file`. These are read through a read-only helper bind of each parent directory.
  - Only the files named in the labels are read. They must be regular files, at most 1 MiB each.
  - They are stored under `compose/<n>/`.
- tmpfs mounts are skipped and recorded in the manifest.
- Image scope:
  - Uses the raw `/images/{ref}/get?platform=` endpoint on API 1.48 and later, and dedupes by image ID.
- `all` scope:
  - Saves every image by default.
  - A per-job toggle, `images_reference_only_if_pullable`, records only the ref and digest for images that have RepoDigests.

Storage:
- `storage/base.py`: the `StorageBackend` Protocol with `put(local, name, progress, cancel)`, `get`, `read_head(name, max_bytes)`, `list(prefix)`, `delete` and `test`.
- `storage/local.py`:
  - The root must resolve inside `DRYDOCK_LOCAL_STORAGE_ROOTS` and must not overlap `/data`, `/run` or the app directory.
  - Files are written under a temp name and then renamed atomically.
  - File names come from IDs plus a slug, never from user input.

Runs (`jobs/dispatcher.py`):
- One entry point, also used later by the scheduler and by restores.
- Locking:
  - One `asyncio.Lock` per container ID.
  - A run takes the locks for every container it touches, in sorted ID order.
  - Restores use the same locks, so backups and restores never overlap on a container.
- Work runs on a `ThreadPoolExecutor` (default 2 workers).
- Cancellation uses a `threading.Event` checked between chunks of at most 8 MiB.
- Stop mode only in this phase:
  - The "stopped by drydock" list is written to the run row before anything is stopped.
  - Containers are restarted in a `finally` block.
- Each run logs to `/data/logs/<run_id>.log`. The path comes only from the run ID, and known secret values are redacted.
- Lifespan shutdown:
  - Sets every run's cancel event.
  - Restarts the containers drydock stopped.
  - Marks those runs `cancelled`.
  - All of this finishes inside the 90 s stop grace period.
- Startup recovery:
  - Runs still marked `running` become `interrupted`.
  - Containers drydock stopped are restarted.
  - Orphaned helpers are reaped and staging is cleaned.

Tables:
- `storage_targets` (config_enc)
- `jobs` (including `images_reference_only_if_pullable`)
- `runs` (kind, status, triggered_by, stopped_containers_json, archive_name, size, sha256, error)
- `backups` (job_id, storage_target_id, name, size, sha256, signed, encrypted, created_at)

Endpoints:
- `/storage` (local only for now), `POST /storage/{id}/test`
- `/jobs` CRUD, `POST /jobs/{id}/run`
- `POST /jobs/{id}/passphrase`: reveals the derived passphrase, for decrypting outside drydock. Superadmin only, requires recent auth, audited.
- `/runs`, `/runs/{id}`
- `GET /runs/{id}/log?offset=N`: an htmx polling fragment that stops polling once the run ends
- `POST /runs/{id}/cancel`
- `/backups`

**Exit criteria**
- Postgres integration test:
  - Each scope produces exactly the expected members.
  - `manifest.json` is first and `checksums.json` is last.
  - The HMAC verifies.
  - The container is running again afterwards.
- A compose-managed single container backed up with config scope holds its compose files and `.env`, byte for byte identical to the host files. A label that points at a non-regular file, or at a file over 1 MiB, is skipped and logged.
- Flipping one byte in any member, or in the manifest, makes the verifier fail. Phase 3 reuses this verifier.
- No `drydock.helper=1` containers remain after either a successful or a failed run.
- After `kill -9` in the middle of a backup and a restart:
  - The run is marked `interrupted`.
  - The container is running.
  - Staging is empty and no helpers remain.
- `docker compose stop drydock` in the middle of a stop-mode backup leaves the container running again and the run `cancelled`.
- Cancel takes effect within 5 s and restores the container's state.
- Running out of disk (ENOSPC) gives a failed run, a restarted container and no partial files.
- A container job and a stack job on the same container never run at the same time. The second one waits.
- A sentinel secret in the container's env appears in the archive's `inspect.json` but not in the run log or the UI.
- A storage root outside the allowlist is rejected. A job named `../../x` still writes inside the root.
- An encrypted archive cannot be read without its passphrase. RSS stays under 300 MB during a 5 GiB encrypted backup.
- Images:
  - The `all` scope saves a pullable image by default.
  - With the toggle on, a pullable image is stored as a reference only.
  - A locally built image shared by two containers is stored once.
- `GET` requests never reveal the passphrase.

**Risks**
- `get_archive` prefixes member names with the basename of the requested path. Restore has to account for that.
- Image platform selection uses docker-py's private `_get`/`_url`. Pin docker-py and cover it with a test.
- The proxy blocks the SYSTEM endpoint, so free space can't be estimated before the run starts.
- Compose `.env` files hold secrets. This is another reason to encrypt.

## Phase 3: Restore from storage (first end-to-end milestone)

**Goal:** Restore any backup onto any host, either under a new name or over the original, and also data-only and image-only archives. Nothing on the target changes until the whole archive has been verified.

**Deliverables**

Catalog-independent listing:
- `GET /restore/storage/{target_id}` lists files from the backend directly and reads each manifest through `read_head`, so restore still works if the DB catalog is lost.
- An encrypted archive's manifest cannot be read without its passphrase. Such archives are listed as "encrypted" with name, size and date only.

`restore/verify.py` (pass 1):
- Decrypts if needed and decompresses.
- `manifest.json` must be first and `checksums.json` last.
- Rejects members not listed in the manifest and duplicate member names.
- Limits member count, total size and compression ratio.
- Checks every member's sha256.
- Checks the HMAC against every key in the MultiFernet list to decide signed or unsigned.
- Reads each inner volume and bind tar header by header and rejects:
  - absolute names and `..` components
  - device nodes and FIFOs
  - hard links that point outside the tree
- Symlinks are allowed.
- Metadata members are extracted with `filter='data'` and `errorlevel=2` into a fresh `$DRYDOCK_STAGING_DIR/<run>/`.
- Local storage archives are read in place for both passes.

`security/hostpaths.py`, a single host-path denylist check:
- Denied for every role, superadmin included, in container create bodies: `/`, `/proc`, `/sys`, `/dev`, `/boot`, exactly `/etc`, and `docker.sock`.
- Also applied to every host-side write target:
  - helper `put_archive` destinations for bind remaps
  - overwrite wipes of bind paths
  - the Phase 4 directory where compose files are written
- Write targets are also denied anything under `/etc`, `/usr`, `/boot`, `/root` and `/var/lib/docker`, plus exactly `/home`.
- Paths are resolved before checking.

`restore/risk.py`: flags `Privileged`, `CapAdd`, `Devices`, host PID/IPC/network/userns modes, unconfined `SecurityOpt`, and binds of `/`, `/etc`, `/root`, `/proc`, `/sys`, `/dev`, `/boot` or `docker.sock`.

`restore/plan.py`, a pure function `(manifest, target_info, mode, new_name, bind_remaps, volume_map, wipe_binds) -> steps`:
- Modes:
  - `new-name`
  - `overwrite`
  - `data-only`: maps archive volumes and binds onto chosen existing target volumes, or onto the volumes of a chosen container. Needs no container config.
  - `image-only`: loads the images and does nothing else.
- New-name mode rewrites:
  - container names and the compose project label
  - network names in `EndpointsConfig` and `NetworkMode`
  - volume names in `Binds` and `Mounts`
  - `VolumesFrom`, `Links` and `container:<id>` references
- Bind paths can be remapped. Remap targets pass `hostpaths`.
- In overwrite mode, a bind path is wiped only if it is opted in individually through `wipe_binds`.
- Fields the target's API version doesn't accept are stripped, for example `Config.MacAddress` from API 1.52 and endpoint IDs and IPs.
- Pullable means the image has RepoDigests. The proxy keeps `DISTRIBUTION=0`, so this is not checked against a registry.
- The plan fails early if an image is neither in the archive nor pullable, and warns if the architecture differs.

`restore/apply.py` (pass 2), holding the per-container-ID locks of every container it touches:
1. Load images from the archive and pull referenced ones. A failed pull aborts before anything is changed.
2. Create networks. Existing networks with the same name are reused and the differences shown.
3. Create volumes with their original driver, options and labels. Compose labels are dropped in new-name mode.
4. Overwrite mode only:
   - Record the original containers in the run row (`restore_originals_json`).
   - Stop them.
   - Rename each one to `<name>-drydock-old`. Do not remove them yet.
5. Overwrite mode only: a wipe helper runs `find -mindepth 1 -delete` on the volumes and the opted-in binds.
   - This helper gets only `DAC_OVERRIDE` and `FOWNER`. `FOWNER` is needed to delete inside sticky directories. The only other helper with capabilities is the data helper: it is started after its put_archive with a fixed chown/chmod of its mount point and gets exactly `CHOWN`, `FOWNER` and `FSETID`, because Docker leaves the existing top directory's owner and mode alone (approved deviation).
6. Stream data with `put_archive` (prefix remapped, no `copyUIDGID`). The image load has no client timeout, for that call only.
7. Create containers through the low-level `/containers/create` and start them. Data-only and image-only modes skip this step.
8. On success, remove the `-drydock-old` containers.

Failure and recovery for overwrite:
- On failure, or during startup recovery of an `interrupted` restore:
  - Remove any containers that were partly created.
  - Rename the originals back.
  - Leave them stopped, because their volume data may be partial.
- The run is marked failed or interrupted, and the UI shows a warning naming the affected volumes.

Runs and UI:
- `runs` gains `kind='restore'`, a nullable job_id, a `plan` JSON field, `restore_originals_json` and the status flow `verifying -> awaiting_confirmation -> running -> done|failed|interrupted`.
- Endpoints:
  - `GET /restore`, `GET /restore/storage/{target_id}`, `POST /restore/from-storage`
  - `GET/POST /restore/runs/{id}/plan`, `POST /restore/runs/{id}/execute`
- The UI is a wizard with these steps:
  1. Source.
  2. Verify, with a live log.
  3. Plan: host, mode, names, remaps, volume mapping, bind wipe opt-ins and the risk summary.
  4. Confirm. Overwrite requires typing the target name and recent auth.
  5. Run.

**Exit criteria**
- Postgres with uid 999, restored under a new name on the same host:
  - The data is intact and file ownership is preserved.
  - An inspect diff shows the original's containers, volumes and networks unchanged.
- An overwrite restore of a running container:
  - completes with no 409 name conflict
  - is byte-identical to the backup, including removal of files that weren't in it
  - leaves no `-drydock-old` containers
- `kill -9` during an overwrite restore, after the wipe:
  - After restart, the originals have their original names and are stopped.
  - The run is `interrupted`.
  - The UI shows the partial-data warning.
- A volume-only archive restores into a chosen existing volume and into the volumes of a chosen container. An image-only archive loads its images and creates nothing else.
- Restoring across hosts works: back up on SSH host A, restore onto local host B.
- An nginx container with a bind mount, plus a custom network with an alias and a static IP, survives a round trip. A normalized inspect diff is empty except for an allowlisted set of fields.
- A unit test scans every create body generated in new-name mode and finds no original name or ID.
- Host paths:
  - A bind remap onto `/etc/x` or `/root` is rejected for every role.
  - An overwrite never wipes a bind that wasn't opted in.
  - A wipe of `/home` is rejected.
- Inspecting the wipe helper shows exactly `CapAdd=[DAC_OVERRIDE, FOWNER]`. A wipe inside a sticky directory owned by another uid succeeds.
- A backup and a restore on the same container never overlap.
- An archive signed under a rotated-out key still verifies as signed.
- Listing local storage with the `backups` table emptied still shows every archive and its manifest. Encrypted ones show as "encrypted".
- A tampered archive fails verification. A recording Docker client logs zero mutating calls, and no helper is created.
- Each archive in the fuzz corpus is rejected:
  - `../` and absolute names
  - a symlink followed by a write through it
  - a hard-link escape
  - device nodes
  - duplicate names
  - 1M empty members
  - a zstd bomb
  - an oversized manifest
- An unsigned archive with `Privileged`, `CapAdd`, `PidMode: host` and binds of `/` and `docker.sock`:
  - An admin gets 403.
  - A superadmin must acknowledge every flagged field and re-authenticate.
  - The denylisted binds are still rejected.
- A wrong passphrase fails during verification.

**Risks**
- The two-pass design doubles read time. This is the cost of verifying before touching anything.
- Docker's archive API drops xattrs and ACLs. Document this.
- After a restore, a later `compose up` on the host sees a config-hash mismatch and recreates the containers. This is expected; document it.
- A referenced image whose tag has moved, or that the registry has deleted, fails at the pull step. This is why `all` saves images by default.

## Phase 4: Stacks, consistency modes, hooks

**Goal:** Back up and restore whole Compose projects in dependency order, with stop, pause and live modes and pre/post hooks.

**Deliverables**

`engine/stacks.py`:
- Discovers stacks by `com.docker.compose.project` and skips `oneoff=True` containers.
- Builds a topological order from `com.docker.compose.depends_on` and rejects cycles.
- Captures compose files per service through `engine/compose_files.py` from Phase 2, deduplicated across services.

Consistency modes:
- Stop: containers stop in reverse order and start in forward order.
- Pause:
  - The "paused by drydock" list is written to the run row (`paused_containers_json`) before anything is paused.
  - Containers are unpaused in `finally`, by lifespan shutdown, and by startup recovery.
- Live: the UI warns that the backup is crash-consistent at best.
- Containers that were already stopped or paused stay that way.

`jobs/hooks.py`:
- A hook is `{container, argv: list[str], user?, workdir?, timeout_s (default 300, max 3600)}`.
- Runs through exec with no shell and no templating.
- Can only target containers in the job's target set.
- Output is truncated and redacted.
- Edits are superadmin only and audited with before and after values.

Stack restore:
- Order: images, networks, volumes, then containers in topological order. Overwrite uses the Phase 3 stop, rename and wipe sequence for every original container.
- New-name mode rewrites the whole project label set and `service:` references.
- Compose files are written to a directory the user picks on the target host. That directory passes `hostpaths`, and files never silently overwrite the originals.
- Single-container restores can also write their compose files this way.

Tables: `jobs.target_type` gains `stack`. `jobs` gains `consistency_mode`, `pre_hooks` and `post_hooks`. `runs` gains `paused_containers_json`.

**Exit criteria**
- An app + postgres (healthy) + redis stack backed up in stop mode on the SSH host. Docker events show services stopping in reverse order and starting forward.
- Pause mode leaves container uptime unchanged. Live mode never stops anything.
- `kill -9` during pause mode: after restart, every container drydock paused is unpaused and the run is `interrupted`.
- `docker compose stop drydock` during pause mode leaves every container unpaused.
- The stack restored under a new project name on another host runs alongside the original. Inspect shows zero shared volumes or networks.
- Compose files and `.env` in the archive match the host files byte for byte. A compose output directory under `/etc` is rejected.
- Hooks:
  - A failing pre-hook aborts the run before anything is stopped.
  - After a hook timeout, the containers are still restarted.
  - A hook argv of `["echo","$(id)"]` prints the literal text.
  - A hook targeting a container outside the job is rejected.
  - An operator or admin gets 403 on hook edits.
- `kill -9` during a stack stop: after restart, every affected container is running again.

**Risks**
- The `depends_on` label format differs in older compose versions.
- `network_mode: service:x` references.
- Compose files with relative bind paths.
- Docker can't kill an exec process when a hook times out. Document that hooks should wrap their own command in `timeout`.

## Phase 5: Scheduling, retention, notifications

**Goal:** Jobs run unattended, with predictable cron behavior, safe pruning and failure alerts.

**Deliverables**

`jobs/scheduler.py`:
- APScheduler 3.11.3 `AsyncIOScheduler` with `MemoryJobStore`.
  - Rebuilt from the `jobs` table at startup and on every job create, edit or delete.
  - Starts only in the process that holds the flock.
- Each job uses `CronTrigger.from_crontab(normalized, timezone=TZ)`, `coalesce=True`, `max_instances=1` and `misfire_grace_time=3600`.
- Numeric day-of-week values are converted to names first (0 and 7 become `sun`), because 3.x treats 0 as Monday.
- Startup catch-up: for each enabled job, compare the last scheduled run with the previous cron fire time.
  - If a fire was missed within the last 3600 s, dispatch the job once.
  - If it was missed earlier, log it as missed and do not run it.
- System jobs:
  - helper reaper (in addition to the startup run)
  - staging cleanup
  - run-history pruning: runs older than 90 days by default, configurable. Deleting a run row also deletes `/data/logs/<run_id>.log`.

`jobs/retention.py`:
- A pure function `select_for_deletion(backups, policy, now)` covering keep last N (the default, N >= 1), maximum age, and GFS (daily, weekly, monthly, yearly counts).
- Runs only after a successful upload.
- Never deletes the newest successful backup.
- Only touches names under the job's ID-derived prefix.

`notify.py`:
- Apprise 2.0.1, using only `Apprise().add(url)`. No `AppriseConfig`, plugin paths or attachments.
- Friendly forms build the URL for webhook (`json://`), SMTP (`mailto(s)://`), ntfy and Gotify.
- Admins can also enter a raw URL, checked against a scheme allowlist.
- `AppriseResult` statuses are logged per service. A notification failure never fails the run.

Tables: `jobs` gains cron, timezone, enabled and `retention` JSON. New tables `notification_targets` (name, kind, url_enc) and `job_notifications` (job_id, target_id, on_success, on_failure).

Endpoints:
- `GET /jobs/cron-preview?expr=&tz=` shows the next 5 fire times.
- `/notifications` CRUD and `POST /notifications/{id}/test`.

**Exit criteria**
- `0 3 * * 0` fires on Sunday at 03:00 in the configured TZ. The preview matches APScheduler, including across a DST change.
- Editing a job changes the schedule with no restart.
- Missed runs:
  - A run that misfires while the process is up, and is less than an hour late, runs once.
  - If drydock is stopped across a fire time and restarted within an hour, the job runs exactly once.
  - If it is restarted after more than an hour, the job doesn't run and the miss is logged.
- A scheduled run and a manual run never overlap on the same container.
- A second process pointed at the same `/data` does not start the scheduler.
- The scheduled reaper removes an orphaned helper.
- Pruning a run row deletes its log file, and no log file is left without a run row.
- Table-driven retention tests pass:
  - keep last N keeps `min(N, count)`
  - N=0 is rejected
  - the newest successful backup always survives
  - GFS selections match expected tables at day, week and month boundaries
  - nothing outside the job's prefix is ever deleted
- Policy changes are audited.
- A failed run notifies a local HTTP sink within 10 seconds, and the message contains no sentinel secret.
- Notification URLs are encrypted at rest and never echoed back into forms. Disallowed schemes are rejected.

**Risks**
- Users may still misread cron day-of-week values. The preview and the README cover this.
- Admins can point notification URLs at internal hosts (SSRF). Admin-only; document it.

### Session chunks

Phases 5 to 8 are split into chunks sized for one session each. Rules for every chunk:
- Run chunks in order. Each chunk has its own Alembic migration where it changes the schema.
- The chunk is done when the full gate is green: ruff, npm check/build/audit, pip-audit, full pytest including slow and Docker tests, and the CSP smoke check.
- Record the end state in memory before the session ends.
- If a chunk runs long, stop at a green gate and carry the rest forward. Never end a session with a half-applied migration or a red gate.

**5a: Retention**
- `jobs/retention.py` `select_for_deletion` (keep last N, max age, GFS) with table-driven tests.
- `jobs.retention` JSON column, form fields, audit of policy changes.
- Runs after a successful upload, only under the job's prefix, and never deletes the newest successful backup.
- Exit criteria covered: all retention table tests and "policy changes are audited".

**5b: Scheduler core**
- `jobs/scheduler.py`: day-of-week normalization, `CronTrigger` settings, rebuilt from the `jobs` table at startup and on every job change, started only under the flock.
- `jobs` gains cron, timezone and enabled. Startup catch-up for missed fires.
- `GET /jobs/cron-preview` and the job form fields.
- Exit criteria covered: Sunday 03:00 and DST preview, edit without restart, all three missed-run cases, no overlap with manual runs, and no scheduler in a second process.

**5c: System jobs**
- Scheduled helper reaper, staging cleanup, and run-history pruning (90 days default, configurable) that deletes the matching log file.
- A sweep for log files with no run row.
- Exit criteria covered: the reaper removes an orphaned helper, and pruning leaves no orphaned rows or logs.

**5d: Notifications**
- `notify.py`, the `notification_targets` and `job_notifications` tables, and URL encryption at rest.
- Friendly forms (webhook, SMTP, ntfy, Gotify), raw URL with a scheme allowlist, `/notifications` CRUD, `POST /notifications/{id}/test`, and attaching targets to jobs.
- Hooked into the end of a run. A notification failure never fails the run.
- Exit criteria covered: local HTTP sink notified within 10 s with no sentinel secret, URLs never echoed back, and disallowed schemes rejected.

## Phase 6: Remote storage through rclone, and Google Drive

**Goal:** SFTP, SMB, WebDAV and Google Drive, configured entirely in the browser with no rclone.conf and no CLI.

**Deliverables**

Build: an rclone v1.75.2 stage that checks the binary against SHA256SUMS. The build fails if the checksum doesn't match.

`storage/rclone_rc.py`:
- The lifespan starts `rclone rcd --rc-addr unix:///run/drydock/rclone.sock --config /dev/null`.
  - Credentials are passed only through the environment: `RCLONE_RC_USER` and a per-boot random `RCLONE_RC_PASS`. They never appear on the command line.
  - The socket is 0600.
- rclone is restarted if it dies.
- Drydock talks to it with an httpx unix-socket client.
- Log level is INFO at most. `--rc-no-auth` and TCP binds are never used.

`storage/rclone.py`, `RcloneBackend`, the second `StorageBackend` implementation:
- Remotes are passed as JSON-blob `fs` values. Password-type fields go through `core/obscure` at call time.
- Uploads use `operations/copyfile` with `_async` and `_group`, polled with `job/status` and `core/stats`.
- Cancel uses `job/stop`. Listing and deletes use `operations/list` and `operations/deletefile`.
- For SFTP, the pinned host key is written to `/run/drydock/rclone/<id>.known_hosts`. (Changed in 6c, approved: the key goes inline as rclone's `host_keys` option, a required field of the SFTP form, and no file is written.)

Restore from remote storage:
- Before downloading, check free space under `$DRYDOCK_STAGING_DIR` against the archive's listed size plus a reserve. Fail early if it is short.
- Download the whole archive to `$DRYDOCK_STAGING_DIR/<run>/`, then run the Phase 3 two-pass verify locally.
- Staging is cleaned when the run ends.

`storage/options.py`:
- An explicit allowlist of option names per backend (sftp, smb, webdav, drive). S3 is not supported in v1.
- Forms are rendered from the cached `config/providers` output with one Jinja macro per option type. Advanced options sit inside `<details>`.
- Secret fields show an "unchanged" placeholder.

`storage/gdrive_oauth.py`:
- Authorization-code flow with PKCE S256, using the user's own Google client. `access_type=offline`, `prompt=consent`, default scope `drive.file` (`drive` is an advanced option).
- Pending flows live in an in-memory dict, keyed by the sha256 of the state:
  - Each entry holds the verifier, user ID and target ID, and expires after 10 minutes.
  - Entries are single-use.
  - A restart drops them, and the user starts again.
- Two redirect modes:
  - Web-app client redirecting to `<base>/storage/oauth/callback`. This works over the SSH tunnel at localhost, or on an HTTPS hostname.
  - Desktop loopback client, where the user pastes the final URL back into drydock. This is for LAN-IP access.
- Drydock builds rclone's token JSON and stores it encrypted. `invalid_grant` sets the target to "reconnect required" and sends a notification.

Endpoints:
- `/storage/new?type=sftp|smb|webdav|drive`
- `POST /storage/{id}/oauth/start`: creates the flow and returns `HX-Redirect` to Google. A plain form redirect to another origin would be blocked by CSP `form-action 'self'`.
- `GET /storage/oauth/callback`: added to the GET exemption list. The single-use, user-bound state check is its guard.
- `POST /storage/{id}/oauth/paste`
- A guide page for creating the Google client and publishing the consent screen.

Test fixtures: `rclone serve sftp|webdav`, a Samba container, and a fake OAuth token server.

**Exit criteria**
- Each backend passes a full cycle: back up, list (including manifests read through `read_head`), restore, and let retention delete the oldest backup. A 5 GB transfer's sha256 matches.
- A remote restore downloads to staging, verifies and applies. With too little free space, it fails before any download with a clear message. Staging is empty afterwards.
- Cancelling mid-upload stops the rclone job, and the partial remote file is removed or recorded in the run log.
- A wrong pinned SFTP host key fails "Test connection".
- These are rejected on the server, even in a hand-crafted POST:
  - sftp `ssh`
  - any `*_command` or `*_file` option
  - `service_account_file`
  - the rclone `local` and `s3` types
  - unknown option names
- Inside the container:
  - rclone has no TCP listener (checked in `/proc/net/tcp`)
  - no rclone.conf exists
  - rc calls fail without the per-boot credentials
  - no secret appears in HTML, in logs, or in `ps` output or `/proc/<pid>/cmdline`
- `kill -9` of rclone: it restarts and the next transfer succeeds.
- OAuth:
  - State is single-use, expires in 10 minutes and is bound to the user.
  - Replayed or mismatched states, PKCE mismatches and pasted URLs with the wrong loopback host or port are rejected.
  - A `GET` to `/storage/{id}/oauth/start` returns 405.
- Manual check with a real Google account, recorded in the PR: both redirect modes, upload and list, then revoke access and see "reconnect required".

**Risks**
- Google OAuth apps left in Testing mode lose their grants after 7 days. Users must publish the app.
- rclone's shared Google client ID is being retired in 2026, so users must create their own.
- With `drive.file`, recreating the OAuth client hides old backups. Document this.
- The rc API can change between rclone versions. Keep the pin and the integration tests.
- `read_head` needs a ranged or partial read through the rc API, which is unverified. Otherwise listing a remote archive's manifest means downloading the whole archive. (Settled by the 6c spike, below.)

### Session chunks

**6a: rclone daemon**
- The Dockerfile rclone stage with a SHA256SUMS check that fails the build on mismatch.
- `storage/rclone_rc.py`: `rcd` on the 0600 unix socket, per-boot credentials passed only through the environment, restart on death, and the httpx unix-socket client.
- Exit criteria covered: no TCP listener, no rclone.conf, rc calls fail without the credentials, no secrets in `ps` or `/proc/<pid>/cmdline`, and rclone restarts after `kill -9`.

**6b: Storage options and forms**
- `storage/options.py` with per-backend allowlists for sftp, smb, webdav and drive.
- Forms rendered from cached `config/providers` with one macro per option type, advanced options in `<details>`, and the "unchanged" placeholder for secret fields.
- `/storage/new?type=` create and edit routes. No transfers yet.
- Exit criteria covered: every server-side rejection (sftp `ssh`, `*_command`, `*_file`, `service_account_file`, `local`, `s3`, unknown options) and no secret in HTML.

**6c: RcloneBackend over SFTP**
- Start with a spike to see whether the rc API supports the ranged read `read_head` needs. If it doesn't, settle the fallback before writing anything else.
- `storage/rclone.py`: JSON `fs` values, `core/obscure`, async `copyfile` with polling, cancel through `job/stop`, list and delete.
- SFTP known_hosts pinning and the `rclone serve sftp` fixture.

6c spike result (2026-10-24, rclone v1.75.2):
- The rc API has no ranged read (no `operations/cat`). `rcd --rc-serve` serves `GET /[<fs>]/<path>` with `Range`, behind the same auth, so `read_head` passes the fs as a connection string in the URL path. rcserver ends the fs at the first `]` whatever the quotes, so drydock refuses `]` in SFTP users and folders, and IPv6 SFTP hosts (rclone joins `host:port` without brackets). The preview reads 64 KiB first and 2 MiB only when the manifest does not fit.
- An empty `host_keys` turns rclone's host key check off. Drydock requires and validates the key, and always sends `shell_type=none`, no known_hosts file, no agent or key file and no `pin_host_key`.
- `operations/copyfile` silently replaces an existing file, so `put` stats first. SFTP uploads go to `<name>.<8 hex>.partial` and are renamed when complete. `job/stop` ends a copy with "context canceled" and rclone removes the partial file; one left by a killed rclone is removed by `put`, or named in the run log.
- rclone keeps every distinct inline configuration for good, and obscuring uses a random IV, so each secret is obscured once per drydock process.
- rclone logs the URL path of a request that fails auth, and httpx logs request URLs at INFO. Both are redacted.
- Exit criteria covered: the full SFTP cycle, cancel mid-upload, and a wrong host key failing "Test connection".

**6d: SMB and WebDAV**
- Fixtures for `rclone serve webdav` and a Samba container.
- The full cycle on each backend, plus a 5 GB transfer with a matching sha256.
- Exit criteria covered: the remaining "each backend passes a full cycle" checks and no secret in logs.

6d result (2026-10-28, rclone v1.75.2):
- WebDAV is https only (user decision). rclone's WebDAV client follows redirects to any host with the method kept, and refuses only https to http, so over http a server could send a retention DELETE to the socket proxy, which allows DELETE.
- Self-signed WebDAV servers (user request): **Fetch from server** next to a "Server certificate" field (`POST /storage/certificate`, superadmin with recent auth, audited `storage.cert_fetch`) shows the certificate; saving pins it. It reaches rclone as each call's `_config` `CaCert` (a file in `/run/drydock/certs` named by its SHA-256), which replaces the system roots for that call's connections. rclone caches a connection by its options and the ranged GET cannot carry `_config`, so the fs carries `description='drydock-cert-<sha256>'`, and `read_head` first makes an rc call under the same connection string; a cold GET fails closed.
- SMB and WebDAV hosts must be host names or IPv4 addresses, and no value sent as is may hold `]` (both for the connection string). SMB gets `use_kerberos=false`; WebDAV gets no `bearer_token_command`, headers, `unix_socket` or `auth_redirect`.
- rclone writes `.partial` files only for backends with PartialUploads (SFTP, SMB). For WebDAV `put` uploads as `<name>.<8 hex>.partial` itself and renames it with `operations/movefile`.
- Test fixtures: `rclone serve webdav` over TLS with a throwaway CA, and a samba service in compose.test.yaml (one share, a test-only password).

**6e: Restore from remote storage**
- Free-space check under `$DRYDOCK_STAGING_DIR` before downloading, a full download to staging, the Phase 3 two-pass verify, and cleanup when the run ends.
- Exit criteria covered: remote restore applies, short free space fails before any download, and staging is empty afterwards.

6e result (2026-10-28):
- `RcloneBackend.get` downloads with `operations/copyfile` into `restore-<run id>/download/`. Before that, it checks free space against the listed size plus the 64 MiB reserve and the bytes other downloads in flight hold (`Reserved`). A transfer that goes past the listed size is stopped (checked each poll). A full staging disk is reported as such, not as a remote error. `open` refuses to read in place.
- `restore.verify.Downloaded`: pass 1 downloads inside `verify_archive`'s cleanup, and pass 2 reopens that same copy, so the identity check still holds.
- Retention and restores: the dispatcher marks an archive it is deleting in memory, in the same write transaction where it checks for open restores, and deletes over the network outside it. `_create_restore_run` refuses a marked archive. Only the primary process runs either.

**6f: Google Drive OAuth**
- `storage/gdrive_oauth.py`: PKCE S256, the in-memory single-use state store, and both redirect modes.
- The OAuth endpoints, the guide page, the fake token server fixture, and `invalid_grant` setting "reconnect required" plus a notification (uses 5d).
- Exit criteria covered: all automated OAuth checks. The manual check with a real Google account is done by the user and recorded in the PR.

6f result (2026-10-28):
- The token lives in the target's encrypted config (`config["token"]`, rclone's oauth2 JSON), next to `config["reconnect"]`. Editing keeps it unless the client ID or scope changes. Drive gets fixed `auth_url`/`token_url` (Google's), `client_credentials=false`, no service account, `env_auth=false` and no impersonation.
- Redirect mode answers the start with `HX-Redirect` (204); without htmx it shows a link. Paste mode shows the consent link and a field; the pasted address must be `http://127.0.0.1:<the flow's port>/` exactly.
- `invalid_grant` from rclone raises `ReconnectRequired`, and the backend's `on_reconnect` (dispatcher and routes) runs `gdrive_oauth.mark_reconnect`: sets the flag once, audits `storage.oauth_revoked`, and notifies the on-failure targets of the jobs using the target.
- Checked live: rclone v1.75.2 takes the inline drive config and token, refreshes at Google, and a wrong client maps to "Google refused the OAuth client ID or secret". The manual check with a real account is still the user's.

## Phase 7: Restore from upload and from a server path

**Goal:** Restore from an archive uploaded in the browser (up to 50 GB) or from an allowlisted server path. Both go through the same verify-before-touch pipeline.

**Deliverables**

`restore/uploads.py`, a single streamed request:
- `PUT /restore/uploads`, where `Content-Length` is the declared size. A request without it gets 411.
- Before reading the body, the server checks the 50 GB cap, and free space minus a reserve minus the declared sizes of uploads already in progress.
- The body is read with `request.stream()`, written via `anyio.to_thread` to a server-named file, and counted against the declared size.
- An `uploads` row is created.
- If the body goes over the declared size, or the client disconnects, the partial file is deleted.
- CSRF is checked through the header.
- A system job deletes uploads after 24h.

Client: `frontend/upload.ts` sends one XHR and shows progress through `upload.onprogress`. htmx 4 is fetch-based and has no upload progress events.

`restore/paths.py`:
- The allowlist comes only from `DRYDOCK_RESTORE_PATHS` in the environment.
- The path is resolved with `realpath` and must be inside an allowlisted directory.
- It is opened with `O_NOFOLLOW`, the fd path is re-checked through `/proc/self/fd`, and only regular files are accepted.
- Compose mounts the inbox directory as `./restore-inbox:/restore-inbox:ro`.

Table `uploads`: id, user_id, declared_size, received, path, status, expires_at.

Endpoints: `POST /restore/from-upload/{id}` and `POST /restore/from-path`, both feeding the Phase 3 wizard.

**Exit criteria**
- Upload checks:
  - A declared size over 50 GB returns 413, and one over free space returns 507, before any bytes are read.
  - A missing `Content-Length` returns 411.
  - Sending past the declared size returns 413 and deletes the partial file.
  - A client disconnect deletes the partial file.
  - A viewer or operator gets 403, and a missing CSRF header gets 403.
- A completed upload's sha256 matches the source.
- An upload older than 24h is deleted by the expiry job.
- A 5 GiB upload in CI keeps RSS under 300 MB with nothing written to tmpfs. A 50 GB upload is checked manually.
- These server paths are rejected:
  - `../`
  - an absolute path outside the allowlist
  - a symlink inside the allowlist pointing outside it
  - a symlink swapped in between check and open (simulated)
  - a directory or a FIFO
- No route can change the allowlist.
- An archive from another drydock instance is unsigned, so only a superadmin can restore it. A wrong passphrase fails during verification.
- Losing the DB:
  - Delete `drydock.db`, complete the wizard, and re-add the storage target with the same secret key.
  - Unencrypted archives are listed and restore as signed.
  - Encrypted archives restore without entering a passphrase, because it is re-derived from the secret key and the job UUID in the archive name. Archives from another instance still need the passphrase entered.

**Risks**
- A reverse proxy may limit request body size. The README documents raising it, for example nginx `client_max_body_size`.
- Uploads running in parallel can fill the disk. The free-space check counts uploads already in progress.
- An interrupted upload has to start again from zero. Resume is deferred.

### Session chunks

**7a: Streamed uploads**
- The `uploads` table, `PUT /restore/uploads` with all pre-read checks, streamed writes, and partial-file cleanup.
- `frontend/upload.ts` with XHR progress, and the 24h expiry system job (uses 5c).
- Exit criteria covered: all upload checks, sha256 match, expiry, and the 5 GiB RSS test in CI.

**7b: Server-path restore and wizard entry points**
- `restore/paths.py` (realpath, `O_NOFOLLOW`, `/proc/self/fd` re-check, regular files only) and the compose inbox mount.
- `POST /restore/from-upload/{id}` and `POST /restore/from-path` feeding the Phase 3 wizard.
- Exit criteria covered: every rejected path case and "no route can change the allowlist".

**7c: Foreign archives and DB loss**
- Unsigned archives from another instance are superadmin only, and a wrong passphrase fails during verification.
- The DB-loss scenario: listing archives with no DB rows, signature checks, and passphrases re-derived from the job UUID in the archive name.
- Exit criteria covered: the foreign-archive and "losing the DB" checks.

## Phase 8: Hardening and release

**Goal:** Prove the threat model with tests and ship a v1 that someone else can deploy safely.

**Deliverables**
- `docs/threat-model.md`, where each threat names the tests that cover it.
- Image and dependency scanning in CI. buildx SBOM and provenance, versioned tags, and a multi-arch build (amd64 and arm64).
- The route inventory tests are re-run against every route added since Phase 0.
- An upgrade test: Alembic migrations run against a populated database from an earlier version.
- A CI matrix of Python 3.14 and 3.15. `requires-python >=3.14` allows both.
- `README.md`, `SECURITY.md` and `CHANGELOG.md`. The README covers:
  - Drydock is root-equivalent on every host it manages.
  - The 127.0.0.1 binding and SSH tunnel, and the setup wizard risk while no account exists.
  - Secret key file ownership (`chown 10001`, `chmod 0400`).
  - The socket proxy is not a security boundary, and the remote SSH user is root-equivalent.
  - Live mode is crash-consistent at best, so databases need hooks.
  - Archives contain env and `.env` secrets, so use encryption.
  - Back up `DRYDOCK_SECRET_KEY` separately from `/data`. Losing it loses stored credentials and archive signatures. Losing the key loses access to every encrypted archive. Losing only the DB loses nothing, because passphrases are derived from the key.
  - xattrs and ACLs are not preserved.
  - Compose config-hash drift after a restore.
  - Cron day-of-week semantics.
  - Google client setup.
  - The cookie `Secure` behavior on plain-HTTP LAN addresses.
- Performance runs: a 50 GB upload and a 100 GB volume backup over SSH, with results recorded.

**Exit criteria**
- Every threat in the threat model names at least one automated test.
- No unaddressed high or critical scan findings. Unfixable base-image CVEs go on a documented exception list with expiry dates.
- On a clean Linux VM, using only the README and the browser after `docker compose up -d`:
  1. Complete the wizard.
  2. Add the local host and one SSH host.
  3. Add local storage and one remote storage target (SFTP, SMB or WebDAV).
  4. Create a scheduled, encrypted stack job.
  5. Run it, restore it under a new name on the other host, and receive the notification.
- After `docker compose down && up`, all state is kept, no run is left `running`, and no container drydock stopped or paused is left down.

### Session chunks

**8a: Threat model and route inventory**
- `docs/threat-model.md`, with each threat linked to the tests that cover it. Write tests for any gaps.
- Re-run the route inventory tests against every route added since Phase 0.
- Exit criteria covered: every threat names at least one automated test.

**8b: CI and supply chain**
- Image and dependency scanning, buildx SBOM and provenance, versioned tags, the amd64 and arm64 build, and the Python 3.14 / 3.15 matrix.
- The base-image CVE exception list with expiry dates.
- Exit criteria covered: no unaddressed high or critical findings.

**8c: Upgrade test and docs**
- The Alembic upgrade test against a populated database from an earlier version.
- The `docker compose down && up` state test.
- `README.md` (every topic listed above), `SECURITY.md` and `CHANGELOG.md`.
- Exit criteria covered: the down/up check.

**8d: Release validation (user-assisted)**
- The clean-VM walkthrough from the README alone.
- Performance runs (50 GB upload, 100 GB volume backup over SSH) with results recorded.
- Exit criteria covered: the clean-VM walkthrough. This chunk needs the user's VM, a remote storage target and a notification target.

## Deferred / out of v1

- An "exec tar" mode (GNU tar with `--xattrs --acls`) to preserve xattrs and ACLs.
- Restoring stacks through `docker compose up`, with the compose CLI bundled in the image.
- Taking an automatic safety backup before an overwrite restore.
- TOTP 2FA, OIDC/SSO. These are worth revisiting given that drydock is root-equivalent.
- Streaming logs over SSE (polling is enough for now).
- Browsing archive contents, a metrics endpoint, and choosing an image platform per restore.
- Resumable or chunked uploads, `GET`/`DELETE` on uploads, and per-user upload caps.
- A Hypothesis-based archive fuzzer. The Phase 3 fuzz corpus covers v1.
- A bulk "re-encrypt all secrets with the newest key" action. Lazy re-encryption on write plus MultiFernet covers v1.
- A CI check that the threat model's test links resolve.
- Python 3.15 as the base image, if Phase 0 chose 3.14.
- S3-compatible storage (dropped 2026-10-17: no S3 endpoint to test against). Adding it later means one allowlist entry in `storage/options.py` plus a full-cycle test.

## Decisions (resolved 2026-10-12)

1. **Restore permissions:** admin and above only. Operators cannot restore, even under a new name.
2. **Hook editing:** superadmin only. Admins can attach existing hooks to jobs.
3. **Client code:** TypeScript (`app.ts`, `upload.ts`) compiled in a Node build stage. Pin Node LTS by exact version and digest in Phase 0. The final image contains no Node.
4. **Encryption key model:** drydock holds the key. Superadmin can reveal a job passphrase for use outside drydock.
5. **Sessions:** 1h idle, 12h absolute, re-auth within 10 minutes for sensitive actions.
6. **Staging:** `DRYDOCK_STAGING_DIR`, default `/data/staging`. Mount a larger disk there if needed. Free space is checked before any download or upload.
7. **Python version:** 3.14 is approved as the fallback if the Phase 0 wheel check finds a missing cp315 wheel for uvloop, httptools or watchfiles.
8. **Passphrases:** derived from the secret key with HKDF and the job UUID, not stored. Encrypted archives survive losing the DB as long as the secret key is kept.
9. **Pullable images (2026-10-13):** on Docker 29 every image has RepoDigests, even local builds, so RepoDigests alone cannot prove an image is pullable. The socket proxy enables `DISTRIBUTION=1` (read-only registry lookup). An image is stored by reference only when the toggle is on AND `/distribution/{ref}/json` confirms the exact digest exists in the registry. Otherwise the image is saved. This supersedes the `DISTRIBUTION=0` notes in Phases 1 and 3.
