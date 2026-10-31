# Drydock

Drydock is a self-hosted web app that backs up and restores Docker containers, volumes and Compose stacks, on the local host and on remote hosts over SSH.

This is an early build (Phases 0 to 4 of [PLAN.md](PLAN.md)): accounts, roles, CSRF protection, secret encryption, audit logging, the connection layer to Docker hosts (socket proxy, SSH tunnels with pinned host keys, helper containers, container inventory), "Run now" backups of single containers and Compose stacks into signed, optionally encrypted archives in a local directory, in stop, pause or live mode and with pre- and post-hooks (see [Jobs and runs](#jobs-and-runs)), and restores from that directory onto any host (see [Restore](#restore)).

**Upgrading from a Phase 3 build is one-way.** Drydock migrates its database at startup, and the Phase 4 migration (revision 0005) adds stack jobs, consistency modes and hooks. An older image refuses to start on a database at revision 0005, and archives written by Phase 4 (which record the job's mode and target type) cannot be verified or restored by an older build. Archives from earlier builds still restore. Stop drydock and copy the `drydock-data` volume before upgrading; to go back, restore that copy, which loses everything done since.

## Read this first

**Drydock is root-equivalent on every host it manages.** Anyone who controls drydock can start privileged containers, read every volume and replace any container. Treat access to its UI like root SSH access to all of those hosts.

**The first visitor becomes superadmin.** There is no setup token. Until the setup form at `/setup` has been submitted, anyone who can reach the port can create the superadmin account and take over. Drydock logs a warning at every start while no superadmin exists. Complete setup immediately after the first start, over an SSH tunnel.

## Install

Drydock publishes its port on `127.0.0.1` only. Reach it through an SSH tunnel (or a reverse proxy on the same host).

1. Generate the secret key. It encrypts stored credentials and signs archives; keep a copy somewhere safe, separate from the `/data` volume.

   ```sh
   mkdir -p secrets
   python3 -c "import base64, secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())" > secrets/drydock_secret_key
   ```

2. Restrict the key file. Outside Docker swarm, a Compose secret is a plain bind mount, so the file's own owner and mode apply inside the container. Drydock runs as uid 10001 and refuses to start if it cannot read the key.

   ```sh
   sudo chown 10001:10001 secrets/drydock_secret_key
   sudo chmod 0400 secrets/drydock_secret_key
   ```

3. Start drydock.

   ```sh
   docker compose up -d --build
   ```

4. From your workstation, open a tunnel and complete setup right away:

   ```sh
   ssh -L 8000:127.0.0.1:8000 you@docker-host
   ```

   Then browse to <http://localhost:8000/>, which redirects to `/setup`.

Browsers treat `http://localhost` as a secure context, so session cookies keep the `Secure` flag and the `__Host-` prefix over the tunnel. If `DRYDOCK_BASE_URL` is plain HTTP on a LAN address, cookies lose the `Secure` flag and drydock logs a warning at every start. Use HTTPS or the tunnel instead.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DRYDOCK_SECRET_KEY_FILE` | | Path to the key file (preferred). Several keys, newest first, allow rotation. |
| `DRYDOCK_SECRET_KEY` | | The key itself, if a file is not possible. |
| `DRYDOCK_BASE_URL` | `http://localhost:8000` | Origin users browse to. Used for CSRF origin checks and cookie flags. |
| `DRYDOCK_ALLOWED_HOSTS` | host of the base URL | Accepted `Host` headers. `localhost` and `127.0.0.1` are always allowed. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies whose `X-Forwarded-For` is trusted. Required behind a reverse proxy; see below. |
| `DRYDOCK_STAGING_DIR` | `/data/staging` | Scratch space for transfers. A backup needs about the size of its largest member (volume, bind mount or image) here; mount a larger disk if needed. It must not be the data or run directory or contain them. It must belong to this one installation and hold nothing else: archives uploaded for a restore wait in its `uploads` folder for 24 hours. Drydock deletes its own scratch names there (`member-*`, `probe-*.tar`, `trash-*`, `restore-<number>`) at startup, and in an hourly cleanup (scratch files only while no run is active; a staged restore once its run is finished). |
| `DRYDOCK_LOCAL_STORAGE_ROOTS` | | Directories (separated by commas or spaces) inside which storage targets may live. Each must be mounted into the container and writable by uid 10001. |
| `DRYDOCK_RESTORE_PATHS` | | Directories (separated by commas or spaces) whose files an admin may restore from by path, on the restore page. `compose.yaml` sets `/restore-inbox`, mounted read-only from `./restore-inbox`; files there must be readable by uid 10001. Symlinks are resolved and must stay inside; only regular files with drydock's archive names are opened. Unset: restores from a path are off. Only the environment sets it. |
| `DRYDOCK_LOCAL_DOCKER_URL` | | Docker URL suggested when an admin adds the local host. `compose.yaml` sets it to the socket proxy. Drydock never registers a host by itself. |
| `DRYDOCK_HELPER_IMAGE` | `busybox:1.37.0` pinned by digest | Image for helper containers. Must be pinned by digest (`name@sha256:...`); use the multi-arch index digest. Point it at a mirror on air-gapped hosts. |
| `DRYDOCK_RUN_DIR` | `/run/drydock` | Private tmpfs for the SSH forward sockets. |
| `TZ` | `UTC` | Time zone for schedules without one of their own. Must be a listed zone name such as `Europe/Berlin`. |
| `DRYDOCK_RUN_HISTORY_DAYS` | `90` | Finished runs older than this many days (1 to 36500) are deleted with their log files, hourly from 5 minutes after start. It cannot be turned off; 36500 keeps history for good. |

### Behind a reverse proxy

Point the proxy on the same host at `http://127.0.0.1:8000`, have it set `X-Forwarded-For`, and set `DRYDOCK_BASE_URL` to the public `https://` URL. Drydock then sends `Strict-Transport-Security`.

Docker's published port delivers the proxy's connections from the gateway of drydock's Compose network (for example `172.18.0.1`), never from `127.0.0.1`, so the default `FORWARDED_ALLOW_IPS` does not match. Set it to that gateway address:

```sh
docker network inspect drydock_default --format '{{(index .IPAM.Config 0).Gateway}}'
```

If the proxy is itself a container on a network shared with drydock, use its address or subnet instead. Without this setting drydock sees every visitor as the proxy: one person's failed logins (50 per address in 15 minutes) lock out every user, and the audit log records only the proxy address. Drydock logs a warning at startup when the base URL is HTTPS on a non-loopback host and `FORWARDED_ALLOW_IPS` is still the default.

Once the gateway is trusted, anything that can connect to `127.0.0.1:8000` on the host, including SSH tunnel users, can choose the client address drydock records. The gateway address can change if the network is recreated; check it after `docker compose down`.

Archive uploads on the restore page are single requests of up to 50 GB. Raise the proxy's body limit for `/restore/uploads` and let it stream the body instead of buffering it on its own disk first. For nginx:

```nginx
location = /restore/uploads {
    client_max_body_size 50g;
    proxy_request_buffering off;
    proxy_pass http://127.0.0.1:8000;
    # the usual proxy_set_header lines, as for /
}
```

## Docker hosts

Drydock talks to every host through the Docker Engine API, versions 1.44 to 1.56 (Docker Engine 25.0 or later). It reads the daemon's `/version` and uses the highest version both sides support, capped at 1.56. Older daemons are refused.

**Every host you add hands drydock root on that host.** Docker API access is root-equivalent: whoever can create containers can mount `/` and start privileged containers. That holds for the local socket proxy and for every SSH user drydock logs in as. Only admins manage hosts, and drydock never adds one by itself, not even the local host. Every role may view a host's container inventory (`/hosts/<id>/containers`), as the role matrix allows.

### The local host

`compose.yaml` runs [linuxserver/socket-proxy](https://github.com/linuxserver/docker-socket-proxy) next to drydock. Only the proxy mounts `/var/run/docker.sock` (read-only, on an `internal` network with no route out); drydock reaches it at `tcp://socket-proxy:2375` and never mounts the socket. The proxy allows containers, images, volumes, networks, exec, archive, start, stop, restart, pause and unpause, plus the read-only registry lookup `GET /distribution/<image>/json` (see [Images stored by reference](#images-stored-by-reference)). It denies everything else, including events, logs, build, commit, swarm, secrets, plugins and system.

**The socket proxy is not a security boundary.** It narrows the API to what drydock uses, which limits accidents and makes misuse noisier, but the endpoints drydock needs (container create, exec, archive) are already enough to take over the host. Treat anything that can reach `socket-proxy:2375` as root on the host; that is why it sits on an internal network shared only with drydock.

To add it, open **Hosts > Add local host**. The Docker URL is prefilled from `DRYDOCK_LOCAL_DOCKER_URL`. A local host's `tcp://` or `http(s)://` URL must name a service on drydock's Docker network (such as `socket-proxy`) or a loopback or private address, since that API is unauthenticated; link-local addresses such as cloud metadata are refused. Reach any other machine over SSH. **Test connection** then shows the engine version, the negotiated API version and the platform, and the container inventory loads below.

### Remote hosts over SSH

Drydock keeps one SSH connection per host and forwards a private unix socket (`/run/drydock/hosts/<id>.sock`, mode 0600 in a 0700 directory) to the remote Docker socket. The private key is stored encrypted with the secret key and only ever exists in memory; drydock can generate an ed25519 key pair or accept a pasted key. A pasted key's passphrase is used once to decrypt it and then discarded: the key is kept decrypted inside the encrypted token, so no passphrase is stored and no passphrase KDF runs when tunnels start. Encrypted OpenSSH keys with more than 1024 KDF rounds and encrypted PKCS#8 keys are refused (`ssh-keygen -p -f <file>` converts them). Pages show only the public key and fingerprints, and a pasted key or passphrase is never sent back to the browser. Only public key authentication is offered, and only AEAD ciphers (AES-GCM first, then chacha20-poly1305).

On the remote host:

- The SSH user needs access to the Docker socket, which is root-equivalent on that host. Use a dedicated user, for example one in the `docker` group, for nothing else.
- sshd must allow local forwarding (sshd only allows unix socket forwards together with TCP forwards). A `Match` block keeps everything else off for that user:

  ```
  Match User drydock
    AllowStreamLocalForwarding local
    AllowTcpForwarding local
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    ForceCommand /bin/false
  ```

- Restrict the key in `authorized_keys`. The host page shows the line to paste: `restrict,port-forwarding,command="/bin/false" ssh-ed25519 AAAA... drydock`. The forced command refuses shells, commands and subsystems such as sftp; the forward still works. OpenSSH cannot allow the socket forward while refusing TCP forwards (`permitopen` and `PermitOpen` block unix socket forwards too), so the key can still open TCP connections from the host. That adds nothing to the Docker access it already grants, which is root on the host.
- For rootless Docker, set the host's socket path (for example `/run/user/1000/docker.sock`).

To add a host:

1. Open **Hosts > Add SSH host** and enter the name, address, port, user and socket path. Leave "Generate a new ed25519 key" selected, or paste an existing private key.
2. Copy the `restrict,port-forwarding,...` line from the host page into the user's `~/.ssh/authorized_keys` on the host.
3. Click **Scan host key**. Drydock shows the SHA256 fingerprint the server presents and trusts nothing yet.
4. Compare it with the host itself, out of band (for example `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on its console). Only then click **Trust this key**. Drydock scans again and pins the key only if the fingerprint still matches the one you confirmed, so a key swapped in between is never trusted. Trusting needs your password from the last 10 minutes and is audited.
5. The tunnel connects within seconds. **Test connection** confirms it.

The host key is pinned to that address and port. Changing either clears the trusted key, and the new endpoint has to be scanned and trusted again. If a host later presents a different key, including a key of another type (which fails key exchange, because drydock offers only the pinned key's algorithm), drydock refuses the connection, makes no Docker call, shows a host key mismatch on the host pages and writes a `host.hostkey_mismatch` audit event with the presented fingerprint. It does not retry until an admin trusts a key again. A changed host key after a reinstall is expected; treat one you cannot explain as an attack until proven otherwise.

### Helper containers

To read and write volumes drydock runs short-lived helper containers (`busybox`, pinned by multi-arch digest) with no network, a read-only root filesystem, no capabilities (except two restore helpers, each running a fixed command: the wipe helper gets exactly `DAC_OVERRIDE` and `FOWNER`, and the data helper, which gives a restored directory its archived owner and mode after the data is written, exactly `CHOWN`, `FOWNER` and `FSETID`), `no-new-privileges`, a PID limit and the labels `drydock.helper=1` and `drydock.instance=<installation ID>` (a random ID made when the database is created). Volume data moves through the daemon's archive API, so a transfer helper is never even started. Helpers are removed when the transfer ends, and a reaper removes leftovers when drydock starts and hourly after that on every host reachable at that moment, skipping any helper a run is still using. The reaper and the container inventory act only on helpers carrying this installation's ID, so two drydock instances (or the test suite) can share a daemon.

## Backups

### Storage

Archives go to a storage target: for now, a directory mounted into the drydock container. Mount it, list it in `DRYDOCK_LOCAL_STORAGE_ROOTS`, and make it writable by uid 10001:

```yaml
services:
  drydock:
    environment:
      DRYDOCK_LOCAL_STORAGE_ROOTS: /backups
    volumes:
      - drydock-data:/data
      - /srv/drydock-backups:/backups
```

```sh
sudo install -d -o 10001 -g 10001 -m 0700 /srv/drydock-backups
```

Then add it under **Storage > Add storage** (admins). A storage directory must resolve inside one of the allowed roots, symlinks included, and must not overlap `/data`, `/run`, the staging directory or the application. **Test storage** writes and removes a probe file. The directory is stored encrypted with the secret key, like every backend's settings. Archive names are built from a slug of the job name, the job's random ID and the UTC time (`drydock-<slug>-<job uuid>-<YYYYMMDDTHHMMSSZ>.tar.zst[.age]`), never from raw user input. Each archive is written straight into the storage directory under a temporary name (`.partial-<random>`) and published under its real name when complete, without ever replacing an existing file, so a reader never sees a partial archive. Startup recovery removes temporary files left by a crash.

#### Remote storage

A superadmin can also set up SFTP, SMB, WebDAV and Google Drive targets under **Storage > Add storage**. Jobs can back up to all of them, and **Restore** lists a target's archives with their previews and restores them.

A Google Drive target uses your own Google OAuth client: the storage page links to a guide (**Storage > Add storage > Google Drive**, then "how to create the OAuth client"). Enter the client ID and secret, save, then click **Connect to Google** on the storage page. Use a *web application* client when you reach drydock over the SSH tunnel at `localhost` or on an https host name, with the redirect URI `<DRYDOCK_BASE_URL>/storage/oauth/callback`. Use a *desktop app* client when you reach it on a LAN address over plain http: Google then sends the browser to `http://127.0.0.1:<port>/`, where nothing answers, and you paste that address back into drydock. A connection attempt works once, for 10 minutes, and only for the superadmin who started it. Publish the client's consent screen: Google drops a testing-mode app's access after 7 days. If Google refuses drydock's access later (revoked, or a testing-mode client), the next transfer fails, the storage shows "reconnect required", and the failure notification targets of its jobs get one message. With the default `drive.file` access drydock sees only the files its client created, so deleting and recreating the client hides older backups. Changing the client ID or the access scope forgets the connection.

A restore from remote storage first downloads the whole archive into the staging directory (`restore-<run id>/download/`), after checking that the disk there has the archive's size free plus a 64 MiB reserve; with less, it fails before downloading anything. Both verification passes then read that copy, and it is removed with the rest of the run's staged data when the run ends, is discarded or expires (startup recovery removes what a crash left). While retention deletes a remote archive, a restore of it is refused, and an archive an open restore names is kept.

An SFTP target needs the server's public host key. **Fetch from server**, next to the field, fills it with the key the server presents and shows its SHA256 fingerprint. Compare that with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server before saving, because saving trusts the key, and on the first connection anyone between drydock and the server could present their own. You can also paste the contents of that `.pub` file (or the ecdsa or rsa one) yourself, and separate several keys with commas. Drydock never trusts a key on its own and never connects without one. A changed key fails the run and **Test connection** with "The server's host key does not match the host key in the settings". The host must be a host name or an IPv4 address, and neither the user nor the folder may contain `]`. Admins can run **Test connection**, which logs in, writes a small file, reads it back and removes it.

A WebDAV target needs an `https://` URL. Over plain http, the server, or anyone on the way to it, could redirect rclone's requests (deletes included) to the Docker socket proxy, which drydock's container can reach. If no public certificate authority signed the server's certificate, as with a NAS's self-signed one, click **Fetch from server** next to **Server certificate**. Drydock shows the certificate the server presents, with its names, dates and SHA-256 fingerprint. Compare the fingerprint with the server's own (`openssl x509 -noout -fingerprint -sha256 -in` its certificate file, or the NAS's certificate page) before saving, because saving trusts the certificate. You can also paste the certificate in PEM format yourself. A pinned certificate is that target's only trust anchor; rclone still checks the validity dates and that the certificate lists the host in the URL (as a DNS name or IP address, not only as the common name), so drydock refuses one that does not. A certificate a public authority already vouches for is shown but not filled in: pinning it would break at its next renewal. The URL's host must be a host name or an IPv4 address.

An SMB target names the share, then optionally a folder in it, under **Share and folder**. The host must be a host name or an IPv4 address, and the user may not contain `]`.

A backup to remote storage is first written to the staging directory (`DRYDOCK_STAGING_DIR`), which therefore needs room for a whole archive, and uploaded once the containers run again. It is uploaded under a temporary name (`<archive>.<8 hex>.partial`) and renamed when complete, so the archive name never shows a partial upload. Cancelling stops the upload and removes the partial file; any that could not be removed is named in the run log.

A remote target makes drydock connect, through rclone, to whatever host its settings name, from a container that can also reach the Docker socket proxy. So, like notification targets, only a superadmin who has re-entered their password in the last 10 minutes can create, change or remove one. Admins see remote targets (without credentials) and local storage stays an admin task. This is a deliberate change from the role matrix in PLAN.md.

Each form offers a short list of rclone's options, checked on the server; anything else in a submitted form, including a hand-crafted one, refuses the whole form. Left out on purpose:

- **sftp:** external `ssh`, every `*_command`, key and known_hosts *files* (paste the key instead), agents, proxies, cipher lists and insecure ciphers, `pin_host_key`. Drydock pins the host key itself (above) and tells rclone never to run commands on the server (`shell_type none`), so SFTP integrity is checked by size only until a restore verifies the archive.
- **smb:** Kerberos, which needs local credential files. NTLM user, password and domain work.
- **webdav:** plain `http://`, `bearer_token_command`, `unix_socket`, custom headers, `auth_redirect`, and the `sharepoint` and `infinitescale` vendors.
- **drive:** service accounts, `env_auth`, impersonation, custom auth and token URLs, and a pasted token. You use your own OAuth client (above).

Passwords, private keys and tokens are stored encrypted and never shown again. Leave a field empty to keep the stored value, or tick its **Clear** box. Changing where a target points (host, port, user, URL, domain, server type, host key or pinned certificate, OAuth client or Google Drive access, and for WebDAV the folder) requires entering its stored secrets again.

### Jobs and runs

A job backs up one container (by name or ID) or one Compose project on one host into one storage target. Admins create and edit jobs; operators can **Run now** and cancel runs; every role can view jobs, runs, logs and the backup catalog.

| Scope | What the archive holds |
|---|---|
| Configuration | `docker inspect` output for the container, its image, its non-default networks and its named volumes. For a Compose container, also the files its Compose labels name (`config_files`, `environment_file` and `<working_dir>/.env`) and the service's `env_file` entries in those compose files, each only if it is a regular file of at most 1 MiB (64 files and 8 MiB in all). Compose labels that the container inherits from its image are ignored, and files under `/etc`, `/boot`, `/proc`, `/sys`, `/dev`, Docker's storage or any `.ssh` or `.gnupg` directory are never read. |
| Data | Every named volume and bind mount, as tar streams read by the daemon, with ownership and modes kept. tmpfs mounts are never backed up; the manifest lists them. Nor is the data of a bind mount of `/`, `/proc`, `/sys`, `/dev` or Docker's storage (`/var/lib/docker`, `/var/lib/containerd`); the manifest says it was skipped. |
| Images | `docker save` of the container's image, for the host's platform. |
| Everything | All of the above. |

**Consistency modes.** Before touching anything drydock inspects the containers, reads their compose files and checks their images with the registry. Then:

- **Stop** stops the containers (waiting as long as each one's own stop timeout, Compose's `stop_grace_period`, up to 10 minutes), reads their data and starts them again. A stack stops in reverse dependency order and starts in dependency order; before starting a container whose `depends_on` entry says `service_healthy`, drydock waits for that dependency's healthcheck to pass (at most 2 minutes per pass, then it starts anyway and the run log says so). Stop mode refuses running containers started with `--rm`. It also refuses a container in the network, IPC or PID namespace of another one that is not running (`network_mode: service:x` or `container:x`), which Docker would not start again, and stopping a container whose namespaces a running container shares when the run does not stop that one too, which would be left with only loopback until it is restarted. Back such containers up together in one stack job, or use pause mode.
- **Pause** freezes the containers (`docker pause`) while their data is read and unpauses them afterwards, so they keep running and their uptime is unchanged. Clients see a stall instead of a restart.
- **Live** reads the data while the containers run. The backup is crash-consistent at best: files are read while they are being written, so a database may not restore cleanly. The job form and the job page warn about this; prefer stop or pause, or a pre-hook that dumps the database to a file.

Before it stops or pauses anything drydock writes the list of containers it is about to stop or pause into the run, so a crash never leaves them down or frozen, and a stop or pause call that fails or times out still counts. The containers are started and unpaused again once the data is read, also when the run fails or is cancelled. Lifespan shutdown (`docker compose stop`, within the 90 second grace period) cancels runs and starts and unpauses their containers again. Startup recovery marks unfinished runs `interrupted`, unpauses and starts what they paused or stopped (a run on one of those containers waits until that is done), removes leftover helpers before any run can use the host and removes drydock's scratch files from the staging directory. What a run or startup recovery cannot unpause or start again is tried again with a new connection while the host is unreachable (an SSH tunnel that dropped), for as long as drydock runs, and drydock holds those containers until then; if drydock stops first, the next start carries on. What Docker itself refuses is named in the run's error, to be put right by hand. Containers that were already stopped or paused when the run started stay that way: drydock never stops a paused container and never starts one it did not stop. Drydock never stops, pauses or backs up live a running container of its own deployment (stopping or pausing the socket proxy would leave drydock unable to start anything again, and a live archive would hold drydock's own secret key).

**Stacks.** A job can back up a Compose project by its name, as `docker compose ls` shows it (1 to 63 lowercase letters, digits, `_` or `-`, Compose's own rule). Drydock finds the project's containers at run time by their `com.docker.compose.project` label, skipping one-off containers (`docker compose run`), drydock's own helper containers and originals a restore has set aside (`<name>-drydock-old`); a project with no containers fails the run. Compose files that several services share are stored once. The dependency order comes from the `com.docker.compose.depends_on` label, plus links, `volumes_from` and container network, IPC and PID modes; the containers of Compose v1 or an early v2, which carry no such label, stop and start in name order, and the run log says so. Stack jobs, and restores that stop, rename or recreate any container of a project, never overlap on that project.

**Hooks.** A hook is a command drydock runs with `docker exec` in a container before (pre-hook) or after (post-hook) a backup reads its data, such as a database dump. Hooks live in a library under **Hooks** in the menu: only a superadmin can add, change or delete one, with the password from the last 10 minutes, and every change is recorded in the audit log with its old and new values. Admins attach existing hooks to jobs by name. Each hook is bound by the superadmin to one host entry and either to one container (it attaches only to container jobs on that host whose target is exactly that container, so a job that names its container by ID needs a hook that names the same ID) or to one Compose project (it attaches only to that project's stack job on that host, and runs in one of its services or containers). Drydock checks the binding on every job save, on every hook edit and again when the run starts, so an admin cannot point a hook at another container or host. One known limit: an admin who changes a host entry's URL moves its hooks (and its jobs) with it. A host with hooks cannot be deleted, and a hook attached to a job cannot be deleted until it is detached.

- The command is a JSON array, the program and its arguments, passed to Docker as it is: no shell and no templating, so `["echo", "$(id)"]` prints `$(id)`. It runs as the container's user unless the hook sets one, without a TTY, stdin, extra privileges or environment variables of its own.
- The timeout is 1 to 3600 seconds (default 300). Docker cannot kill an exec, so a command that outlives its timeout keeps running in the container: wrap long commands in `timeout`, for example `["timeout", "250", "pg_dump", "-U", "postgres", "-f", "/var/lib/postgresql/data/dump.sql", "app"]`. The socket proxy closes a hook's connection after 10 minutes without output; drydock then keeps waiting for the exit code until the timeout.
- Pre-hooks run in order right before the first container is stopped or paused (in live mode, right before the data is read). A failing or timed-out pre-hook stops the run before anything is stopped or paused.
- Post-hooks run in order after every container is running again (after a bounded wait for the healthchecks of the containers drydock restarted). They run whenever the pre-hooks started, even after a failed pre-hook or a failed backup, so they must be safe to run when the pre-hooks did not all finish. Every post-hook is attempted, all of them together within one hour, and a failing one fails the run after the archive is stored. A cancel stops drydock waiting for post-hooks, but it still starts each remaining one.
- Output is not logged by default: the run log gets the number of bytes the hook wrote and, when it fails, the last 4 KiB of its standard error. A superadmin can turn on **Log the hook's output** for up to 64 KiB. Logged output is redacted like the rest of the log, but run logs are visible to every role that can see runs, viewers included, so write dumps to a file (`pg_dump -f`), not to standard output, and never print secrets. Drydock never logs a hook's command, but a shell's own messages may echo it (`sh -x`).
- A hook that is edited or deleted while a run waits for its turn fails that run; start it again.

**Schedules.** A job runs on a schedule when it has a cron expression and is enabled; without one it runs only when started by hand. The expression is standard five-field crontab (minute, hour, day of month, month, day of week), evaluated in the job's time zone, or in drydock's `TZ` when the job has none. The job form previews the next five runs as you type, computed exactly as the scheduler computes them.

- Day of week follows cron: `0` and `7` are Sunday, `1-5` is Monday to Friday, and `sun` to `sat` work too. (The scheduler library underneath numbers Monday as 0; drydock converts the field to day names first, so `0 3 * * 0` runs on Sundays at 03:00.)
- Restrict the day of the month or the day of the week, not both. Cron runs such an expression on either day, the scheduler only on days that match both, so drydock refuses it. Drydock also refuses a schedule that never runs (`0 0 31 2 *`), `N/step` in the day of week, and `@daily`-style names. The other fields also take the scheduler's extensions, such as `last` for the last day of the month and `5/10` for every 10 minutes from minute 5; the preview shows what they mean.
- Across a daylight-saving change a job keeps its local time. A local time that the clocks skip runs an hour later that day, and one they repeat runs twice (once in each offset; the preview shows both). Schedule outside the changeover hour, or use UTC, for a job that must run exactly once a day.
- Edits take effect at once, with no restart. A scheduled run is like **Run now**: it waits for other runs on its containers and never starts a second run of the same job while one is queued or running (it is skipped, and the server log says so). Runs started by the schedule show "the schedule" as who triggered them.
- If drydock is busy or stopped at a fire time, the run starts once when drydock gets to it, as long as that is within an hour of the fire time; several missed fires of the same job still run at most once. A fire missed by more than an hour does not run. When drydock starts, it writes the first such miss of each job (if no fire within the hour ran) to the server log and to the audit log (`job.schedule_missed`); a fire that a running drydock was too busy for is only in the server log. A scheduled run that drydock's own restart interrupted is not run again; startup recovery marks it interrupted and the next fire runs as usual.
- Only the process that holds the data directory lock runs the scheduler.

**Retention.** After each backup is stored, drydock deletes the job's older archives that its retention policy does not keep. A job has one policy:

- **Keep the newest backups** (the default, 7; at least 1).
- **Keep backups for a number of days.**
- **Daily, weekly, monthly and yearly**: the newest backup of each of that many recent days, ISO weeks (Monday to Sunday), months and years that have a backup, in the job's time zone. One backup can count for several, so daily 7 and weekly 4 usually keeps about 10.

The newest backup always stays, whatever the policy. Retention only touches archives whose name carries the job's ID, so a renamed job still prunes its old archives and never another job's, and it skips any archive an open restore uses. It is skipped when a post-hook failed. An archive it cannot delete does not stop it deleting the others, but the run then fails with the backup stored; a cancel stops it before the next deletion. A job edit that sends no retention fields (an API client older than retention) keeps the stored policy. Each deletion removes the catalog entry, is written to the run log and is recorded in the audit log, and policy changes are audited like every job edit. Deleting a job deletes no archives.

Runs that touch the same container or Compose project never overlap: the second one waits as `queued`, with a line in its log naming the run it waits for. A job has at most one queued or running run; **Run now** refuses another. **Cancel** takes effect within seconds and starts and unpauses the containers again (while a container is still stopping, drydock waits for the stop to finish first).

Each run has a log (`/data/logs/<run id>.log`) that the run page follows live. Once an hour drydock deletes finished runs older than `DRYDOCK_RUN_HISTORY_DAYS` (90 by default) with their logs, and any log left without its run. It keeps runs that startup recovery may still act on and runs whose page lists something to put right by hand (containers it could not start again, objects a restore left behind). Each pass deletes at most 10,000 runs, so the first pass after an upgrade may take a few hours to catch up, and each pass with deletions is recorded in the audit log (`runs.prune`). The backup catalog and the audit log are not pruned. The values of the container's environment variables, of the env files read with its compose files and the job passphrase are redacted before anything is written to it, and the UI never shows environment values.

### Notifications

Superadmins manage notification targets under **Notifications** (with the password from the last 10 minutes, like hooks); admins see them and attach them to jobs on the job page, for successful runs, failed ones or both (failed includes runs that were cancelled or interrupted by a restart of drydock). A target is one of:

- **Webhook**: drydock POSTs JSON (`title`, `message`, `type`) to an `http://` or `https://` URL. The URL's own query parameters are sent as they are; nothing in it can change the method, the headers or the payload.
- **Email** over SMTP, with STARTTLS (port 587 by default), TLS (465) or no encryption (25), and optional login.
- **ntfy** (ntfy.sh or your own server, with an optional access token) or **Gotify** (server and application token).
- **Other**: the [Apprise](https://github.com/caronc/apprise/wiki) URL of a chat or push service: `discord://`, `slack://`, `msteams://`, `tgram://`, `pover://`, `pbul://`, `gchat://`, `matrix(s)://`, `mmost(s)://`, `rocket(s)://` or `signal(s)://`. Anything else is refused, including local services such as `syslog://`, Apprise relays (`apprise://`) and a URL that holds more than one service.

The message names the job, the host, the run and its outcome, with the start of the run's error as the run page shows it (redacted like the run log) and a link to the run. It never contains log lines or archive contents, but the error and the job and host names do leave the system, to whatever service the target names. Each target is tried once, on its own, with a 10 second deadline (an SMTP server may take up to 15 seconds to refuse a connection); a failed notification is written to the server log and never changes the run. **Send a test message** on a target's page sends one now and shows whether the service accepted it.

A target's URL holds its credentials, so drydock stores it encrypted with the secret key and never shows it again: not on its page, in the form (even after a mistake), in the audit log or in the server log. To change it, enter the destination again. Notifications are sent from the drydock container to whatever host the URL names, internal addresses included, which is why only superadmins create targets: drydock's container can reach the Docker socket proxy, and a request there acts on Docker.

### Archives

An archive is a tar stream inside zstd:

1. `manifest.json`: what was captured, from which host, and how.
2. `config/` and `compose/`.
3. `volumes/`, `binds/` and `images/`.
4. `checksums.json`: the size and SHA-256 of every member, and an HMAC-SHA256 over that list made with the secret key.

A skippable zstd frame at the end holds the SHA-256 of the compressed stream, so any flipped byte is caught. Standard tools ignore that frame: `tar --zstd -xf drydock-....tar.zst` extracts an unencrypted archive. Archives signed with an older key still verify after a key rotation.

### Encryption and the passphrase

**Archives contain secrets.** The configuration scope stores the container's full inspect output, environment variables included, and Compose `.env` files usually hold database and API passwords. Jobs encrypt by default. Turn encryption off only if the storage itself is encrypted and private.

Encrypted archives (`.tar.zst.age`) use [age](https://age-encryption.org/) with a passphrase. Drydock never stores the passphrase: it derives it from the secret key and the job's random ID, which is in every archive name. As long as you keep the secret key, encrypted archives stay readable even after losing drydock's database.

To decrypt outside drydock, a superadmin opens the job and clicks **Reveal passphrase**. This needs the password from the last 10 minutes and is recorded in the audit log; no GET request ever returns a passphrase. After a key rotation the page also lists the passphrases under older keys, for older archives. Then:

```sh
age -d -o backup.tar.zst drydock-web-....tar.zst.age   # prompts for the passphrase
tar --zstd -xf backup.tar.zst
```

### Images stored by reference

The **Everything** scope saves every image by default. A job can instead store images "by reference only" when their registry still serves them. Drydock then asks the daemon to look up each of the image's registry digests (`GET /distribution/<repo>@<digest>/json`) and stores the image by reference only if the registry confirms that exact digest. Docker 29's default image store gives locally built and committed images a registry digest too, so a digest alone proves nothing. The image is saved in full whenever the lookup does not confirm it: a locally built image, a private registry the daemon cannot read without credentials, a digest the registry no longer has, or any error or timeout (10 seconds). The run log says which path each image took. A restore has to pull referenced images, so the registry must still serve them then.

## Restore

Admins restore from **Restore** in the menu. Every step is recorded in the audit log.

1. **Source.** Pick a storage target. Its archives are listed straight from the storage directory, newest first, so restore works even after drydock's database (and its backup catalog) is lost. The job, scope, source host and containers shown for each archive come from its first bytes and are an unverified preview; an encrypted archive shows only its name, size and time until it is verified.
2. **Verify.** Drydock reads the whole archive (an encrypted one with the passphrase it derives from the current or an older secret key) and checks every member's checksum, the signature, every name and path in the volume and bind mount data, and the images' embedded names, before any host is contacted. The page follows the log live. Metadata is staged encrypted in the staging directory (`restore-<run id>`, mode 0700), together with the image tars. At most 5 restores can be verified or waiting at once, and one not confirmed within 24 hours is discarded. **Discard** removes the staged data at any time. A restart of drydock ends every restore still verifying or waiting for confirmation (it becomes interrupted) and removes its staged data, so a long verification has to start over; restart drydock between restores, not during one.
3. **Plan.** Choose the target host and the mode. Planning reads the host's current state and changes nothing.
4. **Confirm.** The page lists every image, network, volume, container, wipe and data write the restore will make, its warnings and its flagged fields. Drydock plans again right before it runs, and refuses to run anything that differs from what was confirmed.
5. **Run.** The run page follows the log.

| Mode | What it does |
|---|---|
| New name | Restores the container beside the original under a new name. Its volumes and networks become `<new name>-<name>`. Compose labels, reverse-proxy and updater labels (`traefik.*`, `caddy*`, Watchtower), published host ports, static IP and MAC addresses and explicit subnets are dropped with a warning, so the copy cannot clash with the original. A writable bind mount must be remapped, skipped or explicitly shared with the original. |
| Overwrite | Stops the original, renames it `<name>-drydock-old`, wipes and rewrites its volumes (and the bind mounts you opt in one by one), creates the new container under the original name, and removes the old one only once the new one runs. On another host, with no original, it creates the original names. The network endpoints keep their static IP and MAC addresses; Docker does not report whether a MAC was set or generated, so a generated one stays fixed from then on. Typing the container name and your password from the last 10 minutes are required. |
| Data only | Writes volume and bind mount data into volumes that already exist on the target, chosen by name or as the volumes of a chosen container (by mount destination). Never into host paths, never wiped, and never into a volume that a container other than a created, exited or dead one uses. Needs your password from the last 10 minutes. |
| Images only | Loads the saved images and pulls the referenced ones. Nothing else. |

**Stacks.** An archive of a stack job restores in dependency order: the originals are stopped in reverse order, and the restored containers are created and started in dependency order, waiting for `service_healthy` dependencies as Compose does (at most 2 minutes each, then with a warning). A new-name restore of a stack takes a new Compose project name (Compose's rule, 1 to 63 characters) instead of a container name: the containers become `<project>-<service>-<number>`, the project's volumes and networks `<project>_<name>`, and nothing is shared with the original stack. The project labels are rewritten, and links, network aliases and endpoint links follow the new names. A new project name that already has containers on the target, or whose volumes or networks already exist there, is refused. An overwrite of a stack asks you to type the project name. Other archives with more than one container cannot be restored under a new name.

**Compose files.** A new-name or overwrite restore, of a stack or of a single container, can also write the archived compose files and `.env` files to a directory on the target host. It must be a new directory whose parent exists and is not `/` or a system directory (`/etc` and the other paths restored data never goes to are refused). Drydock creates it with `mkdir` (never `mkdir -p`), so it is never merged into a directory someone else made; it is owned by root with mode 0700 and the files by root with mode 0600, because `.env` files hold secrets. Files under the project's working directory keep their relative paths; the others go to `external/`. They are written after the restore has committed, and a failure to write them is logged without undoing the restore; the run page then warns that the files were not written (or, after a crash between the two steps, may not have been). The plan warns when a running container mounts a directory above the new one, since that container can then read the `.env` files.

**Unsigned archives and flagged fields need a superadmin.** An archive this drydock's secret keys did not sign could come from anyone with access to the storage, so only a superadmin can restore it, with the password from the last 10 minutes. A signature only proves that this drydock made the archive, not that what it holds is harmless (admins can add hosts and jobs), so the same applies to every flagged field, signed or not: privileged mode, added capabilities, devices and device requests, host or container PID, IPC and network modes, user namespace, UTS and cgroup namespace modes, security options other than no-new-privileges, another runtime, sysctls, a cgroup parent, a negative OOM score adjustment, a disabled OOM killer, a non-local volume driver, volumes from other containers, binds of sensitive paths and their mount propagation, host-backed or non-local volumes, macvlan, ipvlan and custom bridge networks (including existing ones a restore joins), image tags that would move, setuid, setgid or file-capability files in bind data and in host-backed volumes, and bind data written to another host or another path than the archive's. A superadmin acknowledges each flagged field separately.

**The host-path denylist applies to every role, superadmin included.** A restored container may not bind `/`, exactly `/etc`, `/run`, `/var/run`, `/var` or `/var/lib`, anything under `/proc`, `/sys`, `/dev`, `/boot`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`, `/var/lib/rancher`, `/var/lib/kubelet`, `/var/lib/buildkit`, `/etc/rancher` or `/etc/kubernetes`, the runtime directories `/run/{docker,containerd,podman,crio,k3s,buildkit,user}` (and the same under `/var/run`; `/run/user` holds rootless daemons' sockets), or any file named `docker.sock`, `containerd.sock`, `podman.sock`, `crio.sock`, `cri-dockerd.sock` or `buildkitd.sock`. Restored data and wipes also never go under `/etc`, `/usr`, `/bin`, `/sbin`, `/lib*` or `/root`, nor into `/home` or `/var/home` itself, nor under `/var/roothome`, `/var/usrlocal`, `/sysroot` or `/ostree` (the ostree locations of those directories). A new-name restore refuses volumes on network shares (`nfs`, `nfs4`, `cifs`, `smb3`) and volumes of non-local drivers; restore those in overwrite mode. A local volume with a `device` and `o=bind` counts as a bind of that host path. Paths are checked as written when planning and again as the host resolves them, symbolic links followed, right before each mount, and the resolved path is what is mounted. Data goes into a host directory only if it already exists. Nothing may join or mount drydock's own containers, networks or volumes, and no tag of an image drydock itself uses is moved.

**Restored objects are labelled.** Every container, volume and network a restore creates carries `drydock.restore.run=<run id>` for good. If a restore fails or is cancelled, drydock removes only what it created (by the IDs it journaled, and only with that label), gives the originals their names back and, if no data was touched yet, starts them again. Once a wipe or data write has begun the originals stay stopped, because their data may be partial, and the run page says which volumes and bind mounts are affected. After a crash, startup recovery does the same. Images are the exception: a rollback does not remove the images a restore loaded or pulled, nor move back the tags it moved (an `app:latest` it retagged keeps pointing at the restored image), so check the image list after a failed restore that the plan said would move a tag. `drydock.*` labels inside an archive are never restored.

**Permissions and attributes.** Data moves through Docker's archive API, which keeps numeric owners, modes, setuid and setgid bits and the `security.capability` attribute (file capabilities), but drops ACLs and other extended attributes. Setuid, setgid and file-capability files in bind mount data are flagged rather than stripped, so a restore keeps them as they were.

**Compose.** An overwrite restore keeps the container's Compose labels, including `com.docker.compose.config-hash` from the time of the backup. If the compose file has changed since, the next `docker compose up` sees a different hash and recreates the container from the current file; its volumes and their restored data stay. A new-name copy of a single container has no Compose labels, so Compose does not manage it; a new-name copy of a stack is a Compose project of its own.

**Time.** A restore reads the archive twice: once to verify all of it before anything changes, and again to stream the data onto the host, checking every member against the first pass. Plan for two full reads (and decryptions) of the archive, plus room in the staging directory for its images and metadata.

**The socket proxy closes a request that stays idle for 10 minutes.** Drydock never leaves one idle that long: it waits for helpers in one-minute polls, and an image load streams progress the whole time.

## Container hardening

The container runs with a read-only root filesystem, no capabilities and `no-new-privileges`. State lives in the `drydock-data` volume at `/data`. `stop_grace_period` is 90 seconds so drydock can restart containers it stopped before Docker kills it.

Remote storage goes through rclone v1.75.2 (checked against a pinned SHA-256 at build time), which drydock runs as a child process, `rclone rcd`. It listens only on `/run/drydock/rclone.sock` (mode 0600), never on TCP, and every call needs a random password made when drydock starts. The password reaches rclone through its environment, so it is not visible in `ps`. rclone gets no `rclone.conf`: its configuration stays in memory, and none of the container's `RCLONE_*` variables reach it. Drydock restarts rclone if it exits. Each call carries the target's settings inline, passwords obscured. rclone also serves objects on the same socket (`--rc-serve`, same password) because that is its only ranged read, which the restore listing uses to preview archives. Drydock redacts the settings from any log line that would quote them.

## Phase 1 measurements and decisions

Measured on 2026-10-13 on Windows 11 with Docker Desktop (engine 29.8.2, 32 CPUs). The SSH host is the `docker:29.9.0-dind` container from `compose.test.yaml`, so SSH runs over a local network with almost no round-trip time. Real hardware will give other numbers; rerun them with the commands at the end of this section.

### Volume round trip (`tests/test_stream_probe.py`)

A 1 GiB volume (four 256 MiB files owned by uid 999 with mode 0600, a 0700 directory, an absolute symlink and empty directories) is exported with `get_archive` into a staging file under `DRYDOCK_STAGING_DIR`, imported with `put_archive` into a new volume and read back. On all three paths every member's type, uid, gid, mode, size, link target and sha256 matched, and so did checksums written inside the volume by the container that filled it. `/healthz` was requested every 50 ms during each transfer.

| Path | Export (get_archive) | Import (put_archive) | /healthz max (p99) |
|---|---|---|---|
| Local host through the socket proxy (Docker Desktop daemon) | 177 MiB/s | 14 MiB/s | 27 ms (4 ms) |
| sshhost daemon over plain TCP (baseline) | 333 MiB/s | 505 MiB/s | 15 ms (3 ms) |
| sshhost daemon over the SSH tunnel | 326 MiB/s | 354 MiB/s | 15 ms (6 ms) |

The slow local import comes from Docker Desktop's daemon, not the proxy: `put_archive` straight to its `docker.sock` measured 13 to 15 MiB/s too, whether the body was chunked, had a `Content-Length` or was sent from memory. Comparing SSH with that daemon would say nothing about SSH, so the throughput gate compares the tunnel with plain TCP to the same dind daemon.

### SSH throughput gate: passed

SSH reaches **98% of plain TCP for export and 70% for import**, against a gate of 30%, so parallel channels are not needed. asyncssh prefers chacha20-poly1305 by default; switching to AES-GCM was the change that mattered (512 MiB volume, same daemon):

| SSH setting | Export | Import |
|---|---|---|
| Plain TCP, no SSH | 323 MiB/s | 469 MiB/s |
| chacha20-poly1305, 2 MiB window, 32 KiB packets (asyncssh defaults) | 259 MiB/s | 255 MiB/s |
| chacha20-poly1305, 8 MiB window, 256 KiB packets | 256 MiB/s | 251 MiB/s |
| aes128-gcm | 332 MiB/s | 356 MiB/s |
| aes256-gcm | 332 MiB/s | 361 MiB/s |
| aes128-gcm, 8 MiB window, 256 KiB packets | 336 MiB/s | 359 MiB/s |

Window and packet size made no difference here because the link has almost no round-trip time. Drydock still uses an 8 MiB window and 256 KiB packets, because one channel never moves more than window / RTT: the default 2 MiB window caps a 50 ms link at 40 MiB/s, and 8 MiB raises that to 160 MiB/s. The cipher order is AES-256-GCM, AES-128-GCM, then chacha20-poly1305, AEAD only.

### Archive encryption (`tests/test_age_spike.py`): the age CLI

The plan's order was pyrage with an age passphrase, then the `age` binary through pipes, then chunked AES-GCM. Each mode runs in its own process. Encryption feeds decryption through a pipe, so nothing touches disk; plaintext is hashed on both sides, RSS is sampled every 100 ms, and a 10 ms ticker thread records the longest GIL stall. MiB/s is plaintext throughput with encryption and decryption running at the same time.

| Method | 10 GiB round trip | Throughput | RSS growth | Longest GIL stall |
|---|---|---|---|---|
| 1. pyrage 1.4.0 `passphrase.encrypt/decrypt` (scrypt) | Not streamable (bytes in, bytes out). 256 MiB grew RSS by 514 MiB, so 10 GiB needs about 20 GiB of RAM | 60 MiB/s (at 256 MiB) | Twice the input | 2 s (scrypt holds the GIL) |
| 2. age 1.3.2 CLI through pipes, with `age-plugin-batchpass` | Passed, sha256 matched | 392 MiB/s | 2.3 MiB in Python; the age processes peaked at 5 and 10 MiB | 0.3 ms |
| Outside the plan: pyrage `encrypt_io/decrypt_io` with an X25519 identity | Passed, sha256 matched | 197 MiB/s | 0.8 MiB | 1.4 ms |

**Decision: step 2, the age CLI driven through pipes.** Step 1 fails because pyrage streams only to recipients and identities, never to passphrases. The CLI streams with flat memory, runs twice as fast as pyrage's streaming API and keeps archives in the plain age passphrase format the plan asked for: batchpass writes a standard `scrypt` stanza, so `age -d backup.tar.zst.age` decrypts an archive with an interactive passphrase prompt and no plugin. Drydock will hand the per-job passphrase to age through an inherited file descriptor (`AGE_PASSPHRASE_FD`), never on the command line or in the environment, and run age without a shell. Chunked AES-GCM (step 3) is not needed.

Consequences for Phase 2: a build stage downloads the age v1.3.2 release for the target architecture, checks a pinned SHA-256 (linux-amd64: `cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10`, linux-arm64: `6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4`; `compose.test.yaml` already fetches it this way for the tests) and copies only `age` and `age-plugin-batchpass` into the image. pyrage stays a test-only dependency.

The alternative in the last row needs your approval before anything uses it. It streams through pyrage with no extra binary, and the age manual recommends native keys over passphrases when a program holds the secret. It would turn decision 8's per-job passphrase into a per-job age identity (`AGE-SECRET-KEY-1...`), still derived from the secret key with HKDF and the job UUID, so it still survives losing the database. Decrypting outside drydock would then take `age -d -i key.txt` instead of a typed passphrase. Stock age 1.3.2 and pyrage decrypted each other's output with an X25519 identity. The spike now uses a random identity, which streams the same way; the derivation would be written and tested in Phase 2 if this is approved.

To repeat these runs:

```sh
docker compose -f compose.test.yaml run --rm tests uv run --no-sync pytest -s tests/test_stream_probe.py
# 10 GiB encryption runs. The tests image carries age 1.3.2, checked against the SHA-256s above.
docker compose -f compose.test.yaml run --rm -e DRYDOCK_AGE_SPIKE_GIB=10 tests uv run --no-sync pytest -s tests/test_age_spike.py
```

## Phase 2 measurements

Same machine as above, local host through the socket proxy (`tests/test_runs_docker.py`):

| Check | Result |
|---|---|
| 5 GiB volume, encrypted backup, fresh drydock process | 70 to 71 s; drydock RSS 137 MiB at the start of the run, peak 163 to 165 MiB; age peaked at 6 to 17 MiB (limit: 300 MB together) |
| Cancel during a 1 GiB volume capture | container running again 0.24 to 0.25 s after the request (limit: 5 s); the run is marked `cancelled` once Docker Desktop releases the helper, 7 to 21 s later, because it finishes reading the volume first |
| SIGTERM (`docker compose stop`) mid stop-mode backup | drydock exited in 9 to 22 s (grace period: 90 s) with the container running again and the run `cancelled` |
| `/healthz` during a 1 GiB transfer through the proxy | max 25 to 33 ms, p99 5 ms |

```sh
docker compose -f compose.test.yaml run --rm tests uv run --no-sync pytest -s tests/test_runs_docker.py
```

## Development

The app needs Linux (`fcntl`, unix sockets), so Python always runs in containers. Node 24 LTS on the host builds the client code and stylesheet.

### Dev loop (Windows or Linux)

```sh
npm ci --ignore-scripts
npm run build                      # TypeScript, Tailwind CSS + daisyUI, vendored htmx
mkdir -p secrets && <generate a key into secrets/drydock_secret_key as above>
docker compose -f compose.dev.yaml up --build
```

`src/` is bind-mounted into the container and uvicorn reloads when Python files change. On Windows the repo sits on NTFS, where inotify events do not reach the Linux VM, so the dev compose file sets `WATCHFILES_FORCE_POLLING=true`. Run `npm run watch:css` and `npm run watch:js` on the host while editing templates or `frontend/`.

### Tests

```sh
# Ruff and pytest, in Linux
docker compose -f compose.test.yaml run --rm tests
docker compose -f compose.test.yaml down --volumes

# CSP smoke test: headless Chromium against the production image
docker compose -f compose.test.yaml up --build --abort-on-container-exit --exit-code-from smoke app smoke
docker compose -f compose.test.yaml down

# TypeScript type checks
npm run check
```

CI runs only on git.wenberg.net (Forgejo Actions, `.forgejo/workflows/ci.yml`), on a runner whose jobs drive its host's Docker daemon; `compose.ci.yaml` swaps the checkout's bind mount for a volume there and skips the `slow` tests, whose latency ceilings a busy shared runner cannot hold. A newer push cancels the run in progress, and Markdown-only changes start none. The repository is pushed to GitHub too, without any workflow.

The integration tests reach the host's Docker daemon through the same socket proxy as production and create (then remove) containers and volumes there. A privileged `docker:dind` container running sshd stands in for a remote host; the tests generate the SSH key pair in memory and authorize it at test time. The Phase 1 spikes (marked `slow`) move a gigabyte through each path and need about 4 GB free in the Docker VM; `pytest -m 'not slow'` skips them.

### Frontend rules

- The CSP allows no inline scripts, inline styles or eval. Scripts need the per-response nonce, and DOM HTML sinks are limited to htmx's Trusted Types policy.
- No `hx-on` attributes. Client behaviour lives in `frontend/app.ts`.
- Every element with an `hx-` attribute carries `hx-nonce="{{ csp_nonce }}"`. The hx-csp extension strips htmx attributes from any element without it, so injected markup cannot send requests that inherit the CSRF header.
- One stylesheet, `/static/css/app.css`, compiled from `frontend/app.css` by the Tailwind CLI. daisyUI components that embed `data:` URLs are excluded.
