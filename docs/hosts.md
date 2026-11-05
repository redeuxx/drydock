# Docker hosts

Drydock talks to every host through the Docker Engine API, versions 1.44 to 1.56 (Docker Engine 25.0 or later). It reads the daemon's `/version` and uses the highest version both sides support, capped at 1.56. Older daemons are refused.

**Every host you add hands drydock root on that host.** Docker API access is root-equivalent: whoever can create containers can mount `/` and start privileged containers. That holds for the local socket proxy and for every SSH user drydock logs in as. Only admins manage hosts, and drydock never adds one by itself, not even the local host. Every role may view a host's container inventory (`/hosts/<id>/containers`), as the role matrix allows.

## The local host

`compose.yaml` runs [linuxserver/socket-proxy](https://github.com/linuxserver/docker-socket-proxy) next to drydock. Only the proxy mounts `/var/run/docker.sock` (read-only, on an `internal` network with no route out); drydock reaches it at `tcp://socket-proxy:2375` and never mounts the socket. The proxy allows containers, images, volumes, networks, exec, archive, start, stop, restart, pause, unpause, container logs (for the [logs page](#container-logs)) and events (for [activity](#activity)), plus the read-only registry lookup `GET /distribution/<image>/json` (see [Images stored by reference](backups.md#images-stored-by-reference)). It denies everything else, including build, commit, swarm, secrets, plugins and system.

**The socket proxy is not a security boundary.** It narrows the API to what drydock uses, which limits accidents and makes misuse noisier, but the endpoints drydock needs (container create, exec, archive) are already enough to take over the host. Treat anything that can reach `socket-proxy:2375` as root on the host; that is why it sits on an internal network shared only with drydock.

To add it, open **Hosts > Add local host**. The Docker URL is prefilled from `DRYDOCK_LOCAL_DOCKER_URL`. A local host's `tcp://` or `http(s)://` URL must name a service on drydock's Docker network (such as `socket-proxy`) or a loopback or private address, since that API is unauthenticated; link-local addresses such as cloud metadata are refused. Reach any other machine over SSH. **Test connection** then shows the engine version, the negotiated API version and the platform, and the container inventory loads below.

## Remote hosts over SSH

Any user on the host who can use Docker will do: root, or a user in the `docker` group. Stock sshd settings are enough.

1. **Hosts > Add SSH host**: a name, the host's address (host name, domain or IP) and the user. Port 22, the Docker socket path and "Generate a new ed25519 key" are filled in.
2. On the host page, click **Scan host key** and compare the fingerprint with the host's own (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on it). This is what makes sure drydock talks to that host and not to something in between.
3. Enter the user's SSH password and click **Trust this key**. Drydock scans again and pins the key only if it still matches, then logs in once with the password, against that pinned key, and adds its own public key to the user's `~/.ssh/authorized_keys`, as `ssh-copy-id` does. The password is never stored or logged.

The tunnel connects within seconds; **Test connection** confirms it. Trusting needs your drydock password from the last 10 minutes, and both the trust and the key install are in the audit log.

If the host refuses password logins (root usually does), leave the password empty: paste the line shown under **SSH key** into that user's `~/.ssh/authorized_keys` yourself, then trust the host key. A trusted host shows the password field again after a scan, for example after you replace drydock's key.

### How the connection works

Drydock keeps one SSH connection per host and forwards a private unix socket (`/run/drydock/hosts/<id>.sock`, mode 0600 in a 0700 directory) to the remote Docker socket. The private key is stored encrypted with the secret key and only ever exists in memory; drydock can generate an ed25519 key pair or accept a pasted key. A pasted key's passphrase is used once to decrypt it and then discarded: the key is kept decrypted inside the encrypted token, so no passphrase is stored and no passphrase KDF runs when tunnels start. Encrypted OpenSSH keys with more than 1024 KDF rounds and encrypted PKCS#8 keys are refused (`ssh-keygen -p -f <file>` converts them). Pages show only the public key and fingerprints, and a pasted key or passphrase is never sent back to the browser. The tunnel offers only public key authentication (the password above is used once, for the key install), and only AEAD ciphers (AES-GCM first, then chacha20-poly1305).

### Optional hardening

The user drydock logs in as can reach the Docker socket, which is root-equivalent on that host. To narrow everything else down:

- Use a dedicated user in the `docker` group, for nothing else.
- Keep everything but the forward off for that user in `sshd_config` (sshd only allows unix socket forwards together with TCP forwards):

  ```
  Match User drydock
    AllowStreamLocalForwarding local
    AllowTcpForwarding local
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    ForceCommand /bin/false
  ```

  With `ForceCommand` set, the password install cannot run; paste the key line instead.
- The key line drydock installs is already restricted: `restrict,port-forwarding,command="/bin/false" ssh-ed25519 AAAA... drydock`. The forced command refuses shells, commands and subsystems such as sftp; the forward still works. OpenSSH cannot allow the socket forward while refusing TCP forwards (`permitopen` and `PermitOpen` block unix socket forwards too), so the key can still open TCP connections from the host. That adds nothing to the Docker access it already grants, which is root on the host.
- For rootless Docker, set the host's socket path (for example `/run/user/1000/docker.sock`).

The host key is pinned to that address and port. Changing either clears the trusted key, and the new endpoint has to be scanned and trusted again. If a host later presents a different key, including a key of another type (which fails key exchange, because drydock offers only the pinned key's algorithm), drydock refuses the connection, makes no Docker call, shows a host key mismatch on the host pages and writes a `host.hostkey_mismatch` audit event with the presented fingerprint. It does not retry until an admin trusts a key again. A changed host key after a reinstall is expected; treat one you cannot explain as an attack until proven otherwise.

## Container status

The dashboard shows a card per host: containers by state, unhealthy containers by name, CPU and memory, images, volumes, networks and Compose stacks (all, some or none of their containers running). Every role sees the cards; only admins see each host's address and a link to its settings. Each card's memory is what its containers use, of the host's total. The counters open the containers page filtered to their state.

**Containers** in the top menu lists one host's containers: state and health, uptime, restarts, CPU, memory, network and disk I/O, address, published ports, Compose stack, and the backup jobs that cover each container. Clicking a row shows all of it. Search (name, image, label), filter by state or stack, and sort by any column; the table refreshes every 10 seconds and keeps all of these, and the address bar keeps them too, so a filtered view can be bookmarked. The menu's Containers link opens the last host chosen in this browser. Published ports link to the host: drydock's own address (`BASE_URL`) for the local host, the SSH host's address for admins. Every role sees the page, but only admins see an SSH host's address, and only their searches match label values, since labels can hold credentials.

Operators can start, stop, restart, pause and unpause containers, one row at a time or the selected rows together; stop and restart ask first, and give each container its own stop timeout. Drydock refuses to act on itself, its own Compose project (the socket proxy among them) and its helper containers, and on a container a backup or restore is using; a backup that starts meanwhile waits for the action. Every container acted on is in the audit log, and the page shows the host as read right after. Admins can also inspect a container (its row's dialog): the full `docker inspect` output, with environment values, secret-looking labels and log driver options shown as `***`. Command lines are shown as they are, so keep secrets out of them.

For them drydock reads each host's containers (list and inspect), their one-shot stats, `/info`, and the volume and network lists, over the same connection as everything else: the socket proxy, or the host's SSH tunnel. It needs nothing beyond what the proxy already allows. One background task reads a host every 10 seconds, and only while a page has shown it in the last minute, so an idle drydock makes no extra Docker calls; pages show what it last read and never call Docker themselves. CPU is the containers' share of the whole host and shows from a host's second reading on, since one reading has nothing to compare with. Memory leaves out page cache, as `docker stats` does. A host that cannot be read keeps its last reading, marked stale, and the error goes to the server log.

Sparklines under the cards' CPU and memory bars, and under each container's CPU and memory in the table, show the latest readings: about 10 minutes of a host and 5 of a container. They live in memory only, so they start empty after a restart and when a page shows the host again after a quiet spell, and a missing reading breaks the line.

### Newer images

Drydock checks every 6 hours (the first time 2 minutes after it starts) whether a host's containers run the image their tag names on the registry now. It asks the registry through the host's daemon (`GET /distribution/<image>/json`, the read-only lookup the socket proxy already allows) which digest the tag names, and compares it with the digests the container's image was pulled as; nothing is pulled or changed. The containers page marks such a container "update" and filters them ("Update available"), and the host's card counts them. A tag that was already pulled anew on the host (say by `docker compose pull`) while the container still runs the old image counts as an update too. Not checked: containers pinned by digest or created from an image ID, and images built on the host. A private registry refuses the daemon's anonymous lookup, which the row shows as an error.

Operators can check a host at once with **Check for updates** (at most once a minute per host; in the audit log, since it makes drydock contact registries). Registries limit lookups (Docker Hub counts them against the host's pull allowance), so one lookup answers every container of the same image and tag, and is reused for 6 hours. Results live in memory and are made again after a restart. Updating them is described in [Container updates](updates.md).

## Container logs

**Logs** in the top menu (admins only) shows container logs, live. Pick a host and a container from the list on the left; the filter box narrows the list, and a star keeps a container at the top (per host, in this browser). Check up to 10 containers and **Show checked** to see them together, merged into one log by time (each line starts with its container's name) or side by side; **Whole stacks** opens every container of a Compose project side by side. A log opens with its last 500 lines (100, 500, 1,000 or 5,000) and adds new lines every 2 seconds, in drydock's time zone, with stderr in red. It follows the end while you are there; scroll up to read and it stays put. Pause stops the updates without losing lines, and Clear empties the view only. Timestamps, line wrap and text size can be switched, a search marks matches in the lines shown, Copy puts them on the clipboard (over HTTPS), and Download saves the last lines as a text file (times in UTC, at most 16 MiB read).

Application logs routinely hold tokens, email addresses and stack traces with secrets, so only admins read them, and drydock never stores them. Escape sequences and control characters are removed, a line longer than 16 KiB is cut, and one update reads at most 2 MiB of logs, shared by the containers shown (a busy log catches up over the next updates). Reading a log is not audited: drydock audits changes, not reads.

The local host's socket proxy allows `GET /containers/<id>/logs` for this (`ALLOW_LOGS=1` in `compose.yaml`); an install from before this version needs the new `compose.yaml` and `docker compose up -d`, which recreates the proxy. SSH hosts need nothing new.

## Activity

Drydock keeps a record of what happens to containers on every enabled host: created, started, stopped, died (with the exit code), killed, restarted, paused, health check results, exec sessions and so on, as Docker reports them. Each host's card on the dashboard counts its events today (in drydock's time zone) and in all, and links to them.

**Activity** in the top menu lists them, newest first, for every role: time, host, action, container, image and exit code (green for 0, red otherwise); clicking a row shows every stored field. Filter by container (part of its name, or the start of its ID), action, host and time range (the last hour, 24 hours, 7 or 30 days, or all); the address keeps the filters. The newest page adds new events every 5 seconds; older pages stay as they are while events arrive. Admins can clear the record of one host or of all hosts, which needs their password from the last 10 minutes and is in the audit log.

Unlike the container status, this runs all the time, whether or not anyone looks: one long-lived `GET /events` stream per host (container events only), over the same connection as everything else. A host's first stream starts from the daemon's present. When a stream drops, drydock opens it again after a growing pause (up to a minute) from the newest event it stored for that host, so a short outage or a drydock restart within Docker's own event buffer loses nothing, and an event sent twice is stored once. A disabled host is not followed. Drydock leaves out its own helper containers.

Only the time, the action, the container's ID, name and image, a die's exit code and a health check's result are stored. Docker's events also carry every label of the container and, for exec sessions, the command line; drydock drops all of that, since either can hold secrets. Events are written in batches, so hundreds of containers created at once (a CI runner) cost a few database writes. Drydock keeps 30 days of events and at most 200,000 in all, pruned at start and hourly, so a very busy host can push older events of every host out sooner. Deleting a host deletes its events, and a host whose connection changes (another daemon) is followed from that moment on.

The local host's socket proxy allows `GET /events` for this (`EVENTS=1` in `compose.yaml`); an install from before this version needs the new `compose.yaml`. SSH hosts need nothing new.

## Alerts

Each host page has an **Alerts** card (admins): turn alerts on, and pick a notification target to tell besides the bell. With alerts on, drydock tells, once per change and again when it recovers:

- a container becomes unhealthy (and healthy again);
- a container exits with a nonzero code nobody asked for: an exit right after `docker stop`, `docker kill` or `docker compose down` (a kill within 30 seconds) does not count;
- a container restarts 5 times within 10 minutes (and when it has been quiet for 10 minutes);
- the host's event stream has failed for 5 minutes (and when it is back).

Alerts come from the same container events as [Activity](#activity), so they need nothing more from the host. Containers a backup, restore or update is working on are left out: stopping and starting them is the run's job. Admins see alerts in the bell, which links to the host's containers; each is also in the audit log. What drydock last told is kept in memory, so after a restart an ongoing problem is told again when it next changes. Deleting a notification target removes it from the hosts that told it.

## Helper containers

To read and write volumes drydock runs short-lived helper containers (`busybox`, pinned by multi-arch digest) with no network, a read-only root filesystem, no capabilities (except two restore helpers, each running a fixed command: the wipe helper gets exactly `DAC_OVERRIDE` and `FOWNER`, and the data helper, which gives a restored directory its archived owner and mode after the data is written, exactly `CHOWN`, `FOWNER` and `FSETID`), `no-new-privileges`, a PID limit and the labels `drydock.helper=1` and `drydock.instance=<installation ID>` (a random ID made when the database is created). Volume data moves through the daemon's archive API, so a transfer helper is never even started. Helpers are removed when the transfer ends, and a reaper removes leftovers when drydock starts and hourly after that on every host reachable at that moment, skipping any helper a run is still using. The reaper and the container inventory act only on helpers carrying this installation's ID, so two drydock instances (or the test suite) can share a daemon.
