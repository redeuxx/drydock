# Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DRYDOCK_SECRET_KEY_FILE` | | Path to the key file (preferred). Several keys, newest first, allow rotation. |
| `DRYDOCK_SECRET_KEY` | | The key itself, if a file is not possible. |
| `DRYDOCK_BASE_URL` | `http://localhost:8000` | Origin users browse to, exactly (scheme, host and port). Used for CSRF origin checks and cookie flags. Set it in `.env` next to `compose.yaml`. |
| `DRYDOCK_ALLOWED_HOSTS` | host of the base URL | Accepted `Host` headers. `localhost` and `127.0.0.1` are always allowed. |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies whose `X-Forwarded-For` is trusted. Required behind a reverse proxy; see below. |
| `DRYDOCK_STAGING_DIR` | `/data/staging` | Scratch space for transfers. A backup needs about the size of its largest member (volume, bind mount or image) here; mount a larger disk if needed. It must not be the data or run directory or contain them. It must belong to this one installation and hold nothing else: archives uploaded for a restore wait in its `uploads` folder for 24 hours. Drydock deletes its own scratch names there (`member-*`, `probe-*.tar`, `trash-*`, `restore-<number>`) at startup, and in an hourly cleanup (scratch files only while no run is active; a staged restore once its run is finished). |
| `DRYDOCK_LOCAL_STORAGE_ROOTS` | | Directories (separated by commas or spaces) inside which storage targets may live. Each must be mounted into the container and writable by uid 10001. |
| `DRYDOCK_RESTORE_PATHS` | | Directories (separated by commas or spaces) whose files an admin may restore from by path, on the restore page. `compose.yaml` sets `/restore-inbox`, mounted read-only from `./restore-inbox`; files there must be readable by uid 10001. Symlinks are resolved and must stay inside; only regular files with drydock's archive names are opened. Unset: restores from a path are off. Only the environment sets it. |
| `DRYDOCK_LOCAL_DOCKER_URL` | | Docker URL suggested when an admin adds the local host. `compose.yaml` sets it to the socket proxy. Drydock never registers a host by itself. |
| `DRYDOCK_HELPER_IMAGE` | `busybox:1.37.0` pinned by digest | Image for helper containers. Must be pinned by digest (`name@sha256:...`); use the multi-arch index digest. Point it at a mirror on air-gapped hosts. |
| `DRYDOCK_RUN_DIR` | `/run/drydock` | Private tmpfs for the SSH forward sockets. |
| `TZ` | `UTC` | Time zone for schedules without one of their own. Must be a listed zone name such as `America/Chicago`. A container does not inherit the host's zone: set it in `.env`, then run `docker compose up -d`. |
| `DRYDOCK_RUN_HISTORY_DAYS` | `90` | Finished runs older than this many days (1 to 36500) are deleted with their log files, hourly from 5 minutes after start. It cannot be turned off; 36500 keeps history for good. |

## Changing the address

`DRYDOCK_BASE_URL` is the one address drydock answers on, for example when you move from the host's IP to a domain, or put HTTPS in front later. It is set only in `.env`, never in the UI, because it drives the Host and origin checks that stop cross-site requests.

1. Edit `.env` in the drydock folder, for example `DRYDOCK_BASE_URL=https://drydock.example.com`.
2. Run `docker compose up -d` there. Compose recreates the container with the new value; the database, jobs and archives are untouched.
3. Browse to the new address. The old one now answers `Invalid host header`.

Also check:

- **HTTP to HTTPS (or back)** renames the session cookie, so everyone signs in again once.
- **A reverse proxy** needs `FORWARDED_ALLOW_IPS` and, usually, the port published on loopback only; see [Behind a reverse proxy](#behind-a-reverse-proxy).
- **Google Drive storage with a web application client** uses `<DRYDOCK_BASE_URL>/storage/oauth/callback` as its redirect URI. Add the new one to the client in the Google Cloud console, then click **Connect to Google** on the storage page again. A desktop app client is not affected.

## Who can reach drydock

`compose.yaml` publishes port 8000 on every interface. Docker adds its own firewall rules for published ports, ahead of ufw and firewalld, so a host firewall does not limit who reaches it; a firewall in front of the host does. To keep drydock off the network, publish `"127.0.0.1:8000:8000"` instead and reach it through an SSH tunnel (`ssh -L 8000:127.0.0.1:8000 you@host`, then <http://localhost:8000>, with `DRYDOCK_BASE_URL=http://localhost:8000`) or a reverse proxy on the host.

Over plain HTTP on a LAN address, session cookies go without the `Secure` flag and drydock warns at every start. Anything beyond a trusted LAN should use HTTPS through a reverse proxy.

## Behind a reverse proxy

Publish `"127.0.0.1:8000:8000"` in `compose.yaml` so only the proxy reaches drydock, point the proxy on the same host at `http://127.0.0.1:8000`, have it set `X-Forwarded-For`, and set `DRYDOCK_BASE_URL` to the public `https://` URL. Drydock then sends `Strict-Transport-Security`.

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
