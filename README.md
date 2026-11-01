# Drydock

Drydock is a self-hosted web app that backs up and restores Docker containers, volumes and Compose stacks, on the local host and on remote hosts over SSH.

Backups run on a schedule or by hand, in stop, pause or live mode, with pre- and post-hooks. Archives are signed and encrypted by default, and go to a local directory, SFTP, SMB, WebDAV or Google Drive. A restore goes onto any managed host, under a new name or over the original.

## Read this first

- **Drydock is root-equivalent on every host it manages.** Anyone who controls it can start privileged containers, read every volume and replace any container. Treat access to its UI like root SSH access to all of those hosts. The same goes for the SSH user it logs in as on each host, and for the socket proxy, which narrows the local Docker API but is not a security boundary ([hosts](docs/hosts.md)).
- **The first visitor becomes superadmin.** Until `/setup` has been submitted, anyone who can reach the port can take over. Complete setup right after the first start, over an SSH tunnel.
- **Archives contain secrets**: environment variables and Compose `.env` files. Keep jobs encrypted unless the storage itself is encrypted and private.
- **Live mode is crash-consistent at best.** Back databases up in stop or pause mode, or dump them with a pre-hook ([backups](docs/backups.md#jobs-and-runs)).
- **Back up the secret key on its own, away from `/data`.** It encrypts stored credentials, signs archives and is the source of every archive passphrase:

  | You lose | What happens |
  |---|---|
  | Only the database (`/data`) | Nothing in your archives. A new drydock with the same key lists, verifies and restores them all. Hosts, storage, jobs and users have to be set up again. |
  | Only the key | Stored credentials have to be entered again. Every encrypted archive is unreadable for good, and the unencrypted ones show as unsigned, so only a superadmin can restore them. |
  | Both | Every encrypted archive is gone. |

  Don't keep the key in the same backup as the `drydock-data` volume: anyone holding both can read every archive.

## Install

You need Docker Engine 25 or later with the Compose plugin, and this repository:

```sh
git clone https://github.com/redeuxx/drydock.git
cd drydock
```

1. Generate the secret key and restrict it. Drydock runs as uid 10001 and refuses to start if it cannot read the key.

   ```sh
   mkdir -p secrets
   openssl rand -base64 32 | tr '+/' '-_' > secrets/drydock_secret_key
   sudo chown 10001:10001 secrets/drydock_secret_key
   sudo chmod 0400 secrets/drydock_secret_key
   ```

2. Start drydock:

   ```sh
   docker compose up -d --build
   ```

3. Drydock listens on `127.0.0.1:8000` only. From your workstation, open a tunnel and complete setup right away:

   ```sh
   ssh -L 8000:127.0.0.1:8000 you@docker-host
   ```

   Then browse to <http://localhost:8000/>, which redirects to `/setup`.

Over the tunnel, `localhost` is a secure context, so session cookies keep their `Secure` flag. On a plain-HTTP LAN address they lose it, and drydock warns at every start; use HTTPS or the tunnel. For a reverse proxy, see [configuration](docs/configuration.md#behind-a-reverse-proxy).

## First backup

1. **Hosts > Add local host** (the Docker URL is prefilled), or **Add SSH host** for a remote one ([hosts](docs/hosts.md)).
2. **Storage > Add storage**: a directory mounted into the container, or a remote target ([backups](docs/backups.md#storage)).
3. **Jobs > Add job**: pick the container or Compose project, the scope, the mode and optionally a schedule, retention and notifications ([backups](docs/backups.md#jobs-and-runs)).
4. **Run now**, then **Restore** to bring an archive back ([restore](docs/restore.md)).

## Documentation

- [Configuration](docs/configuration.md): environment variables and reverse proxies.
- [Hosts](docs/hosts.md): the local socket proxy, remote hosts over SSH and helper containers.
- [Backups](docs/backups.md): storage, jobs, consistency modes, stacks, hooks, schedules, retention, notifications and the archive format.
- [Restore](docs/restore.md): restore modes, what needs a superadmin, and the host-path denylist.
- [Running drydock](docs/operations.md): upgrading and container hardening.
- [Threat model](docs/threat-model.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).
- [Development](docs/development.md): dev loop, tests, CI and releases. [Measurements](docs/measurements.md): Phase 1 and 2 results.
