# Drydock

Drydock is a self-hosted web app that backs up and restores Docker containers, volumes and Compose stacks, on the local host and on remote hosts over SSH.

Backups run on a schedule or by hand, in stop, pause or live mode, with pre- and post-hooks. Archives are signed and encrypted by default, and go to a local directory, SFTP, SMB, WebDAV or Google Drive. A restore goes onto any managed host, under a new name or over the original.

## Read this first

- **Drydock is root-equivalent on every host it manages.** Anyone who controls it can start privileged containers, read every volume and replace any container. Treat access to its UI like root SSH access to all of those hosts. The same goes for the SSH user it logs in as on each host, and for the socket proxy, which narrows the local Docker API but is not a security boundary ([hosts](docs/hosts.md)).
- **The first visitor becomes superadmin.** Until `/setup` has been submitted, anyone who can reach port 8000 can take over. Create the account right after the first start.
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

On the Docker host, over SSH. You need Docker Engine 25 or later with the Compose plugin.

1. Get drydock. Any folder works, `/opt/drydock` for example; keep it, since it holds `compose.yaml`, `.env` and the secret key file. Drydock's database lives in the `drydock-data` volume, not here.

   ```sh
   git clone https://github.com/redeuxx/drydock.git
   cd drydock
   ```

2. Generate the secret key and restrict it. Drydock runs as uid 10001 and refuses to start if it cannot read the key.

   ```sh
   mkdir -p secrets
   openssl rand -base64 32 | tr '+/' '-_' > secrets/drydock_secret_key
   sudo chown 10001:10001 secrets/drydock_secret_key
   sudo chmod 0400 secrets/drydock_secret_key
   ```

3. Set the address you will browse to, exactly as you will type it: a domain if you have one, otherwise the host's IP. You can [change it later](docs/configuration.md#changing-the-address).

   ```sh
   echo "DRYDOCK_BASE_URL=http://192.168.1.50:8000" > .env
   ```

4. Start drydock:

   ```sh
   docker compose up -d --build
   ```

5. Browse to that address right away and create the superadmin account.

   `Invalid host header` means the address in your browser is not `DRYDOCK_BASE_URL`: fix `.env` and run `docker compose up -d` again.

Port 8000 is open to every network that can reach the host; Docker's published ports bypass ufw. Over plain HTTP, session cookies lack the `Secure` flag and drydock warns at every start. Outside a trusted LAN, put HTTPS in front or keep drydock on loopback ([configuration](docs/configuration.md#who-can-reach-drydock)).

## First backup

1. **Hosts > Add local host** (the Docker URL is prefilled), or **Add SSH host** for a remote one: its address and a user that can use Docker, then scan its host key and enter that user's password once so drydock can install its own key ([hosts](docs/hosts.md)).
2. **Storage > Add storage**: a directory mounted into the container, or a remote target ([backups](docs/backups.md#storage)).
3. **Jobs > Add job**: pick the container or Compose project, the scope, the mode and optionally a schedule, retention and notifications ([backups](docs/backups.md#jobs-and-runs)).
4. **Run now**, then **Restore** to bring an archive back ([restore](docs/restore.md)).

## Documentation

- [Configuration](docs/configuration.md): environment variables and reverse proxies.
- [Hosts](docs/hosts.md): the local socket proxy, remote hosts over SSH and helper containers.
- [Backups](docs/backups.md): storage, jobs, consistency modes, stacks, hooks, schedules, retention, notifications and the archive format.
- [Restore](docs/restore.md): restore modes, what needs a superadmin, and the host-path denylist.
- [Running drydock](docs/operations.md): backing up drydock itself, upgrading and container hardening.
- [Threat model](docs/threat-model.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).
- [Development](docs/development.md): dev loop, tests, CI and releases. [Measurements](docs/measurements.md): Phase 1 and 2 results.
