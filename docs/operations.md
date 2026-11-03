# Running drydock

## Backing up drydock itself

Drydock never backs up its own deployment: stopping itself or its socket proxy would leave nothing to start them again, and a live archive would hold its own secret key. Protect these yourself:

| What | Why |
|---|---|
| `secrets/drydock_secret_key` | The only key to every encrypted archive. Losing it cannot be undone. Copy it once into a password manager or offline, never next to the archives. |
| `.env` and `compose.override.yaml` | The address and the mounts. Small; keep them with the key. |
| The `drydock-data` volume | Users, hosts, storage, jobs and history. Losing it loses no archive: a new drydock with the same key restores them all, after hosts and storage are added again. |

To copy the volume (the paths are examples):

```sh
cd /opt/drydock
docker compose stop drydock     # up to 90 s: it starts anything it had stopped first
docker run --rm -v drydock_drydock-data:/data:ro -v /srv/drydock:/out busybox tar czf /out/drydock-data-$(date +%F).tgz -C /data .
docker compose start drydock
```

To restore it, stop drydock, unpack the copy into an empty `drydock_drydock-data` volume, put the same key file back and start drydock.

## Upgrading

Drydock migrates its database at startup, and a migration is one-way: an older image refuses to start on a database a newer one has migrated, and archives a newer build writes may not verify in an older one. Archives from older builds restore in newer ones. To upgrade:

1. Stop drydock (`docker compose stop`, which gives it 90 seconds to start any containers it stopped) and copy the `drydock-data` volume.
2. Change the image tag (or pull the checkout and rebuild with `DRYDOCK_COMMIT=$(git rev-parse HEAD) docker compose up -d --build`) and start it again.

To go back, restore that copy with the older image, which loses everything done since. `docker compose down` keeps the volume and every setting; `down --volumes` deletes the database.

## Container hardening

The container runs with a read-only root filesystem, no capabilities and `no-new-privileges`. State lives in the `drydock-data` volume at `/data`. `stop_grace_period` is 90 seconds so drydock can restart containers it stopped before Docker kills it.

Remote storage goes through rclone v1.75.2 (checked against a pinned SHA-256 at build time), which drydock runs as a child process, `rclone rcd`. It listens only on `/run/drydock/rclone.sock` (mode 0600), never on TCP, and every call needs a random password made when drydock starts. The password reaches rclone through its environment, so it is not visible in `ps`. rclone gets no `rclone.conf`: its configuration stays in memory, and none of the container's `RCLONE_*` variables reach it. Drydock restarts rclone if it exits. Each call carries the target's settings inline, passwords obscured. rclone also serves objects on the same socket (`--rc-serve`, same password) because that is its only ranged read, which the restore listing uses to preview archives. Drydock redacts the settings from any log line that would quote them.
