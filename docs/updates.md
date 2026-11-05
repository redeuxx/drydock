# Container updates

Drydock can update a container to the image its tag names on the registry now: it pulls that image, makes the container again with the same configuration and the new image, checks that the new one runs, and puts the old one back if it does not.

## Finding newer images

See [Newer images](hosts.md#newer-images): drydock checks every 6 hours, and operators can check a host at once from the containers page. A container with a newer image is marked "update" there.

## Updating one container

Operators click **Update** on that container's row (it asks first). This starts an update run, with its own page and log like a backup:

1. Drydock asks the registry again which digest the tag names, and pulls exactly that digest. Nothing changes if the pull fails.
2. The tag moves to the new image. The container is stopped with its own stop timeout, its restart policy is turned off for the moment, and it is renamed `<name>-drydock-old`.
3. A new container with the original's name and full configuration (command, environment, mounts, networks and addresses, ports, labels, restart policy) is created from the tag and started, if the original was running.
4. Drydock checks the new container. One with a healthcheck must become healthy within 2 minutes; one without must keep running, without restarting, for 15 seconds.
5. If it passes, the old container is removed. Its image stays on the host until you prune it.

If anything fails, or the check does not pass, everything is put back: the new container is removed, the old one gets its name, restart policy and state back, and the tag names the old image again. The run fails and its log says why. If drydock itself stops during an update, it puts things back the same way when it starts again.

An update holds the same locks as a backup or restore of the container, so they never overlap: an update waits for a backup of that container to end, and the other way round. Drydock does not back the container up first on its own.

## What is not updated

- Containers pinned by digest (`image@sha256:...`) or created from an image ID.
- Images built on the host, with no registry digest.
- Drydock's own containers (itself and its Compose project, the socket proxy among them) and its helper containers.
- Containers already running the newest image.

Compose files are never edited, and the new container keeps the Compose labels, so `docker compose up` on the host still sees it as its own. If the compose file pins another image, the next `docker compose up` goes back to that one.

## Trust

An update runs whatever the registry serves under that tag. A tag like `latest` can move to a new major version, or to an image the publisher did not intend; pin minor version tags (`postgres:17.2`) for containers that matter, and keep backups. The registry lookup and pull go through the host's Docker daemon without credentials, so private registries are not supported: the lookup fails with "the registry refused the lookup".
