# Container updates

Drydock can update a container to the image its tag names on the registry now: it pulls that image, makes the container again with the same configuration and the new image, checks that the new one runs, and puts the old one back if it does not.

## Finding newer images

See [Newer images](hosts.md#newer-images): drydock checks every 6 hours by default (**Settings**), and operators can check a host at once from the containers, stacks or images page. A container with a newer image is marked "update" there.

## Updating one container

Operators click **Update** on that container's row (it asks first). This starts an update run, with its own page and log like a backup:

1. Drydock asks the registry again which digest the tag names, and pulls exactly that digest. Nothing changes if the pull fails.
2. The tag moves to the new image. The container is stopped with its own stop timeout, its restart policy is turned off for the moment, and it is renamed `<name>-drydock-old`.
3. A new container with the original's name and full configuration (command, environment, mounts, networks and addresses, ports, labels, restart policy) is created from the tag and started, if the original was running.
4. Drydock checks the new container. One with a healthcheck must become healthy within the time its own healthcheck allows (its start period, then its retries; at least 2 minutes, at most 15); one without must keep running, without restarting, for 15 seconds.
5. If it passes, the old container is removed. Its image stays on the host until you prune it (**Prune images** on the Images page).

If anything fails, or the check does not pass, everything is put back: the new container is removed, the old one gets its name, restart policy and state back, and the tag names the old image again. The run fails and its log says why. If drydock itself stops during an update, it puts things back the same way when it starts again.

An update holds the same locks as a backup or restore of the container, so they never overlap: an update waits for a backup of that container to end, and the other way round. Drydock does not back the container up first on its own.

## Updating a stack

On the **Stacks** page (under Docker), or with a Compose stack chosen in the containers page's stack filter, operators can **Update stack** when any of its containers has a newer image. Drydock finds the stack's containers when the run starts and orders them by their `depends_on` (dependencies first), then:

1. Pulls every newer image first, so a failed pull changes nothing.
2. Stops the members it updates (dependents first) and makes them again in dependency order. A member whose `depends_on` says `service_healthy` waits for an updated dependency to be healthy before it starts.
3. Checks every new container as for a single update.

It is all or nothing: if any member fails, every member already made again is put back, the others in reverse order. Members without a newer image (or pinned, or built on the host) are left running as they are, except one that joins the network of, links to or takes volumes from a member made again: it is made again too, with its own image, so it uses the new one. Drydock's own containers and members whose registry cannot be asked are left alone, with a note in the log.

A container that another container joins the network of (`network_mode: service:vpn`, as with a VPN gateway) is not updated without that other one, since it would lose its network: update their stack instead, or both stacks together.

## Switching tags

A container follows the tag its image names: `1.27` in `nginx:1.27`, or `latest` when it names none. The containers page shows it in a **Tag** column (**Tags** on the stacks page), and an "i" beside it explains it in place. To move to another tag, an operator opens the container's row and uses **Switch tag**: drydock makes the container again from the same repository at the new tag, exactly as an update does (pulled by digest first, the configuration kept, put back if the new one does not start or become healthy). It works for a container pinned by digest too, which then follows the tag; not for one made from an image ID, which names no repository.

A stack switches as a whole from its **Switch tag** on the Stacks page. The tag is for its **main service**: the one the rest of the stack is there for. Drydock picks the service no other service depends on (by `depends_on`), preferring one that binds a host port, then the first by name, and names it under the stack; the dialog lets you pick another. The main service's replicas move with it, and so do images of the same app: from the same publisher (registry and path, say `ghcr.io/immich-app`), whose names start like the main's (`immich-server`, `immich-machine-learning`), on the main's tag or that tag with a suffix (`v1.120-cuda` becomes `v1.121-cuda`). So an app and its workers stay on one version. The others, a database or a cache, keep their tags and get the newest image of them, as in a stack update. Docker Hub's official images (`nextcloud`, `mariadb`, `redis`) come from many publishers, and every image has a `latest`, so a main service that is one of them, or follows `latest`, moves alone. It is all or nothing, in dependency order, and each container is stopped meanwhile; putting it back does not undo what a new version did to its data, so back up first for a major version or an older tag.

Drydock does not edit Compose files: the file still names the old tags, so `docker compose up` on the host brings them back. Change the file too when the switch should last. An update policy can also follow a tag (below), which keeps the container on it at every run.

## Scheduled updates

**Docker > Update policies** lists them; admins create and edit them, operators can run one now. A policy names a host, a container (by name) or a Compose stack, and a schedule (a preset or a cron expression, in drydock's time zone or its own). When it fires, drydock starts an update run as above, for the container or for every member of the stack with a newer image.

A policy may name a **Tag to follow**: its next run switches the container, or the stack's main service and the services that follow it, to that tag (Switching tags, above), and later runs keep them on its newest image. For a stack it may also name the **Main service** when drydock's choice is not the one. Without a tag, a policy follows whatever tag each container has.

A stack policy whose target is `*` updates every Compose stack on its host, drydock's own left out, so stacks added later are covered too. When it fires, drydock lists the stacks and checks each one; every stack with something to update gets its own stack update run as above, one after another, so a failed stack is put back without touching the others. The policy's run lists them and fails if any of them did, and only it tells the notification target. It cannot back up first (no single job covers every stack): pair it with backup jobs on their own schedule. On the **Stacks** page, each stack lists the policies that update it, and admins can schedule one stack or every stack from there.

- **Back up first:** pick a job that backs up that container or stack on that host. Drydock runs it and waits for every one of its targets. If any of them does not end done, the update does not run (the run fails and says why), unless you untick "Do not update when the backup first fails".
- **Tell:** a notification target hears about every failed or interrupted update, and about successful ones too if you tick that.
- A fire missed while drydock was stopped runs late if it was less than an hour ago; an older one is skipped, recorded in the audit log and shown in the bell, like a job's.

The dashboard's "Next scheduled runs" includes the policies, and the containers page shows which policy updates each container, with its next run. Every create, edit, delete and run now is in the audit log.

## What is not updated

- Containers pinned by digest (`image@sha256:...`) or created from an image ID.
- Images built on the host, with no registry digest.
- Drydock's own containers (itself and its Compose project, the socket proxy among them) and its helper containers.
- Containers that remove themselves when stopped (`docker run --rm`): there would be nothing to put back.
- Containers already running the newest image.

Compose files are never edited, and the new container keeps the Compose labels, so `docker compose up` on the host still sees it as its own. If the compose file pins another image, the next `docker compose up` goes back to that one.

## Trust

An update runs whatever the registry serves under that tag. A tag like `latest` can move to a new major version, or to an image the publisher did not intend; pin minor version tags (`postgres:17.2`) for containers that matter, and keep backups. The registry lookup and pull go through the host's Docker daemon without credentials, so private registries are not supported: the lookup fails with "the registry refused the lookup".
