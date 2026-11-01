# Docker hosts

Drydock talks to every host through the Docker Engine API, versions 1.44 to 1.56 (Docker Engine 25.0 or later). It reads the daemon's `/version` and uses the highest version both sides support, capped at 1.56. Older daemons are refused.

**Every host you add hands drydock root on that host.** Docker API access is root-equivalent: whoever can create containers can mount `/` and start privileged containers. That holds for the local socket proxy and for every SSH user drydock logs in as. Only admins manage hosts, and drydock never adds one by itself, not even the local host. Every role may view a host's container inventory (`/hosts/<id>/containers`), as the role matrix allows.

## The local host

`compose.yaml` runs [linuxserver/socket-proxy](https://github.com/linuxserver/docker-socket-proxy) next to drydock. Only the proxy mounts `/var/run/docker.sock` (read-only, on an `internal` network with no route out); drydock reaches it at `tcp://socket-proxy:2375` and never mounts the socket. The proxy allows containers, images, volumes, networks, exec, archive, start, stop, restart, pause and unpause, plus the read-only registry lookup `GET /distribution/<image>/json` (see [Images stored by reference](backups.md#images-stored-by-reference)). It denies everything else, including events, logs, build, commit, swarm, secrets, plugins and system.

**The socket proxy is not a security boundary.** It narrows the API to what drydock uses, which limits accidents and makes misuse noisier, but the endpoints drydock needs (container create, exec, archive) are already enough to take over the host. Treat anything that can reach `socket-proxy:2375` as root on the host; that is why it sits on an internal network shared only with drydock.

To add it, open **Hosts > Add local host**. The Docker URL is prefilled from `DRYDOCK_LOCAL_DOCKER_URL`. A local host's `tcp://` or `http(s)://` URL must name a service on drydock's Docker network (such as `socket-proxy`) or a loopback or private address, since that API is unauthenticated; link-local addresses such as cloud metadata are refused. Reach any other machine over SSH. **Test connection** then shows the engine version, the negotiated API version and the platform, and the container inventory loads below.

## Remote hosts over SSH

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

## Helper containers

To read and write volumes drydock runs short-lived helper containers (`busybox`, pinned by multi-arch digest) with no network, a read-only root filesystem, no capabilities (except two restore helpers, each running a fixed command: the wipe helper gets exactly `DAC_OVERRIDE` and `FOWNER`, and the data helper, which gives a restored directory its archived owner and mode after the data is written, exactly `CHOWN`, `FOWNER` and `FSETID`), `no-new-privileges`, a PID limit and the labels `drydock.helper=1` and `drydock.instance=<installation ID>` (a random ID made when the database is created). Volume data moves through the daemon's archive API, so a transfer helper is never even started. Helpers are removed when the transfer ends, and a reaper removes leftovers when drydock starts and hourly after that on every host reachable at that moment, skipping any helper a run is still using. The reaper and the container inventory act only on helpers carrying this installation's ID, so two drydock instances (or the test suite) can share a daemon.
