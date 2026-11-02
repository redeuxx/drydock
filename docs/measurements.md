# Measurements

Results of the Phase 1 spikes, the Phase 2 checks and the Phase 8 release runs, with the commands to repeat them.

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

## Phase 8 release runs

Measured on 2026-11-01 on the release-validation VM: Ubuntu 26.04, 4 vCPUs, 3.3 GiB of RAM, Docker 29.9.2, with staging and local storage on one 250 GB virtual disk. All data was random (incompressible) and every archive encrypted.

| Run | Result |
|---|---|
| 100 GB over SSH: five bind mounts (23, 23, 18, 18 and 18 GB) of one container on the VM itself, added as an SSH host, stop mode, into local storage | 18 min 16 s, 91 MB/s (87 MiB/s) end to end; drydock RSS 145 MiB at the start, peak 155 MiB; age peak 4.7 MiB; `/healthz` median 1.4 ms, p99 21 ms, max 55 ms (one sample every 5 s) |
| 46 GB upload: the first two bind mounts of the run above as one archive, PUT from a Windows PC on the LAN the way the browser sends it | 81 s, 567 MB/s (541 MiB/s); drydock RSS peak 63 MiB; `/healthz` max 8 ms. Verifying the uploaded archive (decrypt, decompress, every member's checksum and the signature) took 3 min 21 s, 229 MB/s |
| SSH across a VPN to a remote server (115 ms round trip) | The link limits it, and it varied during the day: scp moved 10 MB/s at 16:54 and 2.6 MB/s at 19:46. At the fast time drydock received 9.2 MB/s (a 100 GB run, cancelled after the link was measured); a 5 GB run averaged 3.9 MB/s (21 min 8 s) while the link was slower. drydock stayed at 155 to 185 MiB throughout |

The 100 GB run is bound by the one disk: each byte is read from the bind mount, written to staging, read back and written into the archive, so the disk moves about four times the data.

**Found by these runs: unbounded buffering over SSH.** The first 100 GB attempt grew drydock from 150 MiB to 3 GiB in 20 seconds until the kernel killed it (the run was then marked interrupted, the container started again and the partial archive removed, as recovery should). asyncssh 2.24.1 grants a full channel window again on the first delivery after reading resumes, although up to a window of earlier data still waits in its buffer, so each pause and resume lets the server send another window: a reader slower than the link buffers the whole stream. Over the slow VPN link it never showed. `drydock.hosts.ssh` now counts the buffered data in the window it grants, and `tests/test_ssh_memory.py` reads 256 MiB slowly over the test SSH host and fails if drydock grows by 64 MiB or more (it grew by 227 MiB without the fix). The Phase 1 throughput is unchanged: SSH reaches 94% of plain TCP for export and 88% for import.

**Staging needs room for the largest member.** The VM's staging directory was first left on its 30 GB root disk; a 23 GB member fits there only once. Mount a larger disk at `DRYDOCK_STAGING_DIR` (see [configuration](configuration.md)) before backing up big volumes.

```sh
# The memory check and the SSH throughput probe
docker compose -f compose.test.yaml run --rm tests uv run --no-sync pytest -s tests/test_ssh_memory.py tests/test_stream_probe.py
```
