"""Phase 1 spike: a 1 GiB volume round trip through the socket proxy and over SSH.

The source volume holds files owned by uid 999 with mode 0600, an absolute symlink and
empty directories. It is exported with get_archive into a staging file, imported with
put_archive into a new volume, and read back; every member's type, uid, gid, mode,
size, link target and sha256 must match. /healthz must keep answering in under 200 ms
while the transfer runs.

Throughput gate: the SSH tunnel must reach 30% of a plain stream. The baseline is the
sshhost daemon itself over unencrypted TCP, not the host daemon behind the proxy: Docker
Desktop's daemon extracts archives far more slowly than dind (about 14 MiB/s even on its
raw socket), which makes a comparison across the two daemons meaningless. The proxy
path is still measured and reported.

DRYDOCK_PROBE_MIB shrinks the volume for quick runs (default 1024).
"""

import gc
import os
import tarfile
import time
import uuid

import anyio
import pytest

from drydock.engine import stream_probe
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from drydock.models import Host
from tests.conftest import Browser
from tests.docker_support import (
    DOCKER_URL,
    TEST_LABEL,
    add_ssh_host,
    get_host,
    insert_host,
    needs_docker,
    needs_ssh,
    wait_until,
)

pytestmark = [pytest.mark.anyio, pytest.mark.slow]

SIZE_MIB = int(os.environ.get("DRYDOCK_PROBE_MIB", "1024"))
PLAIN_URL = os.environ.get("DRYDOCK_TEST_SSHHOST_PLAIN_URL", "")
HEALTHZ_LIMIT = 0.2
THROUGHPUT_GATE = 0.30
# Runs as root with Docker's default capabilities (it must chown); test only, never a helper.
POPULATE = r"""
set -e
mkdir -p /v/data/nested /v/data/empty-owned /v/empty
count=$(( $1 / 4 ))
for i in 1 2 3 4; do dd if=/dev/urandom of=/v/data/blob$i bs=1M count=$count 2>/dev/null; done
echo hello > /v/data/nested/small.txt
ln -s /etc/hostname /v/abs-link
chown -R 999:999 /v/data
find /v/data -type f -exec chmod 0600 {} +
chmod 0700 /v/data /v/data/nested
cd /v && sha256sum data/blob* data/nested/small.txt > /v/SHA256SUMS
"""
# Throughput per path, filled by the round trip tests for the gate below.
RESULTS: dict[str, dict[str, float]] = {}


def populate(client, image: str, volume: str) -> None:
    container = client.containers.create(
        image,
        ["sh", "-c", POPULATE, "sh", str(SIZE_MIB)],
        mounts=stream_probe.volume_mount(volume, read_only=False),
        network_mode="none",
        labels={TEST_LABEL: "1"},
    )
    try:
        container.start()
        assert container.wait(timeout=600)["StatusCode"] == 0
    finally:
        container.remove(force=True)


def expected_sums(staged) -> dict[str, str]:
    with tarfile.open(staged) as tar:
        member = tar.extractfile("./SHA256SUMS")
        assert member is not None
        lines = member.read().decode().splitlines()
    return {name: digest for digest, name in (line.split() for line in lines)}


def roundtrip(handle: docker_client.DockerHandle, browser: Browser) -> dict[str, float]:
    client = handle.client
    image = browser.settings.helper_image
    instance = browser.app.state.hosts.instance_id
    suffix = uuid.uuid4().hex[:10]
    source = client.volumes.create(f"drydock-test-src-{suffix}", labels={TEST_LABEL: "1"})
    target = client.volumes.create(f"drydock-test-dst-{suffix}", labels={TEST_LABEL: "1"})
    staged = stream_probe.staging_file(browser.settings.staging_dir)
    try:
        helper.ensure_image(client, image)
        populate(client, image, source.name)
        exported = stream_probe.export_volume(client, image, instance, source.name, staged)
        assert staged.stat().st_mode & 0o777 == 0o600
        imported = stream_probe.import_volume(client, image, instance, staged, target.name)
        original = stream_probe.describe_file(staged)
        restored = stream_probe.describe_volume(client, image, instance, target.name)

        # The export matches what the container wrote.
        for name, digest in expected_sums(staged).items():
            assert original[name].sha256 == digest, name
        assert sum(e.size for e in original.values()) >= SIZE_MIB * 1024 * 1024
        blob = original["data/blob1"]
        assert (blob.type, blob.uid, blob.gid, blob.mode) == (tarfile.REGTYPE, 999, 999, 0o600)
        assert original["data"].mode == 0o700 and original["data"].uid == 999
        link = original["abs-link"]
        assert (link.type, link.linkname) == (tarfile.SYMTYPE, "/etc/hostname")
        assert original["empty"].type == tarfile.DIRTYPE
        assert original["data/empty-owned"].uid == 999
        # The import reproduces every member exactly.
        assert restored == original
        return {
            "export_mib_s": exported.mib_per_s,
            "import_mib_s": imported.mib_per_s,
            "export_s": exported.seconds,
            "import_s": imported.seconds,
            "bytes": exported.size,
        }
    finally:
        staged.unlink(missing_ok=True)
        for volume in (source, target):
            volume.remove(force=True)


async def roundtrip_with_healthz(
    browser: Browser, handle: docker_client.DockerHandle
) -> dict[str, float]:
    latencies: list[float] = []
    result: dict[str, float] = {}
    done = anyio.Event()

    async def transfer() -> None:
        try:
            result.update(await docker_client.run_blocking(roundtrip, handle, browser))
        finally:
            done.set()

    async def probe_health() -> None:
        while not done.is_set():
            start = time.perf_counter()
            response = await browser.get("/healthz")
            latencies.append(time.perf_counter() - start)
            assert response.status_code == 200
            await anyio.sleep(0.05)

    pauses: list[float] = []
    gc_started = [0.0]

    def gc_timer(phase: str, info: dict) -> None:
        if phase == "start":
            gc_started[0] = time.perf_counter()
        else:
            pauses.append(time.perf_counter() - gc_started[0])

    # Earlier tests leave a large heap in this process, and one full collection of it can
    # stall the event loop for over 200 ms. A drydock process carries no such heap, so
    # freeze it out of the measurement; pauses during the transfer are still reported.
    gc.collect()
    gc.freeze()
    gc.callbacks.append(gc_timer)
    try:
        async with anyio.create_task_group() as group:
            group.start_soon(transfer)
            group.start_soon(probe_health)
    finally:
        gc.callbacks.remove(gc_timer)
        gc.unfreeze()
    result["gc_max_ms"] = max(pauses, default=0) * 1000
    latencies.sort()
    result["healthz_max_ms"] = latencies[-1] * 1000
    result["healthz_p99_ms"] = latencies[int(len(latencies) * 0.99)] * 1000
    result["healthz_samples"] = len(latencies)
    return result


def report(path: str, result: dict[str, float]) -> None:
    RESULTS[path] = result
    print(
        f"\n{path}: {result['bytes'] / 2**20:.0f} MiB, export {result['export_mib_s']:.0f} MiB/s "
        f"({result['export_s']:.1f} s), import {result['import_mib_s']:.0f} MiB/s "
        f"({result['import_s']:.1f} s), healthz max {result['healthz_max_ms']:.0f} ms "
        f"p99 {result['healthz_p99_ms']:.0f} ms over {result['healthz_samples']:.0f} requests, "
        f"longest GC pause {result['gc_max_ms']:.0f} ms"
    )


@needs_docker
async def test_volume_roundtrip_through_the_proxy(admin: Browser) -> None:
    host = Host(name="local", kind="local", docker_url=DOCKER_URL, enabled=True)
    host_id = await docker_client.run_blocking(insert_host, admin, host)
    hosts = admin.app.state.hosts
    handle = await docker_client.connect(hosts.docker_url(get_host(admin, host_id)))
    try:
        result = await roundtrip_with_healthz(admin, handle)
    finally:
        await docker_client.run_blocking(handle.close)
    report("local", result)
    assert result["healthz_max_ms"] < HEALTHZ_LIMIT * 1000


@needs_ssh
async def test_volume_roundtrip_plain_baseline(admin: Browser) -> None:
    if not PLAIN_URL:
        pytest.skip("needs DRYDOCK_TEST_SSHHOST_PLAIN_URL from compose.test.yaml")
    handle = await docker_client.connect(PLAIN_URL)
    try:
        result = await roundtrip_with_healthz(admin, handle)
    finally:
        await docker_client.run_blocking(handle.close)
    report("plain", result)
    assert result["healthz_max_ms"] < HEALTHZ_LIMIT * 1000


@needs_ssh
async def test_volume_roundtrip_over_ssh(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    hosts = admin.app.state.hosts
    await wait_until(
        lambda: hosts.status(get_host(admin, host_id)).state == "connected", 30, "the tunnel"
    )
    handle = await docker_client.connect(hosts.docker_url(get_host(admin, host_id)))
    try:
        result = await roundtrip_with_healthz(admin, handle)
    finally:
        await docker_client.run_blocking(handle.close)
    report("ssh", result)
    assert result["healthz_max_ms"] < HEALTHZ_LIMIT * 1000


def test_ssh_throughput_gate() -> None:
    if not {"plain", "ssh"} <= RESULTS.keys():
        pytest.skip("needs the plain and SSH round trip results from this run")
    for direction in ("export_mib_s", "import_mib_s"):
        ratio = RESULTS["ssh"][direction] / RESULTS["plain"][direction]
        line = f"\nSSH {direction}: {ratio:.0%} of plain TCP to the same daemon"
        if "local" in RESULTS:
            line += f", {RESULTS['ssh'][direction] / RESULTS['local'][direction]:.0%} of the proxy"
        print(line)
        assert ratio >= THROUGHPUT_GATE, f"{direction}: SSH reaches {ratio:.0%} of plain TCP"
