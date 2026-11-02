"""Memory of a slow reader on a fast SSH stream: the tunnel must hold back, not buffer.

asyncssh granted a fresh channel window on every resume while earlier data still waited in
its buffer (see drydock.hosts.ssh, CHANNEL WINDOW), so a backup writing to a disk slower
than the link buffered the whole stream until the kernel killed drydock.
"""

import threading
import time
import uuid
from pathlib import Path

import pytest

from drydock.engine import stream_probe
from drydock.hosts import client as docker_client
from drydock.hosts import helper
from tests.conftest import Browser
from tests.docker_support import TEST_LABEL, add_ssh_host, get_host, needs_docker, wait_until

pytestmark = pytest.mark.anyio

SIZE_MIB = 256
LIMIT_MIB = 64  # a few channel windows (8 MiB each) and the reader's own chunks


def rss_mib() -> float:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024
    return 0.0


@needs_docker
async def test_a_slow_reader_over_ssh_keeps_memory_flat(admin: Browser) -> None:
    host_id = await add_ssh_host(admin)
    hosts = admin.app.state.hosts
    await wait_until(
        lambda: hosts.status(get_host(admin, host_id)).state == "connected", 30, "the tunnel"
    )
    handle = await docker_client.connect(hosts.docker_url(get_host(admin, host_id)))
    client = handle.client
    image = admin.settings.helper_image
    instance = hosts.instance_id
    peak = {"rss": 0.0}

    # Blocking calls run off the event loop: the tunnel is served on it.
    def read_slowly() -> int:
        name = f"drydock-test-mem-{uuid.uuid4().hex[:8]}"
        volume = client.volumes.create(name, labels={TEST_LABEL: "1"})
        try:
            helper.ensure_image(client, image)
            filler = client.containers.run(
                image,
                ["sh", "-c", f"head -c {SIZE_MIB * 1024 * 1024} /dev/zero > /v/blob"],
                mounts=stream_probe.volume_mount(name, read_only=False),
                detach=True,
                labels={TEST_LABEL: "1"},
            )
            try:
                filler.wait(timeout=600)
            finally:
                filler.remove(force=True)
            mounts = stream_probe.volume_mount(name, read_only=True)
            with helper.helper(client, image, instance, mounts=mounts) as box:
                stream, _ = box.get_archive(f"{stream_probe.MOUNT}/.", chunk_size=1024 * 1024)
                seen = 0
                for chunk in stream:
                    seen += len(chunk)
                    time.sleep(0.002)  # slower than the tunnel delivers
                return seen
        finally:
            volume.remove(force=True)

    def sample(done: threading.Event) -> None:
        while not done.wait(0.2):
            peak["rss"] = max(peak["rss"], rss_mib())

    start = rss_mib()
    done = threading.Event()
    sampler = threading.Thread(target=sample, args=(done,))
    sampler.start()
    try:
        seen = await docker_client.run_blocking(read_slowly)
    finally:
        done.set()
        sampler.join()
        await docker_client.run_blocking(handle.close)
    assert seen >= SIZE_MIB * 1024 * 1024
    assert peak["rss"] - start < LIMIT_MIB, f"RSS grew from {start:.0f} to {peak['rss']:.0f} MiB"
