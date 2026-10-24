"""Phase 1 encryption spike: can drydock stream archives through age with flat memory?

Run as a subprocess, so the peak RSS it reports is its own, and print one JSON object:

    python -m tests.age_spike pyrage-passphrase --mib 256
    python -m tests.age_spike pyrage-stream --gib 10
    python -m tests.age_spike age-binary --gib 10 --age-dir /path/to/age

Modes, in the decision order of PLAN.md:
- pyrage-passphrase: pyrage.passphrase.encrypt/decrypt (scrypt). pyrage 1.4.0 offers
  these only as bytes in, bytes out, so the whole archive must sit in memory.
- pyrage-stream: pyrage.encrypt_io/decrypt_io, which stream between file objects but
  accept only recipients and identities, not passphrases. A random X25519 identity
  stands in for the per-job key the README's alternative would derive.
- age-binary: the age CLI through pipes, with the batchpass plugin (age 1.3+) reading the
  passphrase from an inherited file descriptor, never argv or the environment.

Plaintext is a repeating random block; it is hashed on the way in and again after
decryption. Encryption feeds decryption through an OS pipe, so nothing touches disk.
A sampler records RSS every 100 ms, and a ticker thread records the longest stall it
sees, which shows whether the encryption holds the GIL long enough to starve the event
loop (drydock's SSH tunnels and HTTP handlers).
"""

import argparse
import fcntl
import hashlib
import json
import os
import resource
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pyrage

BLOCK = os.urandom(1024 * 1024)
PIPE_SIZE = 1024 * 1024
F_SETPIPE_SZ = 1031


# MEASUREMENT


def rss_bytes() -> int:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return 0


class Monitor:
    """Samples RSS and the longest scheduling stall of a 10 ms ticker thread."""

    def __init__(self) -> None:
        self.baseline = rss_bytes()
        self.peak = self.baseline
        self.max_stall = 0.0
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._sample, daemon=True),
            threading.Thread(target=self._tick, daemon=True),
        ]

    def __enter__(self) -> Monitor:
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join()
        self.peak = max(self.peak, rss_bytes())

    def _sample(self) -> None:
        while not self._stop.wait(0.1):
            self.peak = max(self.peak, rss_bytes())

    def _tick(self) -> None:
        last = time.perf_counter()
        while not self._stop.wait(0.01):
            now = time.perf_counter()
            self.max_stall = max(self.max_stall, now - last - 0.01)
            last = now


class Source:
    """A readable file of `size` bytes that hashes what it hands out."""

    def __init__(self, size: int) -> None:
        self.remaining = size
        self.offset = 0
        self.sha256 = hashlib.sha256()

    def read(self, n: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        n = min(n if n > 0 else len(BLOCK), self.remaining, len(BLOCK) - self.offset)
        chunk = BLOCK[self.offset : self.offset + n]
        self.offset = (self.offset + n) % len(BLOCK)
        self.remaining -= n
        self.sha256.update(chunk)
        return chunk


class Sink:
    """A writable file that hashes and counts what it receives."""

    def __init__(self) -> None:
        self.size = 0
        self.sha256 = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.sha256.update(data)
        self.size += len(data)
        return len(data)

    def flush(self) -> None:
        pass


def pipe() -> tuple[int, int]:
    read_fd, write_fd = os.pipe()
    fcntl.fcntl(write_fd, F_SETPIPE_SZ, PIPE_SIZE)
    return read_fd, write_fd


def result(mode: str, size: int, seconds: float, monitor: Monitor, ok: bool, **extra) -> dict:
    return {
        "mode": mode,
        "bytes": size,
        "seconds": round(seconds, 2),
        "mib_per_s": round(size / 2**20 / seconds, 1),
        "rss_baseline_mib": round(monitor.baseline / 2**20, 1),
        "rss_peak_mib": round(monitor.peak / 2**20, 1),
        "rss_growth_mib": round((monitor.peak - monitor.baseline) / 2**20, 1),
        # Peak since exec only if the parent was small: Linux carries ru_maxrss across exec.
        "ru_maxrss_mib": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
        "max_gil_stall_ms": round(monitor.max_stall * 1000, 1),
        "roundtrip_ok": ok,
        **extra,
    }


# MODES


def pyrage_passphrase(size: int) -> dict:
    passphrase = secrets.token_urlsafe(32)
    with Monitor() as monitor:
        start = time.perf_counter()
        source = Source(size)
        plaintext = b"".join(iter(lambda: source.read(len(BLOCK)), b""))
        ciphertext = pyrage.passphrase.encrypt(plaintext, passphrase)
        del plaintext
        decrypted = pyrage.passphrase.decrypt(ciphertext, passphrase)
        ok = hashlib.sha256(decrypted).digest() == source.sha256.digest()
        seconds = time.perf_counter() - start
    return result("pyrage-passphrase", size, seconds, monitor, ok)


def run_threads(*targets: Callable[[], None]) -> None:
    errors: list[BaseException] = []

    def guarded(target: Callable[[], None]) -> None:
        try:
            target()
        except BaseException as exc:  # reported after join
            errors.append(exc)

    threads = [threading.Thread(target=guarded, args=(t,)) for t in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise errors[0]


def pyrage_stream(size: int) -> dict:
    identity = pyrage.x25519.Identity.generate()
    recipient = identity.to_public()
    source, sink = Source(size), Sink()
    read_fd, write_fd = pipe()
    with Monitor() as monitor:
        start = time.perf_counter()

        def encrypt() -> None:
            with os.fdopen(write_fd, "wb", buffering=0) as out:
                pyrage.encrypt_io(source, out, [recipient])

        def decrypt() -> None:
            with os.fdopen(read_fd, "rb", buffering=0) as encrypted:
                pyrage.decrypt_io(encrypted, sink, [identity])

        run_threads(encrypt, decrypt)
        seconds = time.perf_counter() - start
    ok = sink.size == size and sink.sha256.digest() == source.sha256.digest()
    return result("pyrage-stream", size, seconds, monitor, ok)


def child_peak_rss(pid: int) -> int:
    """VmHWM of a running child; 0 once it has exited (a zombie has no memory lines)."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return 0
    lines = [line for line in status.splitlines() if line.startswith("VmHWM:")]
    return int(lines[0].split()[1]) * 1024 if lines else 0


def age_binary(size: int, age_dir: Path) -> dict:
    passphrase = secrets.token_urlsafe(32)
    env = {"PATH": str(age_dir)}  # age finds age-plugin-batchpass on PATH

    def spawn(args: list[str], stdin) -> subprocess.Popen:
        pass_read, pass_write = os.pipe()
        os.write(pass_write, passphrase.encode())
        os.close(pass_write)
        process = subprocess.Popen(
            [str(age_dir / "age"), *args, "-j", "batchpass"],
            stdin=stdin,
            stdout=subprocess.PIPE,
            env={**env, "AGE_PASSPHRASE_FD": str(pass_read)},
            pass_fds=(pass_read,),
        )
        os.close(pass_read)
        return process

    source, sink = Source(size), Sink()
    peaks = {}
    with Monitor() as monitor:
        start = time.perf_counter()
        encrypt = spawn(["-e"], subprocess.PIPE)
        decrypt = spawn(["-d"], encrypt.stdout)
        assert encrypt.stdin and encrypt.stdout and decrypt.stdout
        encrypt.stdout.close()  # decrypt holds the only read end now

        def feed() -> None:
            assert encrypt.stdin
            with encrypt.stdin:
                while chunk := source.read(len(BLOCK)):
                    encrypt.stdin.write(chunk)

        def drain() -> None:
            assert decrypt.stdout
            while chunk := decrypt.stdout.read(len(BLOCK)):
                sink.write(chunk)
                for name, process in (("encrypt", encrypt), ("decrypt", decrypt)):
                    if process.poll() is None:
                        peaks[name] = max(peaks.get(name, 0), child_peak_rss(process.pid))

        run_threads(feed, drain)
        codes = (encrypt.wait(), decrypt.wait())
        seconds = time.perf_counter() - start
    ok = codes == (0, 0) and sink.size == size and sink.sha256.digest() == source.sha256.digest()
    return result(
        "age-binary",
        size,
        seconds,
        monitor,
        ok,
        age_peak_rss_mib={k: round(v / 2**20, 1) for k, v in peaks.items()},
    )


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("pyrage-passphrase", "pyrage-stream", "age-binary"))
    parser.add_argument("--gib", type=float, default=0)
    parser.add_argument("--mib", type=float, default=0)
    parser.add_argument("--age-dir", type=Path)
    args = parser.parse_args(argv)
    size = int(args.gib * 2**30 + args.mib * 2**20)
    if args.mode == "pyrage-passphrase":
        output = pyrage_passphrase(size)
    elif args.mode == "pyrage-stream":
        output = pyrage_stream(size)
    else:
        output = age_binary(size, args.age_dir)
    print(json.dumps(output))


if __name__ == "__main__":
    main(sys.argv[1:])
