"""Phase 1 encryption spike. The measurements and the decision are in README.md.

Each mode runs in its own process (tests/age_spike.py) so the RSS it reports is its own.
DRYDOCK_AGE_SPIKE_GIB sets the streamed size (default 1; the README numbers are for 10).
The age CLI mode needs DRYDOCK_TEST_AGE_DIR, an age 1.3+ release directory (age and
age-plugin-batchpass); the tests image in compose.test.yaml provides a checksummed one.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parents[1]
SPIKE_GIB = os.environ.get("DRYDOCK_AGE_SPIKE_GIB", "1")
AGE_DIR = os.environ.get("DRYDOCK_TEST_AGE_DIR", "")
FLAT_MIB = 32


def run_spike(*args: str) -> dict:
    done = subprocess.run(
        [sys.executable, "-m", "tests.age_spike", *args],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=3600,
    )
    result = json.loads(done.stdout)
    print(f"\n{json.dumps(result)}")
    return result


def test_pyrage_passphrase_mode_holds_the_archive_in_memory() -> None:
    """Decision step 1 fails: pyrage's scrypt API takes and returns whole byte strings."""
    result = run_spike("pyrage-passphrase", "--mib", "64")
    assert result["roundtrip_ok"]
    # Plaintext and ciphertext are both resident: growth is about twice the input.
    assert result["rss_growth_mib"] > 64


def test_pyrage_stream_mode_keeps_memory_flat() -> None:
    result = run_spike("pyrage-stream", "--gib", SPIKE_GIB)
    assert result["roundtrip_ok"]
    assert result["rss_growth_mib"] < FLAT_MIB
    assert result["max_gil_stall_ms"] < 100


@pytest.mark.skipif(not AGE_DIR, reason="set DRYDOCK_TEST_AGE_DIR to an age 1.3+ directory")
def test_age_binary_mode_keeps_memory_flat() -> None:
    """Decision step 2, the chosen method: the age CLI through pipes."""
    result = run_spike("age-binary", "--gib", SPIKE_GIB, "--age-dir", AGE_DIR)
    assert result["roundtrip_ok"]
    assert result["rss_growth_mib"] < FLAT_MIB
    assert all(peak < FLAT_MIB for peak in result["age_peak_rss_mib"].values())
