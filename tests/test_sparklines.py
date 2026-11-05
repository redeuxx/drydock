"""Sparklines: the readings the status collector keeps, and how pages draw them."""

from datetime import UTC, datetime

import pytest

from drydock.hosts import status
from drydock.templating import spark
from tests.conftest import Browser
from tests.test_status import add_host, cached, reading, stats, summary

pytestmark = pytest.mark.anyio

A, B = "a" * 64, "b" * 64


def test_points_scale_to_the_top_and_gaps_break_the_line() -> None:
    assert spark([]) == [] and spark([5]) == [], "one reading draws nothing"
    assert spark([0, 50, 100], top=100) == ["0.0,19.5 50.0,10.0 100.0,0.5"]
    assert spark([200, 50], top=100) == ["0.0,0.5 100.0,10.0"], "clamped to the top"
    assert spark([1, 2, None, 4, 4]) == ["0.0,14.8 25.0,10.0", "75.0,0.5 100.0,0.5"]
    assert spark([None, 1, None, 1]) == [], "single points draw nothing"
    assert spark([0, 0]) == ["0.0,19.5 100.0,19.5"], "all zero: a flat line at the bottom"


def snapshot(containers: list[dict], by_id: dict[str, dict]) -> status.HostSnapshot:
    taken, _ = status.summarize(1, reading(containers, by_id), {}, datetime.now(UTC))
    return taken


def test_the_cache_keeps_a_bounded_history_and_drops_what_is_gone() -> None:
    cache = status.HostCache(key=())
    both = [summary(A, "web"), summary(B, "db")]
    for _ in range(status.HOST_HISTORY + 5):
        cache.remember(snapshot(both, {A: stats(0, 0)}))
    assert len(cache.history) == status.HOST_HISTORY
    assert len(cache.container_history[A]) == status.CONTAINER_HISTORY
    assert cache.container_history[B][-1] == (None, None), "no stats: no values"
    cache.remember(snapshot([summary(A, "web")], {}))
    assert B not in cache.container_history, "gone"
    cache.cool()
    assert not cache.history and not cache.container_history, "no line across a pause"


async def test_cards_and_rows_draw_the_lines(admin: Browser, monkeypatch) -> None:
    collector = await cached(admin, monkeypatch)
    host_id = add_host(admin)
    cache = collector._caches[host_id] = status.HostCache(key=())
    samples: dict = {}
    for n, cpu in enumerate((0, 10**9, 3 * 10**9, 4 * 10**9)):
        busy = reading([summary(A, "web")], {A: stats(cpu, 8 * 10**9 * (n + 1))})
        taken, samples = status.summarize(host_id, busy, samples, datetime.now(UTC))
        cache.snapshot = taken
        cache.remember(taken)
    cards = (await admin.get("/status/hosts", headers={"HX-Request": "true"})).text
    assert cards.count('viewBox="0 0 100 20"') == 2, "CPU and memory"
    assert 'aria-hidden="true" focusable="false"' in cards
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert page.count("<polyline") >= 2, "the row's CPU and memory"
    assert "style=" not in page.split('id="containers"', 1)[1], "no inline styles (CSP)"


def test_a_failed_reading_breaks_the_line_and_idle_noise_stays_flat() -> None:
    cache = status.HostCache(key=())
    cache.remember(snapshot([summary(A, "web")], {A: stats(0, 0)}))
    cache.missed()
    assert cache.history[-1] == (None, None) and cache.container_history[A][-1] == (None, None)
    assert spark([0.01, 0.03, 0.02], floor=1)[0].endswith("100.0,19.1"), "near the bottom"
    assert spark([0.01, 0.03])[0] == "0.0,13.2 100.0,0.5", "without a floor: full height"
