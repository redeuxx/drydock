"""Checking for newer images without a daemon (the daemon side, with a local registry:
test_updates_docker.py), and the containers page's "Check for updates"."""

from datetime import UTC, datetime
from typing import Any

import docker.errors
import pytest
import requests

from drydock.hosts import status
from drydock.hosts.helper import helper_labels
from drydock.updates import check
from drydock.updates.check import Cached, HostChecks, Verdict, reference, verdict
from tests.conftest import Browser, add_user
from tests.test_status import a_host_with_containers

pytestmark = pytest.mark.anyio

OLD = "sha256:" + "1" * 64
NEW = "sha256:" + "2" * 64


def test_the_reference_a_container_was_created_from() -> None:
    assert reference("nginx") == "nginx:latest"
    assert reference("nginx:1.27") == "nginx:1.27"
    assert reference("ghcr.io/owner/app:v2") == "ghcr.io/owner/app:v2"
    assert reference("localhost:5000/app") == "localhost:5000/app:latest", "a port is no tag"
    assert reference(f"nginx@{OLD}") is None
    assert reference(f"nginx:1.27@{OLD}") is None
    assert reference(OLD) is None and reference("1" * 12) is None and reference("") is None


def test_verdicts() -> None:
    def registry(ref: str) -> str:
        assert ref == "nginx:1.27"
        return NEW

    assert verdict("nginx:1.27", [f"nginx@{NEW}"], registry).state == "current"
    found = verdict("nginx:1.27", [f"nginx@{OLD}", "junk"], registry)
    assert found == Verdict("update", "The registry has a newer nginx:1.27.", "nginx:1.27", NEW)
    assert verdict("nginx:1.27", [], registry).state == "skipped", "built locally"
    assert verdict(f"nginx@{OLD}", [f"nginx@{OLD}"], registry).state == "skipped"


@pytest.mark.parametrize(
    ("error", "shown"),
    [
        (docker.errors.APIError("x", response=type("R", (), {"status_code": 401})()), "refused"),
        (
            docker.errors.APIError("x", response=type("R", (), {"status_code": 404})()),
            "no such tag",
        ),
        (requests.ConnectionError("secret.example:443"), "lookup failed"),
        (KeyError("Descriptor"), "not understood"),
    ],
)
def test_lookup_errors_never_quote_the_registry(error: Exception, shown: str) -> None:
    def registry(ref: str) -> str:
        raise error

    found = verdict("nginx:1.27", [f"nginx@{OLD}"], registry)
    assert found.state == "error" and shown in found.reason and "secret" not in found.reason


class FakeApi:
    """Three containers of one image and reference, one of another, and a helper."""

    def __init__(self, instance: str, fail: bool = False) -> None:
        self.lookups: list[str] = []
        self.fail = fail
        self.listed = [{"Id": f"{i:064x}", "Labels": {}} for i in range(4)] + [
            {"Id": "f" * 64, "Labels": helper_labels(instance)}
        ]

    def containers(self, all: bool) -> list[dict[str, Any]]:
        return self.listed

    def inspect_container(self, container_id: str) -> dict[str, Any]:
        other = container_id == f"{3:064x}"
        return {
            "Image": "sha256:" + ("b" if other else "a") * 64,
            "Config": {"Image": "redis:7" if other else "nginx:1.27"},
        }

    def inspect_image(self, image_id: str) -> dict[str, Any]:
        return {"RepoDigests": [f"x@{OLD}"]}

    def _url(self, path: str, *args: str) -> str:
        return path.format(*args)

    def _get(self, url: str, timeout: float) -> str:
        self.lookups.append(url)
        if self.fail:
            raise requests.ConnectionError("down")
        return url

    def _result(self, response: str, json: bool) -> dict[str, Any]:
        return {"Descriptor": {"digest": NEW if "nginx" in response else OLD}}


def test_one_lookup_per_image_and_reference_reused_for_hours() -> None:
    api = FakeApi("me")
    cache: dict[tuple[str, str], Cached] = {}
    found = check.check(api, "me", cache, now=1000.0)
    assert {v.state for k, v in found.items() if k != f"{3:064x}"} == {"update"}
    assert found[f"{3:064x}"].state == "current" and "f" * 64 not in found
    assert api.lookups == ["/distribution/nginx:1.27/json", "/distribution/redis:7/json"]
    check.check(api, "me", cache, now=1000.0 + check.CHECK_EVERY - 1)
    assert len(api.lookups) == 2, "reused"
    check.check(api, "me", cache, now=1000.0 + check.CHECK_EVERY)
    assert len(api.lookups) == 4, "asked again after CHECK_EVERY"


def test_failed_lookups_are_not_kept() -> None:
    api = FakeApi("me", fail=True)
    cache: dict[tuple[str, str], Cached] = {}
    assert {v.state for v in check.check(api, "me", cache, now=0.0).values()} == {"error"}
    assert cache == {}


# THE CONTAINERS PAGE


def checked(browser: Browser, host_id: int, verdicts: dict[str, Verdict]) -> None:
    browser.app.state.updates._results[host_id] = HostChecks(datetime.now(UTC), verdicts)


async def test_rows_with_a_newer_image_are_marked_and_filtered(admin: Browser, monkeypatch) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    checked(
        admin,
        host_id,
        {
            "a" * 64: Verdict("update", "The registry has a newer nginx:1.27.", "nginx:1.27", NEW),
            "b" * 64: Verdict("current", "Up to date.", "postgres:17", OLD),
        },
    )
    page = (await admin.get(f"/containers?host={host_id}")).text
    assert page.count(">update</span>") == 1 and "1 with a newer image, checked just now" in page
    assert "The registry has a newer nginx:1.27." in page and "Not checked yet." in page
    filtered = (await admin.get(f"/containers?host={host_id}&status=updates")).text
    assert "1 of 4 containers" in filtered
    cards = (await admin.get("/status/hosts", headers={"HX-Request": "true"})).text
    assert f'href="/containers?host={host_id}&amp;status=updates">1 with a newer image' in cards


async def test_checking_is_for_operators_rate_limited_and_audited(
    admin: Browser, monkeypatch
) -> None:
    _, host_id = await a_host_with_containers(admin, monkeypatch)
    asked: list[int] = []

    async def check_now(host) -> HostChecks:
        asked.append(host.id)
        result = HostChecks(datetime.now(UTC), {"a" * 64: Verdict("update", "newer", "x:1", NEW)})
        admin.app.state.updates._results[host.id] = result
        admin.app.state.updates._asked[host.id] = __import__("time").monotonic()
        return result

    monkeypatch.setattr(admin.app.state.updates, "check_now", check_now)
    form = {"host": str(host_id)}
    htmx = {"HX-Request": "true"}
    assert (await admin.post("/containers/check-updates", form, csrf=False)).status_code == 403
    await add_user(admin, "watcher", "viewer")
    await add_user(admin, "runner", "operator")
    await admin.login("watcher")
    assert (await admin.post("/containers/check-updates", form)).status_code == 403
    assert "Check for updates" not in (await admin.get(f"/containers?host={host_id}")).text
    await admin.login("runner")
    first = await admin.post("/containers/check-updates", form, headers=htmx)
    assert first.status_code == 200 and "1 container with a newer image." in first.text
    again = await admin.post("/containers/check-updates", form, headers=htmx)
    assert "Checked moments ago; try again in" in again.text and asked == [host_id]
    assert admin.sql(
        "SELECT actor, target, outcome FROM audit_events WHERE action = 'container.check_updates'"
    ) == [("runner", f"host:{host_id}", "success"), ("runner", f"host:{host_id}", "failure")]
    assert (await admin.post("/containers/check-updates", {"host": "999999"})).status_code == 404
    plain = await admin.post("/containers/check-updates", form)
    assert plain.status_code == 303, "without script: back to the page"


def test_a_snapshot_is_unchanged_by_checks() -> None:
    """The checker keeps its own results: the status collector's rows carry none."""
    assert "update" not in {f.name for f in status.ContainerStatus.__dataclass_fields__.values()}


def test_one_lookup_per_reference_even_when_it_fails() -> None:
    api = FakeApi("me", fail=True)
    check.check(api, "me", {}, now=0.0)
    assert api.lookups == ["/distribution/nginx:1.27/json", "/distribution/redis:7/json"]


def test_a_container_docker_cannot_inspect_is_one_error_row() -> None:
    api = FakeApi("me")
    real = api.inspect_container

    def inspect(container_id: str) -> dict[str, Any]:
        if container_id == f"{1:064x}":
            raise docker.errors.APIError("boom", response=type("R", (), {"status_code": 500})())
        return real(container_id)

    api.inspect_container = inspect
    found = check.check(api, "me", {}, now=0.0)
    assert found[f"{1:064x}"].state == "error" and "HTTP 500" in found[f"{1:064x}"].reason
    assert found[f"{0:064x}"].state == "update"


async def test_asking_from_the_page_skips_the_cached_lookups(admin: Browser, monkeypatch) -> None:
    checker = admin.app.state.updates
    host = type("H", (), {"id": 5})()
    checker._caches[5] = {("x", "y"): Cached(0.0, Verdict("current", "Up to date."))}
    seen: list[dict] = []

    async def fake_check(h) -> HostChecks:
        seen.append(dict(checker._caches.get(5, {})))
        return HostChecks(datetime.now(UTC))

    monkeypatch.setattr(checker, "_check", fake_check)
    await checker.check_host(host)
    await checker.check_now(host)
    assert seen == [{("x", "y"): Cached(0.0, Verdict("current", "Up to date."))}, {}]


async def test_a_failed_check_keeps_the_last_verdicts_and_their_time(
    admin: Browser, monkeypatch
) -> None:
    checker = admin.app.state.updates
    then = datetime(2026, 11, 1, tzinfo=UTC)
    old = {"a" * 64: Verdict("update", "newer", "x:1", NEW)}
    checker._results[7] = HostChecks(then, old)
    host = type("H", (), {"id": 7})()

    def down(h):
        raise check.HostUnavailable("not connected")

    monkeypatch.setattr(checker._hosts, "docker_url", down)
    result = await checker.check_host(host)
    assert result.checked_at == then and result.verdicts == old
    assert result.error == "Drydock is not connected to this host."
    assert result.count("update", ["b" * 64]) == 0, "only containers still there count"
