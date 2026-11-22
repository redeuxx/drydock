"""Image versions for the update pages (updates/versions.py), without a network: the
registry is a fake requests session."""

import json
from typing import Any

import pytest

from drydock.updates import check, versions
from drydock.updates.check import Cached
from drydock.updates.versions import describe, image_version, registry_version
from tests.test_updates import NEW, OLD, FakeApi

INDEX = "sha256:" + "1" * 64
AMD64 = "sha256:" + "2" * 64
ARM64 = "sha256:" + "3" * 64
CONFIG = "sha256:" + "4" * 64
PLATFORM = ("linux", "amd64", "")


def test_the_version_is_the_label_else_the_official_variable() -> None:
    label = {"Labels": {versions.VERSION_LABEL: " 4.0.9 "}, "Env": ["NGINX_VERSION=1.27.3"]}
    assert image_version(label, "nginx") == "4.0.9"
    assert image_version({"Env": ["PATH=/bin", "NGINX_VERSION=1.27.3"]}, "nginx") == "1.27.3"
    assert image_version({"Env": ["PG_VERSION=17.2"]}, "library/postgres") == "17.2"
    assert image_version({"Env": ["NGINX_VERSION=1"]}, "redis") == ""
    assert image_version(None) == "" and image_version({"Labels": "x"}) == ""
    spoof = {"Labels": {versions.VERSION_LABEL: "1.2‮3\x1b[31m" + "9" * 200}}
    shown = image_version(spoof)
    assert "‮" not in shown and "\x1b" not in shown and len(shown) == versions.MAX_VERSION


def test_describe() -> None:
    assert describe("1.27.2", OLD, "1.27.3", NEW) == "1.27.2 → 1.27.3"
    assert describe("", OLD, "", NEW) == "111111111111 → 222222222222"
    assert describe("24.04", OLD, "24.04", NEW) == (
        "24.04 (111111111111) → 24.04 (222222222222)"
    ), "a rebuild of the same version shows its digests"
    assert describe("", "", "", NEW, "nginx:1.27", "nginx:1.28") == (
        "1.27 unknown → 1.28 222222222222"
    )
    assert describe("1", OLD, "2", NEW, "", "nginx:1.28").startswith("pinned 1 ")


class Response:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None):
        self.status_code = status
        self.headers = headers or {}
        self.data = json.dumps(body).encode() if body is not None else b""
        self.is_redirect = status in (301, 302, 307, 308)

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def close(self) -> None:
        pass

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise versions.requests.HTTPError(str(self.status_code))

    def iter_content(self, size: int) -> list[bytes]:
        return [self.data]


class Session:
    """Docker Hub as it answers: a token first, then the index, manifest and config."""

    def __init__(self, realm: str = "https://auth.docker.io/token", blob_redirect: str = ""):
        self.realm = realm
        self.blob_redirect = blob_redirect
        self.asked: list[tuple[str, dict[str, str]]] = []

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def get(self, url: str, headers: dict[str, str] | None = None, **kw: Any) -> Response:
        headers = headers or {}
        self.asked.append((url, headers))
        if url.startswith("https://auth.docker.io/"):
            assert kw["params"] == {"service": "registry.docker.io", "scope": "pull"}
            return Response(200, {"token": "t"})
        if url.startswith("https://cdn.example/"):
            assert "Authorization" not in headers, "the token stays with the registry"
            return Response(200, {"config": {"Env": ["NGINX_VERSION=1.27.3"]}})
        if headers.get("Authorization") != "Bearer t":
            challenge = f'Bearer realm="{self.realm}",service="registry.docker.io",scope="pull"'
            return Response(401, headers={"WWW-Authenticate": challenge})
        base = "https://registry-1.docker.io/v2/library/nginx/"
        if url == base + f"manifests/{INDEX}":
            entries = [
                {"digest": ARM64, "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": AMD64, "platform": {"os": "linux", "architecture": "amd64"}},
            ]
            return Response(200, {"manifests": entries})
        if url == base + f"manifests/{AMD64}":
            return Response(200, {"config": {"digest": CONFIG}})
        if url == base + f"blobs/{CONFIG}":
            if self.blob_redirect:
                return Response(307, headers={"Location": self.blob_redirect})
            return Response(200, {"config": {"Labels": {versions.VERSION_LABEL: "1.27.3"}}})
        return Response(404)


@pytest.fixture
def session(monkeypatch) -> Session:
    fake = Session()
    monkeypatch.setattr(versions.requests, "Session", lambda: fake)
    return fake


def test_the_registry_gives_the_new_version(session: Session) -> None:
    assert registry_version("nginx:latest", INDEX, PLATFORM) == "1.27.3"
    tails = [url.rpartition("/")[2] for url, _ in session.asked]
    assert tails == [INDEX, "token", INDEX, AMD64, CONFIG], "one token, then the image"
    assert registry_version("nginx:latest", INDEX, ("linux", "s390x", "")) == ""


def test_a_blob_redirect_keeps_the_token_home(session: Session) -> None:
    session.blob_redirect = "https://cdn.example/blob"
    assert registry_version("nginx:latest", INDEX, PLATFORM) == "1.27.3"
    session.blob_redirect = "http://cdn.example/blob"
    assert registry_version("nginx:latest", INDEX, PLATFORM) is None, "never off HTTPS"


def test_only_public_registries_and_their_own_realms(session: Session) -> None:
    for ref in ("registry.internal:5000/app:1", "10.0.0.5/app:1", "localhost/app:1"):
        assert registry_version(ref, INDEX, PLATFORM) == ""
    assert session.asked == [], "nothing asked of a registry drydock does not know"
    assert registry_version("nginx:latest", "sha256:../../x", PLATFORM) == ""
    session.realm = "https://169.254.169.254/token"
    assert registry_version("nginx:latest", INDEX, PLATFORM) is None
    assert not any("169.254" in url for url, _ in session.asked)


def test_the_check_shows_both_versions() -> None:
    class Labelled(FakeApi):
        def inspect_image(self, image_id: str) -> dict[str, Any]:
            return {
                "RepoDigests": [f"nginx@{OLD}"],
                "Config": {"Env": ["NGINX_VERSION=1.27.2"]},
                "Os": "linux",
                "Architecture": "amd64",
            }

    asked = []

    def newer_version(ref: str, digest: str, platform: versions.Platform) -> str:
        asked.append((ref, digest, platform))
        return "1.27.3"

    cache: dict[tuple[str, str], Cached] = {}
    found = check.check(Labelled("me"), "me", cache, now=0.0, newer_version=newer_version)
    web = found[f"{0:064x}"]
    assert (web.state, web.version, web.new_version, web.digest) == (
        "update",
        "1.27.2",
        "1.27.3",
        OLD,
    )
    assert web.moves == "1.27.2 → 1.27.3"
    assert set(asked) == {("nginx:1.27", NEW, ("linux", "amd64", ""))}
    assert found[f"{3:064x}"].new_version == "", "an image that is current asks nothing"
