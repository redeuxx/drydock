"""Docker Engine API clients with an explicitly negotiated API version.

Drydock never calls docker.from_env() and never lets docker-py pick a version: it reads
the daemon's /version, then drives the daemon at min(server max, 1.56), so request bodies
are never sent to an API version drydock was not tested against. Daemons below 1.44 are
refused because container create accepts multiple networks only from 1.44 on.

docker-py is blocking. Every call from async code goes through run_blocking().
"""

import functools
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import anyio.to_thread
import docker
import docker.errors
import requests

MIN_API_VERSION = "1.44"
MAX_API_VERSION = "1.56"
ALLOWED_SCHEMES = ("unix", "tcp", "http", "https")
VERSION_TIMEOUT = 10
DEFAULT_TIMEOUT = 60
API_VERSION_RE = re.compile(r"(\d{1,3})\.(\d{1,3})")


class DockerUnavailable(Exception):
    """The daemon could not be reached or refused the request."""


class UnsupportedDaemon(DockerUnavailable):
    """The daemon speaks no API version drydock supports."""


async def run_blocking[T](fn: Callable[..., T], /, *args: Any, **kwargs: Any) -> T:
    """Runs a blocking call (any docker-py call) on a worker thread."""
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


def api_tuple(value: object) -> tuple[int, int]:
    match = API_VERSION_RE.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise UnsupportedDaemon(f"The daemon reported an invalid API version: {value!r}.")
    return int(match.group(1)), int(match.group(2))


def negotiate(version_info: dict[str, Any]) -> str:
    """Picks the API version to use from the daemon's /version response."""
    server_max = api_tuple(version_info.get("ApiVersion"))
    server_min = api_tuple(version_info.get("MinAPIVersion") or version_info.get("ApiVersion"))
    engine = version_info.get("Version", "unknown")
    if server_max < api_tuple(MIN_API_VERSION):
        raise UnsupportedDaemon(
            f"Docker Engine {engine} supports API versions up to {server_max[0]}.{server_max[1]}. "
            f"Drydock needs API {MIN_API_VERSION} or newer (Docker Engine 25.0 or later)."
        )
    chosen = min(server_max, api_tuple(MAX_API_VERSION))
    if server_min > chosen:
        raise UnsupportedDaemon(
            f"Docker Engine {engine} requires API {server_min[0]}.{server_min[1]} or newer. "
            f"This drydock release supports API {MIN_API_VERSION} to {MAX_API_VERSION}."
        )
    return f"{chosen[0]}.{chosen[1]}"


def check_url(base_url: str) -> str:
    scheme = urlsplit(base_url).scheme
    if scheme not in ALLOWED_SCHEMES:
        raise DockerUnavailable(
            f"Unsupported Docker URL scheme {scheme!r}; use one of {', '.join(ALLOWED_SCHEMES)}."
        )
    return base_url


@dataclass
class DockerHandle:
    client: docker.DockerClient
    api_version: str
    engine_version: str
    arch: str
    os: str

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> DockerHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_version(base_url: str) -> dict[str, Any]:
    """GET /version without a version prefix, so it works on any daemon."""
    probe = docker.APIClient(
        base_url=check_url(base_url), version=MIN_API_VERSION, timeout=VERSION_TIMEOUT
    )
    probe.trust_env = False  # no HTTP(S)_PROXY or .netrc from the environment
    try:
        return probe.version(api_version=False)
    except docker.errors.APIError as exc:
        # Only the status: the body is whatever the URL serves, and this text is shown.
        status = exc.status_code or "an error"
        raise DockerUnavailable(
            f"Cannot reach the Docker daemon: it answered HTTP {status}."
        ) from None
    except (docker.errors.DockerException, requests.RequestException) as exc:
        raise DockerUnavailable(f"Cannot reach the Docker daemon: {exc}") from None
    finally:
        probe.close()


def open_client(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> DockerHandle:
    """Blocking. Use connect() from async code."""
    info = read_version(base_url)
    api_version = negotiate(info)
    client = docker.DockerClient(base_url=base_url, version=api_version, timeout=timeout)
    client.api.trust_env = False
    return DockerHandle(
        client=client,
        api_version=api_version,
        engine_version=str(info.get("Version", "unknown")),
        arch=str(info.get("Arch", "unknown")),
        os=str(info.get("Os", "unknown")),
    )


async def connect(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> DockerHandle:
    return await run_blocking(open_client, base_url, timeout)
