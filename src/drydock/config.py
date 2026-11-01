"""Settings read from the environment. Startup fails on anything invalid."""

import base64
import binascii
import functools
import ipaddress
import os
import re
import stat
import zoneinfo
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from drydock.hosts.client import ALLOWED_SCHEMES

KEY_HELP = (
    'Generate a key with: python -c "import base64, secrets; '
    'print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"'
)
MAX_KEY_FILE_BYTES = 4096
LOOPBACK_NAMES = {"localhost", "localhost.localdomain"}
# Short-lived helper containers that mount volumes. Pinned by multi-arch index digest, so
# hosts on any architecture pull the matching image. DRYDOCK_HELPER_IMAGE overrides it (for
# example a mirror on an air-gapped network), and must be pinned by digest too.
DEFAULT_HELPER_IMAGE = (
    "docker.io/library/busybox:1.37.0"
    "@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
)
DIGEST_PINNED_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}")
DEFAULT_PROXIES = "127.0.0.1"  # uvicorn's own default for FORWARDED_ALLOW_IPS
DEFAULT_RUN_HISTORY_DAYS = 90
MAX_RUN_HISTORY_DAYS = 36500


class ConfigError(Exception):
    """Raised when the environment cannot produce a safe configuration."""


@dataclass(frozen=True)
class Settings:
    secret_keys: tuple[bytes, ...]  # newest first
    base_url: str  # origin only, for example "https://drydock.example.com"
    allowed_hosts: tuple[str, ...]
    data_dir: Path
    staging_dir: Path
    run_dir: Path  # private tmpfs for SSH forward sockets and the rclone rc socket
    local_docker_url: str | None
    helper_image: str
    restore_paths: tuple[Path, ...]
    local_storage_roots: tuple[Path, ...]
    forwarded_allow_ips: tuple[str, ...]
    tz: str
    run_history_days: int = DEFAULT_RUN_HISTORY_DAYS  # older finished runs and logs are pruned

    @property
    def public_https(self) -> bool:
        """HTTPS on a non-loopback host: a real deployment, normally behind a reverse proxy."""
        parts = urlsplit(self.base_url)
        return parts.scheme == "https" and not is_loopback(parts.hostname or "")

    @property
    def cookie_secure(self) -> bool:
        """False only for plain HTTP on a non-loopback address."""
        parts = urlsplit(self.base_url)
        return parts.scheme == "https" or is_loopback(parts.hostname or "")


def is_loopback(host: str) -> bool:
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# SECRET KEY


def parse_keys(text: str, source: str) -> tuple[bytes, ...]:
    tokens = split_list(text)
    if not tokens:
        raise ConfigError(f"{source} is empty. {KEY_HELP}")
    keys: list[bytes] = []
    for index, token in enumerate(tokens, start=1):
        try:
            raw = base64.b64decode(token.replace("+", "-").replace("/", "_"), b"-_", validate=True)
        except binascii.Error:
            raw = b""
        if len(raw) != 32:
            raise ConfigError(
                f"{source}: key {index} is malformed. Each key must be 32 random bytes encoded "
                f"as base64 (44 characters). {KEY_HELP}"
            )
        if len(set(raw)) < 16:
            raise ConfigError(f"{source}: key {index} is not random enough. {KEY_HELP}")
        if raw in keys:
            raise ConfigError(f"{source}: key {index} is listed twice.")
        keys.append(raw)
    return tuple(keys)


def read_key_file(path_text: str) -> str:
    path = Path(path_text)
    hint = "The file must be readable by uid 10001 (chown 10001 and chmod 0400 on the host file)."
    try:
        with path.open("rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ConfigError(f"DRYDOCK_SECRET_KEY_FILE={path} is not a regular file.")
            data = handle.read(MAX_KEY_FILE_BYTES + 1)
    except OSError as exc:
        raise ConfigError(
            f"DRYDOCK_SECRET_KEY_FILE={path} could not be read ({exc.strerror}). {hint}"
        ) from None
    if len(data) > MAX_KEY_FILE_BYTES:
        raise ConfigError(
            f"DRYDOCK_SECRET_KEY_FILE={path} is larger than {MAX_KEY_FILE_BYTES} bytes."
        )
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigError(f"DRYDOCK_SECRET_KEY_FILE={path} is not ASCII text.") from None


def load_secret_keys(env: Mapping[str, str]) -> tuple[bytes, ...]:
    inline = env.get("DRYDOCK_SECRET_KEY")
    file_path = env.get("DRYDOCK_SECRET_KEY_FILE")
    if inline and file_path:
        raise ConfigError("Set only one of DRYDOCK_SECRET_KEY and DRYDOCK_SECRET_KEY_FILE.")
    if file_path:
        return parse_keys(read_key_file(file_path), "DRYDOCK_SECRET_KEY_FILE")
    if inline:
        return parse_keys(inline, "DRYDOCK_SECRET_KEY")
    raise ConfigError(
        "No secret key configured. Set DRYDOCK_SECRET_KEY_FILE (preferred) or DRYDOCK_SECRET_KEY. "
        + KEY_HELP
    )


# OTHER SETTINGS


def parse_base_url(value: str) -> str:
    try:
        parts = urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise ConfigError(f"DRYDOCK_BASE_URL={value!r} is not a valid URL.") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("DRYDOCK_BASE_URL must be an http:// or https:// URL with a host.")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfigError("DRYDOCK_BASE_URL must not contain credentials, a query or a fragment.")
    if parts.path not in ("", "/"):
        raise ConfigError(
            "DRYDOCK_BASE_URL must point at the root path; sub-paths are not supported."
        )
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parts.scheme == "https" else 80
    netloc = host if port in (None, default_port) else f"{host}:{port}"
    return f"{parts.scheme}://{netloc}"


def split_list(value: str | None) -> list[str]:
    return [item for item in re.split(r"[\s,]+", value or "") if item]


def parse_paths(name: str, value: str | None) -> tuple[Path, ...]:
    paths = []
    for item in split_list(value):
        path = Path(item)
        if not path.is_absolute():
            raise ConfigError(f"{name}: {item!r} is not an absolute path.")
        paths.append(path)
    return tuple(paths)


def parse_proxies(value: str | None) -> tuple[str, ...]:
    items = split_list(value if value is not None else DEFAULT_PROXIES)
    for item in items:
        if item == "*":
            continue
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ConfigError(
                f"FORWARDED_ALLOW_IPS: {item!r} is not an IP address or network."
            ) from None
    return tuple(items)


def parse_allowed_hosts(value: str | None, base_url: str) -> tuple[str, ...]:
    base_host = urlsplit(base_url).hostname or ""
    hosts = split_list(value) or [base_host]
    if "*" in hosts:
        raise ConfigError("DRYDOCK_ALLOWED_HOSTS must not contain '*'; list the real host names.")
    # Loopback names cannot be used for DNS rebinding, and the SSH tunnel and HEALTHCHECK use them.
    return tuple(dict.fromkeys([h.lower() for h in hosts] + ["localhost", "127.0.0.1"]))


@functools.cache
def known_zones() -> frozenset[str]:
    """IANA zone names. Before Python 3.15, available_timezones() also lists "localtime"
    (Debian's link to /etc/localtime), which names no zone."""
    return frozenset(zoneinfo.available_timezones()) - {"localtime"}


def load_settings(env: Mapping[str, str] = os.environ) -> Settings:
    keys = load_secret_keys(env)
    base_url = parse_base_url(env.get("DRYDOCK_BASE_URL", "http://localhost:8000"))
    data_dir = Path(env.get("DRYDOCK_DATA_DIR", "/data"))
    staging_dir = Path(env.get("DRYDOCK_STAGING_DIR", "/data/staging"))
    run_dir = Path(env.get("DRYDOCK_RUN_DIR", "/run/drydock"))
    for name, path in (
        ("DRYDOCK_DATA_DIR", data_dir),
        ("DRYDOCK_STAGING_DIR", staging_dir),
        ("DRYDOCK_RUN_DIR", run_dir),
    ):
        if not path.is_absolute():
            raise ConfigError(f"{name} must be an absolute path.")
    # Startup recovery empties the staging directory of drydock's scratch files.
    staging = Path(os.path.normpath(staging_dir))
    if any(Path(os.path.normpath(path)).is_relative_to(staging) for path in (data_dir, run_dir)):
        raise ConfigError(
            "DRYDOCK_STAGING_DIR must be a directory of its own, not the data or run "
            "directory or one that contains them (the default is /data/staging)."
        )
    helper_image = env.get("DRYDOCK_HELPER_IMAGE") or DEFAULT_HELPER_IMAGE
    if not DIGEST_PINNED_RE.fullmatch(helper_image):
        raise ConfigError(
            "DRYDOCK_HELPER_IMAGE must be pinned by digest, for example "
            f"{DEFAULT_HELPER_IMAGE}. Use the digest of the multi-arch index."
        )
    docker_url = env.get("DRYDOCK_LOCAL_DOCKER_URL") or None
    if docker_url and urlsplit(docker_url).scheme not in ALLOWED_SCHEMES:
        schemes = ", ".join(f"{scheme}://" for scheme in ALLOWED_SCHEMES)
        raise ConfigError(f"DRYDOCK_LOCAL_DOCKER_URL must use one of {schemes}.")
    tz = env.get("TZ") or "UTC"
    # The same check as a job's own time zone (jobs.scheduler.zone): a listed name only.
    if tz not in known_zones():
        raise ConfigError(f"TZ={tz!r} is not a known time zone.")
    history = env.get("DRYDOCK_RUN_HISTORY_DAYS") or str(DEFAULT_RUN_HISTORY_DAYS)
    if not (
        history.isascii()
        and history.isdigit()
        and len(history) <= 5
        and 1 <= int(history) <= MAX_RUN_HISTORY_DAYS
    ):
        raise ConfigError(
            f"DRYDOCK_RUN_HISTORY_DAYS must be a whole number of days from 1 to "
            f"{MAX_RUN_HISTORY_DAYS}."
        )
    return Settings(
        secret_keys=keys,
        base_url=base_url,
        allowed_hosts=parse_allowed_hosts(env.get("DRYDOCK_ALLOWED_HOSTS"), base_url),
        data_dir=data_dir,
        staging_dir=staging_dir,
        run_dir=run_dir,
        local_docker_url=docker_url,
        helper_image=helper_image,
        restore_paths=parse_paths("DRYDOCK_RESTORE_PATHS", env.get("DRYDOCK_RESTORE_PATHS")),
        local_storage_roots=parse_paths(
            "DRYDOCK_LOCAL_STORAGE_ROOTS", env.get("DRYDOCK_LOCAL_STORAGE_ROOTS")
        ),
        forwarded_allow_ips=parse_proxies(env.get("FORWARDED_ALLOW_IPS")),
        tz=tz,
        run_history_days=int(history),
    )
