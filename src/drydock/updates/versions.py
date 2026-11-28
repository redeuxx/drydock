"""Which version an image is, for the pages that show updates.

An image's version is the <NAME>_VERSION environment variable Docker's official images
set (NGINX_VERSION for nginx, PG_VERSION for postgres), else its
org.opencontainers.image.version label, unless that label came with a base image (its
ref.name label names another image: mongo inherits ubuntu's 22.04). With neither, the
pages show the short digest.

The version an update brings is in the new image's config, which the daemon's
distribution lookup (updates/check.py) does not give. registry_version reads it from the
registry itself: anonymously, over HTTPS, and only from the public registries in
REGISTRIES, so an image name on a managed host never sends drydock's own requests
anywhere else (an internal address, say). Private images, other registries and failures
give no version. Docker Hub counts the two manifest reads of each new digest as pulls of
drydock's address; the checker asks once per digest.
"""

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

import docker.auth
import docker.errors
import docker.utils
import requests

from drydock.models import Run

log = logging.getLogger("drydock.updates")

VERSION_LABEL = "org.opencontainers.image.version"
REF_NAME_LABEL = "org.opencontainers.image.ref.name"
MAX_VERSION = 80  # characters of a version kept
# Control and bidirectional characters: a label must not reorder the line it is shown in.
UNSHOWN_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# ponytail: official images whose variable is not <NAME>_VERSION; add more as they turn up.
ENV_NAMES = {"postgres": "PG_VERSION"}

# The registry as image names give it: (its API host, the hosts its tokens may come from).
REGISTRIES = {
    "docker.io": ("registry-1.docker.io", frozenset({"auth.docker.io"})),
    "ghcr.io": ("ghcr.io", frozenset({"ghcr.io"})),
    "lscr.io": ("ghcr.io", frozenset({"ghcr.io"})),  # LinuxServer's name for ghcr.io
    "quay.io": ("quay.io", frozenset({"quay.io"})),
    "gcr.io": ("gcr.io", frozenset({"gcr.io"})),
    "mcr.microsoft.com": ("mcr.microsoft.com", frozenset()),
    "registry.gitlab.com": ("registry.gitlab.com", frozenset({"gitlab.com"})),
    "public.ecr.aws": ("public.ecr.aws", frozenset({"public.ecr.aws"})),
}
MANIFESTS = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
REPOSITORY_RE = re.compile(r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*")
TIMEOUT = 10  # seconds per connection or read
DEADLINE = 20  # seconds one registry_version may take in all
MAX_BODY = 4 * 1024 * 1024
MAX_REDIRECTS = 3

Platform = tuple[str, str, str]  # os, architecture, variant ("" for none)
UPDATE_FIELDS = ("name", "old", "new", "old_ref", "new_ref", "old_version", "new_version")
UNFINISHED = ("failed", "cancelled", "interrupted")  # an update that ended so put all back


def clean(text: str) -> str:
    return UNSHOWN_RE.sub("", text).strip()[:MAX_VERSION]


def image_version(config: Any, repository: str = "") -> str:
    """The version an image's config (inspect's Config, or a registry config blob's
    config) names, or ""."""
    if not isinstance(config, dict):
        return ""
    name = repository.rpartition("/")[2]
    variable = ENV_NAMES.get(name, re.sub(r"[^A-Z0-9]", "_", name.upper()) + "_VERSION")
    for entry in config.get("Env") or []:
        key, _, found = entry.partition("=") if isinstance(entry, str) else ("", "", "")
        if key == variable and (value := clean(found)):
            return value
    labels = config.get("Labels")
    labels = labels if isinstance(labels, dict) else {}
    label, ref_name = labels.get(VERSION_LABEL), labels.get(REF_NAME_LABEL)
    if isinstance(ref_name, str) and ref_name and ref_name.rpartition("/")[2] != name:
        return ""  # the base image's
    return clean(label) if isinstance(label, str) else ""


def repository_key(repository: str) -> tuple[str, str]:
    """(registry, name) of a repository however it is written: nginx,
    docker.io/library/nginx and index.docker.io/library/nginx are one."""
    try:
        index, name = docker.auth.resolve_repository_name(repository)
    except docker.errors.DockerException:
        return ("", repository)
    if index == "docker.io" and "/" not in name:
        name = f"library/{name}"
    return (index, name)


def own_digest(repo_digests: Any, repository: str) -> str:
    """The digest an image was pulled as from repository (its RepoDigests entry for it),
    else its first one, else ""."""
    entries = [d for d in repo_digests or [] if isinstance(d, str) and "@" in d]
    key = repository_key(repository)
    for entry in entries:
        if repository_key(entry.partition("@")[0]) == key:
            return entry.partition("@")[2]
    return entries[0].partition("@")[2] if entries else ""


def short_digest(digest: str) -> str:
    return digest.removeprefix("sha256:")[:12]


def describe(
    old_version: str,
    old_digest: str,
    new_version: str,
    new_digest: str,
    old_ref: str = "",
    new_ref: str = "",
) -> str:
    """'old -> new' for one container: the versions, else the short digests (and both
    when the versions are the same, as for a rebuild), with the tags when they differ."""
    if old_version and old_version == new_version:
        old_version = f"{old_version} ({short_digest(old_digest) or 'no digest'})"
        new_version = f"{new_version} ({short_digest(new_digest)})"
    old = old_version or short_digest(old_digest) or "unknown"
    new = new_version or short_digest(new_digest) or "unknown"
    if old_ref != new_ref:
        old = f"{old_ref.rpartition(':')[2] or 'pinned'} {old}"
        new = f"{new_ref.rpartition(':')[2]} {new}"
    return f"{old} → {new}"


def plan_object(text: str | None) -> dict[str, Any]:
    try:
        doc = json.loads(text or "{}")
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def update_entries(run: Run, key: str) -> list[dict[str, str]]:
    """An update run's recorded containers (dispatcher _set_changes), each field a string."""
    entries = plan_object(run.plan).get(key) if run.kind == "update" else None
    return [
        {k: v if isinstance(v := entry.get(k), str) else "" for k in UPDATE_FIELDS}
        for entry in (entries if isinstance(entries, list) else [])
        if isinstance(entry, dict)
    ]


def update_current(run: Run) -> list[str]:
    """The version each container an update left as it is runs, one line each."""
    return [
        f"{get['name']}: {get['old_version'] or short_digest(get['old']) or 'unknown'}"
        for get in update_entries(run, "current")
    ]


def stack_runs(run: Run) -> list[int]:
    """The stack update runs an every-stack update run started (dispatcher
    _add_stack_run)."""
    ids = plan_object(run.plan).get("stacks") if run.kind == "update" else None
    return [i for i in ids if type(i) is int] if isinstance(ids, list) else []


def update_changes(run: Run) -> list[str]:
    """What an update moved each container from and to, one line each
    (updates/versions.py describe)."""
    lines = []
    for get in update_entries(run, "changes"):
        moved = describe(
            get["old_version"],
            get["old"],
            get["new_version"],
            get["new"],
            get["old_ref"],
            get["new_ref"],
        )
        # All or nothing: a run that did not finish put every container back.
        undone = " (not applied)" if run.status in UNFINISHED else ""
        lines.append(f"{get['name']}: {moved}{undone}")
    return lines


class Reader:
    """GETs from one repository of one registry, with an anonymous token when asked."""

    def __init__(self, session: requests.Session, host: str, realms: frozenset[str], name: str):
        self.session = session
        self.base = f"https://{host}/v2/{name}/"
        self.realms = realms
        self.token: str | None = None
        self.deadline = time.monotonic() + DEADLINE

    def in_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise TimeoutError("the registry took too long")

    def get(self, url: str, headers: dict[str, str]) -> requests.Response:
        """Follows redirects by hand: HTTPS only, the token only to the same host."""
        for _ in range(MAX_REDIRECTS + 1):
            self.in_time()
            response = self.session.get(
                url, headers=headers, timeout=TIMEOUT, allow_redirects=False, stream=True
            )
            if not response.is_redirect:
                return response
            response.close()
            target = urljoin(url, response.headers.get("Location", ""))
            if urlsplit(target).scheme != "https":
                raise ValueError("redirect away from HTTPS")
            if urlsplit(target).netloc != urlsplit(url).netloc:
                headers = {k: v for k, v in headers.items() if k != "Authorization"}
            url = target
        raise ValueError("too many redirects")

    def body(self, response: requests.Response) -> Any:
        with response:
            response.raise_for_status()
            data = b""
            for chunk in response.iter_content(65536):
                self.in_time()
                data += chunk
                if len(data) > MAX_BODY:
                    raise ValueError("answer too large")
        return json.loads(data)

    def fetch(self, path: str, accept: str) -> Any:
        headers = {"Accept": accept}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = self.get(self.base + path, headers)
        if response.status_code == 401 and self.token is None:
            challenge = response.headers.get("WWW-Authenticate", "")
            response.close()
            self.token = self.anonymous_token(challenge)
            return self.fetch(path, accept)
        return self.body(response)

    def anonymous_token(self, challenge: str) -> str:
        scheme, _, params = challenge.partition(" ")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', params))
        realm = fields.get("realm", "")
        where = urlsplit(realm)
        if (
            scheme.lower() != "bearer"
            or where.scheme != "https"
            or where.hostname not in self.realms
        ):
            raise ValueError("unexpected token realm")
        self.in_time()
        response = self.session.get(
            realm,
            params={k: fields[k] for k in ("service", "scope") if k in fields},
            timeout=TIMEOUT,
            allow_redirects=False,
            stream=True,
        )
        doc = self.body(response)
        token = doc.get("token") or doc.get("access_token") if isinstance(doc, dict) else None
        if not isinstance(token, str) or not token:
            raise ValueError("no token")
        return token


def pick(manifests: Any, platform: Platform) -> str | None:
    """The digest of an index's manifest for the platform."""
    os_name, architecture, variant = platform
    for entry in manifests if isinstance(manifests, list) else []:
        found = entry.get("platform") if isinstance(entry, dict) else None
        if not isinstance(found, dict):
            continue
        if (found.get("os"), found.get("architecture")) != (os_name, architecture):
            continue
        if variant and found.get("variant") not in (None, variant):
            continue
        digest = entry.get("digest")
        if isinstance(digest, str) and DIGEST_RE.fullmatch(digest):
            return digest
    return None


def registry_version(ref: str, digest: str, platform: Platform) -> str | None:
    """Blocking. The version the image ref names at digest (an index or a manifest) has,
    for the platform; "" when it names none or the registry is not a public one drydock
    asks; None when asking failed. Never raises."""
    repository, _ = docker.utils.parse_repository_tag(ref)
    index, name = repository_key(repository)
    known = REGISTRIES.get(index)
    if known is None or not DIGEST_RE.fullmatch(digest) or not REPOSITORY_RE.fullmatch(name):
        return ""
    try:
        with requests.Session() as session:
            reader = Reader(session, known[0], known[1], name)
            doc = reader.fetch(f"manifests/{digest}", MANIFESTS)
            if isinstance(doc, dict) and "manifests" in doc:
                chosen = pick(doc["manifests"], platform)
                if chosen is None:
                    return ""
                doc = reader.fetch(f"manifests/{chosen}", MANIFESTS)
            config = doc.get("config") if isinstance(doc, dict) else None
            blob = config.get("digest") if isinstance(config, dict) else None
            if not isinstance(blob, str) or not DIGEST_RE.fullmatch(blob):
                return ""
            image = reader.fetch(f"blobs/{blob}", "application/json, */*")
            return image_version(image.get("config") if isinstance(image, dict) else None, name)
    except Exception as exc:  # only a label for the pages: never in the way of the check
        log.info("Reading the version of %s from its registry failed: %s", ref, exc)
        return None
