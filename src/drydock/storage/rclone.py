"""Remote storage through rclone: RcloneBackend, the second StorageBackend.

Remotes are inline. Every call carries the whole backend configuration (an rclone "fs"),
built here from the target's stored options and nothing else:
- Only allowlisted options (storage.options) go in, checked again here, and drydock's FIXED
  options come last, so nothing stored can override them. For sftp that is no known_hosts
  file, no agent or key file, no trust on first use, and shell_type none (rclone never runs
  commands on the server). The pinned host key (host_keys) is required and never empty:
  rclone checks no host key at all when it is empty. For smb it is no Kerberos (which reads
  a credential cache file), and for webdav no command, header, unix socket or credentials
  kept across redirects.
- WebDAV is https only, and a pinned certificate (storage.certs) goes to rclone as every
  call's _config CaCert, a file in the run directory named by its fingerprint.
- Password options (rclone's IsPassword) are obscured through rclone, once per secret
  (RcloneDaemon.obscure). The private key carries its newlines as \\n, as rclone expects.
- rc calls take the fs as a JSON object. read_head's ranged read goes through rcd's
  --rc-serve with the fs as a connection string in the URL path, where rclone ends it at the
  first "]". Values and folders holding one are refused (forms refuse them too).

rclone's error text is untrusted: it can quote parameters and gives advice drydock does not
follow (trust on first use). It is logged redacted, and a StorageError carries one of the
fixed messages in ERRORS instead.

Uploads: rclone writes <name>.<8 hex>.partial and renames it once complete, so nothing
appears under the archive name early. copyfile replaces silently, so put checks first.
Cancel stops the rclone job, which removes its partial file; one left behind is removed or
named in the error. The source of every upload is a file drydock made in its staging
directory: rclone runs as drydock's user and could read anything drydock can.

Downloads (restores): get copies an archive into a new file below the staging directory,
after checking that the disk there has room for it, and leaves nothing behind unless the
whole archive arrived. Restores read that copy (restore.verify.Downloaded), so open, which
would read in place, is refused.
"""

import contextlib
import logging
import os
import re
import secrets
import shutil
import stat
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from drydock.archive.writer import RESERVE, STAGING, InsufficientSpace, create_new, ensure_space
from drydock.storage import certs, options
from drydock.storage.base import Progress, StorageError, StoredObject, check_name
from drydock.storage.rclone_rc import (
    MAX_ERROR,
    RcloneDaemon,
    RcloneError,
    RcloneUnavailable,
    redact_connections,
)

log = logging.getLogger("drydock.rclone")

KINDS = frozenset({"sftp", "smb", "webdav"})  # kinds drydock transfers to; 6f adds drive
FIXED: dict[str, dict[str, str]] = {
    "sftp": {
        "shell_type": "none",
        "known_hosts_file": "",
        "pin_host_key": "false",
        "key_use_agent": "false",
        "key_file": "",
    },
    "smb": {"use_kerberos": "false", "kerberos_ccache": ""},
    "webdav": {
        "bearer_token_command": "",
        "headers": "",
        "unix_socket": "",
        "auth_redirect": "false",
    },
}
# rclone writes <name>.<8 hex>.partial itself only where the backend has PartialUploads (sftp
# and smb). For these kinds put() does the same: upload as such a name, then rename.
OWN_PARTIAL = frozenset({"webdav"})
FS_PARAMS = ("fs", "srcFs", "dstFs")  # where a call names a backend
UPLOAD_RE = re.compile(r"upload-[0-9a-f]{32}")  # staging files put() uploads
CHECK_PREFIX = "check-"  # test()'s staging file: not a scratch name the hourly clean takes
PROBE_PREFIX = ".drydock-test-"  # never an archive name, so list() ignores a leftover
# rclone's partial name is <name>.<8 hex>.partial, but a name over PARTIAL_MAX characters
# first loses as many characters as that suffix has (fs/operations/copy.go).
PARTIAL_MAX = 100
PARTIAL_SUFFIX_LEN = len(".01234567.partial")
POLL = 1.0  # seconds between job/status calls during a transfer
STOP_WAIT = 15.0  # for a stopped job to finish; with the sweep, well inside SHUTDOWN_WAIT
QUICK = 10.0  # timeout of calls that open no connection, and of those made while stopping
TIMEOUT = 90.0  # above rclone's 1 minute connect timeout, so its own error arrives first
PREVIEW_TIMEOUT = 15.0  # read_head: a listing previews archives one after another
LATER = "Transfers to this kind of storage arrive in a later release."
NOT_IN_PLACE = "A remote archive is read from its download in the staging directory."
CANCELLED = "The transfer was cancelled."
RESTARTED = "rclone restarted during the transfer, so it did not finish."
BAD_CONFIG = "The storage settings are not valid. Edit the storage and save it again."
NO_HOST_KEY = (
    "This storage has no valid host key. Edit it and enter the server's public host key: "
    "drydock never connects without one."
)
UNKNOWN = "The remote storage reported an error. See the drydock server log."
WRONG_KEY = "The server's host key does not match the host key in the settings."
UNTRUSTED = (
    "The server's certificate is not trusted. If no public authority signed it, fetch it on "
    "the storage page, compare its fingerprint and save it."
)
NOT_HTTPS = "WebDAV storage needs an https:// URL. Edit the storage and save it again."
SHARE_MISSING = "The share does not exist on the server."
# (lower-case text in rclone's error, the message to show). First match wins.
ERRORS = (
    ("host key mismatch", WRONG_KEY),
    ("no key is pinned for this algorithm", WRONG_KEY),
    ("no common algorithm for host key", WRONG_KEY),
    ("ssh certificate", "The server presents an SSH certificate, which drydock cannot pin."),
    ("unable to authenticate", "The server refused the user name, password or key."),
    ("certificate signed by unknown authority", UNTRUSTED),
    ("certificate is valid for", "The server's certificate is not for the host in the URL."),
    ("certificate is not valid for any names", "The server's certificate lists no host names."),
    ("certificate has expired", "The server's certificate has expired or is not valid yet."),
    ("refusing to follow https to http redirect", "The server redirected to plain http."),
    ("401 unauthorized", "The server refused the user name, password or token."),
    ("logon is invalid", "The server refused the user name or password."),
    ("network name not found", SHARE_MISSING),
    ("doesn't contain any ip sans", "The server's certificate is not for the host in the URL."),
    ("403 forbidden", "The server denied access to the folder."),
    ("access denied", "The server denied access to the folder."),
    ("507 insufficient storage", "The remote storage is full."),
    ("pem key not formatted", "The private key cannot be used."),
    ("failed to parse private key", "The private key or its passphrase cannot be used."),
    ("connection refused", "The server refused the connection. Check the host and port."),
    ("no such host", "The host name cannot be resolved."),
    ("i/o timeout", "The server did not answer in time."),
    ("deadline exceeded", "The server did not answer in time."),
    ("no route to host", "The server cannot be reached."),
    ("network is unreachable", "The server cannot be reached."),
    ("permission denied", "The server denied access to the folder."),
    ("no space left", "The remote storage is full."),
    ("quota exceeded", "The remote storage is full."),
    ("disk quota", "The remote storage is full."),
    ("disk was full", "The remote storage is full."),
    ("insufficient quota", "The remote storage is full."),
    ("quota was exceeded", "The remote storage is full."),
    ("job not found", RESTARTED),
    ("context canceled", CANCELLED),
)
SHORTEST_NEEDLE = min(len(needle) for needle, _ in (*ERRORS, ("not found", "")))
FRACTION_RE = re.compile(r"(\.\d{6})\d+")


class NotFound(StorageError):
    """The object (or the folder) does not exist. The message is safe to show."""


def settings_for(
    kind: str, config: dict[str, Any], obscure: Callable[[str], str]
) -> dict[str, str]:
    """The rclone options of a target, from its stored config. Raises StorageError."""
    if kind not in KINDS:
        raise StorageError(LATER)
    stored, folder = config.get("options"), config.get("folder")
    if not isinstance(stored, dict) or not isinstance(folder, str):
        raise StorageError(BAD_CONFIG)
    values: dict[str, str] = {}
    # Checked before obscure calls rclone: a target that cannot be used makes no call.
    if kind == "sftp":
        try:
            values["host_keys"] = options.host_keys(str(stored.get("host_keys", "")))
        except ValueError:
            raise StorageError(NO_HOST_KEY) from None
    if ":" in str(stored.get("host", "")):
        raise StorageError(BAD_CONFIG)
    if kind == "webdav":
        if options.url_error(str(stored.get("url", ""))):
            raise StorageError(NOT_HTTPS)
        if cert := pinned(config):
            values["description"] = f"drydock-cert-{certs.fingerprint(cert)}"
    allowed = {o.name: o for o in options.BACKENDS[kind].options}
    for name, value in stored.items():
        option = allowed.get(name)
        if option is None or not isinstance(value, str):
            raise StorageError(BAD_CONFIG)
        if not value or name in values or not option.rclone:
            continue
        if option.obscure:
            value = obscure(value)
        elif option.type == "pem":
            value = value.replace("\n", "\\n")  # options refuses backslashes in keys
        values[name] = value
    return values | FIXED[kind]


def pinned(config: dict[str, Any]) -> Any:
    """The target's pinned certificate (x509.Certificate), or None. Raises StorageError."""
    stored = config.get("options")
    text = stored.get("tls_cert") if isinstance(stored, dict) else None
    if not text:
        return None
    try:
        return certs.load(str(text))
    except certs.CertificateError:
        raise StorageError(BAD_CONFIG) from None


def partial_name(name: str) -> str:
    """A partial upload's name as rclone makes it (partial_pattern matches it)."""
    stem, _ = partial_pattern(name)
    return f"{stem}.{secrets.token_hex(4)}.partial"


def quote_value(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def connection_string(kind: str, values: dict[str, str], folder: str) -> str:
    """The fs as a connection string, for the ranged GET. rcserver ends it at the first "]"
    whatever the quotes, so a "]" anywhere is refused rather than cut short."""
    body = ",".join(f"{k}={quote_value(v)}" for k, v in sorted(values.items()))
    conn = f":{kind},{body}:{folder}"
    if "]" in conn or options.CONTROL_RE.search(conn):
        raise StorageError("The storage settings hold a ] or a control character.")
    return conn


def partial_pattern(name: str) -> tuple[str, re.Pattern[str]]:
    """The stem of rclone's partial files of name, and a pattern matching their names."""
    stem = name if len(name) <= PARTIAL_MAX else name[: len(name) - PARTIAL_SUFFIX_LEN]
    return stem, re.compile(re.escape(stem) + r"\.[0-9a-f]{8}\.partial")


class Reserved:
    """Bytes promised to downloads in flight, so that two restores downloading at once
    cannot each pass the free-space check alone. ponytail: one total for every staging
    disk; per-device totals if staging ever spans several."""

    lock = threading.Lock()
    total = 0

    @classmethod
    @contextlib.contextmanager
    def space(cls, folder: Path, size: int) -> Iterator[None]:
        with cls.lock:
            ensure_space(folder, cls.total + size, STAGING)
            cls.total += size
        try:
            yield
        finally:
            with cls.lock:
                cls.total -= size


def remove_download(local: Path) -> None:
    """Removes a download that did not finish: the file and rclone's partial files of it.
    rclone removes its partial file itself, unless it was killed first."""
    local.unlink(missing_ok=True)
    _, partial = partial_pattern(local.name)
    with contextlib.suppress(FileNotFoundError), os.scandir(local.parent) as entries:
        for entry in entries:
            if partial.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                Path(entry.path).unlink(missing_ok=True)


def parse_time(value: Any) -> datetime:
    """rclone's ModTime (RFC 3339, up to nanoseconds); the epoch if it is not one."""
    try:
        return datetime.fromisoformat(FRACTION_RE.sub(r"\1", str(value))).astimezone(UTC)
    except ValueError:
        return datetime.fromtimestamp(0, UTC)


class RcloneBackend:
    def __init__(
        self, daemon: RcloneDaemon, kind: str, config: dict[str, Any], staging_dir: Path
    ) -> None:
        if kind not in KINDS:
            raise StorageError(LATER)
        self._daemon = daemon
        self._kind = kind
        self._config = config
        self._staging = staging_dir
        self._values: dict[str, str] | None = None  # built on first use: obscure calls rclone
        self._ca: Path | None = None  # the pinned certificate's file, once _settings ran

    # FS VALUES

    def _settings(self) -> dict[str, str]:
        if self._values is None:
            values = settings_for(self._kind, self._config, self._obscure)
            self._ca = self._write_ca()
            self._values = values
        return self._values

    def _write_ca(self) -> Path | None:
        """Writes the pinned certificate where rclone reads it, named by its fingerprint.
        rclone ends a call that names a missing or broken file, so it is written whole and
        then renamed into place."""
        cert = pinned(self._config)
        if cert is None:
            return None
        folder = self._daemon.run_dir / "certs"
        path = folder / f"{certs.fingerprint(cert)}.pem"
        if path.is_file():
            return path
        try:
            folder.mkdir(mode=0o700, exist_ok=True)
            temporary = folder / f".{uuid.uuid4().hex}.tmp"
            try:
                with create_new(temporary) as handle:
                    handle.write(certs.pem(cert).encode())
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
        except OSError as exc:
            log.error("Cannot write the pinned certificate %s: %s", path, exc)
            raise StorageError("Drydock could not pass the pinned certificate to rclone.") from None
        return path

    def _obscure(self, secret: str) -> str:
        try:
            return self._daemon.obscure(secret)
        except RcloneUnavailable as exc:
            raise StorageError(str(exc)) from None
        except RcloneError:
            raise StorageError("Drydock could not pass a password to rclone.") from None

    def _fs(self) -> dict[str, str]:
        return {"type": self._kind, "_root": self._config["folder"], **self._settings()}

    def _source(self) -> dict[str, str]:
        return self._local(self._staging)

    def _local(self, directory: Path) -> dict[str, str]:
        return {"type": "local", "_root": str(directory)}

    def secrets(self) -> list[str]:
        """Every form of the stored secrets that reaches rclone, for redaction. Builds the
        settings first, so it raises StorageError for a target that cannot be used."""
        self._settings()
        return self._secrets()

    def _secrets(self) -> list[str]:
        backend = options.BACKENDS[self._kind]
        stored = self._config.get("options")
        stored = stored if isinstance(stored, dict) else {}
        found = [str(stored[o.name]) for o in backend.secrets if stored.get(o.name)]
        found += [v.replace("\n", "\\n") for v in found if "\n" in v]
        values = self._values or {}
        found += [values[o.name] for o in backend.options if o.obscure and values.get(o.name)]
        return found

    # CALLS

    def _call(
        self,
        method: str,
        params: dict[str, Any],
        timeout: float = TIMEOUT,
        missing: str | None = None,
    ) -> dict[str, Any]:
        if self._ca is not None and any(k in params for k in FS_PARAMS):
            params = params | {"_config": {"CaCert": [str(self._ca)]}}
        try:
            return self._daemon.call(method, params, timeout)
        except RcloneUnavailable as exc:
            raise StorageError(str(exc)) from None
        except RcloneError as exc:
            raise self._error(exc, missing) from None

    def _error(self, exc: RcloneError, missing: str | None = None) -> StorageError:
        """A fixed message for rclone's error; its own text only goes to the log, redacted."""
        text = str(exc)
        for secret in sorted(self._secrets(), key=len, reverse=True):
            text = text.replace(secret, "[redacted]")
        log.warning("rclone %s: %s", self._kind, redact_connections(text))
        lower = text.lower()
        # rclone quotes the host, user and folder: what they say must not pick the message.
        # One shorter than every needle cannot hold one, and is left alone.
        stored = self._config.get("options")
        stored = stored if isinstance(stored, dict) else {}
        # SMB quotes the folder below the share, with backslashes: each part goes too.
        folder = self._config.get("folder")
        parts = folder.split("/") if isinstance(folder, str) else []
        for value in (folder, *parts, stored.get("host"), stored.get("user"), stored.get("url")):
            if isinstance(value, str) and len(value) >= SHORTEST_NEEDLE:
                lower = lower.replace(value.lower(), "")
        if "network name not found" in lower:  # not a missing object: the share is wrong
            return StorageError(SHARE_MISSING)
        if missing is not None and (exc.status == 404 or "not found" in lower):
            return NotFound(f"{missing} does not exist in storage.")
        for needle, message in ERRORS:
            if needle in lower:
                return StorageError(message)
        return StorageError(UNKNOWN)

    def _stat(self, name: str, timeout: float = TIMEOUT) -> dict[str, Any] | None:
        try:
            item = self._call(
                "operations/stat",
                {"fs": self._fs(), "remote": name, "opt": {"noMimeType": True}},
                timeout,
                missing=name,
            ).get("item")
        except NotFound:  # the folder does not exist yet
            return None
        return item if isinstance(item, dict) else None

    # STORAGEBACKEND

    def put(
        self, local: Path, name: str, progress: Progress | None, cancel: threading.Event
    ) -> StoredObject:
        check_name(name)
        if local.parent != self._staging or not UPLOAD_RE.fullmatch(local.name):
            raise ValueError("Uploads come from drydock's staging directory only.")
        try:
            info = local.lstat()
        except FileNotFoundError:
            raise StorageError("The archive to upload is missing.") from None
        if not stat.S_ISREG(info.st_mode):
            raise StorageError("The archive to upload is not a regular file.")
        if cancel.is_set():
            raise StorageError(CANCELLED)
        if self._stat(name) is not None:
            raise StorageError(f"{name} already exists in storage.")
        if cancel.is_set():
            raise StorageError(CANCELLED)
        own = partial_name(name) if self._kind in OWN_PARTIAL else None
        endpoints = {
            "srcFs": self._source(),
            "srcRemote": local.name,
            "dstFs": self._fs(),
            "dstRemote": own or name,
        }
        try:
            done = self._transfer(endpoints, progress, cancel)
            failure = None if done else CANCELLED
            if done and own is not None:
                fs = self._fs()
                self._call(
                    "operations/movefile",
                    {"srcFs": fs, "srcRemote": own, "dstFs": fs, "dstRemote": name},
                )
        except StorageError as exc:
            failure = str(exc)
        # name did not exist before: whatever is there now is this upload, complete (rclone
        # renames only a complete file), even when the stop or a restart came too late.
        try:
            item = self._stat(name, QUICK if failure else TIMEOUT) or {}
        except StorageError:
            if failure is None:
                raise
            item = {}
        if item.get("Size") == info.st_size:
            return StoredObject(name, info.st_size, parse_time(item.get("ModTime")))
        if failure is not None:
            raise StorageError(f"{failure}{self._leftovers(name)}")
        with contextlib.suppress(StorageError):
            self._call("operations/deletefile", {"fs": self._fs(), "remote": name}, QUICK)
        raise StorageError("The uploaded archive does not have the expected size.")

    def _transfer(
        self, endpoints: dict[str, Any], progress: Progress | None, cancel: threading.Event
    ) -> bool:
        """Copies one file (copyfile's srcFs, srcRemote, dstFs and dstRemote). False when
        cancel stopped it first. Whatever ends the wait, the job is stopped: an rclone job
        left running would go on copying unseen."""
        group = f"drydock-{uuid.uuid4().hex}"  # this transfer's stats, and how it is stopped
        job = self._call("operations/copyfile", {**endpoints, "_async": True, "_group": group}).get(
            "jobid"
        )
        if type(job) is not int:
            raise StorageError("rclone did not start the transfer.")
        try:
            return self._wait(job, group, progress, cancel)
        except StorageError:
            self._stop(group)
            raise

    def _wait(
        self, job: int, group: str, progress: Progress | None, cancel: threading.Event
    ) -> bool:
        deadline: float | None = None  # set once the job is stopped
        while True:
            if deadline is None and cancel.wait(POLL):
                deadline = time.monotonic() + STOP_WAIT
                self._stop(group)
            elif deadline is not None:
                time.sleep(POLL / 2)
            status = self._call("job/status", {"jobid": job}, QUICK)
            if status.get("group") != group:  # a job id rclone reused after a restart
                raise StorageError(RESTARTED)
            if status.get("finished") is True:
                if status.get("success") is True:
                    return True  # finished before the stop: the archive is complete
                if deadline is not None:
                    return False
                raise self._error(RcloneError(500, str(status.get("error") or "")[:MAX_ERROR]))
            if deadline is not None:
                if time.monotonic() > deadline:
                    return False
            elif progress is not None:
                done = self._call("core/stats", {"group": group}, QUICK).get("bytes")
                if type(done) is int:
                    progress(done)

    def _stop(self, group: str) -> None:
        """By group, never by job id: a restarted rclone hands out the same ids again."""
        with contextlib.suppress(StorageError):
            self._call("job/stopgroup", {"group": group}, QUICK)

    def _leftovers(self, name: str) -> str:
        """Removes the partial files of name; names any it could not remove."""
        stem, partial = partial_pattern(name)
        try:
            found = [o for o in self._entries(QUICK) if partial.fullmatch(o)]
        except StorageError:
            return f" A partial upload may be left on the storage as {stem}.<8 hex>.partial."
        left = []
        for entry in found:
            try:
                self._call("operations/deletefile", {"fs": self._fs(), "remote": entry}, QUICK)
            except NotFound:
                pass
            except StorageError:
                left.append(entry)
        if left:
            return f" A partial upload is left on the storage: {', '.join(left)}. Remove it."
        return ""

    def _entries(self, timeout: float = TIMEOUT) -> list[str]:
        return [str(e.get("Name")) for e in self._list(timeout)]

    def _list(self, timeout: float = TIMEOUT) -> list[dict[str, Any]]:
        try:
            listed = self._call(
                "operations/list",
                {"fs": self._fs(), "remote": "", "opt": {"filesOnly": True, "noMimeType": True}},
                timeout,
                missing="The folder",
            ).get("list")
        except NotFound:
            return []
        return [e for e in listed if isinstance(e, dict)] if isinstance(listed, list) else []

    def get(
        self, name: str, local: Path, progress: Progress | None, cancel: threading.Event
    ) -> int:
        """Downloads name into local, a new file below the staging directory, and returns
        its size. Checks the free space there against the listed size first. Nothing is
        left under local, or as rclone's partial file beside it, unless all of it arrived."""
        check_name(name)
        check_name(local.name)  # also rclone's dstRemote: a plain name, never a path
        if not local.parent.resolve().is_relative_to(self._staging.resolve()):
            raise ValueError("Downloads go to drydock's staging directory only.")
        if cancel.is_set():
            raise StorageError(CANCELLED)
        item = self._stat(name)
        if item is None or item.get("IsDir"):
            raise NotFound(f"{name} does not exist in storage.")
        size = item.get("Size")
        if type(size) is not int or size < 0:
            raise StorageError(UNKNOWN)
        if local.exists() or local.is_symlink():
            raise StorageError(f"{local.name} is already in the staging directory.")
        endpoints = {
            "srcFs": self._fs(),
            "srcRemote": name,
            "dstFs": self._local(local.parent),
            "dstRemote": local.name,
        }

        def bounded(done: int) -> None:
            # A remote that listed a small size and sends more (or a file replaced since)
            # is stopped, not left to fill the disk. ponytail: checked every POLL, so it
            # can overrun by a second of transfer; RESERVE absorbs that on most disks.
            if done > size:
                raise StorageError("The archive in storage is larger than it was listed.")
            if progress is not None:
                progress(done)

        with Reserved.space(local.parent, size):
            try:
                if not self._transfer(endpoints, bounded, cancel):
                    raise StorageError(CANCELLED)
                info = local.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                    raise StorageError("The downloaded archive does not have the expected size.")
            except StorageError:
                remove_download(local)
                # A full staging disk shows up as rclone's "no space left": not the remote's.
                if shutil.disk_usage(local.parent).free < RESERVE:
                    raise InsufficientSpace(f"The disk holding {STAGING} is full.") from None
                raise
            except BaseException:
                remove_download(local)
                raise
        return size

    def read_head(self, name: str, max_bytes: int) -> bytes:
        check_name(name)
        return self._read(name, max_bytes, PREVIEW_TIMEOUT)

    def _read(self, name: str, max_bytes: int, timeout: float = TIMEOUT) -> bytes:
        conn = connection_string(self._kind, self._settings(), self._config["folder"])
        if self._ca is not None:
            # The ranged GET cannot carry _config: it reuses the connection an rc call with
            # the certificate made under this same string (rclone writes a JSON fs as these
            # sorted, quoted pairs). Made here first; without one, the GET fails closed.
            self._stat(name, timeout)
        try:
            return self._daemon.read_range(conn, name, max_bytes, timeout)
        except RcloneUnavailable as exc:
            raise StorageError(str(exc)) from None
        except RcloneError as exc:
            raise self._error(exc, missing=name) from None

    def open(self, name: str) -> BinaryIO:
        raise StorageError(NOT_IN_PLACE)

    def list(self, prefix: str = "") -> list[StoredObject]:
        found = []
        for entry in self._list():
            name, size = entry.get("Name"), entry.get("Size")
            if not isinstance(name, str) or not name.startswith(prefix) or entry.get("IsDir"):
                continue
            if type(size) is not int or size < 0:
                continue
            try:
                check_name(name)
            except StorageError:
                continue  # partial uploads, test probes and anything not made by drydock
            found.append(StoredObject(name, size, parse_time(entry.get("ModTime"))))
        return sorted(found, key=lambda o: o.name)

    def delete(self, name: str) -> None:
        check_name(name)
        self._call("operations/deletefile", {"fs": self._fs(), "remote": name}, missing=name)

    def test(self) -> None:
        """Writes a test file, reads it back through the ranged read, and removes it: the
        connection, the host key, the login, the folder and read_head's path all work."""
        probe = f"{PROBE_PREFIX}{uuid.uuid4().hex}"
        self._staging.mkdir(mode=0o700, parents=True, exist_ok=True)
        local = self._staging / f"{CHECK_PREFIX}{uuid.uuid4().hex}"
        try:
            with create_new(local) as handle:
                handle.write(b"drydock")
            self._call(
                "operations/copyfile",
                {
                    "srcFs": self._source(),
                    "srcRemote": local.name,
                    "dstFs": self._fs(),
                    "dstRemote": probe,
                },
            )
            try:
                if self._read(probe, 16) != b"drydock":
                    raise StorageError("The test file read back is not what was written.")
            finally:
                try:
                    self._call("operations/deletefile", {"fs": self._fs(), "remote": probe})
                except StorageError as exc:
                    raise StorageError(
                        f"The storage is writable, but the test file {probe} could not be "
                        f"removed: {exc}"
                    ) from None
        finally:
            local.unlink(missing_ok=True)
