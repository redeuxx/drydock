"""Remote storage options: what a storage form may set, per rclone backend.

The allowlist here is the source of truth. rclone's cached config/providers output only
supplies help text, and is checked against it: an allowlisted option that rclone no longer
has, or has with another type, disables the forms until this file is updated.

A submitted form is refused whole (nothing is saved) if it holds anything but drydock's own
fields and the allowlisted options of its backend. That covers unknown names, rclone
options that drydock denies or will set itself (sftp ssh, every *_command and *_file, drive
service_account_file, token_url, ...), rclone's global.* and override.* keys, and repeated
fields. Names match exactly: rclone itself ignores a misspelt option silently. Only the four
backend types below exist; rclone's local and s3 types and its wrapping types (alias,
crypt, union, ...) cannot be chosen.

Secret options live only in the encrypted config and are never rendered. On edit an empty
input keeps the stored value and a clear_<name> box removes it. Changing a destination
field (host, port, user, URL, client ID, ...) requires every stored secret to be entered
again or cleared, so stored credentials are never sent to a new destination unseen.

Why the rest is denied, from rclone v1.75.2's source: sftp ssh, bearer_token_command and
the *_command options run commands; *_file options, kerberos and env_auth read local files
(with $VAR expansion); webdav unix_socket dials any local socket; drive token_url,
auth_url and service accounts send credentials to a URL of the editor's choosing; proxies,
cipher lists, use_insecure_cipher and pin_host_key weaken or bypass the connection's
security; the rest is tuning drydock does not need.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import asyncssh

from drydock.hosts import ssh

OWN_FIELDS = frozenset({"csrf_token", "kind", "name", "enabled", "folder"})
OPTION_PREFIX = "opt_"
CLEAR_PREFIX = "clear_"
MAX_FOLDER = 512
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# Underscores too: Docker's DNS resolves container names such as backup_nas.
HOST_RE = re.compile(r"[A-Za-z0-9_]([A-Za-z0-9._-]{0,251}[A-Za-z0-9_])?")
NAME_SHOWN = 64  # characters of an unknown field name quoted back in the error
HOST_KEY_TYPES = frozenset(
    {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}
)
MAX_HOST_KEYS = 16  # rclone's own limit
HOST_KEYS_ERROR = (
    "Host key: paste the server's public host key, such as the contents of "
    "/etc/ssh/ssh_host_ed25519_key.pub on the server. Separate several keys with commas."
)


class OptionsError(Exception):
    """rclone's options no longer match the allowlist. The message is safe to show."""


@dataclass(frozen=True)
class Option:
    name: str  # rclone's option name, exactly
    label: str
    type: str  # the form macro: string, int, bool, enum, password, pem
    rclone_type: str  # the type config/providers must report
    required: bool = False
    advanced: bool = False
    default: str = ""
    max_length: int = 256
    choices: tuple[str, ...] = ()
    pattern: re.Pattern[str] | None = None
    pattern_hint: str = ""
    destination: bool = False  # a change needs the stored secrets entered again
    help: str = ""  # drydock's own help where rclone's would describe a refused feature
    obscure: bool = False  # rclone's IsPassword: sent through core/obscure

    @property
    def secret(self) -> bool:
        return self.type in ("password", "pem")


@dataclass(frozen=True)
class Backend:
    kind: str
    label: str
    folder_label: str
    folder_hint: str
    options: tuple[Option, ...]

    @property
    def secrets(self) -> tuple[Option, ...]:
        return tuple(o for o in self.options if o.secret)


def host_option() -> Option:
    return Option("host", "Host", "string", "string", True, max_length=253, destination=True)


def port_option(default: str) -> Option:
    return Option("port", "Port", "int", "int", default=default, destination=True)


def password_option(
    name: str = "pass", label: str = "Password", *, obscure: bool = True, **kwargs: Any
) -> Option:
    return Option(name, label, "password", "string", max_length=1024, obscure=obscure, **kwargs)


def id_option(name: str, label: str) -> Option:
    return Option(
        name,
        label,
        "string",
        "string",
        advanced=True,
        max_length=128,
        pattern=re.compile(r"[A-Za-z0-9_-]{1,128}"),
        pattern_hint="letters, digits, dashes and underscores",
    )


BACKENDS: dict[str, Backend] = {
    "sftp": Backend(
        "sftp",
        "SFTP",
        "Folder",
        "A path on the server: absolute (/srv/backups) or relative to the user's home.",
        (
            host_option(),
            port_option("22"),
            Option(
                "host_keys",
                "Host key",
                "string",
                "CommaSepList",
                True,
                max_length=8192,
                destination=True,
                help="The server's public host key, such as the contents of "
                "/etc/ssh/ssh_host_ed25519_key.pub on the server. Drydock connects only to a "
                "server holding it. Separate several keys with commas.",
            ),
            Option(
                "user",
                "User",
                "string",
                "string",
                True,
                pattern=re.compile(r"[^\]]{1,256}"),  # see rclone.connection_string
                pattern_hint="a user name without ]",
                destination=True,
            ),
            password_option(help="Leave it empty to log in with a private key instead."),
            Option(
                "key_pem",
                "Private key",
                "pem",
                "string",
                max_length=16384,
                help="Paste the whole key, in OpenSSH or PEM format.",
            ),
            password_option(
                "key_file_pass",
                "Private key passphrase",
                help="Only for a private key protected by a passphrase.",
            ),
            Option(
                "set_modtime",
                "Set modification times",
                "bool",
                "bool",
                advanced=True,
                default="true",
            ),
        ),
    ),
    "smb": Backend(
        "smb",
        "SMB",
        "Share and folder",
        "The share, then an optional folder in it: backups or backups/drydock.",
        (
            host_option(),
            port_option("445"),
            Option("user", "User", "string", "string", destination=True),
            password_option(),
            Option(
                "domain",
                "Domain",
                "string",
                "string",
                default="WORKGROUP",
                max_length=64,
                pattern=re.compile(r"[A-Za-z0-9._-]{1,64}"),
                pattern_hint="letters, digits, dots, dashes and underscores",
                destination=True,
            ),
            Option(
                "spn",
                "Service principal name",
                "string",
                "string",
                advanced=True,
                pattern=re.compile(r"[A-Za-z0-9/._:@-]{1,256}"),
                pattern_hint="for example cifs/server.example.com",
            ),
        ),
    ),
    "webdav": Backend(
        "webdav",
        "WebDAV",
        "Folder",
        "An optional folder below the URL.",
        (
            Option("url", "URL", "string", "string", True, max_length=2048, destination=True),
            Option(
                "vendor",
                "Server",
                "enum",
                "string",
                default="other",
                choices=("other", "nextcloud", "owncloud", "fastmail", "sharepoint-ntlm"),
                destination=True,
            ),
            Option(
                "user",
                "User",
                "string",
                "string",
                pattern=re.compile(r"[^:]{1,256}"),  # basic auth splits at the first colon
                pattern_hint="a user name without a colon",
                destination=True,
            ),
            password_option(),
            password_option("bearer_token", "Bearer token", obscure=False, advanced=True),
        ),
    ),
    "drive": Backend(
        "drive",
        "Google Drive",
        "Folder",
        "An optional folder in the drive.",
        (
            Option(
                "client_id",
                "OAuth client ID",
                "string",
                "string",
                True,
                pattern=re.compile(
                    r"[0-9]{1,64}-[A-Za-z0-9_]{1,128}\.apps\.googleusercontent\.com"
                ),
                pattern_hint="the ID of your own Google OAuth client, ending in"
                " .apps.googleusercontent.com",
                destination=True,
                help="The client ID of your own Google OAuth client. rclone's shared client is"
                " not used.",
            ),
            password_option(
                "client_secret",
                "OAuth client secret",
                obscure=False,
                required=True,
                help="The client secret of that OAuth client.",
            ),
            Option(
                "scope",
                "Access",
                "enum",
                "string",
                advanced=True,
                default="drive.file",
                choices=("drive.file", "drive"),
                destination=True,
                help="drive.file (the default) lets drydock see only the files it created;"
                " drive gives it the whole drive.",
            ),
            id_option("root_folder_id", "Root folder ID"),
            id_option("team_drive", "Shared drive ID"),
            Option(
                "use_trash",
                "Move deleted backups to the trash",
                "bool",
                "bool",
                advanced=True,
                default="true",
            ),
        ),
    ),
}


# PARSING


@dataclass
class Parsed:
    """A checked form. config is what to store, None when there are errors. shown holds the
    non-secret values and the folder, for a re-render; changed names the options that
    differ from the stored config, secrets included."""

    errors: list[str]
    config: dict[str, Any] | None = None
    shown: dict[str, str] = field(default_factory=dict)
    changed: list[str] = field(default_factory=list)


def parse(kind: str, items: list[tuple[str, Any]], stored: dict[str, Any] | None) -> Parsed:
    """Checks a submitted remote storage form against kind's allowlist and merges it with
    the stored config (None on create)."""
    backend = BACKENDS[kind]
    errors = shape_errors(backend, items)
    if errors:
        return Parsed(errors)
    values: dict[str, str] = dict(items)
    old: dict[str, str] = dict((stored or {}).get("options", {}))
    new: dict[str, str] = {}
    shown: dict[str, str] = {}
    kept: list[Option] = []
    for option in backend.options:
        raw = values.get(OPTION_PREFIX + option.name, "")
        if option.secret:
            clear = values.get(CLEAR_PREFIX + option.name, "")
            error = secret_error(option, raw, clear)
            if error:
                errors.append(error)
            elif raw:
                new[option.name] = raw.replace("\r\n", "\n")
            elif not clear and old.get(option.name):
                new[option.name] = old[option.name]
                kept.append(option)
        else:
            value, error = check_value(option, raw)
            shown[option.name] = raw.strip() if error else value
            if error:
                errors.append(error)
            else:
                new[option.name] = value
    folder, error = check_folder(kind, values.get("folder", ""))
    shown["folder"] = folder
    if error:
        errors.append(error)
    if errors:
        return Parsed(errors, shown=shown)
    errors = [
        f"Enter the {o.label.lower()}."
        for o in backend.secrets
        if o.required and not new.get(o.name)
    ]
    moved = [
        o.label.lower()
        for o in backend.options
        if o.destination and new.get(o.name) != old.get(o.name)
    ]
    # WebDAV appends the folder to the URL: a shared host's other paths are other tenants.
    if kind == "webdav" and stored is not None and stored.get("folder", "") != folder:
        moved.append("folder")
    if stored is not None and kept and moved:
        errors.append(
            f"The {', '.join(moved)} changed, so the stored "
            f"{', '.join(o.label.lower() for o in kept)} must be entered again or cleared."
        )
    errors += combination_errors(kind, new, {o.name for o in kept})
    if errors:
        return Parsed(errors, shown=shown)
    changed = sorted(n for n in new.keys() | old.keys() if new.get(n) != old.get(n))
    if stored is not None and stored.get("folder") != folder:
        changed.append("folder")
    return Parsed([], {"folder": folder, "options": new}, shown, changed)


def shape_errors(backend: Backend, items: list[tuple[str, Any]]) -> list[str]:
    allowed = (
        OWN_FIELDS
        | {OPTION_PREFIX + o.name for o in backend.options}
        | {CLEAR_PREFIX + o.name for o in backend.secrets}
    )
    errors: list[str] = []
    seen: set[str] = set()
    for key, value in items:
        name = repr(key[:NAME_SHOWN])  # the name only: a refused value is never echoed
        if not isinstance(value, str):
            errors.append(f"The field {name} must be text.")
        elif key in seen:
            errors.append(f"The field {name} was sent more than once.")
        elif key not in allowed:
            errors.append(f"{backend.label} storage has no setting {name}.")
        seen.add(key)
    return list(dict.fromkeys(errors))


def check_value(option: Option, raw: str) -> tuple[str, str | None]:
    """The value to store for a non-secret option, or an error."""
    label = option.label
    if option.type == "bool":
        if raw not in ("", "1"):
            return "", f"{label}: tick the box or leave it clear."
        return ("true" if raw else "false"), None
    value = raw.strip()
    if not value:
        if option.required:
            return "", f"Enter the {label.lower()}."
        return option.default, None
    if len(value) > option.max_length:
        return "", f"{label} is longer than {option.max_length} characters."
    if CONTROL_RE.search(value):
        return "", f"{label} must not contain control characters."
    if option.type == "int" and not (
        value.isascii() and value.isdigit() and 1 <= int(value) <= 65535
    ):
        return "", f"{label} must be a number from 1 to 65535."
    if option.type == "int":
        value = str(int(value))  # 022 is 22, not a new destination
    if option.type == "enum" and value not in option.choices:
        return "", f"Choose a {label.lower()} from the list."
    if option.pattern is not None and not option.pattern.fullmatch(value):
        return "", f"{label}: use {option.pattern_hint}."
    if option.name == "host" and not valid_host(value):
        return "", "Host must be a host name or an IP address, without a port or brackets."
    if option.name == "url" and (error := url_error(value)):
        return "", error
    if option.name == "host_keys":
        try:
            value = host_keys(value)
        except ValueError:
            return "", HOST_KEYS_ERROR
    return value, None


def secret_error(option: Option, raw: str, clear: str) -> str | None:
    label = option.label
    if clear not in ("", "1"):
        return f"{label}: tick the clear box or leave it empty."
    if raw and clear:
        return f"Enter a new {label.lower()} or clear it, not both."
    if len(raw) > option.max_length:
        return f"{label} is longer than {option.max_length} characters."
    text = raw.replace("\r\n", "\n")
    if option.type == "pem":
        # rclone unquotes the key as a Go string literal: quotes and backslashes change it.
        printable = text.isascii() and not CONTROL_RE.search(text.replace("\n", ""))
        if not printable or '"' in text or "\\" in text:
            return f"{label} is not a PEM or OpenSSH private key."
    elif CONTROL_RE.search(text):
        return f"{label} must not contain control characters."
    return None


def valid_host(value: str) -> bool:
    if HOST_RE.fullmatch(value):
        return True
    if "%" in value:  # no IPv6 zone IDs
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def host_keys(raw: str) -> str:
    """rclone's host_keys value ("type base64,type base64") from public host keys given as
    "type base64 [comment]", comma-separated. Never empty: rclone checks no host key at all
    when host_keys is empty. Raises ValueError."""
    keys = []
    for entry in raw.split(","):
        fields = entry.split()
        if not fields:
            continue
        if len(fields) < 2 or fields[0] not in HOST_KEY_TYPES:
            raise ValueError("not a public host key")
        try:
            key = asyncssh.import_public_key(f"{fields[0]} {fields[1]}")
        except asyncssh.KeyImportError, ValueError:
            raise ValueError("not a public host key") from None
        algorithm, data = key.export_public_key("openssh").decode().split()[:2]
        if algorithm != fields[0]:
            raise ValueError("not a public host key")
        keys.append(f"{algorithm} {data}")
    keys = list(dict.fromkeys(keys))
    if not keys or len(keys) > MAX_HOST_KEYS:
        raise ValueError("no host key, or too many")
    return ",".join(keys)


def url_error(value: str) -> str | None:
    if any(c.isspace() for c in value):
        return "The URL must not contain spaces."
    try:
        parts = urlsplit(value)
        hostname = parts.hostname  # raises on malformed brackets
    except ValueError:
        hostname = None
    if hostname is None or parts.scheme not in ("http", "https"):
        return "Enter the URL as http:// or https:// with a host."
    if parts.username or parts.password or parts.query or parts.fragment:
        return "The URL must not hold a user name, password, query or fragment."
    try:
        port = parts.port
    except ValueError:
        port = 0
    if port == 0:
        return "The URL has an invalid port."
    if not valid_host(hostname):
        return "The URL has an invalid host."
    return None


def check_folder(kind: str, raw: str) -> tuple[str, str | None]:
    folder = raw.strip()
    if folder != "/":
        folder = folder.rstrip("/")
    if len(folder) > MAX_FOLDER:
        return folder, f"The folder is longer than {MAX_FOLDER} characters."
    if CONTROL_RE.search(folder) or "\\" in folder:
        return folder, "The folder must not contain control characters or backslashes."
    if "]" in folder:  # see rclone.connection_string
        return folder, "The folder must not contain ]."
    absolute = kind == "sftp" and folder.startswith("/")
    body = folder[1:] if absolute else folder
    if body.startswith("/"):
        return folder, "The folder must not start with /."
    segments = body.split("/") if body else []
    if any(segment in ("", ".", "..") for segment in segments):
        return folder, "The folder must not contain empty, . or .. parts."
    if kind == "smb" and not segments:
        return folder, "Enter the share, optionally followed by a folder in it."
    return folder, None


def combination_errors(kind: str, opts: dict[str, str], kept: set[str]) -> list[str]:
    """Rules across options. kept names the secrets carried over from the stored config."""
    errors = []
    if kind == "sftp":
        # rclone joins host and port without brackets, and brackets cannot go into the
        # connection string read_head needs.
        if ":" in opts.get("host", ""):
            errors.append("SFTP storage needs a host name or an IPv4 address.")
        key, passphrase = opts.get("key_pem", ""), opts.get("key_file_pass", "")
        if not opts.get("pass") and not key:
            errors.append("Enter a password or a private key.")
        if passphrase and not key:
            errors.append("A private key passphrase needs a private key.")
        if key and (key_error := key_problem(key, passphrase)):
            if "key_file_pass" in kept:
                key_error += (
                    " The stored passphrase was used: enter this key's passphrase, or tick"
                    " Clear the stored private key passphrase."
                )
            errors.append(key_error)
    if kind == "webdav":
        https = opts["url"].lower().startswith("https://")
        if opts.get("bearer_token") and (opts.get("user") or opts.get("pass")):
            errors.append("Use a user and password or a bearer token, not both.")
        if opts.get("bearer_token") and not https:
            errors.append("A bearer token needs an https:// URL.")
        if opts["vendor"] == "sharepoint-ntlm" and not https:
            errors.append("SharePoint with NTLM needs an https:// URL.")
    return errors


def key_problem(key: str, passphrase: str) -> str | None:
    """The key must load, with the passphrase exactly when it has one."""
    try:
        ssh.load_private_key(key, passphrase or None)
    except ssh.SSHKeyError as exc:
        return f"Private key: {exc}"
    if passphrase:
        try:
            ssh.load_private_key(key)
        except ssh.SSHKeyError:
            return None
        return "This private key has no passphrase."
    return None


# DISPLAY AND RCLONE


def location(kind: str, config: dict[str, Any]) -> str:
    """Where a remote target writes, without any secret."""
    opts, folder = config.get("options", {}), config.get("folder", "")
    host = opts.get("host", "")
    if ":" in host:
        host = f"[{host}]"
    port = opts.get("port", "")
    if kind == "sftp":
        suffix = "" if port == "22" else f" (port {port})"
        return f"{opts.get('user', '')}@{host}:{folder}{suffix}"
    if kind == "smb":
        suffix = "" if port == "445" else f" (port {port})"
        return f"//{host}/{folder}{suffix}"
    if kind == "webdav":
        return opts.get("url", "").rstrip("/") + (f"/{folder}" if folder else "")
    return "Google Drive" + (f": {folder}" if folder else "")


def help_texts(providers: Any) -> dict[str, dict[str, str]]:
    """{kind: {option: the first paragraph of rclone's help}} from config/providers.

    Raises OptionsError when an allowlisted option is missing or has another type.
    """
    listed = providers.get("providers") if isinstance(providers, dict) else None
    found = {p.get("Name"): p for p in listed or [] if isinstance(p, dict)}
    texts: dict[str, dict[str, str]] = {}
    for kind, backend in BACKENDS.items():
        rclone_options = {
            o.get("Name"): o
            for o in found.get(kind, {}).get("Options") or []
            if isinstance(o, dict)
        }
        texts[kind] = {}
        for option in backend.options:
            rclone = rclone_options.get(option.name)
            if (
                rclone is None
                or rclone.get("Type") != option.rclone_type
                or bool(rclone.get("IsPassword")) != option.obscure
            ):
                raise OptionsError(
                    f"The installed rclone does not offer the {kind} option {option.name} "
                    "as drydock expects, so remote storage forms are disabled."
                )
            help_text = str(rclone.get("Help", "")).split("\n\n")[0].strip()
            texts[kind][option.name] = help_text[:500]
    return texts
