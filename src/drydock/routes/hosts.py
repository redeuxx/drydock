"""Docker hosts: add, edit and remove hosts, trust SSH host keys, test, list containers.

Admin only, except the container inventory, which every role may view. Every change to a
host's connection, key or trusted host key needs the password from the last 10 minutes.
Pages never contain key material: only the public key and fingerprints are shown, and
submitted private keys and passphrases are never echoed.

Routes that talk to a host (scan, trust, test, containers) release the database lock
before the network call, because every transaction takes SQLite's write lock up front.
"""

import ipaddress
import posixpath
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import anyio.from_thread
import asyncssh
import docker.errors
import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from drydock import audit
from drydock.db import get_db
from drydock.hosts import client as docker_client
from drydock.hosts import inventory, ssh
from drydock.hosts.manager import HostManager, HostUnavailable
from drydock.models import Hook, Host, Job, UpdatePolicy, utcnow
from drydock.routes.auth import FormStr, client_ip
from drydock.security.rbac import Role, require_recent_auth, require_role
from drydock.security.sessions import Auth
from drydock.templating import is_htmx, render, see_other

router = APIRouter(prefix="/hosts")

Admin = Annotated[Auth, Depends(require_role(Role.admin))]
Viewer = Annotated[Auth, Depends(require_role(Role.viewer))]

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
SSH_USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}")
SOCKET_PATH_RE = re.compile(r"/[A-Za-z0-9._/-]{1,254}")
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
# Kernel views that alias other paths, for example /proc/self/root/run/drydock/...
ALIASING_ROOTS = (Path("/proc"), Path("/sys"))
KEY_SOURCES = ("generate", "paste")
MAX_PASSPHRASE = 1024
INVENTORY_TIMEOUT = 20
TEST_TIMEOUT = 15
DOCKER_ERRORS = (
    HostUnavailable,
    docker_client.DockerUnavailable,
    docker.errors.DockerException,
    requests.RequestException,
)


# VALIDATION


@dataclass
class HostForm:
    """Connection settings as submitted. Never holds key material."""

    kind: str
    name: str = ""
    enabled: bool = True
    docker_url: str = ""
    address: str = ""
    port: str = str(ssh.DEFAULT_PORT)
    username: str = ""
    remote_socket_path: str = ssh.DEFAULT_REMOTE_SOCKET

    @classmethod
    def from_host(cls, host: Host) -> HostForm:
        return cls(
            kind=host.kind,
            name=host.name,
            enabled=host.enabled,
            docker_url=host.docker_url or "",
            address=host.address or "",
            port=str(host.port or ssh.DEFAULT_PORT),
            username=host.username or "",
            remote_socket_path=host.remote_socket_path or ssh.DEFAULT_REMOTE_SOCKET,
        )


def submitted(kind: str, **values: str) -> HostForm:
    return HostForm(
        kind=kind,
        name=values["name"].strip(),
        enabled=values["enabled"] == "1",
        docker_url=values["docker_url"].strip(),
        address=values["address"].strip(),
        port=values["port"].strip(),
        username=values["username"].strip(),
        remote_socket_path=values["remote_socket_path"].strip(),
    )


def literal_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """value as an IP address, including numeric forms the resolver accepts (2852039166)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            address = ipaddress.IPv4Address(socket.inet_aton(value))
        except OSError:
            return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def unroutable(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Link-local (cloud metadata at 169.254.169.254), multicast and unspecified addresses."""
    return address.is_link_local or address.is_multicast or address.is_unspecified


def check_socket(path: str, run_dir: Path) -> str | None:
    error = "The Docker URL must be unix:///path, tcp://host:port or http(s)://host:port."
    if not SOCKET_PATH_RE.fullmatch(path) or path.startswith("//"):
        return error
    if posixpath.normpath(path) != path:
        return error
    candidates = (Path(path), Path(path).resolve())
    if any(c.is_relative_to(run_dir) or c.is_relative_to(run_dir.resolve()) for c in candidates):
        return f"Sockets under {run_dir} are the SSH forwards of other hosts."
    if any(c.is_relative_to(root) for c in candidates for root in ALIASING_ROOTS):
        return "Sockets under /proc or /sys are not allowed."
    return None


def check_docker_host(hostname: str) -> str | None:
    """Plain tcp:// and http:// carry no authentication, and https:// here has no client
    certificate, so a local host stays on the local network. Other machines use SSH."""
    address = literal_ip(hostname)
    if address is None:
        local = DNS_LABEL_RE.fullmatch(hostname) is not None  # a Compose service name
    else:
        local = (address.is_loopback or address.is_private) and not unroutable(address)
    if local:
        return None
    return (
        "A local host's tcp:// or http(s):// URL must name a service on drydock's Docker "
        "network (such as socket-proxy) or a loopback or private address. Add other "
        "machines as SSH hosts."
    )


def check_docker_url(value: str, run_dir: Path) -> str | None:
    error = "The Docker URL must be unix:///path, tcp://host:port or http(s)://host:port."
    try:
        parts = urlsplit(value)
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError:
        return error
    if len(value) > 255 or parts.scheme not in docker_client.ALLOWED_SCHEMES:
        return error
    if parts.username or parts.password or parts.query or parts.fragment:
        return "The Docker URL must not contain credentials, a query or a fragment."
    if parts.scheme == "unix":
        return error if parts.netloc else check_socket(parts.path, run_dir)
    if not parts.hostname or parts.path not in ("", "/"):
        return error
    return check_docker_host(parts.hostname)


def check_address(value: str) -> str | None:
    error = "Enter a host name, an IPv4 address or an IPv6 address (without brackets)."
    if not value or len(value) > 253 or "%" in value:
        return error
    address = literal_ip(value)
    if address is None:
        if not all(DNS_LABEL_RE.fullmatch(label) for label in value.removesuffix(".").split(".")):
            return error
    elif unroutable(address):
        return "Link-local, multicast and unspecified addresses are not allowed."
    return None


def check_socket_path(value: str) -> str | None:
    if not SOCKET_PATH_RE.fullmatch(value) or posixpath.normpath(value) != value:
        return "The remote socket path must be an absolute path such as /var/run/docker.sock."
    return None


def parse_port(value: str) -> int | None:
    return int(value) if value.isdigit() and 1 <= int(value) <= 65535 else None


def validate(form: HostForm, run_dir: Path) -> list[str]:
    errors = []
    if not NAME_RE.fullmatch(form.name):
        errors.append("Name must be 1 to 64 letters, digits, dots, dashes or underscores.")
    if form.kind == "local":
        errors.append(check_docker_url(form.docker_url, run_dir))
    else:
        errors.append(check_address(form.address))
        if parse_port(form.port) is None:
            errors.append("Port must be a number from 1 to 65535.")
        if not SSH_USER_RE.fullmatch(form.username):
            errors.append("User must be a valid user name, for example backup.")
        errors.append(check_socket_path(form.remote_socket_path))
    return [e for e in errors if e]


def apply(host: Host, form: HostForm) -> None:
    host.name = form.name
    host.enabled = form.enabled
    if host.kind == "local":
        host.docker_url = form.docker_url
    else:
        host.address = form.address.removesuffix(".").lower()
        host.port = parse_port(form.port)
        host.username = form.username
        host.remote_socket_path = form.remote_socket_path


def set_key(host: Host, request: Request, source: str, private_key: str, passphrase: str) -> None:
    """Generates or stores the host's key. Raises SSHKeyError with a safe message."""
    crypto = request.app.state.crypto
    if source == "generate":
        ssh.generate_key(host, crypto)
    elif source == "paste":
        if len(passphrase) > MAX_PASSPHRASE:
            raise ssh.SSHKeyError("The passphrase is too long.")
        ssh.store_key(host, crypto, private_key.strip() + "\n", passphrase or None)
    else:
        raise ssh.SSHKeyError("Choose to generate a key or paste one.")


def name_taken(db: Session, name: str, host_id: int | None = None) -> bool:
    query = select(Host.id).where(Host.name == name)
    if host_id is not None:
        query = query.where(Host.id != host_id)
    return db.scalar(query) is not None


# HELPERS


def manager(request: Request) -> HostManager:
    return request.app.state.hosts


def get_host(db: Session, host_id: int) -> Host:
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404)
    return host


def release(db: Session, host: Host) -> Host:
    """Ends the transaction (and its write lock) but keeps host usable, detached."""
    db.expunge(host)
    db.rollback()
    return host


def get_ssh_host(db: Session, host_id: int) -> Host:
    host = get_host(db, host_id)
    if host.kind != "ssh" or not host.address or not host.port:
        raise HTTPException(status_code=404)
    return host


def reload(request: Request, host_id: int) -> None:
    """Applies a committed change to the running tunnels. Called from a worker thread."""
    anyio.from_thread.run(manager(request).reload, host_id)


def target(host: Host) -> str:
    if host.kind == "local":
        return host.docker_url or ""
    return f"{host.username}@{host.address}:{host.port}"


def summary(host: Host) -> dict[str, Any]:
    return {"name": host.name, "enabled": host.enabled, "target": target(host)}


def edit_page(
    request: Request,
    auth: Auth,
    host: Host,
    status_code: int = 200,
    **context: Any,
) -> Response:
    context.setdefault("form", HostForm.from_host(host))
    for name in ("errors", "key_errors"):
        context.setdefault(name, [])
    for name in ("scan", "test", "error"):
        context.setdefault(name, None)
    return render(
        request,
        "hosts/edit.html",
        status_code,
        auth=auth,
        host=host,
        status=manager(request).status(host),
        authorized_key_options=ssh.AUTHORIZED_KEY_OPTIONS,
        **context,
    )


def scan_now(address: str, port: int) -> tuple[str, str]:
    """Runs the async scan from this worker thread. Raises SSHKeyError with a safe message."""
    try:
        return anyio.from_thread.run(ssh.scan_host_key, address, port)
    except TimeoutError:
        raise ssh.SSHKeyError(f"{address} port {port} did not answer in time.") from None
    except (OSError, asyncssh.Error) as exc:
        raise ssh.SSHKeyError(f"Could not read the host key of {address}: {exc}") from None


def open_host(request: Request, host: Host, timeout: float) -> docker_client.DockerHandle:
    """Blocking. Raises one of DOCKER_ERRORS with a message that is safe to show."""
    return docker_client.open_client(manager(request).docker_url(host), timeout=timeout)


# LIST AND CREATE


@router.get("")
def list_hosts(request: Request, auth: Admin, db: Session = Depends(get_db)) -> Response:
    hosts = db.scalars(select(Host).order_by(Host.name)).all()
    rows = [(host, manager(request).status(host), target(host)) for host in hosts]
    return render(request, "hosts/list.html", auth=auth, rows=rows)


@router.get("/new")
def new_host_form(request: Request, auth: Admin, kind: str = "ssh") -> Response:
    if kind not in ("local", "ssh"):
        raise HTTPException(status_code=404)
    form = HostForm(kind=kind, docker_url=request.app.state.settings.local_docker_url or "")
    return render(request, "hosts/new.html", auth=auth, form=form, errors=[], key_source="generate")


@router.post("")
def create_host(
    request: Request,
    auth: Admin,
    kind: FormStr = "",
    name: FormStr = "",
    enabled: FormStr = "",
    docker_url: FormStr = "",
    address: FormStr = "",
    port: FormStr = "",
    username: FormStr = "",
    remote_socket_path: FormStr = "",
    key_source: FormStr = "generate",
    private_key: FormStr = "",
    key_passphrase: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    if kind not in ("local", "ssh"):
        raise HTTPException(status_code=422, detail="Unknown host kind.")
    form = submitted(
        kind,
        name=name,
        enabled=enabled,
        docker_url=docker_url,
        address=address,
        port=port,
        username=username,
        remote_socket_path=remote_socket_path,
    )
    errors = validate(form, request.app.state.settings.run_dir)
    host = Host(kind=kind)
    if not errors and kind == "ssh":
        try:
            set_key(host, request, key_source, private_key, key_passphrase)
        except ssh.SSHKeyError as exc:
            errors.append(str(exc))
    if not errors and name_taken(db, form.name):
        errors.append("A host with that name exists.")
    if errors:
        db.rollback()
        # Re-rendered without the pasted key or its passphrase.
        source = key_source if key_source in KEY_SOURCES else "generate"
        return render(
            request, "hosts/new.html", 422, auth=auth, form=form, errors=errors, key_source=source
        )
    apply(host, form)
    db.add(host)
    db.flush()
    details = summary(host) | {"kind": kind}
    if kind == "ssh":
        details["identity"] = key_source
    audit.record(
        db,
        actor=auth.user.username,
        action="host.create",
        target=f"host:{host.id}",
        ip=client_ip(request),
        details=details,
    )
    db.commit()
    reload(request, host.id)
    return see_other(request, f"/hosts/{host.id}")


# EDIT


@router.get("/{host_id}")
def edit_host(
    request: Request, host_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    return edit_page(request, auth, get_host(db, host_id))


@router.post("/{host_id}")
def update_host(
    request: Request,
    host_id: int,
    auth: Admin,
    name: FormStr = "",
    enabled: FormStr = "",
    docker_url: FormStr = "",
    address: FormStr = "",
    port: FormStr = "",
    username: FormStr = "",
    remote_socket_path: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    host = get_host(db, host_id)
    form = submitted(
        host.kind,
        name=name,
        enabled=enabled,
        docker_url=docker_url,
        address=address,
        port=port,
        username=username,
        remote_socket_path=remote_socket_path,
    )
    errors = validate(form, request.app.state.settings.run_dir)
    if not errors and name_taken(db, form.name, host.id):
        errors.append("A host with that name exists.")
    if errors:
        db.rollback()
        return edit_page(request, auth, host, 422, form=form, errors=errors)
    before, endpoint = summary(host), (host.address, host.port)
    apply(host, form)
    after = summary(host)
    details: dict[str, Any] = {
        field: {"from": before[field], "to": after[field]}
        for field in before
        if before[field] != after[field]
    }
    # A pinned host key belongs to one address and port; a new endpoint is trusted anew.
    if (host.address, host.port) != endpoint and host.known_host_line:
        host.known_host_line = None
        host.host_key_fingerprint = None
        details["trust_cleared"] = True
    audit.record(
        db,
        actor=auth.user.username,
        action="host.update",
        target=f"host:{host.id}",
        ip=client_ip(request),
        details=details,
    )
    db.commit()
    reload(request, host.id)
    return see_other(request, f"/hosts/{host.id}")


@router.post("/{host_id}/key")
def replace_key(
    request: Request,
    host_id: int,
    auth: Admin,
    key_source: FormStr = "generate",
    private_key: FormStr = "",
    key_passphrase: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    require_recent_auth(auth)
    host = get_ssh_host(db, host_id)
    try:
        set_key(host, request, key_source, private_key, key_passphrase)
    except ssh.SSHKeyError as exc:
        db.rollback()
        return edit_page(request, auth, get_host(db, host_id), 422, key_errors=[str(exc)])
    audit.record(
        db,
        actor=auth.user.username,
        action="host.key",
        target=f"host:{host.id}",
        ip=client_ip(request),
        details={"identity": key_source, "algorithm": (host.ssh_public_key or "").split()[0]},
    )
    db.commit()
    reload(request, host.id)
    return see_other(request, f"/hosts/{host.id}")


@router.post("/{host_id}/delete")
def delete_host(
    request: Request, host_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    require_recent_auth(auth)
    host = get_host(db, host_id)
    users = db.scalars(select(Job.name).where(Job.host_id == host.id).order_by(Job.name)).all()
    if users:
        db.rollback()
        error = f"Jobs still use this host: {', '.join(users)}. Move or delete them first."
        return edit_page(request, auth, get_host(db, host_id), 409, error=error)
    policies = db.scalars(
        select(UpdatePolicy.name).where(UpdatePolicy.host_id == host.id).order_by(UpdatePolicy.name)
    ).all()
    if policies:
        db.rollback()
        error = f"Update policies still use this host: {', '.join(policies)}. Delete them first."
        return edit_page(request, auth, get_host(db, host_id), 409, error=error)
    # The foreign key is RESTRICT: only a superadmin can remove what is bound here.
    bound = db.scalars(select(Hook.name).where(Hook.host_id == host.id).order_by(Hook.name)).all()
    if bound:
        db.rollback()
        error = (
            f"Hooks are bound to this host: {', '.join(bound)}. A superadmin must delete them"
            " first."
        )
        return edit_page(request, auth, get_host(db, host_id), 409, error=error)
    audit.record(
        db,
        actor=auth.user.username,
        action="host.delete",
        target=f"host:{host.id}",
        ip=client_ip(request),
        details=summary(host),
    )
    db.delete(host)
    db.commit()
    reload(request, host_id)
    return see_other(request, "/hosts")


# HOST KEYS


@router.post("/{host_id}/scan-hostkey")
def scan_hostkey(
    request: Request, host_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    """Shows the key the server presents now. Trusts nothing."""
    host = release(db, get_ssh_host(db, host_id))  # no lock while waiting on the network
    address, port = host.address, host.port
    try:
        line, fingerprint = scan_now(address, port)
    except ssh.SSHKeyError as exc:
        line, fingerprint, error = "", None, str(exc)
    else:
        error = None
    host = get_ssh_host(db, host_id)
    audit.record(
        db,
        actor=auth.user.username,
        action="host.hostkey_scan",
        target=f"host:{host.id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details={"fingerprint": fingerprint} if error is None else {"error": error},
    )
    db.commit()
    if error is not None:
        # Not a 5xx: reverse proxies may replace those bodies with their own error page.
        return edit_page(request, auth, host, 422, error=error)
    scan = {
        "fingerprint": fingerprint,
        "algorithm": line.split()[1],
        "trusted": fingerprint == host.host_key_fingerprint,
    }
    return edit_page(request, auth, host, scan=scan)


@router.post("/{host_id}/trust-hostkey")
def trust_hostkey(
    request: Request,
    host_id: int,
    auth: Admin,
    fingerprint: FormStr = "",
    password: FormStr = "",
    db: Session = Depends(get_db),
) -> Response:
    """Pins the key the server presents now, but only if it is the one the admin confirmed.

    With a password, drydock then logs in once against that pinned key and adds its own
    public key to the user's authorized_keys. The password is never stored or logged."""
    require_recent_auth(auth)
    host = get_ssh_host(db, host_id)
    confirmed = fingerprint.strip()

    def record(host: Host, outcome: str, **details: Any) -> None:
        audit.record(
            db,
            actor=auth.user.username,
            action="host.hostkey_trust",
            target=f"host:{host.id}",
            outcome=outcome,
            ip=client_ip(request),
            details=details,
        )
        db.commit()

    if not FINGERPRINT_RE.fullmatch(confirmed):
        error = "Enter the SHA256 fingerprint to trust."
        record(host, "failure", error=error, submitted=confirmed[:100])
        return edit_page(request, auth, host, 422, error=error)
    if len(password) > ssh.MAX_PASSWORD or (password and not host.ssh_public_key):
        error = "The password is too long." if host.ssh_public_key else "The host has no key."
        record(host, "failure", error=error, confirmed_fingerprint=confirmed)
        return edit_page(request, auth, host, 422, error=error)
    address, port = release(db, host).address, host.port
    try:
        line, presented = scan_now(address, port)
    except ssh.SSHKeyError as exc:
        host = get_ssh_host(db, host_id)
        record(host, "failure", error=str(exc), confirmed_fingerprint=confirmed)
        return edit_page(request, auth, host, 422, error=str(exc))
    host = get_ssh_host(db, host_id)
    accepted = presented == confirmed and (host.address, host.port) == (address, port)
    previous = host.host_key_fingerprint
    if accepted:
        host.known_host_line = line
        host.host_key_fingerprint = presented
    record(
        host,
        "success" if accepted else "failure",
        confirmed_fingerprint=confirmed,
        presented_fingerprint=presented,
        previous_fingerprint=previous,
    )
    if not accepted:
        message = (
            f"The server now presents {presented}, not the fingerprint you confirmed. "
            "Nothing was trusted. Check the host, then scan again."
        )
        return edit_page(request, auth, host, 409, error=message)
    if password:
        args = (address, port, host.username, line, password)
        key_line = f"{ssh.AUTHORIZED_KEY_OPTIONS} {host.ssh_public_key}"
        release(db, host)
        try:
            anyio.from_thread.run(ssh.install_key, *args, key_line)
        except ssh.SSHKeyError as exc:
            error = str(exc)
        else:
            error = None
        host = get_ssh_host(db, host_id)
        audit.record(
            db,
            actor=auth.user.username,
            action="host.key_install",
            target=f"host:{host.id}",
            outcome="success" if error is None else "failure",
            ip=client_ip(request),
            details={"username": args[2]} | ({"error": error} if error else {}),
        )
        db.commit()
        if error is not None:
            reload(request, host_id)  # the host key is trusted either way
            return edit_page(request, auth, host, 422, error=error)
    reload(request, host_id)
    return see_other(request, f"/hosts/{host_id}")


# CONNECTION TEST AND INVENTORY


@router.post("/{host_id}/test")
def test_host(
    request: Request, host_id: int, auth: Admin, db: Session = Depends(get_db)
) -> Response:
    host = release(db, get_host(db, host_id))
    try:
        with open_host(request, host, TEST_TIMEOUT) as handle:
            handle.client.ping()
            test = {
                "engine": handle.engine_version,
                "api": handle.api_version,
                "arch": handle.arch,
                "os": handle.os,
            }
        error = None
    except DOCKER_ERRORS as exc:
        test, error = {}, str(exc) or type(exc).__name__
    host = get_host(db, host_id)
    if error is None:
        host.api_version = test["api"]
        host.last_seen = utcnow()
    audit.record(
        db,
        actor=auth.user.username,
        action="host.test",
        target=f"host:{host.id}",
        outcome="success" if error is None else "failure",
        ip=client_ip(request),
        details=test if error is None else {"error": error},
    )
    db.commit()
    return edit_page(request, auth, host, test=test | {"error": error})


@router.get("/{host_id}/containers")
def host_containers(
    request: Request, host_id: int, auth: Viewer, db: Session = Depends(get_db)
) -> Response:
    """The inventory fragment (#inventory), also a page of its own. Every role may view it."""
    host = release(db, get_host(db, host_id))
    groups: list[inventory.ProjectGroup] = []
    error = None
    try:
        with open_host(request, host, INVENTORY_TIMEOUT) as handle:
            groups = inventory.list_inventory(handle.client, manager(request).instance_id)
    except DOCKER_ERRORS as exc:
        error = str(exc) or type(exc).__name__
    return render(
        request,
        "hosts/containers.html",
        auth=auth,
        host=host,
        groups=groups,
        error=error,
        embedded=is_htmx(request),  # inside the host page, under its "Containers" heading
    )
