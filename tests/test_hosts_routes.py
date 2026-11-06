"""Host pages without a real daemon: validation, recent auth, key handling, host key trust."""

import json
import sqlite3

import asyncssh
import pytest
from markupsafe import escape

from drydock.hosts import ssh
from tests.conftest import PASSWORD, Browser, add_user
from tests.docker_support import KEY_MARKERS

pytestmark = pytest.mark.anyio

SSH_FORM = {
    "kind": "ssh",
    "name": "remote",
    "address": "203.0.113.9",
    "port": "22",
    "username": "backup",
    "remote_socket_path": "/var/run/docker.sock",
    "key_source": "generate",
    "enabled": "1",
}
LOCAL_FORM = {"kind": "local", "name": "local", "docker_url": "tcp://socket-proxy:2375"}
SENTINEL_PASSPHRASE = "sentinel passphrase 4f1d"


def host_id_from(response) -> int:
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def host_row(browser: Browser, host_id: int) -> dict:
    with browser.db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    return dict(row) if row else {}


def audit_rows(browser: Browser, action: str) -> list[tuple[str, dict]]:
    rows = browser.sql(
        "SELECT outcome, details FROM audit_events WHERE action = ? ORDER BY id", (action,)
    )
    return [(outcome, json.loads(details)) for outcome, details in rows]


def assert_no_key_material(html: str) -> None:
    for marker in KEY_MARKERS:
        assert marker.decode() not in html
    assert "gAAAAA" not in html, "a Fernet token (encrypted secret) reached the page"
    assert SENTINEL_PASSPHRASE not in html


def stale_reauth(browser: Browser) -> None:
    browser.sql("UPDATE sessions SET reauth_at = NULL")


def authorized_keys_line(public_key: str) -> str:
    return str(escape(f"{ssh.AUTHORIZED_KEY_OPTIONS} {public_key}"))


# CREATE AND VALIDATE


async def test_add_local_host(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", LOCAL_FORM | {"enabled": "1"}))
    row = host_row(admin, host_id)
    assert (row["kind"], row["docker_url"], row["enabled"]) == (
        "local",
        LOCAL_FORM["docker_url"],
        1,
    )
    assert row["ssh_key_enc"] is None
    page = await admin.get("/hosts")
    assert "tcp://socket-proxy:2375" in page.text
    assert audit_rows(admin, "host.create")[0][1]["kind"] == "local"


async def test_new_local_host_form_suggests_the_configured_proxy(admin: Browser) -> None:
    page = await admin.get("/hosts/new?kind=local")
    assert page.status_code == 200
    assert (await admin.get("/hosts/new?kind=other")).status_code == 404


async def test_new_host_form_asks_for_the_password_first(admin: Browser) -> None:
    stale_reauth(admin)
    page = await admin.get("/hosts/new?kind=ssh")
    assert page.status_code == 303
    assert page.headers["location"] == "/reauth?next=%2Fhosts%2Fnew%3Fkind%3Dssh"
    back = await admin.post("/reauth", {"password": PASSWORD, "next": "/hosts/new?kind=ssh"})
    assert back.headers["location"] == "/hosts/new?kind=ssh"
    assert (await admin.get("/hosts/new?kind=ssh")).status_code == 200


async def test_add_ssh_host_generates_a_key_and_shows_only_the_public_half(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    row = host_row(admin, host_id)
    assert row["ssh_public_key"].startswith("ssh-ed25519 ")
    assert row["ssh_key_enc"].startswith("gAAAAA")
    assert row["known_host_line"] is None
    page = await admin.get(f"/hosts/{host_id}")
    assert page.status_code == 200
    assert authorized_keys_line(row["ssh_public_key"]) in page.text
    assert "command=&#34;/bin/false&#34;" in page.text
    assert "No host key is trusted yet" in page.text
    assert_no_key_material(page.text)
    assert audit_rows(admin, "host.create")[0][1]["identity"] == "generate"


async def test_pasted_key_with_passphrase_is_never_echoed(admin: Browser) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519", comment="pasted")
    pem = key.export_private_key("openssh", SENTINEL_PASSPHRASE).decode()
    form = SSH_FORM | {"key_source": "paste", "private_key": pem}

    wrong = await admin.post("/hosts", form | {"key_passphrase": "not the passphrase"})
    assert wrong.status_code == 422
    assert "The passphrase is wrong." in wrong.text
    assert_no_key_material(wrong.text)
    assert admin.sql("SELECT count(*) FROM hosts") == [(0,)]

    host_id = host_id_from(
        await admin.post("/hosts", form | {"key_passphrase": SENTINEL_PASSPHRASE})
    )
    row = host_row(admin, host_id)
    assert row["ssh_public_key"] == ssh.public_key_line(key)
    assert SENTINEL_PASSPHRASE not in json.dumps(row)
    page = await admin.get(f"/hosts/{host_id}")
    assert ssh.public_key_line(key) in page.text
    assert_no_key_material(page.text)
    # The audit log records how the key was set, never the key or the passphrase.
    audit_text = json.dumps(admin.sql("SELECT details FROM audit_events"))
    assert SENTINEL_PASSPHRASE not in audit_text and "PRIVATE KEY" not in audit_text


async def test_replacing_the_key(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    first = host_row(admin, host_id)["ssh_public_key"]
    bad = await admin.post(
        f"/hosts/{host_id}/key", {"key_source": "paste", "private_key": "not a key"}
    )
    assert bad.status_code == 422 and "not a supported private key" in bad.text
    assert host_row(admin, host_id)["ssh_public_key"] == first
    done = await admin.post(f"/hosts/{host_id}/key", {"key_source": "generate"})
    assert done.status_code == 303
    assert host_row(admin, host_id)["ssh_public_key"] != first
    assert audit_rows(admin, "host.key")[-1][1] == {
        "algorithm": "ssh-ed25519",
        "identity": "generate",
    }


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"name": "has space"}, "Name must be"),
        ({"name": ""}, "Name must be"),
        ({"address": "-oProxyCommand=x"}, "Enter a host name"),
        ({"address": "host_name.example"}, "Enter a host name"),
        ({"address": "[::1]"}, "Enter a host name"),
        ({"address": "fe80::1%eth0"}, "Enter a host name"),
        ({"address": "169.254.169.254"}, "Link-local"),
        ({"address": "2852039166"}, "Link-local"),  # 169.254.169.254 to the resolver
        ({"address": "0xa9fea9fe"}, "Link-local"),
        ({"address": "fe80::1"}, "Link-local"),
        ({"address": "::ffff:169.254.169.254"}, "Link-local"),
        ({"address": "0.0.0.0"}, "Link-local"),  # noqa: S104
        ({"address": "224.0.0.1"}, "Link-local"),
        ({"port": "0"}, "Port must be"),
        ({"port": "65536"}, "Port must be"),
        ({"port": "22x"}, "Port must be"),
        ({"username": "root; rm"}, "User must be"),
        ({"username": "-l"}, "User must be"),
        ({"remote_socket_path": "var/run/docker.sock"}, "remote socket path"),
        ({"remote_socket_path": "/var/run/../docker.sock"}, "remote socket path"),
        ({"remote_socket_path": "/var/run/docker sock"}, "remote socket path"),
        ({"key_source": "paste", "private_key": ""}, "not a supported private key"),
        ({"key_source": "other"}, "generate a key or paste one"),
    ],
)
async def test_ssh_host_validation(admin: Browser, changes: dict, message: str) -> None:
    response = await admin.post("/hosts", SSH_FORM | changes)
    assert response.status_code == 422
    assert message in response.text
    assert admin.sql("SELECT count(*) FROM hosts") == [(0,)]


@pytest.mark.parametrize(
    "url",
    [
        "ssh://root@host",
        "file:///var/run/docker.sock",
        "npipe:////./pipe/docker_engine",
        "tcp://user:secret@proxy:2375",
        "tcp://proxy:2375/path",
        "tcp://proxy:2375?x=1",
        "tcp://proxy:99999",
        "tcp://",
        "unix://relative.sock",
        "unix:///var/run/../docker.sock",
        "unix:///proc/1/root/var/run/docker.sock",
        "unix:///sys/fs/cgroup/x.sock",
        # Plain or unauthenticated APIs stay on the local network; the rest goes over SSH.
        "tcp://169.254.169.254:80",
        "http://2852039166:80",
        "tcp://[fe80::1]:2375",
        "tcp://[::ffff:169.254.169.254]:2375",
        "tcp://docker.example.com:2375",
        "https://1.1.1.1:2376",
    ],
)
async def test_docker_url_validation(admin: Browser, url: str) -> None:
    response = await admin.post("/hosts", LOCAL_FORM | {"docker_url": url})
    assert response.status_code == 422, url
    assert admin.sql("SELECT count(*) FROM hosts") == [(0,)]


@pytest.mark.parametrize(
    "url",
    [
        "tcp://socket-proxy:2375",
        "http://localhost:2375",
        "tcp://127.0.0.1:2375",
        "tcp://[::1]:2375",
        "tcp://192.168.1.20:2375",
        "https://10.0.0.5:2376",
        "unix:///var/run/docker.sock",
    ],
)
async def test_local_docker_urls_are_accepted(admin: Browser, url: str) -> None:
    host_id_from(await admin.post("/hosts", LOCAL_FORM | {"docker_url": url}))


@pytest.mark.parametrize(
    "path",
    [
        "{run_dir}/hosts/1.sock",
        "/{run_dir}/hosts/1.sock",  # a POSIX double-slash root names the same file
        "/proc/self/root{run_dir}/hosts/1.sock",
    ],
)
async def test_drydock_run_dir_sockets_are_refused(admin: Browser, path: str) -> None:
    url = "unix://" + path.format(run_dir=admin.settings.run_dir)
    response = await admin.post("/hosts", LOCAL_FORM | {"docker_url": url})
    assert response.status_code == 422, url
    assert admin.sql("SELECT count(*) FROM hosts") == [(0,)]


async def test_names_are_unique_ignoring_case(admin: Browser) -> None:
    host_id_from(await admin.post("/hosts", LOCAL_FORM))
    response = await admin.post("/hosts", LOCAL_FORM | {"name": "LOCAL"})
    assert response.status_code == 422 and "A host with that name exists." in response.text


async def test_escaping(admin: Browser) -> None:
    response = await admin.post("/hosts", LOCAL_FORM | {"name": "<script>x"})
    assert response.status_code == 422
    assert "<script>x" not in response.text and "&lt;script&gt;x" in response.text


# EDIT


async def test_changing_address_or_port_clears_the_trusted_key(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    line = f"203.0.113.9 {ssh.public_key_line(asyncssh.generate_private_key('ssh-ed25519'))}"
    trust = "UPDATE hosts SET known_host_line = ?, host_key_fingerprint = 'SHA256:x' WHERE id = ?"
    admin.sql(trust, (line, host_id))

    renamed = await admin.post(f"/hosts/{host_id}", SSH_FORM | {"username": "other", "name": "r2"})
    assert renamed.status_code == 303
    row = host_row(admin, host_id)
    assert (row["username"], row["name"], row["known_host_line"]) == ("other", "r2", line)

    moved = await admin.post(f"/hosts/{host_id}", SSH_FORM | {"port": "2222"})
    assert moved.status_code == 303
    row = host_row(admin, host_id)
    assert row["port"] == 2222
    assert row["known_host_line"] is None and row["host_key_fingerprint"] is None
    _, details = audit_rows(admin, "host.update")[-1]
    assert details["trust_cleared"] is True
    assert details["target"] == {"from": "other@203.0.113.9:22", "to": "backup@203.0.113.9:2222"}


async def test_disabling_a_host(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", LOCAL_FORM | {"enabled": "1"}))
    assert (await admin.post(f"/hosts/{host_id}", LOCAL_FORM)).status_code == 303
    assert host_row(admin, host_id)["enabled"] == 0
    page = await admin.get(f"/hosts/{host_id}")
    assert "This host is disabled." in page.text
    inventory = await admin.get(f"/hosts/{host_id}/containers")
    assert "This host is disabled." in inventory.text


async def test_delete(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    response = await admin.post(f"/hosts/{host_id}/delete")
    assert response.status_code == 303 and response.headers["location"] == "/hosts"
    assert host_row(admin, host_id) == {}
    assert (await admin.get(f"/hosts/{host_id}")).status_code == 404


# RECENT AUTH AND ROLES


async def test_changes_need_recent_auth(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    before = host_row(admin, host_id)
    stale_reauth(admin)
    attempts = [
        ("/hosts", LOCAL_FORM),
        (f"/hosts/{host_id}", SSH_FORM | {"name": "renamed"}),
        (f"/hosts/{host_id}/key", {"key_source": "generate"}),
        (f"/hosts/{host_id}/trust-hostkey", {"fingerprint": "SHA256:" + "A" * 43}),
        (f"/hosts/{host_id}/delete", {}),
    ]
    for path, data in attempts:
        response = await admin.post(path, data)
        assert response.status_code == 403, path
        assert "Confirm your drydock password" in response.text
    assert host_row(admin, host_id) == before
    assert admin.sql("SELECT count(*) FROM hosts") == [(1,)]


@pytest.mark.parametrize("role", ["viewer", "operator"])
async def test_hosts_are_admin_only_but_the_inventory_is_not(admin: Browser, role: str) -> None:
    host_id = host_id_from(await admin.post("/hosts", LOCAL_FORM | {"enabled": "1"}))
    await add_user(admin, f"user-{role}", role)
    await admin.login(f"user-{role}", PASSWORD)
    for path in ("/hosts", "/hosts/new", f"/hosts/{host_id}"):
        assert (await admin.get(path)).status_code == 403, path
    response = await admin.post(f"/hosts/{host_id}/test")
    assert response.status_code == 403
    assert "Hosts" not in (await admin.get("/")).text.split("<main")[0]
    # The role matrix lets every role view the inventory, without the admin-only host page.
    inventory = await admin.get(f"/hosts/{host_id}/containers")
    assert inventory.status_code == 200
    assert 'id="inventory"' in inventory.text
    assert f'href="/hosts/{host_id}"' not in inventory.text


# HOST KEY TRUST


@pytest.fixture
def fake_server(monkeypatch) -> dict:
    """A stand-in for the scanned server; tests swap its key to simulate a change."""
    server = {"key": asyncssh.generate_private_key("ssh-ed25519")}

    async def scan(address: str, port: int) -> tuple[str, str]:
        key = server["key"]
        return ssh.known_host_line(address, port, key), ssh.fingerprint(key)

    monkeypatch.setattr(ssh, "scan_host_key", scan)
    return server


async def test_scan_then_trust(admin: Browser, fake_server: dict) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    fingerprint = ssh.fingerprint(fake_server["key"])

    scan = await admin.post(f"/hosts/{host_id}/scan-hostkey")
    assert scan.status_code == 200
    assert fingerprint in scan.text and "Trust this key" in scan.text
    assert host_row(admin, host_id)["known_host_line"] is None, "scanning trusts nothing"
    assert audit_rows(admin, "host.hostkey_scan") == [("success", {"fingerprint": fingerprint})]

    trust = await admin.post(f"/hosts/{host_id}/trust-hostkey", {"fingerprint": fingerprint})
    assert trust.status_code == 303
    row = host_row(admin, host_id)
    assert row["host_key_fingerprint"] == fingerprint
    assert row["known_host_line"] == ssh.known_host_line("203.0.113.9", 22, fake_server["key"])
    outcome, details = audit_rows(admin, "host.hostkey_trust")[-1]
    assert outcome == "success"
    assert details["presented_fingerprint"] == fingerprint
    assert details["previous_fingerprint"] is None

    again = await admin.post(f"/hosts/{host_id}/scan-hostkey")
    assert "It matches the trusted key." in again.text and "Trust this key" not in again.text


async def test_trust_refuses_a_key_that_changed_after_the_scan(
    admin: Browser, fake_server: dict
) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    confirmed = ssh.fingerprint(fake_server["key"])
    fake_server["key"] = asyncssh.generate_private_key("ssh-ed25519")  # an impostor answers

    response = await admin.post(f"/hosts/{host_id}/trust-hostkey", {"fingerprint": confirmed})
    assert response.status_code == 409
    assert "not the fingerprint you confirmed" in response.text
    assert host_row(admin, host_id)["known_host_line"] is None
    outcome, details = audit_rows(admin, "host.hostkey_trust")[-1]
    assert outcome == "failure"
    assert details["presented_fingerprint"] == ssh.fingerprint(fake_server["key"])


SSH_PASSWORD = "sentinel ssh password 9b3e"


def leaked_password(browser: Browser) -> bool:
    with browser.db() as conn:
        dump = "\n".join(conn.iterdump())
    return SSH_PASSWORD in dump


async def test_trust_with_a_password_installs_drydocks_key(
    admin: Browser, fake_server: dict, monkeypatch
) -> None:
    calls = []

    async def install(*args: str) -> None:
        calls.append(args)

    monkeypatch.setattr(ssh, "install_key", install)
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    fingerprint = ssh.fingerprint(fake_server["key"])
    response = await admin.post(
        f"/hosts/{host_id}/trust-hostkey", {"fingerprint": fingerprint, "password": SSH_PASSWORD}
    )
    assert response.status_code == 303
    row = host_row(admin, host_id)
    known = ssh.known_host_line("203.0.113.9", 22, fake_server["key"])
    assert row["known_host_line"] == known
    line = f"{ssh.AUTHORIZED_KEY_OPTIONS} {row['ssh_public_key']}"
    # The password goes only against the host key just pinned.
    assert calls == [("203.0.113.9", 22, "backup", known, SSH_PASSWORD, line)]
    assert audit_rows(admin, "host.key_install") == [("success", {"username": "backup"})]
    assert not leaked_password(admin)


async def test_a_refused_password_still_trusts_the_host_key(
    admin: Browser, fake_server: dict, monkeypatch
) -> None:
    async def refuse(*args: str) -> None:
        raise ssh.SSHKeyError("203.0.113.9 refused the password for backup.")

    monkeypatch.setattr(ssh, "install_key", refuse)
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    fingerprint = ssh.fingerprint(fake_server["key"])
    response = await admin.post(
        f"/hosts/{host_id}/trust-hostkey", {"fingerprint": fingerprint, "password": SSH_PASSWORD}
    )
    assert response.status_code == 422
    assert "refused the password for backup" in response.text
    assert SSH_PASSWORD not in response.text
    assert host_row(admin, host_id)["host_key_fingerprint"] == fingerprint
    outcome, details = audit_rows(admin, "host.key_install")[-1]
    assert outcome == "failure" and "refused the password" in details["error"]
    assert not leaked_password(admin)


async def test_a_trusted_host_offers_to_install_the_key(admin: Browser, fake_server: dict) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    fingerprint = ssh.fingerprint(fake_server["key"])
    await admin.post(f"/hosts/{host_id}/trust-hostkey", {"fingerprint": fingerprint})
    page = (await admin.post(f"/hosts/{host_id}/scan-hostkey")).text
    assert "Install drydock&#39;s key" in page or "Install drydock's key" in page
    assert 'name="password"' in page and "Trust this key" not in page


@pytest.mark.parametrize("value", ["", "MD5:aa:bb", "SHA256:short", "SHA256:" + "A" * 43 + "x"])
async def test_trust_needs_a_sha256_fingerprint(
    admin: Browser, fake_server: dict, value: str
) -> None:
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    response = await admin.post(f"/hosts/{host_id}/trust-hostkey", {"fingerprint": value})
    assert response.status_code == 422
    assert host_row(admin, host_id)["known_host_line"] is None
    outcome, details = audit_rows(admin, "host.hostkey_trust")[-1]
    assert outcome == "failure"
    assert details["submitted"] == value


async def test_scan_failure_is_shown_and_audited(admin: Browser, monkeypatch) -> None:
    async def unreachable(address: str, port: int) -> tuple[str, str]:
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(ssh, "scan_host_key", unreachable)
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    response = await admin.post(f"/hosts/{host_id}/scan-hostkey")
    assert response.status_code == 422  # not 5xx, which proxies may replace
    assert "Could not read the host key" in response.text
    assert audit_rows(admin, "host.hostkey_scan")[0][0] == "failure"

    fingerprint = "SHA256:" + "A" * 43
    trust = await admin.post(f"/hosts/{host_id}/trust-hostkey", {"fingerprint": fingerprint})
    assert trust.status_code == 422
    assert "Could not read the host key" in trust.text
    outcome, details = audit_rows(admin, "host.hostkey_trust")[-1]
    assert outcome == "failure"
    assert details["confirmed_fingerprint"] == fingerprint
    assert "Could not read the host key" in details["error"]


async def test_local_hosts_have_no_host_key(admin: Browser) -> None:
    host_id = host_id_from(await admin.post("/hosts", LOCAL_FORM))
    for path in ("scan-hostkey", "trust-hostkey", "key"):
        assert (await admin.post(f"/hosts/{host_id}/{path}")).status_code == 404, path


# CONNECTION TEST AND INVENTORY WITHOUT A DAEMON


async def test_unreachable_host_is_reported(admin: Browser) -> None:
    host_id = host_id_from(
        await admin.post("/hosts", LOCAL_FORM | {"docker_url": "tcp://127.0.0.1:9", "enabled": "1"})
    )
    test = await admin.post(f"/hosts/{host_id}/test")
    assert test.status_code == 200
    assert "Test failed: Cannot reach the Docker daemon" in test.text
    assert audit_rows(admin, "host.test")[0][0] == "failure"
    inventory = await admin.get(f"/hosts/{host_id}/containers")
    assert inventory.status_code == 200
    assert 'id="inventory"' in inventory.text and "Could not list containers" in inventory.text


async def test_untrusted_ssh_host_is_never_contacted(admin: Browser, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(asyncssh, "connect", lambda *a, **k: calls.append(a))
    host_id = host_id_from(await admin.post("/hosts", SSH_FORM))
    test = await admin.post(f"/hosts/{host_id}/test")
    assert "The host key has not been trusted yet." in test.text
    inventory = await admin.get(f"/hosts/{host_id}/containers")
    assert "The host key has not been trusted yet." in inventory.text
    assert calls == []
