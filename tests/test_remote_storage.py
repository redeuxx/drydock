"""Remote storage targets (Phase 6b): the option allowlist, secrets, roles and schema."""

import asyncio
import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

import asyncssh
import pytest

from drydock.db import make_engine
from drydock.storage import options
from drydock.storage.rclone_rc import RCLONE_BINARY, RcloneUnavailable
from tests.conftest import PASSWORD, Browser, add_user
from tests.test_jobs import add_host, add_storage
from tests.test_restore_schema import alembic_to
from tests.test_stacks_schema import add_job as add_job_row
from tests.test_stacks_schema import add_parents, table_sql, version
from tests.test_upgrade import head

pytestmark = pytest.mark.anyio

SENTINEL = "s3cr3t-Sentinel-7f1c"
REFUSED_VALUE = "refused-value-91b2"
HOST_KEY = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
VALID = {
    "sftp": {
        "opt_host": "nas.lan",
        "opt_host_keys": HOST_KEY,
        "opt_user": "backup",
        "opt_pass": SENTINEL,
    },
    "smb": {"opt_host": "192.168.1.10", "opt_pass": SENTINEL, "folder": "backups"},
    "webdav": {"opt_url": "https://dav.example.com/remote.php/dav", "opt_pass": SENTINEL},
    "drive": {
        "opt_client_id": "1234-abc.apps.googleusercontent.com",
        "opt_client_secret": SENTINEL,
    },
}
# Options rclone has but drydock denies or sets itself: the plan's exit criteria first.
REFUSED = [
    ("sftp", "opt_ssh"),
    ("sftp", "opt_md5sum_command"),
    ("sftp", "opt_sha256sum_command"),
    ("sftp", "opt_server_command"),
    ("sftp", "opt_key_file"),
    ("sftp", "opt_pubkey_file"),
    ("sftp", "opt_known_hosts_file"),
    ("sftp", "opt_pin_host_key"),
    ("sftp", "opt_key_use_agent"),
    ("sftp", "opt_use_insecure_cipher"),
    ("sftp", "opt_socks_proxy"),
    ("sftp", "opt_shell_type"),
    ("sftp", "opt_set_env"),
    ("smb", "opt_kerberos_ccache"),
    ("smb", "opt_use_kerberos"),
    ("webdav", "opt_bearer_token_command"),
    ("webdav", "opt_unix_socket"),
    ("webdav", "opt_headers"),
    ("webdav", "opt_auth_redirect"),
    ("drive", "opt_service_account_file"),
    ("drive", "opt_service_account_credentials"),
    ("drive", "opt_token_url"),
    ("drive", "opt_auth_url"),
    ("drive", "opt_token"),
    ("drive", "opt_env_auth"),
    # rclone's global and override keys, and spellings rclone itself would ignore
    ("sftp", "opt_global.no_check_certificate"),
    ("webdav", "opt_override.ca_cert"),
    ("sftp", "opt_SSH"),
    ("sftp", "opt_sftp_ssh"),
    ("sftp", "opt__name"),
    ("sftp", "opt__root"),
    ("sftp", "opt_type"),
    # bare rclone names and other strangers
    ("sftp", "ssh"),
    ("drive", "service_account_file"),
    ("smb", "path"),
    ("webdav", "clear_url"),
    ("drive", "unknown"),
]


def form(kind: str, name: str = "remote", **fields: str) -> dict[str, str]:
    return {"name": name, "kind": kind, "enabled": "1"} | VALID[kind] | fields


async def new_remote(browser: Browser, kind: str, name: str = "remote", **fields: str) -> int:
    response = await browser.post("/storage", form(kind, name, **fields))
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def stored_config(browser: Browser, storage_id: int) -> dict:
    (blob,) = browser.sql("SELECT config_enc FROM storage_targets WHERE id = ?", (storage_id,))[0]
    assert SENTINEL not in blob
    return json.loads(browser.app.state.crypto.decrypt(blob))


def openssh_key(passphrase: str | None = None) -> str:
    key = asyncssh.generate_private_key("ssh-ed25519")
    return key.export_private_key("openssh", passphrase).decode()


# EXIT CRITERIA: REFUSED OPTIONS AND KINDS


@pytest.mark.parametrize(("kind", "field"), REFUSED)
async def test_refused_options_save_nothing(admin: Browser, kind: str, field: str) -> None:
    response = await admin.post("/storage", form(kind, **{field: REFUSED_VALUE}))
    assert response.status_code == 422
    assert repr(field) in response.text.replace("&#39;", "'")
    assert REFUSED_VALUE not in response.text  # only the field's name is quoted back
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


async def test_file_fields_are_refused(admin: Browser) -> None:
    response = await admin.client.post(
        "/storage",
        data=form("sftp") | {"csrf_token": await admin.csrf_token()},
        files={"opt_key_pem": ("id_ed25519", b"key", "text/plain")},
        headers=admin.origin_headers,
    )
    assert response.status_code == 422 and "must be text" in response.text
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


@pytest.mark.parametrize(("kind", "field"), REFUSED[:8])
async def test_refused_options_change_nothing_on_edit(
    admin: Browser, kind: str, field: str
) -> None:
    storage_id = await new_remote(admin, kind)
    before = admin.sql("SELECT config_enc FROM storage_targets")
    response = await admin.post(f"/storage/{storage_id}", form(kind, **{field: "x"}))
    assert response.status_code == 422
    assert admin.sql("SELECT config_enc FROM storage_targets") == before


@pytest.mark.parametrize("kind", ["s3", "alias", "crypt", "union", "LOCAL", "sftp2"])
async def test_other_rclone_types_are_refused(admin: Browser, kind: str) -> None:
    assert (await admin.get(f"/storage/new?type={kind}")).status_code == 404
    response = await admin.post("/storage", {"name": "x", "kind": kind, "opt_host": "h"})
    assert response.status_code == 422
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


async def test_repeated_fields_are_refused(admin: Browser) -> None:
    response = await admin.post("/storage", form("sftp") | {"opt_host": ["nas.lan", "x.lan"]})
    assert response.status_code == 422 and "more than once" in response.text
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


async def test_the_kind_cannot_be_changed(admin: Browser) -> None:
    storage_id = await new_remote(admin, "sftp")
    response = await admin.post(f"/storage/{storage_id}", form("sftp") | {"kind": "webdav"})
    assert response.status_code == 422
    assert admin.sql("SELECT kind FROM storage_targets") == [("sftp",)]


# SECRETS


@pytest.mark.parametrize("kind", list(VALID))
async def test_secrets_are_stored_encrypted_and_never_shown(
    admin: Browser, kind: str, caplog
) -> None:
    caplog.set_level(logging.INFO)
    storage_id = await new_remote(admin, kind)
    secret = next(o.name for o in options.BACKENDS[kind].secrets if f"opt_{o.name}" in VALID[kind])
    assert stored_config(admin, storage_id)["options"][secret] == SENTINEL
    for path in ("/storage", f"/storage/{storage_id}", "/audit", "/restore", "/jobs/new"):
        page = await admin.get(path)
        assert page.status_code == 200 and SENTINEL not in page.text, path
    edit = (await admin.get(f"/storage/{storage_id}")).text
    assert 'placeholder="unchanged"' in edit and f'name="clear_{secret}"' in edit
    created = admin.sql("SELECT outcome, details FROM audit_events WHERE action = 'storage.create'")
    assert len(created) == 1 and created[0][0] == "success"
    assert json.loads(created[0][1])["kind"] == kind
    assert SENTINEL not in str(admin.sql("SELECT details FROM audit_events"))
    assert SENTINEL not in caplog.text


async def test_keys_passphrases_and_tokens_are_never_shown(admin: Browser, caplog) -> None:
    caplog.set_level(logging.INFO)
    key = openssh_key(SENTINEL)
    key_line = key.splitlines()[2]  # a line of the key's body
    sftp_id = await new_remote(
        admin, "sftp", "keyed", opt_pass="", opt_key_pem=key, opt_key_file_pass=SENTINEL
    )
    dav_id = await new_remote(admin, "webdav", "token", opt_pass="", opt_bearer_token=SENTINEL)
    assert stored_config(admin, dav_id)["options"]["bearer_token"] == SENTINEL
    assert key_line not in admin.sql("SELECT config_enc FROM storage_targets")[0][0]
    pages = [await admin.get(p) for p in ("/storage", f"/storage/{sftp_id}", f"/storage/{dav_id}")]
    pages.append(await admin.post(f"/storage/{sftp_id}", form("sftp", name="bad name!")))
    pages.append(await admin.post(f"/storage/{dav_id}", form("webdav", name="bad name!")))
    await add_user(admin, "plain-admin", "admin")
    await admin.login("plain-admin")
    pages += [await admin.get(f"/storage/{sftp_id}"), await admin.get("/audit")]
    for page in pages:
        assert SENTINEL not in page.text and key_line not in page.text
    assert key_line not in caplog.text and SENTINEL not in caplog.text


@pytest.mark.parametrize("kind", list(VALID))
async def test_a_refused_form_never_echoes_secrets(admin: Browser, kind: str) -> None:
    response = await admin.post("/storage", form(kind, name="bad name!"))
    assert response.status_code == 422 and SENTINEL not in response.text
    storage_id = await new_remote(admin, kind)
    response = await admin.post(f"/storage/{storage_id}", form(kind, name="bad name!"))
    assert response.status_code == 422 and SENTINEL not in response.text
    assert 'placeholder="unchanged"' in response.text


async def test_an_empty_secret_keeps_the_stored_one(admin: Browser) -> None:
    storage_id = await new_remote(admin, "sftp")
    response = await admin.post(f"/storage/{storage_id}", form("sftp", opt_pass="", folder="b"))
    assert response.status_code == 303, response.text
    config = stored_config(admin, storage_id)
    assert config["options"]["pass"] == SENTINEL and config["folder"] == "b"
    (details,) = admin.sql("SELECT details FROM audit_events WHERE action = 'storage.update'")[0]
    assert json.loads(details)["options_changed"] == ["folder"]


async def test_a_new_destination_needs_the_secrets_again(admin: Browser) -> None:
    storage_id = await new_remote(admin, "sftp")
    moved = form("sftp", opt_pass="", opt_host="elsewhere.example.com")
    response = await admin.post(f"/storage/{storage_id}", moved)
    assert response.status_code == 422 and "must be entered again" in response.text
    assert stored_config(admin, storage_id)["options"]["host"] == "nas.lan"
    again = moved | {"opt_pass": "new-password"}
    assert (await admin.post(f"/storage/{storage_id}", again)).status_code == 303
    assert stored_config(admin, storage_id)["options"]["host"] == "elsewhere.example.com"
    # The same port written differently is no new destination.
    same = form("sftp", opt_pass="", opt_host="elsewhere.example.com", opt_port="022")
    assert (await admin.post(f"/storage/{storage_id}", same)).status_code == 303
    assert stored_config(admin, storage_id)["options"]["port"] == "22"


async def test_a_new_webdav_folder_needs_the_secrets_again(admin: Browser) -> None:
    """A shared WebDAV host serves other tenants under other paths."""
    storage_id = await new_remote(admin, "webdav", folder="alice")
    response = await admin.post(f"/storage/{storage_id}", form("webdav", opt_pass="", folder="bob"))
    assert response.status_code == 422 and "folder changed" in response.text
    assert stored_config(admin, storage_id)["folder"] == "alice"
    sftp_id = await new_remote(admin, "sftp", "other", folder="alice")
    moved = form("sftp", "other", opt_pass="", folder="bob")
    assert (await admin.post(f"/storage/{sftp_id}", moved)).status_code == 303


async def test_a_secret_can_be_cleared(admin: Browser) -> None:
    key = openssh_key()
    storage_id = await new_remote(admin, "sftp", opt_key_pem=key)
    response = await admin.post(f"/storage/{storage_id}", form("sftp", opt_pass="", clear_pass="1"))
    assert response.status_code == 303, response.text
    config = stored_config(admin, storage_id)["options"]
    assert "pass" not in config and config["key_pem"] == key.replace("\r\n", "\n")
    response = await admin.post(
        f"/storage/{storage_id}", form("sftp", opt_pass="", clear_key_pem="1")
    )
    assert response.status_code == 422 and "password or a private key" in response.text


# ROLES


async def test_remote_storage_is_changed_by_superadmins_with_recent_auth(admin: Browser) -> None:
    storage_id = await new_remote(admin, "webdav")
    local_id = await add_storage(admin, "local-one")
    await add_user(admin, "plain-admin", "admin")
    await admin.login("plain-admin")
    page = await admin.get(f"/storage/{storage_id}")
    assert page.status_code == 200
    assert "dav.example.com" in page.text and "Only a superadmin" in page.text
    assert 'name="opt_url"' not in page.text and "Remove remote" not in page.text
    assert (await admin.get("/storage/new?type=webdav")).status_code == 403
    assert "?type=webdav" not in (await admin.get("/storage/new")).text
    for path, data in (
        ("/storage", form("webdav", name="other")),
        (f"/storage/{storage_id}", form("webdav")),
        (f"/storage/{storage_id}/delete", {}),
    ):
        assert (await admin.post(path, data)).status_code == 403, path
    # Local storage stays an admin task.
    assert (await admin.post(f"/storage/{local_id}/delete")).status_code == 303
    await admin.login("admin")
    admin.sql("UPDATE sessions SET reauth_at = NULL")
    before = admin.sql("SELECT id, name, config_enc FROM storage_targets")
    for path, data in (
        ("/storage", form("webdav", name="other")),
        (f"/storage/{storage_id}", form("webdav", name="renamed")),
        (f"/storage/{storage_id}/delete", {}),
    ):
        response = await admin.post(path, data)
        assert response.status_code == 403 and "Re-enter your password" in response.text, path
    assert admin.sql("SELECT id, name, config_enc FROM storage_targets") == before
    assert (await admin.post("/reauth", {"password": PASSWORD, "next": "/"})).status_code == 303
    assert (await admin.post(f"/storage/{storage_id}/delete")).status_code == 303
    deleted = admin.sql("SELECT outcome FROM audit_events WHERE action = 'storage.delete'")
    assert deleted == [("success",), ("success",)]  # the local one, then the remote one


# GOOGLE DRIVE BEFORE CONNECTING


async def test_an_unconnected_drive_says_so(admin: Browser) -> None:
    storage_id = await new_remote(admin, "drive", "nas-share")
    host_id = add_host(admin)
    response = await admin.post(
        "/jobs",
        {
            "name": "web",
            "host_id": str(host_id),
            "target": "web",
            "storage_target_id": str(storage_id),
            "scope": "config",
            "enabled": "1",
        },
    )
    assert response.status_code == 303, response.text
    listing = await admin.get(f"/restore/storage/{storage_id}")
    assert "not connected to Google yet" in listing.text
    test = await admin.post(f"/storage/{storage_id}/test")
    assert "not connected to Google yet" in test.text
    assert admin.sql("SELECT COUNT(*) FROM runs") == [(0,)]


# FIELD CHECKS


@pytest.mark.parametrize(
    ("kind", "fields", "message"),
    [
        ("sftp", {"opt_host": "nas.lan:22"}, "host name or an IP address"),
        ("sftp", {"opt_host": "[::1]"}, "host name or an IP address"),
        ("sftp", {"opt_host": "fe80::1%eth0"}, "host name or an IP address"),
        ("sftp", {"opt_port": "0"}, "from 1 to 65535"),
        ("sftp", {"opt_port": chr(0xFF12) * 2}, "from 1 to 65535"),  # fullwidth digits
        ("sftp", {"opt_user": ""}, "Enter the user"),
        ("sftp", {"opt_pass": ""}, "password or a private key"),
        ("sftp", {"opt_user": "a\nb"}, "control characters"),
        ("sftp", {"folder": "a/../b"}, ". or .. parts"),
        ("sftp", {"folder": "a\\b"}, "backslashes"),
        ("sftp", {"opt_key_file_pass": "x"}, "passphrase needs a private key"),
        (
            "sftp",
            {"opt_key_pem": "-----BEGIN NOT A KEY-----"},
            "Private key: This is not a supported private key.",
        ),
        (
            "sftp",
            {"opt_key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbné\n"},
            "Private key is not a PEM or OpenSSH private key.",
        ),
        ("sftp", {"opt_set_modtime": "true"}, "tick the box"),
        ("smb", {"folder": "/share"}, "must not start with /"),
        ("smb", {"opt_domain": "bad domain"}, "Domain: use"),
        ("smb", {"opt_host": "fd00::1"}, "SMB storage needs a host name or an IPv4"),
        ("smb", {"opt_user": "a]b"}, "without ]"),
        ("webdav", {"opt_url": "ftp://dav.example.com"}, "as https:// with a host"),
        ("webdav", {"opt_url": "http://dav.lan"}, "does not use plain http"),
        ("webdav", {"opt_url": "https://[::1]/dav"}, "IPv4 address, and no ]"),
        ("webdav", {"opt_url": "https://dav.lan/a]b"}, "IPv4 address, and no ]"),
        ("webdav", {"opt_url": "https://u:p@dav.example.com"}, "user name, password"),
        ("webdav", {"opt_url": "https://dav.example.com/?x=1"}, "query"),
        ("webdav", {"opt_url": "https://dav.example.com:99999"}, "invalid port"),
        ("webdav", {"opt_url": "https://dav.example.com:0/"}, "invalid port"),
        ("webdav", {"opt_url": "https://[::1/x"}, "as https:// with a host"),
        ("webdav", {"opt_url": "https://a]b/"}, "as https:// with a host"),
        ("webdav", {"opt_url": "https://[notip]/"}, "as https:// with a host"),
        ("webdav", {"opt_vendor": "sharepoint"}, "from the list"),
        ("webdav", {"opt_vendor": "infinitescale"}, "from the list"),
        ("webdav", {"opt_user": "a:b"}, "without a colon"),
        ("webdav", {"opt_bearer_token": "t"}, "not both"),
        ("webdav", {"opt_pass": "", "opt_bearer_token": "a]b"}, "must not contain ]"),
        ("webdav", {"opt_tls_cert": "junk"}, "Server certificate: Paste exactly one"),
        ("drive", {"opt_client_id": "my-client"}, "apps.googleusercontent.com"),
        ("drive", {"opt_client_secret": ""}, "Enter the oauth client secret"),
        ("drive", {"opt_scope": "drive.readonly"}, "from the list"),
        ("drive", {"opt_root_folder_id": "a/b"}, "Root folder ID: use"),
    ],
)
async def test_values_are_checked(admin: Browser, kind: str, fields: dict, message: str) -> None:
    response = await admin.post("/storage", form(kind, **fields))
    assert response.status_code == 422
    assert message in response.text.replace("&#39;", "'"), response.text
    assert admin.sql("SELECT COUNT(*) FROM storage_targets") == [(0,)]


async def test_private_keys_are_checked_with_their_passphrase(admin: Browser) -> None:
    locked = openssh_key("pw")
    bad = await admin.post("/storage", form("sftp", opt_key_pem=locked, opt_key_file_pass="no"))
    assert bad.status_code == 422 and "passphrase is wrong" in bad.text
    plain = await admin.post(
        "/storage", form("sftp", opt_key_pem=openssh_key(), opt_key_file_pass="x")
    )
    assert plain.status_code == 422 and "has no passphrase" in plain.text
    storage_id = await new_remote(admin, "sftp", opt_key_pem=locked, opt_key_file_pass="pw")
    assert stored_config(admin, storage_id)["options"]["key_file_pass"] == "pw"
    # A new key without a passphrase, while the old one's is still stored.
    swapped = await admin.post(f"/storage/{storage_id}", form("sftp", opt_key_pem=openssh_key()))
    assert swapped.status_code == 422 and "Clear the stored private key passphrase" in swapped.text


async def test_host_names_with_underscores_are_accepted(admin: Browser) -> None:
    storage_id = await new_remote(admin, "smb", opt_host="backup_nas")
    assert stored_config(admin, storage_id)["options"]["host"] == "backup_nas"


async def test_defaults_and_locations(admin: Browser) -> None:
    sftp = stored_config(admin, await new_remote(admin, "sftp", "a", folder="/srv/b/"))
    assert sftp == {
        "folder": "/srv/b",
        "options": {
            "host": "nas.lan",
            "port": "22",
            "host_keys": HOST_KEY,
            "user": "backup",
            "pass": SENTINEL,
            "set_modtime": "false",  # an unticked box
        },
    }
    drive_id = await new_remote(admin, "drive", "b", opt_use_trash="1", folder="drydock")
    drive = stored_config(admin, drive_id)
    assert drive["options"]["scope"] == "drive.file" and drive["options"]["use_trash"] == "true"
    listing = (await admin.get("/storage")).text
    assert "backup@nas.lan:/srv/b" in listing and "Google Drive: drydock" in listing


@pytest.mark.parametrize(
    ("kind", "basic", "advanced"),
    [("sftp", "opt_host", "opt_set_modtime"), ("drive", "opt_client_id", "opt_scope")],
)
async def test_advanced_options_sit_in_details(
    admin: Browser, kind: str, basic: str, advanced: str
) -> None:
    page = (await admin.get(f"/storage/new?type={kind}")).text.partition("<main")[
        2
    ]  # not the menus
    before, details, _ = page.partition("<details")
    assert details and f'name="{basic}"' in before and f'name="{advanced}"' not in before
    assert f'name="{advanced}"' in page.partition("<details")[2].partition("</details>")[0]


async def test_drydock_help_replaces_rclones_where_drydock_narrows_it(admin: Browser) -> None:
    page = (await admin.get("/storage/new?type=drive")).text
    assert "your own Google OAuth client" in page
    assert "shared client_id" not in page and "service account" not in page.lower()
    assert "ssh-agent" not in (await admin.get("/storage/new?type=sftp")).text


# RCLONE PROVIDERS


@pytest.mark.skipif(not RCLONE_BINARY.is_file(), reason=f"needs rclone in {RCLONE_BINARY}")
async def test_the_allowlist_matches_the_pinned_rclone(admin: Browser) -> None:
    providers = await asyncio.to_thread(admin.app.state.rclone.call, "config/providers")
    texts = options.help_texts(providers)
    assert set(texts) == set(options.BACKENDS)
    assert texts["sftp"]["host"].startswith("SSH host")
    page = await admin.get("/storage/new?type=sftp")
    assert "SSH host to connect to." in page.text and "<details" in page.text


def test_a_changed_rclone_disables_the_forms() -> None:
    providers = {
        "providers": [
            {
                "Name": kind,
                "Options": [
                    {"Name": o.name, "Type": o.rclone_type, "IsPassword": o.obscure}
                    for o in b.options
                ],
            }
            for kind, b in options.BACKENDS.items()
        ]
    }
    assert options.help_texts(providers)["smb"]["domain"] == ""
    providers["providers"][0]["Options"][1]["Type"] = "string"  # sftp port
    with pytest.raises(options.OptionsError, match="sftp option port"):
        options.help_texts(providers)
    with pytest.raises(options.OptionsError):
        options.help_texts({"providers": []})


def providers_with(kind: str, option: str, rclone_type: str) -> dict:
    return {
        "providers": [
            {
                "Name": k,
                "Options": [
                    {
                        "Name": o.name,
                        "Type": rclone_type if (k, o.name) == (kind, option) else o.rclone_type,
                        "IsPassword": o.obscure,
                        "Help": f"help for {o.name}",
                    }
                    for o in b.options
                ],
            }
            for k, b in options.BACKENDS.items()
        ]
    }


async def test_a_changed_rclone_refuses_remote_forms(admin: Browser, monkeypatch) -> None:
    storage_id = await new_remote(admin, "sftp")
    before = admin.sql("SELECT config_enc FROM storage_targets")
    state = admin.app.state
    state.storage_help = None
    monkeypatch.setattr(
        state.rclone, "call", lambda method, *a, **k: providers_with("sftp", "port", "string")
    )
    assert (await admin.get("/storage/new?type=sftp")).status_code == 503
    assert (await admin.post("/storage", form("sftp", "other"))).status_code == 503
    assert (await admin.post(f"/storage/{storage_id}", form("sftp", folder="x"))).status_code == 503
    assert admin.sql("SELECT config_enc FROM storage_targets") == before
    # The target stays visible, and removable, with its form disabled.
    page = await admin.get(f"/storage/{storage_id}")
    assert page.status_code == 200 and "forms are disabled" in page.text
    assert 'name="opt_host"' not in page.text and "Remove remote" in page.text
    assert (await admin.get("/storage/new")).status_code == 200  # local storage is unaffected
    monkeypatch.setattr(state.rclone, "call", lambda *a, **k: providers_with("", "", ""))
    assert "help for host" in (await admin.get("/storage/new?type=sftp")).text


async def test_remote_forms_render_while_rclone_is_down(admin: Browser, monkeypatch) -> None:
    def down(*_args, **_kwargs):
        raise RcloneUnavailable("rclone is not running.")

    admin.app.state.storage_help = None
    monkeypatch.setattr(admin.app.state.rclone, "call", down)
    page = await admin.get("/storage/new?type=sftp")
    assert page.status_code == 200 and 'name="opt_host"' in page.text
    assert admin.app.state.storage_help is None  # not cached: the next request asks again


# MIGRATION


def test_migration_0009_widens_the_storage_kinds(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    insert = (
        "INSERT INTO storage_targets (name, kind, config_enc, enabled, created_at)"
        " VALUES (?, ?, 'x', 1, '2026-10-22 00:00:00')"
    )
    try:
        alembic_to(engine, "0008")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            add_job_row(conn, 1)
            conn.commit()
        alembic_to(engine, "head")
        with closing(sqlite3.connect(path)) as conn:
            assert version(conn) == [(head(),)]
            assert "AUTOINCREMENT" in (table_sql(conn, "storage_targets") or "")
            for kind in ("sftp", "smb", "webdav", "drive"):
                conn.execute(insert, (kind, kind))
            for kind in ("s3", "local2"):
                with pytest.raises(sqlite3.IntegrityError):
                    conn.execute(insert, (kind, kind))
            conn.execute(
                "INSERT INTO backups (storage_target_id, name, size, sha256, signed, encrypted,"
                " created_at) SELECT id, 'a', 1, 'x', 0, 0, '2026-10-22 00:00:00'"
                " FROM storage_targets WHERE kind = 'sftp'"
            )
            conn.commit()
        alembic_to(engine, "0008", down=True)
        with closing(sqlite3.connect(path)) as conn:
            assert conn.execute("SELECT name, kind FROM storage_targets").fetchall() == [
                ("store", "local")
            ]
            # Both rebuilds kept the sequence: a removed target's ID is never handed out again.
            seq = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'storage_targets'")
            assert seq.fetchone() == (5,)
            assert conn.execute("SELECT COUNT(*) FROM backups").fetchone() == (0,)
            assert "kind IN ('local')" in (table_sql(conn, "storage_targets") or "")
    finally:
        engine.dispose()


def test_migration_0009_downgrade_refuses_jobs_on_remote_storage(tmp_path: Path) -> None:
    path = tmp_path / "schema.db"
    engine = make_engine(path)
    try:
        alembic_to(engine, "head")
        with closing(sqlite3.connect(path)) as conn:
            add_parents(conn)
            conn.execute("UPDATE storage_targets SET kind = 'webdav'")
            add_job_row(conn, 1)
            conn.commit()
        with pytest.raises(RuntimeError, match="use remote storage"):
            alembic_to(engine, "0008", down=True)
    finally:
        engine.dispose()
