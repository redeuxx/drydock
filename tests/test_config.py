import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest

from drydock.config import ConfigError, load_settings
from tests.conftest import new_key


def env(**extra: str) -> dict[str, str]:
    return {"DRYDOCK_DATA_DIR": "/tmp/drydock-test"} | extra  # noqa: S108


# SECRET KEY


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="No secret key configured"):
        load_settings(env())


@pytest.mark.parametrize(
    "key",
    [
        "short",
        "not base64 at all!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        base64.urlsafe_b64encode(os.urandom(16)).decode(),
        base64.urlsafe_b64encode(os.urandom(48)).decode(),
    ],
)
def test_malformed_key_is_rejected(key: str) -> None:
    with pytest.raises(ConfigError, match="malformed"):
        load_settings(env(DRYDOCK_SECRET_KEY=key))


def test_low_entropy_key_is_rejected() -> None:
    with pytest.raises(ConfigError, match="not random enough"):
        load_settings(env(DRYDOCK_SECRET_KEY=base64.urlsafe_b64encode(bytes(32)).decode()))


def test_error_message_never_echoes_the_key() -> None:
    bad = "AAAAsecretmaterialthatmustnotleakAAAA"
    with pytest.raises(ConfigError) as info:
        load_settings(env(DRYDOCK_SECRET_KEY=bad))
    assert bad not in str(info.value)


def test_standard_and_urlsafe_alphabets_are_accepted() -> None:
    raw = bytes(range(200, 232))  # contains bytes that encode to + and /
    standard = base64.b64encode(raw).decode()
    assert "+" in standard or "/" in standard
    assert load_settings(env(DRYDOCK_SECRET_KEY=standard)).secret_keys == (raw,)


def test_key_file_with_rotation_list(tmp_path: Path) -> None:
    newest, oldest = new_key(), new_key()
    path = tmp_path / "key"
    path.write_text(f"{newest}\n{oldest}\n")
    keys = load_settings(env(DRYDOCK_SECRET_KEY_FILE=str(path))).secret_keys
    assert keys == (base64.urlsafe_b64decode(newest), base64.urlsafe_b64decode(oldest))


def test_duplicate_keys_are_rejected() -> None:
    key = new_key()
    with pytest.raises(ConfigError, match="listed twice"):
        load_settings(env(DRYDOCK_SECRET_KEY=f"{key},{key}"))


def test_unreadable_key_file_is_rejected(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can read any file")
    path = tmp_path / "key"
    path.write_text(new_key())
    path.chmod(0)
    with pytest.raises(ConfigError, match=r"could not be read.*chown 10001"):
        load_settings(env(DRYDOCK_SECRET_KEY_FILE=str(path)))


def test_missing_key_file_and_directory_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="could not be read"):
        load_settings(env(DRYDOCK_SECRET_KEY_FILE=str(tmp_path / "nope")))
    with pytest.raises(ConfigError):
        load_settings(env(DRYDOCK_SECRET_KEY_FILE=str(tmp_path)))


def test_both_key_sources_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_text(new_key())
    with pytest.raises(ConfigError, match="only one"):
        load_settings(env(DRYDOCK_SECRET_KEY=new_key(), DRYDOCK_SECRET_KEY_FILE=str(path)))


@pytest.mark.parametrize("case", ["missing", "malformed", "unreadable"])
def test_server_exits_non_zero_with_clear_message(tmp_path: Path, case: str) -> None:
    if case == "unreadable" and os.geteuid() == 0:
        pytest.skip("root can read any file")
    child_env = {k: v for k, v in os.environ.items() if not k.startswith("DRYDOCK_")}
    child_env["DRYDOCK_DATA_DIR"] = str(tmp_path / "data")
    expected = {
        "missing": "No secret key configured",
        "malformed": "malformed",
        "unreadable": "could not be read",
    }[case]
    if case == "malformed":
        child_env["DRYDOCK_SECRET_KEY"] = "bad"
    if case == "unreadable":
        key_file = tmp_path / "key"
        key_file.write_text(new_key())
        key_file.chmod(0)
        child_env["DRYDOCK_SECRET_KEY_FILE"] = str(key_file)
    result = subprocess.run(
        [sys.executable, "-m", "uvicorn", "drydock.main:app", "--port", "0"],
        env=child_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode != 0
    assert "configuration error" in result.stderr
    assert expected in result.stderr
    assert not (tmp_path / "data").exists()


# OTHER SETTINGS


@pytest.mark.parametrize(
    ("base_url", "secure"),
    [
        ("http://localhost:8000", True),
        ("http://127.0.0.1:8000", True),
        ("http://[::1]:8000", True),
        ("https://drydock.example.com", True),
        ("https://192.168.1.10", True),
        ("http://192.168.1.10:8000", False),
        ("http://drydock.lan", False),
    ],
)
def test_cookie_secure_follows_base_url(base_url: str, secure: bool) -> None:
    settings = load_settings(env(DRYDOCK_SECRET_KEY=new_key(), DRYDOCK_BASE_URL=base_url))
    assert settings.cookie_secure is secure


@pytest.mark.parametrize(
    "base_url",
    ["ftp://x", "https://user:pw@x", "https://x/sub", "https://x/?q=1", "not a url", "https://"],
)
def test_bad_base_url_is_rejected(base_url: str) -> None:
    with pytest.raises(ConfigError):
        load_settings(env(DRYDOCK_SECRET_KEY=new_key(), DRYDOCK_BASE_URL=base_url))


def test_allowed_hosts_default_and_wildcard() -> None:
    settings = load_settings(
        env(DRYDOCK_SECRET_KEY=new_key(), DRYDOCK_BASE_URL="https://Drydock.Example.com:8443")
    )
    assert settings.base_url == "https://drydock.example.com:8443"
    assert settings.allowed_hosts == ("drydock.example.com", "localhost", "127.0.0.1")
    with pytest.raises(ConfigError, match="must not contain"):
        load_settings(env(DRYDOCK_SECRET_KEY=new_key(), DRYDOCK_ALLOWED_HOSTS="*"))


def test_paths_proxies_and_timezone() -> None:
    settings = load_settings(
        env(
            DRYDOCK_SECRET_KEY=new_key(),
            DRYDOCK_RESTORE_PATHS="/restore-inbox,/mnt/x",
            DRYDOCK_LOCAL_STORAGE_ROOTS="/backups",
            FORWARDED_ALLOW_IPS="10.0.0.1, 172.16.0.0/12",
            TZ="Europe/Berlin",
        )
    )
    assert settings.restore_paths == (Path("/restore-inbox"), Path("/mnt/x"))
    assert settings.staging_dir == Path("/data/staging")
    assert settings.forwarded_allow_ips == ("10.0.0.1", "172.16.0.0/12")
    assert settings.tz == "Europe/Berlin"
    assert settings.run_history_days == 90
    for value, expected in (("30", 30), ("1", 1), ("36500", 36500), ("", 90)):
        days = load_settings(env(DRYDOCK_SECRET_KEY=new_key(), DRYDOCK_RUN_HISTORY_DAYS=value))
        assert days.run_history_days == expected, value
    for bad in (
        {"DRYDOCK_RUN_HISTORY_DAYS": "0"},
        {"DRYDOCK_RUN_HISTORY_DAYS": "-5"},
        {"DRYDOCK_RUN_HISTORY_DAYS": "36501"},
        {"DRYDOCK_RUN_HISTORY_DAYS": "9" * 5000},
        {"DRYDOCK_RUN_HISTORY_DAYS": "²"},
        {"DRYDOCK_RUN_HISTORY_DAYS": "30d"},
        {"TZ": "localtime"},
        {"DRYDOCK_RESTORE_PATHS": "relative/path"},
        {"FORWARDED_ALLOW_IPS": "not-an-ip"},
        {"TZ": "Mars/Olympus"},
        {"DRYDOCK_STAGING_DIR": "staging"},
        # Startup recovery cleans the staging directory: never the data or run directory.
        {"DRYDOCK_STAGING_DIR": "/tmp/drydock-test"},  # noqa: S108
        {"DRYDOCK_STAGING_DIR": "/tmp/drydock-test/staging/.."},  # noqa: S108
        {"DRYDOCK_STAGING_DIR": "/"},
        {"DRYDOCK_STAGING_DIR": "/run"},
        {"DRYDOCK_LOCAL_DOCKER_URL": "ssh://host"},
    ):
        with pytest.raises(ConfigError):
            load_settings(env(DRYDOCK_SECRET_KEY=new_key(), **bad))
