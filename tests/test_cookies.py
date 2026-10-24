import logging

import pytest

from tests.conftest import PASSWORD, form_token, make_settings, running

pytestmark = pytest.mark.anyio


async def setup_cookies(tmp_path, base_url: str) -> tuple[list[str], list[str]]:
    """Returns the Set-Cookie headers of GET /setup and of a successful POST /setup."""
    settings = make_settings(tmp_path / "data", DRYDOCK_BASE_URL=base_url)
    async with running(settings) as browser:
        page = await browser.get("/setup")
        presession = page.headers.get_list("set-cookie")
        name, value = presession[0].split(";")[0].split("=", 1)
        browser.client.cookies.clear()  # httpx will not resend Secure cookies over http
        response = await browser.client.post(
            "/setup",
            data={
                "csrf_token": form_token(page.text),
                "username": "admin",
                "password": PASSWORD,
                "password_confirm": PASSWORD,
            },
            headers={"Cookie": f"{name}={value}", "Origin": settings.base_url},
        )
        assert response.status_code == 303, response.text
        return presession, response.headers.get_list("set-cookie")


def attributes(header: str) -> tuple[str, set[str]]:
    name = header.split("=", 1)[0]
    attrs = {part.strip().lower() for part in header.split(";")[1:]}
    return name, attrs


@pytest.mark.parametrize(
    "base_url", ["http://127.0.0.1:8000", "http://localhost:8000", "https://drydock.example.com"]
)
async def test_secure_host_cookies_for_loopback_and_https(tmp_path, base_url: str, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="drydock")
    presession, after_setup = await setup_cookies(tmp_path, base_url)
    name, attrs = attributes(presession[0])
    assert name == "__Host-drydock_precsrf"
    assert {"secure", "httponly", "path=/", "samesite=strict"} <= attrs
    session = next(h for h in after_setup if "drydock_session=" in h)
    name, attrs = attributes(session)
    assert name == "__Host-drydock_session"
    assert {"secure", "httponly", "path=/", "samesite=lax"} <= attrs
    assert not any(a.startswith("domain") for a in attrs)
    assert "without the Secure flag" not in caplog.text


async def test_plain_http_lan_address_drops_secure_and_warns(tmp_path, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="drydock")
    presession, after_setup = await setup_cookies(tmp_path, "http://192.168.1.10:8000")
    assert "without the Secure flag" in caplog.text
    name, attrs = attributes(presession[0])
    assert name == "drydock_precsrf"
    assert "secure" not in attrs
    session = next(h for h in after_setup if "drydock_session=" in h)
    name, attrs = attributes(session)
    assert name == "drydock_session"
    assert "secure" not in attrs
    assert {"httponly", "path=/", "samesite=lax"} <= attrs
