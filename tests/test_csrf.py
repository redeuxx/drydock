import pytest

from tests.conftest import PASSWORD, Browser, form_token

pytestmark = pytest.mark.anyio

CROSS_SITE_HEADERS = [
    {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Origin": "https://drydock.test.evil.example"},
    {"Origin": "http://drydock.test"},  # scheme downgrade
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
]


async def presession_form(browser: Browser, path: str) -> dict[str, str]:
    token = form_token((await browser.get(path)).text)
    if path == "/setup":
        return {
            "csrf_token": token,
            "username": "admin",
            "password": PASSWORD,
            "password_confirm": PASSWORD,
        }
    return {"csrf_token": token, "username": "admin", "password": PASSWORD}


async def assert_presession_guards(browser: Browser, path: str) -> None:
    good = await presession_form(browser, path)
    for headers in CROSS_SITE_HEADERS:
        response = await browser.client.post(path, data=good, headers=headers)
        assert response.status_code == 403, (path, headers)
    missing = {k: v for k, v in good.items() if k != "csrf_token"}
    response = await browser.client.post(path, data=missing, headers=browser.origin_headers)
    assert response.status_code == 403
    wrong = good | {"csrf_token": "0" * 64}
    response = await browser.client.post(path, data=wrong, headers=browser.origin_headers)
    assert response.status_code == 403
    # A token is only valid with the cookie it was issued for.
    browser.client.cookies.clear()
    await browser.get(path)
    response = await browser.client.post(path, data=good, headers=browser.origin_headers)
    assert response.status_code == 403
    # A missing cookie fails too, even with a token that was once valid.
    browser.client.cookies.clear()
    response = await browser.client.post(path, data=good, headers=browser.origin_headers)
    assert response.status_code == 403


async def test_setup_presession_csrf(fresh: Browser) -> None:
    await assert_presession_guards(fresh, "/setup")
    assert fresh.sql("SELECT COUNT(*) FROM users") == [(0,)]


async def test_login_presession_csrf(admin: Browser) -> None:
    admin.client.cookies.clear()
    await assert_presession_guards(admin, "/login")
    # Nothing above counted as a failed login or produced a session.
    assert admin.sql("SELECT COUNT(*) FROM audit_events WHERE action='auth.login'") == [(0,)]
    good = await presession_form(admin, "/login")
    response = await admin.client.post("/login", data=good, headers=admin.origin_headers)
    assert response.status_code == 303


async def test_same_origin_without_fetch_metadata_is_allowed(fresh: Browser) -> None:
    data = await presession_form(fresh, "/setup")
    response = await fresh.client.post("/setup", data=data)
    assert response.status_code == 303


@pytest.mark.parametrize("path", ["/setup", "/login", "/healthz", "/", "/static/x.js", "/users"])
async def test_foreign_host_header_gets_400(fresh: Browser, path: str) -> None:
    response = await fresh.client.get(path, headers={"Host": "attacker.example"})
    assert response.status_code == 400
    response = await fresh.client.post(path, headers={"Host": "attacker.example"})
    assert response.status_code == 400


async def test_post_login_csrf_header_and_field(admin: Browser) -> None:
    token = await admin.csrf_token()
    response = await admin.client.post(
        "/users/1/sessions/revoke", headers={"X-CSRF-Token": token, "HX-Request": "true"}
    )
    # htmx requests get HX-Redirect instead of a 303 the browser would follow silently.
    assert response.status_code == 204
    assert response.headers["hx-redirect"] == "/users/1"
    await admin.login("admin")
    response = await admin.post("/users/1/sessions/revoke", {"csrf_token": "nope"})
    assert response.status_code == 403
    response = await admin.post("/users/1/sessions/revoke", csrf=False)
    assert response.status_code == 403
