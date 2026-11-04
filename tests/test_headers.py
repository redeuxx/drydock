import re
from pathlib import Path

import pytest

import drydock
from tests.conftest import Browser, add_user, make_settings, running

pytestmark = pytest.mark.anyio

TEMPLATES = Path(drydock.__file__).parent / "templates"


def csp_directives(header: str) -> dict[str, str]:
    return {d.split()[0]: d.strip() for d in header.split(";") if d.strip()}


async def test_csp_and_security_headers_everywhere(admin: Browser) -> None:
    responses = [
        await admin.get("/"),
        await admin.get("/users"),
        await admin.get("/healthz"),
        await admin.get("/nope"),
        await admin.client.get("/", headers={"Host": "attacker.example"}),
    ]
    for response in responses:
        csp = response.headers["content-security-policy"]
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert "unsafe-" not in csp
        directives = csp_directives(csp)
        assert re.fullmatch(r"script-src 'nonce-[A-Za-z0-9_-]{24}'", directives["script-src"])
        assert directives["default-src"] == "default-src 'self'"
        assert directives["style-src"] == "style-src 'self'"
        assert directives["object-src"] == "object-src 'none'"
        assert directives["frame-ancestors"] == "frame-ancestors 'none'"
        assert directives["base-uri"] == "base-uri 'none'"
        assert directives["form-action"] == "form-action 'self'"
        assert directives["require-trusted-types-for"] == "require-trusted-types-for 'script'"
        assert directives["trusted-types"] == "trusted-types htmx"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "same-origin"
        assert response.headers["cache-control"] == "no-store"


async def test_oversized_bodies_are_rejected(admin: Browser) -> None:
    response = await admin.post("/reauth", {"password": "x" * 70_000})
    assert response.status_code == 413

    async def chunks():
        for _ in range(20):
            yield b"a" * 8192

    response = await admin.client.post(
        "/login", content=chunks(), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 413


def template_sources() -> list[tuple[str, str]]:
    return [(str(p.relative_to(TEMPLATES)), p.read_text()) for p in TEMPLATES.rglob("*.html")]


def test_templates_have_no_external_urls() -> None:
    url = re.compile(r"""(?:src|href|action)\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:|//)""", re.I)
    for name, text in template_sources():
        assert not url.search(text), name


def test_templates_have_no_inline_script_or_style() -> None:
    patterns = [
        re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I),
        re.compile(r"<style", re.I),
        re.compile(r"\sstyle\s*=", re.I),
        re.compile(r"\son[a-z]+\s*=", re.I),
        re.compile(r"hx-on", re.I),
        re.compile(r"javascript:", re.I),
        re.compile(r"\|\s*safe\b"),
    ]
    for name, text in template_sources():
        for pattern in patterns:
            assert not pattern.search(text), f"{name}: {pattern.pattern}"


async def test_csp_nonce_is_fresh_and_matches_the_page(admin: Browser) -> None:
    pages = [await admin.get("/"), await admin.get("/")]
    nonces = []
    for response in pages:
        nonce = re.search(r"'nonce-([^']+)'", response.headers["content-security-policy"])
        assert nonce
        nonces.append(nonce.group(1))
        scripts = re.findall(r"<script[^>]*>", response.text)
        assert len(scripts) == 4
        assert all(f'nonce="{nonce.group(1)}"' in tag for tag in scripts)
        assert f'hx-nonce="{nonce.group(1)}"' in response.text  # the logout form
    assert nonces[0] != nonces[1]


async def test_base_template_wires_htmx(admin: Browser) -> None:
    body = (await admin.get("/")).text
    token = await admin.csrf_token()
    assert f"""hx-headers:inherited='{{"X-CSRF-Token": "{token}"}}'""" in body
    assert 'hx-target:inherited="#main" hx-select:inherited="#main"' in body
    assert '<main id="main"' in body
    config = """content='{"extensions": "hx-csp", "includeIndicatorCSS": false}'"""
    assert f'<meta name="htmx-config" {config}>' in body
    assert 'src="/static/vendor/htmx/htmx.min.js" defer></script>' in body
    assert 'src="/static/vendor/htmx/ext/hx-csp.min.js" defer></script>' in body
    assert 'src="/static/js/app.js" defer></script>' in body


def test_templates_load_only_the_bundled_assets() -> None:
    allowed_scripts = {
        "/static/vendor/htmx/htmx.min.js",
        "/static/vendor/htmx/ext/hx-csp.min.js",
        "/static/js/app.js",
        "/static/js/upload.js",
    }
    for name, text in template_sources():
        links = re.findall(r"<link\b[^>]*>", text)
        bundled = ('href="/static/css/app.css"', 'rel="icon" href="/static/logo.svg"')
        assert all(any(href in tag for href in bundled) for tag in links), name
        for tag in re.findall(r"<script\b[^>]*>", text):
            src = re.search(r'src="([^"]+)"', tag)
            assert src and src.group(1) in allowed_scripts, f"{name}: {tag}"
            assert 'nonce="{{ csp_nonce }}"' in tag, f"{name}: {tag}"
    base = (TEMPLATES / "base.html").read_text()
    assert base.count('<link rel="stylesheet" href="/static/css/app.css">') == 1


def test_every_htmx_element_carries_the_page_nonce() -> None:
    """hx-csp strips every hx- attribute (inherited ones included) from an element whose
    hx-nonce does not match the page nonce, so each element with one needs the nonce."""
    htmx_attr = re.compile(r"\shx-(?!nonce\b)[a-z-]+(?::[a-z]+)*\s*=", re.I)
    checked = 0
    for name, text in template_sources():
        for tag in re.findall(r"<[a-z][^>]*>", text, re.I | re.S):
            if htmx_attr.search(tag):
                checked += 1
                assert 'hx-nonce="{{ csp_nonce }}"' in tag, f"{name}: {tag}"
    assert checked >= 8  # body, logout and the htmx forms


async def test_static_assets_must_be_revalidated(admin: Browser) -> None:
    response = await admin.get("/static/.gitkeep")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    assert "etag" in response.headers


@pytest.mark.parametrize(
    ("base_url", "hsts"),
    [
        ("https://drydock.test", True),
        ("https://localhost:8443", False),
        ("http://localhost:8000", False),
        ("http://192.168.1.10:8000", False),
    ],
)
async def test_hsts_only_for_public_https(tmp_path, base_url: str, hsts: bool) -> None:
    settings = make_settings(tmp_path / "data", DRYDOCK_BASE_URL=base_url)
    async with running(settings) as browser:
        for path in ("/healthz", "/setup", "/static/.gitkeep"):
            response = await browser.get(path)
            header = response.headers.get("strict-transport-security")
            assert header == ("max-age=31536000" if hsts else None), path


async def test_error_pages_keep_the_logged_in_header(admin: Browser) -> None:
    await add_user(admin, "vic", "viewer")
    await admin.login("vic")
    for path, status in (("/audit", 403), ("/users/999", 403)):
        response = await admin.get(path)
        assert response.status_code == status
        header = response.text.split("</header>")[0]
        assert "Log out" in header and "vic" in header.split('id="user-menu"')[1], path
    await admin.login("admin")
    response = await admin.get("/users/999")
    assert response.status_code == 404
    header = response.text.split("</header>")[0]
    assert "Log out" in header and "admin" in header.split('id="user-menu"')[1]
    admin.client.cookies.clear()
    response = await admin.get("/nope")
    assert response.status_code == 404
    assert "Log out" not in response.text


def test_times_show_in_drydocks_zone_with_utc_beside_them() -> None:
    from datetime import UTC, datetime

    from drydock import templating

    moment = datetime(2026, 11, 1, 16, 30, 18, tzinfo=UTC)
    try:
        templating.set_zone("America/Chicago")
        assert templating.stamp(moment) == "2026-11-01 10:30:18 CST (16:30 UTC)"
        assert templating.stamp(moment.replace(tzinfo=None), seconds=False) == (
            "2026-11-01 10:30 CST (16:30 UTC)"
        )
        # Run log lines: each stamp at the start of a line, nothing else.
        log = "2026-11-01 16:30:18 Started at 2026-11-01 16:30:18.\n2026-11-01 16:31:00 Done.\n"
        assert templating.logtimes(log) == (
            "2026-11-01 10:30:18 CST Started at 2026-11-01 16:30:18.\n"
            "2026-11-01 10:31:00 CST Done.\n"
        )
        templating.set_zone("UTC")
        assert templating.stamp(moment) == "2026-11-01 16:30:18 UTC"
    finally:
        templating.set_zone("UTC")
