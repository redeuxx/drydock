"""Jinja2 rendering and redirects. Autoescape is always on; StrictUndefined catches typos."""

from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, PackageLoader, StrictUndefined
from starlette.responses import HTMLResponse, RedirectResponse, Response

from drydock.security.rbac import Role

# Only hx-csp may register; an empty value would allow any extension. Indicator CSS ships
# in app.css instead of being injected as a constructed stylesheet.
HTMX_CONFIG = {"extensions": "hx-csp", "includeIndicatorCSS": False}

env = Environment(
    loader=PackageLoader("drydock", "templates"),
    autoescape=True,
    undefined=StrictUndefined,
)


def filesize(value: int | None) -> str:
    if value is None:
        return ""
    if value < 1024:
        return f"{value} bytes"
    size = value / 1024
    for unit in ("KiB", "MiB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


env.globals.update(Role=Role, htmx_config=HTMX_CONFIG)
env.filters["filesize"] = filesize
templates = Jinja2Templates(env=env)


def render(request: Request, name: str, status_code: int = 200, **context: Any) -> HTMLResponse:
    context.setdefault("auth", None)
    context["csp_nonce"] = request.state.csp_nonce
    return templates.TemplateResponse(request, name, context, status_code=status_code)


def is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def see_other(request: Request, url: str) -> Response:
    """Redirects after a successful POST. url must be a server-chosen local path.

    htmx requests get HX-Redirect instead of a 303: fetch would follow a 303 silently and
    swap the next page into #main, while HX-Redirect makes the browser navigate to it.
    """
    if is_htmx(request):
        return Response(status_code=204, headers={"HX-Redirect": url})
    return RedirectResponse(url, status_code=303)
