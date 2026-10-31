"""Response security headers and request hardening middleware (pure ASGI)."""

import secrets

from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# Scripts need the per-response nonce: htmx's hx-csp extension reads it from the page's
# script tags and strips htmx attributes from any element whose hx-nonce does not match,
# so injected markup cannot issue htmx requests that inherit the CSRF header.
# Trusted Types limit DOM HTML sinks to htmx's own "htmx" policy.
CSP_TEMPLATE = (
    "default-src 'self'; script-src 'nonce-{nonce}'; style-src 'self'; object-src 'none'; "
    "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; "
    "require-trusted-types-for 'script'; trusted-types htmx"
)
# "same-origin", not "no-referrer": with no-referrer, browsers send "Origin: null"
# on form posts, which the CSRF Origin check would reject.
BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
# Sent only when DRYDOCK_BASE_URL is HTTPS on a non-loopback host. Pinning localhost to
# HTTPS would break the SSH tunnel and every other local service on that port.
HSTS = "max-age=31536000"
MAX_BODY_BYTES = 64 * 1024
UPLOAD_PATH = "/restore/uploads"


def is_upload(scope: Scope) -> bool:
    if scope["method"] != "PUT" or scope["path"] != UPLOAD_PATH:
        return False
    # The first one, as Starlette (and so the CSRF check's form parsing) reads it.
    content_type = next((v for k, v in scope["headers"] if k == b"content-type"), b"")
    return content_type.partition(b";")[0].strip().lower() == b"application/octet-stream"


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        static = scope["path"].startswith("/static/")
        # Templates read it as request.state.csp_nonce.
        nonce = secrets.token_urlsafe(18)
        scope.setdefault("state", {})["csp_nonce"] = nonce
        csp = CSP_TEMPLATE.format(nonce=nonce)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("Content-Security-Policy", csp)
                for name, value in BASE_HEADERS.items():
                    headers.setdefault(name, value)
                if self.hsts:
                    headers.setdefault("Strict-Transport-Security", HSTS)
                # Asset URLs are not versioned, so browsers must revalidate (cheap: ETag)
                # or they keep a stale stylesheet or script after an image upgrade.
                headers.setdefault("Cache-Control", "no-cache" if static else "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware:
    """Rejects request bodies over MAX_BODY_BYTES, declared or streamed.

    The one exemption is an application/octet-stream PUT to the upload route, which sets
    limits of its own (restore.uploads). Only that type: the CSRF check parses a form body.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or is_upload(scope):
            await self.app(scope, receive, send)
            return
        for name, value in scope["headers"]:
            if name == b"content-length" and (not value.isdigit() or int(value) > MAX_BODY_BYTES):
                await PlainTextResponse("Request body too large", 413)(scope, receive, send)
                return
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > MAX_BODY_BYTES:
                    raise HTTPException(status_code=413, detail="Request body too large")
            return message

        await self.app(scope, limited_receive, send)
