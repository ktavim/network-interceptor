"""Shared fixtures.

The two in-process aiohttp servers (a config-serving app and an auth-challenge
app) run in daemon threads with their own event loops, so they are ordinary
synchronous, module-scoped fixtures usable from any test module."""

import asyncio
import json
import threading
from urllib.parse import quote

import pytest
from aiohttp import web


# ---------------------------------------------------------------------------
# Config-serving test app (Playwright crawl target)
# ---------------------------------------------------------------------------

INDEX_HTML = """\
<html>
<head>
  <script type="application/json">
    {"strategy_a_url": "https://strategy-a.example.com/api"}
  </script>
</head>
<body>
  <script>
    window.__CONFIG__ = {
      "cdnUrl": "https://strategy-b.example.com/cdn",
      "debug": false
    };
  </script>
  <script>
    fetch("/api/settings.json");
  </script>
  <a href="/deep">Deep page</a>
  <button id="load" type="button"
    onclick="fetch('/api/click-only.json')">Load extra config</button>
  <script>fetch("/protected/config.json").catch(function(){});</script>
</body>
</html>
"""

DEEP_HTML = """\
<html>
<head>
  <script type="application/json">
    {"deep_url": "https://deep-page.example.com/api"}
  </script>
</head>
<body>deep</body>
</html>
"""

CONFIG_JSON = json.dumps({"endpoint": "https://strategy-c.example.com/endpoint"})
SETTINGS_JSON = json.dumps({"dashboard": "https://network.example.com/dashboard"})
CLICK_ONLY_JSON = json.dumps({"click": "https://click-triggered.example.com/api"})

# Simulated lazy chunk (never loaded by the entry page) with a hardcoded URL
CHUNK_ADMIN_JS = (
    'var ADMIN_API="https://chunk-admin.example.com/api";'
    'console.log("admin chunk loaded");'
)
ASSET_MANIFEST_JSON = json.dumps({
    "files": {
        "main.js": "/static/js/main.abc123.js",
        "admin.chunk.js": "/static/js/chunk-admin.js",
    },
    "entrypoints": ["static/js/main.abc123.js"],
})


def _create_app():
    app = web.Application()

    async def handle_index(request):
        return web.Response(text=INDEX_HTML, content_type="text/html")

    async def handle_deep(request):
        return web.Response(text=DEEP_HTML, content_type="text/html")

    async def handle_config_json(request):
        return web.Response(text=CONFIG_JSON, content_type="application/json")

    async def handle_settings_json(request):
        return web.Response(text=SETTINGS_JSON, content_type="application/json")

    async def handle_click_only_json(request):
        return web.Response(text=CLICK_ONLY_JSON, content_type="application/json")

    async def handle_not_json(request):
        return web.Response(text="<html>not json</html>", content_type="text/html")

    async def handle_asset_manifest(request):
        return web.Response(text=ASSET_MANIFEST_JSON, content_type="application/json")

    async def handle_chunk_admin(request):
        return web.Response(text=CHUNK_ADMIN_JS, content_type="application/javascript")

    async def handle_spa_fallback_manifest(request):
        # Simulates an SPA that returns index.html (200) for any unknown path,
        # including manifest probe paths it doesn't actually serve.
        html = (
            '<html><body>'
            '<img src="/assets/img/spa-fallback-image.avif">'
            '</body></html>'
        )
        return web.Response(text=html, content_type="text/html")

    app.router.add_get("/", handle_index)
    app.router.add_get("/deep", handle_deep)
    app.router.add_get("/config.json", handle_config_json)
    app.router.add_get("/api/settings.json", handle_settings_json)
    app.router.add_get("/api/click-only.json", handle_click_only_json)
    app.router.add_get("/not-json", handle_not_json)
    app.router.add_get("/asset-manifest.json", handle_asset_manifest)
    # /manifest.json is in MANIFEST_PATHS; serve SPA fallback HTML here.
    app.router.add_get("/manifest.json", handle_spa_fallback_manifest)
    app.router.add_get("/static/js/chunk-admin.js", handle_chunk_admin)
    return app


def _start_server_in_thread():
    """Start the aiohttp server in a background thread, return (base_url, cleanup_fn)."""
    loop = asyncio.new_event_loop()
    app = _create_app()
    runner = web.AppRunner(app)
    started = threading.Event()
    port_holder = [0]

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port_holder[0] = site._server.sockets[0].getsockname()[1]
        started.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    started.wait(timeout=10)

    base_url = f"http://127.0.0.1:{port_holder[0]}"

    def cleanup():
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)

    return base_url, cleanup


@pytest.fixture(scope="module")
def test_server():
    base_url, cleanup = _start_server_in_thread()
    yield base_url
    cleanup()


# ---------------------------------------------------------------------------
# Auth-challenge test app (probe target)
# ---------------------------------------------------------------------------

AUTH_CONFIG_JSON = json.dumps({
    "endpoint": "https://strategy-c.example.com/endpoint",
    "apiKey": "sk-test-key-12345",
})


def _create_auth_app(gated_root: bool = False):
    """Create test server with auth-aware routes.

    gated_root makes `/` answer a Basic challenge instead of serving the index,
    so a second instance on another port is a *distinguishable* service sharing
    one hostname — what the cross-origin root-probe test needs."""
    app = web.Application()

    async def handle_index(request):
        html = """\
<html>
<head>
  <script type="application/json">
    {"strategy_a_url": "https://strategy-a.example.com/api"}
  </script>
</head>
<body>
  <script>
    window.__CONFIG__ = {
      "cdnUrl": "https://strategy-b.example.com/cdn",
      "debug": false
    };
  </script>
  <script>
    fetch("/api/settings.json");
    fetch("/config.json");
  </script>
</body>
</html>
"""
        return web.Response(text=html, content_type="text/html")

    async def handle_config_json(request):
        return web.Response(text=AUTH_CONFIG_JSON, content_type="application/json")

    async def handle_settings_json(request):
        return web.Response(
            text=json.dumps({"dashboard": "https://network.example.com/dashboard"}),
            content_type="application/json",
        )

    async def handle_basic_auth(request):
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="test"'},
            text="Unauthorized",
        )

    async def handle_bearer_auth(request):
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
            text="Unauthorized",
        )

    async def handle_no_auth(request):
        return web.Response(text='{"ok": true}', content_type="application/json")

    async def handle_forbidden(request):
        return web.Response(status=403, text="Forbidden")

    async def handle_forbidden_bearer(request):
        # RFC 6750 insufficient_scope: valid token, missing scope -> 403 + challenge.
        return web.Response(
            status=403,
            headers={"WWW-Authenticate": 'Bearer error="insufficient_scope", scope="admin"'},
            text="Forbidden",
        )

    async def handle_multi_header_challenge(request):
        # IIS's shape: one challenge per header line, Negotiate first. aiohttp
        # keeps repeats as separate multidict entries, so a .get() would see the
        # Negotiate and never the NTLM behind it.
        resp = web.Response(status=401, text="Unauthorized")
        resp.headers.add("WWW-Authenticate", "Negotiate")
        resp.headers.add("WWW-Authenticate", "NTLM")
        resp.headers.add("WWW-Authenticate", 'Basic realm="corp"')
        return resp

    async def handle_inline_challenge_list(request):
        # The same offer folded into one comma-separated value.
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": "Negotiate, NTLM"},
            text="Unauthorized",
        )

    async def handle_bad_request(request):
        return web.Response(status=400, text="Bad Request")

    async def handle_not_found(request):
        return web.Response(status=404, text="Not Found")

    async def handle_redirect(request):
        return web.Response(status=301, headers={"Location": "/somewhere-else"})

    async def handle_redirect_to_login(request):
        return web.Response(status=302, headers={"Location": "/oauth/authorize?client_id=abc"})

    async def handle_redirect_to_idp(request):
        return web.Response(status=302, headers={
            "Location": "https://login.microsoftonline.com/authorize?client_id=abc"
        })

    async def handle_redirect_to(request):
        # 302 to whatever absolute URL the caller named, so one server can send
        # the prober to the other (a distinct origin on the same host) and a
        # test can build a chain by nesting `?to=` (quote it with safe="").
        to = request.query.get("to")
        if not to:
            return web.Response(status=400, text="missing ?to=")
        return web.Response(status=302, headers={"Location": to})

    async def handle_bounce(request):
        # A redirect loop across two origins: each server bounces to the peer's
        # /auth/bounce naming itself, so A?to=B -> B?to=A -> A?to=B, string-
        # identical to the seed. redirect-to alone can't express a loop (A's
        # Location would have to contain B's, which contains A's, and so on).
        to = request.query.get("to")
        if not to:
            return web.Response(status=400, text="missing ?to=")
        own_origin = f"{request.scheme}://{request.host}"
        return web.Response(status=302, headers={
            "Location": f"{to}/auth/bounce?to={quote(own_origin, safe='')}"
        })

    async def handle_server_error(request):
        return web.Response(status=500, text="Internal Server Error")

    async def handle_bad_request_subpath(request):
        return web.Response(status=400, text="Bad Request — missing required params")

    async def handle_api_root(request):
        """Root of the /api-gated service returns 401 with Bearer."""
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
            text="Unauthorized",
        )

    async def handle_gated_root(request):
        return web.Response(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="gated"'},
            text="Unauthorized",
        )

    # add_get registers HEAD too (allow_head defaults True), which is what the
    # root probe issues.
    app.router.add_get("/", handle_gated_root if gated_root else handle_index)
    app.router.add_get("/config.json", handle_config_json)
    app.router.add_get("/api/settings.json", handle_settings_json)
    app.router.add_get("/auth/basic", handle_basic_auth)
    app.router.add_get("/auth/bearer", handle_bearer_auth)
    app.router.add_get("/auth/none", handle_no_auth)
    app.router.add_get("/auth/forbidden", handle_forbidden)
    app.router.add_get("/auth/forbidden-bearer", handle_forbidden_bearer)
    app.router.add_get("/auth/multi-header", handle_multi_header_challenge)
    app.router.add_get("/auth/multi-inline", handle_inline_challenge_list)
    app.router.add_get("/auth/bad-request", handle_bad_request)
    app.router.add_get("/auth/not-found", handle_not_found)
    app.router.add_get("/auth/redirect", handle_redirect)
    app.router.add_get("/auth/redirect-login", handle_redirect_to_login)
    app.router.add_get("/auth/redirect-idp", handle_redirect_to_idp)
    app.router.add_get("/auth/redirect-to", handle_redirect_to)
    app.router.add_get("/auth/bounce", handle_bounce)
    app.router.add_get("/auth/server-error", handle_server_error)
    app.router.add_get("/api-gated/v1/data", handle_bad_request_subpath)
    app.router.add_get("/api-gated/", handle_api_root)
    # GET only: aiohttp answers a HEAD here with 405, so the probe sees the
    # challenge only by falling back to GET.
    app.router.add_get("/auth/get-only", handle_basic_auth, allow_head=False)
    # Also handle HEAD requests
    app.router.add_route("HEAD", "/auth/basic", handle_basic_auth)
    app.router.add_route("HEAD", "/auth/bearer", handle_bearer_auth)
    app.router.add_route("HEAD", "/auth/none", handle_no_auth)
    app.router.add_route("HEAD", "/auth/forbidden", handle_forbidden)
    app.router.add_route("HEAD", "/auth/forbidden-bearer", handle_forbidden_bearer)
    app.router.add_route("HEAD", "/auth/multi-header", handle_multi_header_challenge)
    app.router.add_route("HEAD", "/auth/multi-inline", handle_inline_challenge_list)
    app.router.add_route("HEAD", "/auth/bad-request", handle_bad_request)
    app.router.add_route("HEAD", "/auth/not-found", handle_not_found)
    app.router.add_route("HEAD", "/auth/redirect", handle_redirect)
    app.router.add_route("HEAD", "/auth/redirect-login", handle_redirect_to_login)
    app.router.add_route("HEAD", "/auth/redirect-idp", handle_redirect_to_idp)
    app.router.add_route("HEAD", "/auth/redirect-to", handle_redirect_to)
    app.router.add_route("HEAD", "/auth/bounce", handle_bounce)
    app.router.add_route("HEAD", "/auth/server-error", handle_server_error)
    app.router.add_route("HEAD", "/api-gated/v1/data", handle_bad_request_subpath)
    app.router.add_route("HEAD", "/api-gated/", handle_api_root)
    return app


def _start_auth_server(gated_root: bool = False):
    loop = asyncio.new_event_loop()
    app = _create_auth_app(gated_root=gated_root)
    runner = web.AppRunner(app)
    started = threading.Event()
    port_holder = [0]

    def run():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, "127.0.0.1", 0)
        loop.run_until_complete(site.start())
        port_holder[0] = site._server.sockets[0].getsockname()[1]
        started.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    started.wait(timeout=10)

    base_url = f"http://127.0.0.1:{port_holder[0]}"

    def cleanup():
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)

    return base_url, cleanup


@pytest.fixture(scope="module")
def auth_server():
    base_url, cleanup = _start_auth_server()
    yield base_url
    cleanup()


@pytest.fixture(scope="module")
def gated_auth_server():
    """A second server on another port — same hostname as `auth_server`, so the
    two are distinct origins on one box — whose root answers a Basic challenge."""
    base_url, cleanup = _start_auth_server(gated_root=True)
    yield base_url
    cleanup()
