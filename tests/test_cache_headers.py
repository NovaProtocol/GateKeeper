"""Cache-Control precedence, and the safety net that makes it safe.

The middleware in ``shared.middleware`` promises that a response which sets its
own ``Cache-Control`` keeps it. It used to break that promise whenever the
deployment ran in debug, and the gateway sat in front of every project, so a
deliberately cacheable asset was pinned to ``no-store`` deployment-wide.

Keeping an upstream header is only correct because the gate keeps a
shared-cacheable value off the paths it decided. These tests cover both halves:

* the middleware's precedence, in debug and in production, including the
  control-plane paths that are always ``private, no-store``;
* :func:`enforce_private_cache_control`, which is what the gateway calls on a
  response it produced or on one whose request it decided;
* through the real gateway app, that an ungated pass-through keeps a ``public``
  header (the NovaProtocol badge case) while a gated one loses it.
"""

from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from starlette.responses import Response

from shared.middleware import (
    CacheControlMiddleware,
    _cache_control_for,
    enforce_private_cache_control,
)
from tests.test_gateway_failclosed import (
    HOST,
    gateway_module,
    install_cache,
    make_group,
    make_route,
)

UPSTREAM_CACHE = "public, max-age=300"


def build_app(
    is_debug: bool, headers: dict[str, str] | None = None, path: str = "/thing"
) -> FastAPI:
    """A minimal app whose one route answers with the headers under test."""

    app = FastAPI()

    @app.get(path)
    async def _route() -> PlainTextResponse:
        return PlainTextResponse("ok", headers=dict(headers or {}))

    app.add_middleware(CacheControlMiddleware, is_debug=is_debug)  # type: ignore[arg-type]
    return app


# --------------------------------------------------------------------------- #
# The middleware, on its own
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("is_debug", [True, False])
def test_a_route_that_sets_its_own_policy_keeps_it(is_debug: bool) -> None:
    """The precedence fix, and the reason this whole change exists."""
    with TestClient(build_app(is_debug, {"Cache-Control": UPSTREAM_CACHE})) as client:
        response = client.get("/thing")

    assert response.headers["Cache-Control"] == UPSTREAM_CACHE


@pytest.mark.parametrize("is_debug", [True, False])
def test_a_route_that_sets_nothing_is_a_no_store_in_debug_only(is_debug: bool) -> None:
    with TestClient(build_app(is_debug)) as client:
        response = client.get("/thing")

    expected = "no-store" if is_debug else _cache_control_for("/thing")
    assert response.headers["Cache-Control"] == expected


@pytest.mark.parametrize("is_debug", [True, False])
@pytest.mark.parametrize("path", ["/api/codes", "/manage", "/manage/rules", "/login", "/logout"])
def test_control_plane_paths_are_always_private_no_store(is_debug: bool, path: str) -> None:
    """A cached verdict would be served to the wrong visitor."""
    with TestClient(build_app(is_debug, {"Cache-Control": UPSTREAM_CACHE}, path=path)) as client:
        response = client.get(path)

    assert response.headers["Cache-Control"] == "private, no-store"


@pytest.mark.parametrize("is_debug", [True, False])
def test_control_plane_paths_fill_a_gap_too(is_debug: bool) -> None:
    with TestClient(build_app(is_debug, path="/manage/login")) as client:
        response = client.get("/manage/login")

    assert response.headers["Cache-Control"] == "private, no-store"


def test_an_ungated_static_path_keeps_the_public_lifespan_in_production() -> None:
    with TestClient(build_app(False, path="/static/app.css")) as client:
        response = client.get("/static/app.css")

    assert response.headers["Cache-Control"] == "public, max-age=86400"


# --------------------------------------------------------------------------- #
# enforce_private_cache_control
# --------------------------------------------------------------------------- #


def response_with(value: str | None) -> Response:
    resp = Response(status_code=200)
    if value is not None:
        resp.headers["Cache-Control"] = value
    return resp


@pytest.mark.parametrize(
    "value",
    ["public, max-age=300", "public, max-age=31536000, immutable", "max-age=300", "no-cache"],
)
def test_a_shared_cacheable_value_is_replaced(value: str) -> None:
    resp = response_with(value)

    enforce_private_cache_control(resp)

    assert resp.headers["Cache-Control"] == "private, no-store"


@pytest.mark.parametrize("value", ["private, max-age=60", "private, no-store", "no-store"])
def test_a_visitor_scoped_value_is_left_alone(value: str) -> None:
    resp = response_with(value)

    enforce_private_cache_control(resp)

    assert resp.headers["Cache-Control"] == value


def test_a_missing_header_becomes_private_no_store() -> None:
    resp = response_with(None)

    enforce_private_cache_control(resp)

    assert resp.headers["Cache-Control"] == "private, no-store"


# --------------------------------------------------------------------------- #
# Through the gateway app
# --------------------------------------------------------------------------- #


class _PublishingUpstream(BaseHTTPRequestHandler):
    """An upstream that deliberately publishes its bytes."""

    protocol_version = "HTTP/1.1"
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        body = b"<svg/>"
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Cache-Control", UPSTREAM_CACHE)
        self.send_header("ETag", '"deadbeef"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


class _LargePublishingUpstream(_PublishingUpstream):
    """The same upstream, big enough to take the gateway's streaming branch.

    The proxy buffers a response under 2 MB and streams anything at or above
    it, and the demotion is applied on both paths. Handled by the same helper
    but written twice, so a test has to cover each one or one of them can be
    deleted without anything going red.
    """

    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        body = b"<svg>" + b"x" * (2 * 1024 * 1024) + b"</svg>"
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml")
        self.send_header("Cache-Control", UPSTREAM_CACHE)
        self.send_header("ETag", '"large"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def publishing_upstream() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PublishingUpstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _PublishingUpstream.hits.clear()
    yield ("127.0.0.1", server.server_address[1])
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module")
def large_publishing_upstream() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LargePublishingUpstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _LargePublishingUpstream.hits.clear()
    yield ("127.0.0.1", server.server_address[1])
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _isolate_gateway_state() -> Any:
    """The gateway's caches are module-scoped state; save and restore them."""
    module = gateway_module()
    saved = (
        module._CacheGroups,
        module._CacheRoutes,
        module._CachePages,
        module._CacheTs,
        dict(module._SettingCache),
    )
    yield
    module._CacheGroups, module._CacheRoutes, module._CachePages, module._CacheTs = (
        saved[0],
        saved[1],
        saved[2],
        saved[3],
    )
    module._SettingCache.clear()
    module._SettingCache.update(saved[4])


def _unique_ip() -> str:
    _unique_ip.counter += 1  # type: ignore[attr-defined]
    return f"10.11.{_unique_ip.counter // 250}.{_unique_ip.counter % 250 + 1}"


_unique_ip.counter = 0  # type: ignore[attr-defined]


def _get(client: Any, host: str, path: str) -> Any:
    return client.get(
        path,
        headers={"X-Forwarded-Host": host, "CF-Connecting-IP": _unique_ip()},
        follow_redirects=False,
    )


def test_an_ungated_path_keeps_the_upstream_public_header(
    gateway_client: Any, publishing_upstream: Any
) -> None:
    """The NovaProtocol badge case: `action == "none"` must not demote.

    A rule the owner configured to gate nothing means the bytes are meant to be
    published. Tightening this would break every embedded badge.
    """
    install_cache(
        [make_group(1, "github", HOST, [("/public/*", "none"), ("/*", "none")])],
        [make_route(HOST, *publishing_upstream)],
    )

    response = _get(gateway_client, HOST, "/public/name.svg")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == UPSTREAM_CACHE
    assert response.headers["ETag"] == '"deadbeef"'


def test_a_gated_path_loses_the_upstream_public_header(
    gateway_client: Any, publishing_upstream: Any
) -> None:
    """The gate decided this request, so the bytes are one visitor's."""
    gateway_module()
    _PublishingUpstream.hits.clear()
    password = "correct-horse"
    from shared.security import hash_custom_password

    digest, salt = hash_custom_password(password)
    group = make_group(1, "github", HOST, [("/private/*", "custom_password"), ("/*", "none")])
    rule = group.rules[0]
    rule.custom_password_hash = digest
    rule.custom_password_salt = salt
    install_cache([group], [make_route(HOST, *publishing_upstream)])

    response = _get(gateway_client, HOST, f"/private/thing.svg?custom_password={password}")

    assert response.status_code == 200, response.text
    assert _PublishingUpstream.hits, "the gate never dialled the upstream"
    assert response.headers["Cache-Control"] == "private, no-store"


def test_a_gated_path_loses_the_header_on_the_streaming_branch_too(
    gateway_client: Any, large_publishing_upstream: Any
) -> None:
    """The buffered and streamed responses are separate call sites.

    A response of 2 MB or more skips the buffered branch entirely, so the
    demotion has to be asserted on that path as well. Deleting either call site
    must turn a test red.
    """
    _LargePublishingUpstream.hits.clear()
    password = "correct-horse"
    from shared.security import hash_custom_password

    digest, salt = hash_custom_password(password)
    group = make_group(1, "github", HOST, [("/private/*", "custom_password"), ("/*", "none")])
    rule = group.rules[0]
    rule.custom_password_hash = digest
    rule.custom_password_salt = salt
    install_cache([group], [make_route(HOST, *large_publishing_upstream)])

    response = _get(gateway_client, HOST, f"/private/big.svg?custom_password={password}")

    assert response.status_code == 200, response.text
    assert _LargePublishingUpstream.hits, "the gate never dialled the upstream"
    assert len(response.content) > 2 * 1024 * 1024, (
        "this took the buffered branch, so it proves nothing"
    )
    assert response.headers["Cache-Control"] == "private, no-store"


def test_the_ungated_path_keeps_the_header_on_the_streaming_branch_too(
    gateway_client: Any, large_publishing_upstream: Any
) -> None:
    """The other half of the same branch: `none` must still not demote."""
    install_cache(
        [make_group(1, "github", HOST, [("/public/*", "none"), ("/*", "none")])],
        [make_route(HOST, *large_publishing_upstream)],
    )

    response = _get(gateway_client, HOST, "/public/big.svg")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == UPSTREAM_CACHE


def test_unauthenticated_redirect_is_never_public(
    gateway_client: Any, publishing_upstream: Any
) -> None:
    install_cache(
        [make_group(1, "github", HOST, [("/private/*", "access_code"), ("/*", "none")])],
        [make_route(HOST, *publishing_upstream)],
    )

    response = _get(gateway_client, HOST, "/private/thing.svg")

    assert response.status_code == 302
    assert "public" not in response.headers.get("Cache-Control", "")


def test_error_page_is_private_no_store(gateway_client: Any, publishing_upstream: Any) -> None:
    """A 404 the gate produced, for a host that is ungated but unrouted."""
    install_cache([make_group(1, "github", HOST, [("/*", "none")])], [])

    response = _get(gateway_client, HOST, "/anything")

    assert response.status_code == 404
    assert response.headers["Cache-Control"] == "private, no-store"


def test_a_denied_request_is_private_no_store(
    gateway_client: Any, publishing_upstream: Any
) -> None:
    """A 403 the gate wrote itself, so a shared cache must not keep it."""
    install_cache(
        [make_group(1, "github", HOST, [("/private/*", "deny"), ("/*", "none")])],
        [make_route(HOST, *publishing_upstream)],
    )

    response = _get(gateway_client, HOST, "/private/thing")

    assert response.status_code == 403
    assert response.headers["Cache-Control"] == "private, no-store"


def test_the_maintenance_503_is_private_no_store(
    gateway_client: Any, publishing_upstream: Any
) -> None:
    """A stored outage page would outlive the outage.

    `_maintenance_response` returns before any rule is consulted, and its HTML
    and JSON shapes are separate return paths, so each is asserted here.
    """
    module = gateway_module()
    install_cache([make_group(1, "github", HOST, [("/*", "none")])], [])
    now = time.monotonic()
    module._SettingCache["maintenance_mode"] = (now, "true")
    module._SettingCache["maintenance_message"] = (now, "back soon")

    html = gateway_client.get(
        "/",
        headers={"X-Forwarded-Host": HOST, "CF-Connecting-IP": _unique_ip()},
        follow_redirects=False,
    )
    as_json = gateway_client.get(
        "/",
        headers={
            "X-Forwarded-Host": HOST,
            "CF-Connecting-IP": _unique_ip(),
            "Accept": "application/json",
        },
        follow_redirects=False,
    )

    assert html.status_code == 503, html.text
    assert as_json.status_code == 503, as_json.text
    assert html.headers["Cache-Control"] == "private, no-store"
    assert as_json.headers["Cache-Control"] == "private, no-store"


def test_a_rate_limited_request_is_private_no_store(
    gateway_client: Any, publishing_upstream: Any, monkeypatch: Any
) -> None:
    """The 429 the access-code limiter writes is a per-visitor verdict.

    The limiter lives in the api service and is reached over HTTP, so the
    verdict is stubbed directly rather than driven by repeated requests.
    """
    module = gateway_module()
    install_cache(
        [make_group(1, "github", HOST, [("/private/*", "access_code"), ("/*", "none")])],
        [make_route(HOST, *publishing_upstream)],
    )

    async def _limited(_ip: str) -> tuple[bool, int, int]:
        return True, 6, 5

    monkeypatch.setattr(module, "_check_access_code_rate_limited", _limited)

    response = _get(gateway_client, HOST, "/private/thing?access_code=wrong")

    assert response.status_code == 429, response.text
    assert response.headers["Cache-Control"] == "private, no-store"


def test_the_login_page_is_not_public_cacheable(gateway_client: Any) -> None:
    """The control-plane prefix, through the real app rather than a built one."""
    response = gateway_client.get("/login", follow_redirects=False)

    assert "public" not in response.headers.get("Cache-Control", "")


def test_health_is_published_in_production() -> None:
    """`/health` is not a verdict, so a monitor may cache it."""
    with TestClient(build_app(False, path="/health")) as client:
        response = client.get("/health")

    assert response.headers["Cache-Control"] == "public, max-age=3600"


def test_the_docs_copy_fills_a_gap_but_keeps_a_page_own_header() -> None:
    """The documentation service is the authority for `/documentation/*`."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "documentation"))
    try:
        import cache as docs_cache

        app = FastAPI()

        @app.get("/")
        async def _index() -> PlainTextResponse:
            return PlainTextResponse("docs", headers={"Cache-Control": UPSTREAM_CACHE})

        @app.get("/plain")
        async def _plain() -> PlainTextResponse:
            return PlainTextResponse("docs")

        app.add_middleware(docs_cache.CacheControlMiddleware, is_debug=True)  # type: ignore[arg-type]

        with TestClient(app) as client:
            assert client.get("/").headers["Cache-Control"] == UPSTREAM_CACHE
            assert client.get("/plain").headers["Cache-Control"] == "no-store"
    finally:
        sys.path.pop(0)


def test_the_gateway_module_exposes_the_helper() -> None:
    """A guard against the import silently disappearing."""
    module = gateway_module()
    assert module.enforce_private_cache_control is enforce_private_cache_control
    assert time.monotonic() > 0
