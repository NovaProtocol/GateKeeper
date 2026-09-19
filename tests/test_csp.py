"""The security headers, and the path a browser actually takes to receive them.

Two services set ``Content-Security-Policy`` on this stack and both serve HTML,
but only one header value can survive a proxied response: the gateway writes its
own headers over the upstream's. A second copy of the policy in the gateway was
therefore not a backup of the management service's copy, it was a replacement for
it, and the two had already drifted by the time the audit map shipped. The map's
tile host was in the policy the management service sent and absent from the policy
the browser received, so every tile was refused with nothing on the page to say
so.

The tests below are written against the two paths that matter:

* what **each service sends on its own response**, asserted equal to the one
  shared definition, so neither can hold a private copy again;
* what a browser **receives through the gateway**, which is the assertion whose
  absence let a broken map ship. It is driven end to end: a real request into the
  gateway, through its proxy path, into the management app over ASGI, and back out
  with the header the browser would see.
"""

from __future__ import annotations

import sys
import time
from typing import Any

import httpx
import pytest

import management.app as management_app
from shared.csp import CONTENT_SECURITY_POLICY, SECURITY_HEADERS
from shared.jwt import create_manage_token
from tests.conftest import BASE

CSRF = "test-csrf-token"
SESSION = create_manage_token()

#: The host the gateway resolves to the management service on this stack.
MANAGE_HOST = "gatekeeper.projectnova.download"
MANAGE_PATH = "/manage/audit"
API_HOST = "api:8002"

#: Two countries, so the audit page renders its map script and not the fallback.
GEO_POINTS = [
    {
        "cc": "PH",
        "name": "Philippines",
        "count": 6,
        "lat": 13.0,
        "lon": 122.0,
        "share": 0.6,
        "radius": 21.3,
    }
]


def gateway_module() -> Any:
    """The ``auth-gateway`` app module, loaded by ``tests/conftest.py``."""
    module = sys.modules.get("auth_gateway.app")
    assert module is not None, "conftest did not load auth_gateway.app"
    return module


def directives(csp: str) -> dict[str, str]:
    """A policy string as ``{directive: value}``."""
    return {
        part.strip().split(" ", 1)[0]: part.strip().split(" ", 1)[1]
        for part in csp.split(";")
        if " " in part.strip()
    }


class _StubResponse:
    """Just enough of ``httpx.Response`` for the two callers that read one."""

    def __init__(
        self, status_code: int = 200, payload: Any = None, headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = ""
        self.content = b""

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _ApiStub:
    """The management service's view of the API, which is unreachable in tests."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get(self, url: str, **kwargs: Any) -> _StubResponse:
        self.calls.append(url)
        if url.endswith("/api/logs/geo"):
            return _StubResponse(200, GEO_POINTS)
        if url.endswith("/api/logs"):
            return _StubResponse(200, [], headers={"X-Total-Count": "12"})
        return _StubResponse(200, [])

    async def post(self, url: str, **kwargs: Any) -> _StubResponse:
        self.calls.append(url)
        return _StubResponse(200, {})


class _RoutedClient:
    """The gateway's outbound client, split by destination.

    Calls to the API are answered from stubs, because that service is not part of
    this test. Everything else is the real management application, reached over
    ASGI without a socket, which is what makes the proxied header assertion an
    end to end one rather than a unit test of the middleware.
    """

    def __init__(self, upstream: httpx.AsyncClient) -> None:
        self._upstream = upstream
        self.hits: list[str] = []

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.hits.append(url)
        if API_HOST in url:
            return _StubResponse(200, {})
        return await self._upstream.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> Any:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Any:
        return await self.request("POST", url, **kwargs)


@pytest.fixture(scope="module")
def manage_upstream() -> Any:
    """The management app behind an ASGI transport, as the gateway dials it."""
    transport = httpx.ASGITransport(app=management_app.app)
    return httpx.AsyncClient(transport=transport, follow_redirects=False)


@pytest.fixture()
def gateway_route(monkeypatch: pytest.MonkeyPatch, manage_upstream: Any) -> _RoutedClient:
    """Point the gateway's proxy path at the management app, and ring-fence state.

    The rule and settings caches are module-scoped state on the gateway, so they
    are saved and restored: without this the injected route leaks into every later
    module that drives the same app.
    """
    module = gateway_module()
    saved = (
        module._CacheGroups,
        module._CacheRoutes,
        module._CachePages,
        module._CacheTs,
        dict(module._SettingCache),
    )
    from shared.models import Route, Rule, RuleGroup

    group = RuleGroup(name="gatekeeper", domain=MANAGE_HOST, display_order=0)
    group.id = 90
    rule = Rule(group_id=90, path="/*", action="none", display_order=0)
    rule.id = 900
    group.rules.append(rule)
    route = Route(
        host=MANAGE_HOST, path="/", route_type="proxy", upstream="gatekeeper_management", port=8003
    )
    route.id = 90

    routed = _RoutedClient(manage_upstream)
    module._CacheGroups = [group]
    module._CacheRoutes = [route]
    module._CachePages = []
    module._CacheTs = time.monotonic()
    module._SettingCache.clear()
    # Geo capture reads a setting; seeding it keeps the request off the network.
    module._SettingCache["geo_lookup_enabled"] = (time.monotonic(), "false")
    monkeypatch.setattr(module, "_get_httpx", lambda: routed)
    monkeypatch.setattr(management_app, "_get_httpx", lambda: _ApiStub())

    yield routed

    module._CacheGroups, module._CacheRoutes, module._CachePages, module._CacheTs = (
        saved[0],
        saved[1],
        saved[2],
        saved[3],
    )
    module._SettingCache.clear()
    module._SettingCache.update(saved[4])


def through_gateway(gateway_client: Any, path: str, session: str | None = SESSION) -> Any:
    """One request down the production path: gateway -> proxy -> management.

    A session is presented by default, because ``/manage/*`` carries the
    management service's own login in addition to the gateway's gate: without one
    the gateway proxies the request faithfully, the upstream answers 302 to its
    login page, and the body under assertion is empty. The redirect case is a
    real case and is asserted on its own further down.
    """
    headers = {"X-Forwarded-Host": MANAGE_HOST, "CF-Connecting-IP": "10.1.2.3"}
    if session:
        headers["Cookie"] = f"manage_session={session}"
    return gateway_client.get(path, headers=headers, follow_redirects=False)


# --------------------------------------------------------------------------- #
# The shared definition
# --------------------------------------------------------------------------- #


def test_the_policy_allows_the_tile_host_that_the_map_needs() -> None:
    img_src = directives(CONTENT_SECURITY_POLICY)["img-src"]

    assert "https://tile.openstreetmap.org" in img_src
    assert "https://*.tile.openstreetmap.org" in img_src
    # Leaflet resolves its own marker images relative to the script URL.
    assert "https://cdn.jsdelivr.net" in img_src


def test_the_tile_host_is_allowed_only_where_tiles_are_loaded() -> None:
    """Tiles arrive as `<img>`, so no other directive needs the host."""
    parsed = directives(CONTENT_SECURITY_POLICY)

    for directive in ("script-src", "style-src", "connect-src", "font-src", "default-src"):
        assert "tile.openstreetmap.org" not in parsed[directive]


def test_the_policy_still_carries_every_host_the_two_services_load() -> None:
    """The union, so one service's needs cannot be dropped for the other's."""
    parsed = directives(CONTENT_SECURITY_POLICY)

    for host in (
        "https://cdn.jsdelivr.net",
        "https://stackpath.bootstrapcdn.com",
        "https://cdnjs.cloudflare.com",
        "https://static.cloudflareinsights.com",
    ):
        assert host in parsed["script-src"], host
    for host in ("https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"):
        assert host in parsed["style-src"], host
    assert parsed["font-src"] == "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com"
    assert parsed["frame-src"] == (
        "'self' https://*.projectnova.download https://portfolio.projectnova.download"
    )
    # Both frame directives name the same frames, so neither can drift alone.
    assert parsed["frame-ancestors"] == (
        "'self' https://portfolio.projectnova.download https://*.projectnova.download"
    )


def test_the_two_other_headers_travel_with_the_policy() -> None:
    assert SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"
    assert SECURITY_HEADERS["Referrer-Policy"] == "strict-origin-when-cross-origin"


# --------------------------------------------------------------------------- #
# Each service, on its own response
# --------------------------------------------------------------------------- #


def test_the_management_service_sends_the_shared_policy(manage_client: Any) -> None:
    response = manage_client.get("/manage/login")

    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_the_gateway_sends_the_shared_policy_on_its_own_response(gateway_client: Any) -> None:
    response = gateway_client.get("/health")

    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_the_two_services_send_byte_identical_policies(
    manage_client: Any, gateway_client: Any
) -> None:
    """The assertion that was missing: equal because shared, not because copied."""
    from_management = manage_client.get("/manage/login").headers["content-security-policy"]
    from_gateway = gateway_client.get("/health").headers["content-security-policy"]

    assert from_management == from_gateway == CONTENT_SECURITY_POLICY


@pytest.mark.parametrize("relative", ["auth-gateway/app.py", "management/app.py"])
def test_no_service_keeps_a_private_copy_of_the_policy(relative: str) -> None:
    """A pasted-back policy string is the defect this fix removes.

    Both services apply :data:`shared.csp.SECURITY_HEADERS`; neither names a
    header value of its own. If a future edit reintroduces a literal here, the two
    copies can drift again -- silently, because only the gateway's reaches a
    browser -- and this test fails at that moment rather than after a deploy.
    """
    source = (BASE / relative).read_text()

    assert "Content-Security-Policy" not in source
    assert "img-src" not in source
    assert "default-src" not in source


# --------------------------------------------------------------------------- #
# Through the gateway, which is the path a browser takes
# --------------------------------------------------------------------------- #


def test_a_proxied_page_carries_the_shared_policy(
    gateway_client: Any, gateway_route: _RoutedClient
) -> None:
    """The regression: the gateway serves this page and used to overwrite the policy."""
    response = through_gateway(gateway_client, MANAGE_PATH)

    assert response.status_code == 200
    assert gateway_route.hits, "the request never reached the upstream"
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert "manage/audit" not in response.headers.get("location", "")


def test_the_proxied_map_page_and_its_policy_agree(
    gateway_client: Any, gateway_route: _RoutedClient
) -> None:
    """The page asks for the tile host, and the delivered policy allows it.

    Both halves are read from the response the gateway returned, so this cannot
    pass while the browser is being told something else.
    """
    response = through_gateway(gateway_client, MANAGE_PATH)

    assert "https://tile.openstreetmap.org/{z}/{x}/{y}.png" in response.text
    received = directives(response.headers["content-security-policy"])
    assert "https://tile.openstreetmap.org" in received["img-src"]
    assert "https://*.tile.openstreetmap.org" in received["img-src"]


def test_a_gated_page_reaches_the_browser_with_the_shared_policy(
    gateway_client: Any, gateway_route: _RoutedClient
) -> None:
    """A session changes the status, not the headers.

    ``/manage/audit`` carries two gates in production: the gateway's rule and the
    management service's own ``manage_session``. Presenting the session is what
    turns the proxied answer from the upstream's 302 into the page, and the policy
    is applied by middleware on the way out in both cases.
    """
    authed = through_gateway(gateway_client, MANAGE_PATH, session=SESSION)

    assert authed.status_code == 200
    assert authed.headers["content-security-policy"] == CONTENT_SECURITY_POLICY


def test_a_redirect_through_the_gateway_still_carries_the_shared_policy(
    gateway_client: Any, gateway_route: _RoutedClient
) -> None:
    """A 302 is not a hole in the policy.

    The upstream's own login redirect is returned to the browser through the
    gateway like any other response, so it must carry the same header. This is the
    case the two failing assertions were accidentally exercising: the assertion
    belongs on the header here, not on a body that a redirect never has.
    """
    response = through_gateway(gateway_client, MANAGE_PATH, session=None)

    assert response.status_code == 302
    assert response.headers["location"].startswith("/manage/login")
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"


def test_the_proxy_does_not_drop_the_other_security_headers(
    gateway_client: Any, gateway_route: _RoutedClient
) -> None:
    response = through_gateway(gateway_client, MANAGE_PATH)

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
