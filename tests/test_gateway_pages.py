"""Serving contract for a custom page.

A page is served from inside the gate's ``action == "none"`` branch and nowhere
else, which is what makes this feature unable to open a gate that was closed.
The cases below pin that claim by request rather than by reading:

* the bytes are the stored bytes, with the stored content type, on two hosts;
* a non-``GET`` request is not a page request and follows the gate;
* a page whose governing rule is ``access_code`` is **not** served — the visitor
  is redirected to login, exactly as before this feature existed;
* ``deny`` still denies;
* an inactive page falls through;
* the control plane wins even when a pattern is broad enough to swallow it;
* one audit row, marked ``custom_page``, is written.

The gateway loads its caches over HTTP from ``api:8002``, which is unreachable
here, so they are injected directly — the same technique
``test_gateway_failclosed.py`` uses for ``_CacheGroups``. They are module-scoped
state, hence the autouse fixture that saves and restores all three.
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest

from shared.models import CustomPage, Route, Rule, RuleGroup
from shared.security import apex_domain
from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

HOST = "portfolio.projectnova.download"
OTHER_HOST = "github.projectnova.download"
MANAGE_HOST = "gatekeeper.projectnova.download"
APEX = "projectnova.download"

BODY = "User-agent: *\nDisallow: /private\n"
PATTERN = f"*.{APEX}/robots.txt"


def login_prefix(host: str) -> str:
    return f"https://gatekeeper.{apex_domain(host)}/login?redirect="


def make_page(
    pattern: str = PATTERN,
    body: str = BODY,
    order: int = 0,
    active: bool = True,
    pid: int = 1,
    content_type: str = "text/plain; charset=utf-8",
) -> CustomPage:
    page = CustomPage(
        pattern=pattern, body=body, content_type=content_type, active=active, display_order=order
    )
    page.id = pid
    return page


def make_group(
    gid: int, name: str, domain: str, rules: list[tuple[str, str]], order: int = 0
) -> RuleGroup:
    group = RuleGroup(name=name, domain=domain, display_order=order, is_default=False)
    group.id = gid
    for index, (path, action) in enumerate(rules):
        rule = Rule(group_id=gid, path=path, action=action, display_order=index)
        rule.id = gid * 100 + index
        group.rules.append(rule)
    return group


def make_route(host: str, upstream: str, port: int, rid: int = 1) -> Route:
    route = Route(host=host, path="/", route_type="proxy", upstream=upstream, port=port)
    route.id = rid
    return route


def install_cache(
    groups: list[RuleGroup],
    routes: list[Route] | None = None,
    pages: list[CustomPage] | None = None,
) -> None:
    module = gateway_module()
    module._CacheGroups = groups
    module._CacheRoutes = routes or []
    module._CachePages = pages or []
    module._CacheTs = time.monotonic()


def gateway_module() -> Any:
    import sys

    module = sys.modules.get("auth_gateway.app")
    assert module is not None, "conftest did not load auth_gateway.app"
    return module


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "11")
        self.end_headers()
        self.wfile.write(b"upstream-ok")

    def _reply(self) -> None:
        """The same reply for any method, so "was this dialled" is observable."""
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "11")
        self.end_headers()
        self.wfile.write(b"upstream-ok")

    do_POST = _reply
    do_HEAD = _reply

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def upstream() -> Any:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield ("127.0.0.1", server.server_address[1])
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _isolate_gateway_state(upstream: Any) -> Any:
    """Save and restore the gateway's module-scoped caches around every test.

    ``_httpx_client`` is reset as well: it is closed by whichever module-scoped
    client fixture ran first, so a retained handle from an earlier module would
    fail the proxying assertions below for a reason that has nothing to do with
    the code under test.
    """
    module = gateway_module()
    saved = (
        module._CacheGroups,
        module._CacheRoutes,
        module._CachePages,
        module._CacheTs,
        dict(module._SettingCache),
    )
    _UpstreamHandler.hits.clear()
    module._httpx_client = None
    yield
    module._CacheGroups, module._CacheRoutes, module._CachePages, module._CacheTs = (
        saved[0],
        saved[1],
        saved[2],
        saved[3],
    )
    module._SettingCache.clear()
    module._SettingCache.update(saved[4])
    module._httpx_client = None
    _UpstreamHandler.hits.clear()


_ip_counter = 0


def _unique_ip() -> str:
    """A fresh visitor address per request, so the per-IP limiter never trips."""
    global _ip_counter
    _ip_counter += 1
    return f"10.11.{_ip_counter // 250}.{_ip_counter % 250 + 1}"


def get(client: Any, host: str, path: str, method: str = "GET") -> Any:
    """A cookie-less request down the wildcard path."""
    return client.request(
        method,
        path,
        headers={"X-Forwarded-Host": host, "CF-Connecting-IP": _unique_ip()},
        follow_redirects=False,
    )


# --------------------------------------------------------------------------- #
# The page is served
# --------------------------------------------------------------------------- #


def test_a_cookie_less_request_gets_the_bytes(gateway_client: Any, upstream: Any) -> None:
    """No cookie, no access code, no session: the page answers anyway."""
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt", "none"), ("/*", "access_code")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.status_code == 200
    assert response.content == BODY.encode("utf-8")
    assert _UpstreamHandler.hits == [], "a page must not be proxied"


def test_the_stored_bytes_are_served_byte_for_byte(gateway_client: Any, upstream: Any) -> None:
    """No escaping, no sanitising, no sniffing — the owner's bytes."""
    html = '<p>gone</p><script>window.location="/";</script>'
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page(body=html, content_type="text/html; charset=utf-8")],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.content == html.encode("utf-8")
    assert response.headers["content-type"] == "text/html; charset=utf-8"


def test_the_same_pattern_serves_two_hosts(gateway_client: Any, upstream: Any) -> None:
    """A host-glob pattern is one row; each host resolves its own group."""
    install_cache(
        [
            make_group(1, "portfolio", HOST, [("/*", "none")]),
            make_group(2, "github", OTHER_HOST, [("/*", "none")], order=1),
        ],
        [make_route(HOST, *upstream), make_route(OTHER_HOST, *upstream, rid=2)],
        [make_page()],
    )

    first = get(gateway_client, HOST, "/robots.txt")
    second = get(gateway_client, OTHER_HOST, "/robots.txt")

    assert first.status_code == 200 and first.content == BODY.encode("utf-8")
    assert second.status_code == 200 and second.content == BODY.encode("utf-8")
    assert _UpstreamHandler.hits == []


def test_a_bare_text_type_gains_a_charset(gateway_client: Any, upstream: Any) -> None:
    """Starlette appends the charset, which the stored value wins over."""
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page(content_type="text/plain")],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.headers["content-type"] == "text/plain; charset=utf-8"


def test_a_head_request_is_served_without_a_body(gateway_client: Any, upstream: Any) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/robots.txt", method="HEAD")

    assert response.status_code == 200
    assert response.content == b""


# --------------------------------------------------------------------------- #
# What is not served
# --------------------------------------------------------------------------- #


def test_a_post_is_not_a_page_request(gateway_client: Any, upstream: Any) -> None:
    """It falls through to ordinary routing instead of being answered."""
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page(pattern=f"{HOST}/robots.txt")],
    )

    response = get(gateway_client, HOST, "/robots.txt", method="POST")

    assert response.content != BODY.encode("utf-8")
    assert _UpstreamHandler.hits == ["/robots.txt"], "the request should have been proxied"


def test_a_page_governed_by_access_code_is_not_served(gateway_client: Any, upstream: Any) -> None:
    """The load-bearing assertion: a closed gate stays closed."""
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt", "access_code"), ("/*", "access_code")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.status_code == 302
    assert response.headers["Location"].startswith(login_prefix(HOST))
    assert response.content != BODY.encode("utf-8")


def test_a_page_governed_by_deny_is_not_served(gateway_client: Any, upstream: Any) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt", "deny"), ("/*", "deny")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.status_code == 403
    assert response.content != BODY.encode("utf-8")


def test_a_page_governed_by_custom_password_is_not_served(
    gateway_client: Any, upstream: Any
) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt", "custom_password"), ("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.status_code == 302
    assert response.content != BODY.encode("utf-8")


def test_an_inactive_page_falls_through_to_the_gate(gateway_client: Any, upstream: Any) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt", "none"), ("/*", "access_code")])],
        [make_route(HOST, *upstream)],
        [make_page(active=False)],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.status_code == 200
    assert response.content != BODY.encode("utf-8")


def test_a_path_the_pattern_does_not_cover_is_not_served(
    gateway_client: Any, upstream: Any
) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt.bak", "none"), ("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/robots.txt.bak")

    assert response.content != BODY.encode("utf-8")


def test_another_path_does_not_match_a_robots_pattern(gateway_client: Any, upstream: Any) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    response = get(gateway_client, HOST, "/stranger.txt")

    assert response.content != BODY.encode("utf-8")


# --------------------------------------------------------------------------- #
# The control plane is a higher tier
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "/login",
        "/logout",
        "/",
        "/manage",
        "/manage/pages",
        "/static/css/manage.css",
        "/static/js/manage.js",
    ],
)
def test_the_control_plane_is_never_shadowed(gateway_client: Any, upstream: Any, path: str) -> None:
    """A pattern broad enough to swallow the panel must not reach these.

    `/static/*` is on the list because the panel's own stylesheet is served by
    the same wildcard proxy the login page is: a pattern could otherwise answer
    the login *and* the CSS it loads, leaving the operator with an unstyled
    panel, which is a lockout by another route.
    """
    install_cache(
        [make_group(1, "gatekeeper", MANAGE_HOST, [("/*", "none")])],
        [make_route(MANAGE_HOST, *upstream)],
        [make_page(pattern=f"{MANAGE_HOST}/*", body="SHADOWED")],
    )

    response = get(gateway_client, MANAGE_HOST, path)

    assert response.content != b"SHADOWED"


def test_the_same_host_still_serves_a_page_off_the_control_plane(
    gateway_client: Any, upstream: Any
) -> None:
    """The predicate is narrow: only the paths that are how the operator gets in."""
    install_cache(
        [make_group(1, "gatekeeper", MANAGE_HOST, [("/*", "none")])],
        [make_route(MANAGE_HOST, *upstream)],
        [make_page(pattern=f"{MANAGE_HOST}/robots.txt")],
    )

    response = get(gateway_client, MANAGE_HOST, "/robots.txt")

    assert response.status_code == 200
    assert response.content == BODY.encode("utf-8")


def test_the_predicate_itself() -> None:
    module = gateway_module()

    assert module._is_control_plane(MANAGE_HOST, "/login", APEX)
    assert module._is_control_plane(MANAGE_HOST, "/", APEX)
    assert module._is_control_plane("gatekeeper", "/manage/pages", APEX)
    assert module._is_control_plane(APEX, "/login", APEX)
    # The panel's own assets, which the wildcard proxy also serves.
    assert module._is_control_plane(MANAGE_HOST, "/static/css/manage.css", APEX)
    assert module._is_control_plane(APEX, "/static/css/manage.css", APEX)
    # Off the control plane, even on a manage host.
    assert not module._is_control_plane(MANAGE_HOST, "/robots.txt", APEX)
    # A different host entirely.
    assert not module._is_control_plane(HOST, "/login", APEX)
    # `/static/*` is only reserved on the gatekeeper hosts: the same path on a
    # project host belongs to that project.
    assert not module._is_control_plane(HOST, "/static/css/site.css", APEX)


# --------------------------------------------------------------------------- #
# Precedence and the audit row
# --------------------------------------------------------------------------- #


def test_the_first_page_in_order_wins(gateway_client: Any, upstream: Any) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
        [
            make_page(pattern=f"*.{APEX}/*", body="broad", order=1, pid=2),
            make_page(pattern=PATTERN, body="specific", order=0, pid=1),
        ],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.content == b"specific"


def test_one_audit_row_marks_the_page(gateway_client: Any, upstream: Any, monkeypatch: Any) -> None:
    """`action`/`matched_action` are the greppable marker a page was served."""
    module = gateway_module()
    rows: list[dict[str, Any]] = []

    async def _capture(**kw: Any) -> None:
        rows.append(kw)

    monkeypatch.setattr(module, "_audit_log_async", _capture)
    install_cache(
        [make_group(5, "portfolio", HOST, [("/robots.txt", "none"), ("/*", "access_code")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    get(gateway_client, HOST, "/robots.txt")

    served = [r for r in rows if r.get("action") == "custom_page"]
    assert len(served) == 1, rows
    assert served[0]["matched_action"] == "custom_page"
    assert served[0]["status_code"] == 200
    assert served[0]["host"] == HOST
    assert served[0]["path"] == "/robots.txt"
    # The rule that allowed the page, because that is the interesting fact.
    assert served[0]["rule_group_id"] == 5
    assert served[0]["rule_id"] == 500


def test_a_request_the_gate_refuses_writes_no_page_row(
    gateway_client: Any, upstream: Any, monkeypatch: Any
) -> None:
    module = gateway_module()
    rows: list[dict[str, Any]] = []

    async def _capture(**kw: Any) -> None:
        rows.append(kw)

    monkeypatch.setattr(module, "_audit_log_async", _capture)
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "access_code")])],
        [make_route(HOST, *upstream)],
        [make_page()],
    )

    get(gateway_client, HOST, "/robots.txt")

    assert not [r for r in rows if r.get("action") == "custom_page"], rows


def test_an_unreadable_page_list_serves_nothing(gateway_client: Any, upstream: Any) -> None:
    """The cache falling back to empty can only ever mean "no page matched"."""
    install_cache(
        [make_group(1, "portfolio", HOST, [("/robots.txt", "none"), ("/*", "access_code")])],
        [make_route(HOST, *upstream)],
        [],
    )

    response = get(gateway_client, HOST, "/robots.txt")

    assert response.content != BODY.encode("utf-8")
