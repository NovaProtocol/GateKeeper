"""Fail-closed contract for the gateway's rule dispatch.

Two paths decide whether a request may be proxied: Caddy's ``forward_auth`` call
and the wildcard proxy path. Before this suite existed they disagreed, because
the proxy path proxied a request it had never authenticated whenever no rule
matched (``if rule is None: pass``) while ``forward_auth`` redirected it.

The cases below are the ones that prove the disagreement is gone:

* a group matches the host but no rule matches its path -> refused, never dialled;
* no group matches the host -> the ``unmatched_action`` setting decides, and the
  setting cannot re-open the case above;
* a ``/*`` catch-all still behaves exactly as before.

The gateway loads its rule cache over HTTP from ``api:8002``, which is
unreachable here (``API_HTTP_ADDR=http://api.invalid:8002``), so the cache is
injected directly. It is module-scoped state, hence the autouse fixture that
saves and restores it -- without that it leaks into every later test module.
"""

from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest

from shared.gate import (
    DEFAULT_UNMATCHED_ACTION,
    UNMATCHED_ACTIONS,
    find_group_rule,
    normalize_unmatched_action,
    resolve_rule_action,
)
from shared.models import Route, Rule, RuleGroup
from shared.security import apex_domain
from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

HOST = "portfolio.projectnova.download"
OTHER_HOST = "unmatched.example.com"


def login_prefix(host: str) -> str:
    """The login the gateway redirects to, which is apex-derived, not fixed."""
    return f"https://gatekeeper.{apex_domain(host)}/login?redirect="


_ip_counter = 0


def _unique_ip() -> str:
    """A fresh visitor address per request, so the per-IP limiter never trips."""
    global _ip_counter
    _ip_counter += 1
    return f"10.9.{_ip_counter // 250}.{_ip_counter % 250 + 1}"


def gateway_module() -> Any:
    """The ``auth-gateway`` app module, loaded by ``tests/conftest.py``."""
    module = sys.modules.get("auth_gateway.app")
    assert module is not None, "conftest did not load auth_gateway.app"
    return module


def make_group(
    gid: int,
    name: str,
    domain: str,
    rules: list[tuple[str, str]],
    order: int = 0,
    is_default: bool = False,
) -> RuleGroup:
    group = RuleGroup(name=name, domain=domain, display_order=order, is_default=is_default)
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


def install_cache(groups: list[RuleGroup], routes: list[Route] | None = None) -> None:
    module = gateway_module()
    module._CacheGroups = groups
    module._CacheRoutes = routes or []
    module._CacheTs = time.monotonic()


def install_action(value: str) -> None:
    """Pre-seed the settings cache, so no HTTP call is needed to read it."""
    gateway_module()._SettingCache["unmatched_action"] = (time.monotonic(), value)


def forget_settings() -> None:
    gateway_module()._SettingCache.clear()


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits: ClassVar[list[str]] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        body = b"upstream-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def upstream() -> Any:
    """A real upstream that answers 200, so "was this dialled" is observable."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _UpstreamHandler.hits.clear()
    yield ("127.0.0.1", server.server_address[1])
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _isolate_gateway_state(upstream: Any) -> Any:
    module = gateway_module()
    saved = (module._CacheGroups, module._CacheRoutes, module._CacheTs, dict(module._SettingCache))
    _UpstreamHandler.hits.clear()
    yield
    module._CacheGroups, module._CacheRoutes, module._CacheTs = saved[0], saved[1], saved[2]
    module._SettingCache.clear()
    module._SettingCache.update(saved[3])


def forward_auth(client: Any, host: str, path: str) -> Any:
    return client.get(
        "/api/authz/forward-auth",
        headers={
            "X-Forwarded-Host": host,
            "X-Forwarded-Uri": path,
            "CF-Connecting-IP": _unique_ip(),
        },
        follow_redirects=False,
    )


def proxy(client: Any, host: str, path: str) -> Any:
    return client.get(
        path,
        headers={"X-Forwarded-Host": host, "CF-Connecting-IP": _unique_ip()},
        follow_redirects=False,
    )


# --------------------------------------------------------------------------- #
# shared.gate: the decision, without an app
# --------------------------------------------------------------------------- #


def test_find_group_rule_reports_a_group_with_no_matching_rule() -> None:
    """`(None, None)` must no longer mean two different things."""
    group = make_group(1, "portfolio", HOST, [("/documentation/*", "access_code")])

    matched_group, matched_rule = find_group_rule(HOST, "/private/app", [group])

    assert matched_group is group
    assert matched_rule is None


def test_find_group_rule_reports_no_group_for_an_unknown_host() -> None:
    group = make_group(1, "portfolio", HOST, [("/*", "access_code")])

    assert find_group_rule(OTHER_HOST, "/anything", [group]) == (None, None)


def test_find_group_rule_takes_the_first_matching_rule_in_order() -> None:
    group = make_group(1, "portfolio", HOST, [("/a/*", "none"), ("/*", "deny")])

    _, rule = find_group_rule(HOST, "/a/b", [group])

    assert rule is not None
    assert rule.path == "/a/*"


@pytest.mark.parametrize("unmatched_action", UNMATCHED_ACTIONS)
def test_group_without_a_matching_rule_is_always_refused(unmatched_action: str) -> None:
    """The invariant a setting must not be able to re-open."""
    group = make_group(1, "portfolio", HOST, [("/documentation/*", "access_code")])

    assert resolve_rule_action(group, None, unmatched_action) == "access_code"


@pytest.mark.parametrize("unmatched_action", UNMATCHED_ACTIONS)
def test_no_group_follows_the_setting(unmatched_action: str) -> None:
    assert resolve_rule_action(None, None, unmatched_action) == unmatched_action


@pytest.mark.parametrize("action", ["access_code", "none", "custom_password", "deny"])
@pytest.mark.parametrize("unmatched_action", UNMATCHED_ACTIONS)
def test_a_matching_rule_decides_itself(action: str, unmatched_action: str) -> None:
    group = make_group(1, "portfolio", HOST, [("/private/*", action)])
    rule = group.rules[0]

    assert resolve_rule_action(group, rule, unmatched_action) == action


def test_an_unknown_rule_action_is_read_as_gating() -> None:
    group = make_group(1, "portfolio", HOST, [("/private/*", "allow")])

    assert resolve_rule_action(group, group.rules[0], "none") == "access_code"


@pytest.mark.parametrize("bad", ["", "  ", "ALLOW", "open", "yes", None, "access-code"])
def test_unknown_unmatched_action_setting_falls_back_to_gating(bad: Any) -> None:
    assert normalize_unmatched_action(bad) == DEFAULT_UNMATCHED_ACTION


# --------------------------------------------------------------------------- #
# auth-gateway: both gate paths
# --------------------------------------------------------------------------- #


def test_proxy_path_refuses_when_the_group_has_no_matching_rule(
    gateway_client: Any, upstream: Any
) -> None:
    """The regression itself: this used to proxy the request unauthenticated."""
    modules = gateway_module()
    modules._SettingCache.clear()
    install_cache(
        [make_group(1, "portfolio", HOST, [("/documentation/*", "access_code")])],
        [make_route(HOST, *upstream)],
    )

    response = proxy(gateway_client, HOST, "/private/app")

    assert response.status_code == 302
    assert response.headers["Location"].startswith(login_prefix(HOST))
    assert _UpstreamHandler.hits == [], "an unauthenticated request reached the upstream"


def test_proxy_path_refuses_even_when_the_setting_is_permissive(
    gateway_client: Any, upstream: Any
) -> None:
    install_action("none")
    install_cache(
        [make_group(1, "portfolio", HOST, [("/documentation/*", "access_code")])],
        [make_route(HOST, *upstream)],
    )

    response = proxy(gateway_client, HOST, "/private/app")

    assert response.status_code == 302
    assert _UpstreamHandler.hits == []


def test_forward_auth_refuses_when_the_group_has_no_matching_rule(
    gateway_client: Any, upstream: Any
) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/documentation/*", "access_code")])],
        [make_route(HOST, *upstream)],
    )

    response = forward_auth(gateway_client, HOST, "/private/app")

    assert response.status_code == 302
    assert response.headers["Location"].startswith(login_prefix(HOST))


def test_proxy_path_with_no_group_follows_the_default_action(
    gateway_client: Any, upstream: Any
) -> None:
    forget_settings()
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "access_code")])],
        [make_route(OTHER_HOST, *upstream)],
    )

    response = proxy(gateway_client, OTHER_HOST, "/public/app")

    assert response.status_code == 302
    assert response.headers["Location"].startswith(login_prefix(OTHER_HOST))
    assert _UpstreamHandler.hits == []


def test_proxy_path_with_no_group_denies_when_configured(
    gateway_client: Any, upstream: Any
) -> None:
    install_action("deny")
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "access_code")])],
        [make_route(OTHER_HOST, *upstream)],
    )

    response = proxy(gateway_client, OTHER_HOST, "/public/app")

    assert response.status_code == 403
    assert _UpstreamHandler.hits == []


def test_proxy_path_with_no_group_serves_when_configured(
    gateway_client: Any, upstream: Any
) -> None:
    """`none` reproduces the old behaviour, now deliberately and by name."""
    install_action("none")
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "access_code")])],
        [make_route(OTHER_HOST, *upstream)],
    )

    response = proxy(gateway_client, OTHER_HOST, "/public/app")

    assert response.status_code == 200
    assert response.text == "upstream-ok"
    assert _UpstreamHandler.hits == ["/public/app"]


def test_catch_all_rule_still_passes_and_gates_as_before(
    gateway_client: Any, upstream: Any
) -> None:
    """The ordinary case must not regress."""
    install_action("deny")
    install_cache(
        [
            make_group(1, "public-project", HOST, [("/*", "none")]),
            make_group(2, "gated-project", "gated.example.com", [("/*", "access_code")]),
        ],
        [make_route(HOST, *upstream)],
    )

    open_rule = forward_auth(gateway_client, HOST, "/anything/at/all")
    assert open_rule.status_code == 200

    gated = forward_auth(gateway_client, "gated.example.com", "/anything/at/all")
    assert gated.status_code == 302
    assert gated.headers["Location"].startswith(login_prefix("gated.example.com"))


def test_deny_rule_still_denies(gateway_client: Any, upstream: Any) -> None:
    install_cache(
        [make_group(1, "portfolio", HOST, [("/*", "deny")])],
        [make_route(HOST, *upstream)],
    )

    assert forward_auth(gateway_client, HOST, "/private/app").status_code == 403
    assert proxy(gateway_client, HOST, "/private/app").status_code == 403
    assert _UpstreamHandler.hits == []


GATE_CASES = [
    pytest.param("group-no-rule", "access_code", 302, id="group-with-no-matching-rule"),
    pytest.param("no-group", "access_code", 302, id="no-group-default"),
    pytest.param("no-group", "deny", 403, id="no-group-deny"),
    pytest.param("no-group", "none", 200, id="no-group-none"),
]


@pytest.mark.parametrize(("case", "setting", "expected"), GATE_CASES)
def test_both_gate_paths_agree(
    gateway_client: Any, upstream: Any, case: str, setting: str, expected: int
) -> None:
    """The two paths used to answer the same request differently."""
    if case == "group-no-rule":
        host = HOST
        forget_settings()
        groups = [make_group(1, "portfolio", HOST, [("/documentation/*", "access_code")])]
    else:
        host = OTHER_HOST
        install_action(setting)
        groups = [make_group(1, "portfolio", HOST, [("/*", "access_code")])]
    install_cache(groups, [make_route(host, *upstream)])

    via_forward_auth = forward_auth(gateway_client, host, "/private/app")
    via_proxy = proxy(gateway_client, host, "/private/app")

    assert via_forward_auth.status_code == expected
    assert via_proxy.status_code == expected


def test_the_setting_is_only_consulted_when_nothing_matched(
    gateway_client: Any, upstream: Any
) -> None:
    """A matching rule wins over a permissive setting, in both paths."""
    install_action("none")
    install_cache(
        [make_group(1, "portfolio", HOST, [("/private/*", "access_code")])],
        [make_route(HOST, *upstream)],
    )

    assert forward_auth(gateway_client, HOST, "/private/app").status_code == 302
    assert proxy(gateway_client, HOST, "/private/app").status_code == 302
    assert _UpstreamHandler.hits == []


# --------------------------------------------------------------------------- #
# api: the setting's validator and seed
# --------------------------------------------------------------------------- #


def test_api_seeds_the_unmatched_action_setting(client: Any) -> None:
    response = client.get("/api/settings/unmatched_action")

    assert response.status_code == 200
    assert response.json()["value"] == DEFAULT_UNMATCHED_ACTION


@pytest.mark.parametrize("value", ["access_code", "deny", "none"])
def test_api_accepts_the_known_unmatched_actions(client: Any, value: str) -> None:
    response = client.put(
        "/api/settings/unmatched_action", json={"value": value}, headers=INTERNAL_KEY_HEADERS
    )

    assert response.status_code == 200
    assert response.json()["value"] == value


@pytest.mark.parametrize("value", ["allow", "OPEN", "", "true", "1"])
def test_api_rejects_unknown_unmatched_actions(client: Any, value: str) -> None:
    response = client.put(
        "/api/settings/unmatched_action", json={"value": value}, headers=INTERNAL_KEY_HEADERS
    )

    assert response.status_code == 400
    assert "access_code, deny, none" in response.json()["detail"]


def test_api_unmatched_action_write_needs_the_internal_key(client: Any) -> None:
    response = client.put("/api/settings/unmatched_action", json={"value": "deny"})

    assert response.status_code == 401


def test_api_restores_the_default_unmatched_action(client: Any) -> None:
    """Leave the shared test database as the other modules expect to find it."""
    response = client.put(
        "/api/settings/unmatched_action",
        json={"value": DEFAULT_UNMATCHED_ACTION},
        headers=INTERNAL_KEY_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["value"] == DEFAULT_UNMATCHED_ACTION
