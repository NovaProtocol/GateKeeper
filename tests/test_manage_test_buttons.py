"""The pre-save test buttons in the routing and rules modals.

Phase 7 added two management POST routes that a `fetch` from a modal calls:
``/manage/routing/test`` (probe the typed upstream, and ask the gate what it
would do with the typed host and path) and ``/manage/rules/test`` (ask the gate
about the typed path). Neither writes anything, but both relay to the internal
API, so each carries the same three gates as every other manage POST.

What is asserted, and why:

* **the three gates, one at a time and with an empty relay log.** A route that
  checks the session and forgets the CSRF pair, or the reverse, looks correct in
  review and fails here instead of in production. The empty log is the point: a
  gate that answers 403 *after* relaying has already done the work.
* **the relayed shape.** The API's own validation refuses a bad payload, so the
  panel's job is to pass the four fields through unchanged and let the API be the
  one authority on what a route may be.
* **the templates.** The Test control, the fetch URLs and the CSRF header are the
  contract between the markup and these two routes; a rename on one side only is
  a button that silently does nothing. The external-host check pins the other
  half of that: a modal that acquired a call to somewhere else would be a new
  outbound request from an admin page.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import management.app as management_app
from shared.jwt import create_manage_token

CSRF = "test-csrf-token"
ORIGIN = "http://testserver"
SESSION = create_manage_token()

API = "http://api:8002"
ROUTING_TEST = f"{API}/api/routes/test"
DRY_RUN = f"{API}/api/dry-run"

GROUPS: list[dict[str, Any]] = [
    {
        "id": 10,
        "name": "alpha",
        "domain": "alpha.test",
        "display_order": 0,
        "is_default": False,
        "rules_count": 1,
    }
]

ROUTES: list[dict[str, Any]] = [
    {
        "id": 5,
        "host": "app.alpha.test",
        "path": "/",
        "route_type": "proxy",
        "upstream": "portfolio-web",
        "port": 8080,
        "redirect_target": None,
        "redirect_code": None,
    }
]

PAYLOADS: dict[str, Any] = {
    f"{API}/api/groups": GROUPS,
    f"{API}/api/groups/10/rules": [],
    f"{API}/api/routes": ROUTES,
    DRY_RUN: {"matched_group": "alpha", "matched_rule": "/x/*", "action": "none", "warnings": []},
    ROUTING_TEST: {"ok": True, "latency": "reachable"},
}


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = ""

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Records every relayed call so a gate that relays anyway is visible."""

    def __init__(
        self,
        post_status: int = 200,
        boom: bool = False,
        overrides: dict[str, Any] | None = None,
    ) -> None:
        self.post_status = post_status
        self.boom = boom
        self.overrides = overrides or {}
        self.calls: list[tuple[str, str, Any]] = []

    def _payload(self, url: str) -> Any:
        if url in self.overrides:
            return self.overrides[url]
        return PAYLOADS.get(url, {})

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None))
        return _FakeResponse(200, self._payload(url))

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json))
        if self.boom:
            raise RuntimeError("api unreachable")
        return _FakeResponse(self.post_status, self._payload(url))

    def posts(self) -> list[tuple[str, Any]]:
        return [(url, body) for method, url, body in self.calls if method == "POST"]


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


def _auth() -> dict[str, str]:
    return {"manage_session": SESSION, "csrf_token": CSRF}


def _routing_test(manage_client, **kwargs: Any):
    body = kwargs.pop(
        "json", {"csrf_token": CSRF, "route_type": "proxy", "upstream": "x", "port": 8080}
    )
    cookies = kwargs.pop("cookies", _auth())
    headers = kwargs.pop("headers", {"Origin": ORIGIN, "Accept": "application/json"})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        "/manage/routing/test", json=body, cookies=cookies, headers=headers, **kwargs
    )


def _rules_test(manage_client, **kwargs: Any):
    body = kwargs.pop("json", {"csrf_token": CSRF, "host": "alpha.test", "path": "/x"})
    cookies = kwargs.pop("cookies", _auth())
    headers = kwargs.pop("headers", {"Origin": ORIGIN, "Accept": "application/json"})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        "/manage/rules/test", json=body, cookies=cookies, headers=headers, **kwargs
    )


# --------------------------------------------------------------------------- #
# Gate 1: the manage session
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("call", [_routing_test, _rules_test], ids=["routing", "rules"])
def test_an_anonymous_caller_is_refused(manage_client, fake_api: _FakeClient, call) -> None:
    r = call(manage_client, cookies={})

    assert r.status_code == 401, "a JSON caller gets 401 rather than a login redirect"
    assert fake_api.posts() == [], "a refused request must not reach the API"


@pytest.mark.parametrize("call", [_routing_test, _rules_test], ids=["routing", "rules"])
def test_an_invalid_session_cookie_is_refused(manage_client, fake_api: _FakeClient, call) -> None:
    r = call(manage_client, cookies={"manage_session": "not-a-token", "csrf_token": CSRF})

    assert r.status_code == 401
    assert fake_api.posts() == []


# --------------------------------------------------------------------------- #
# Gate 2: the CSRF pair
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("call", [_routing_test, _rules_test], ids=["routing", "rules"])
def test_a_missing_csrf_token_is_refused(manage_client, fake_api: _FakeClient, call) -> None:
    cookies = {"manage_session": SESSION}
    body = {"csrf_token": CSRF, "route_type": "proxy", "upstream": "x", "port": 8080}
    if call is _rules_test:
        body = {"csrf_token": CSRF, "host": "alpha.test", "path": "/x"}

    r = call(manage_client, json=body, cookies=cookies)

    assert r.status_code == 403
    assert fake_api.posts() == []


@pytest.mark.parametrize("call", [_routing_test, _rules_test], ids=["routing", "rules"])
def test_a_mismatched_csrf_token_is_refused(manage_client, fake_api: _FakeClient, call) -> None:
    r = call(manage_client, json={"csrf_token": "wrong", "upstream": "x"}, cookies=_auth())

    assert r.status_code == 403
    assert fake_api.posts() == []


def test_the_csrf_token_may_arrive_as_a_header(manage_client, fake_api: _FakeClient) -> None:
    """The modal sends both; the either/or is what the route reads."""
    r = _routing_test(
        manage_client,
        json={"route_type": "proxy", "upstream": "x", "port": 8080},
        headers={"Origin": ORIGIN, "Accept": "application/json", "X-CSRF-Token": CSRF},
    )

    assert r.status_code == 200
    assert len(fake_api.posts()) == 1


# --------------------------------------------------------------------------- #
# Gate 3: same_origin
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("call", [_routing_test, _rules_test], ids=["routing", "rules"])
def test_a_cross_site_post_is_refused(manage_client, fake_api: _FakeClient, call) -> None:
    r = call(manage_client, headers={"Origin": "http://evil.test", "Accept": "application/json"})

    assert r.status_code == 403
    assert fake_api.posts() == []


@pytest.mark.parametrize("call", [_routing_test, _rules_test], ids=["routing", "rules"])
def test_a_post_with_no_origin_at_all_is_refused(
    manage_client, fake_api: _FakeClient, call
) -> None:
    r = call(manage_client, headers={"Accept": "application/json"})

    assert r.status_code == 403
    assert fake_api.posts() == []


# --------------------------------------------------------------------------- #
# What is relayed
# --------------------------------------------------------------------------- #


def test_the_route_probe_relays_the_four_fields_unchanged(
    manage_client, fake_api: _FakeClient
) -> None:
    r = _routing_test(
        manage_client,
        json={
            "csrf_token": CSRF,
            "route_type": "redirect",
            "upstream": "portfolio-web",
            "port": "8080",
            "redirect_target": "/newpath",
        },
    )

    assert r.status_code == 200
    url, body = fake_api.posts()[0]
    assert url == ROUTING_TEST
    assert body == {
        "route_type": "redirect",
        "upstream": "portfolio-web",
        "port": "8080",
        "redirect_target": "/newpath",
    }, "the API is the authority on shape; the panel must not reinterpret it"


def test_the_verdict_is_passed_back_as_json(manage_client, fake_api: _FakeClient) -> None:
    r = _routing_test(manage_client)

    assert r.status_code == 200
    assert r.json() == {"ok": True, "latency": "reachable"}


def test_the_api_status_is_not_turned_into_a_500(
    manage_client, monkeypatch, fake_api: _FakeClient
) -> None:
    """A 400 from validation is the answer the modal has to render."""
    monkeypatch.setattr(management_app, "_get_httpx", lambda: _FakeClient(post_status=400))
    r = _routing_test(manage_client)

    assert r.status_code == 200, "the modal reads the body, not the relay's status"


def test_an_unreachable_api_is_reported_rather_than_raised(manage_client, monkeypatch) -> None:
    monkeypatch.setattr(management_app, "_get_httpx", lambda: _FakeClient(boom=True))

    r = _routing_test(manage_client)

    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert r.json()["error"]


def test_the_rule_probe_reaches_the_keyless_dry_run(manage_client, fake_api: _FakeClient) -> None:
    r = _rules_test(manage_client, json={"csrf_token": CSRF, "host": "alpha.test", "path": "/x"})

    assert r.status_code == 200
    url, body = fake_api.posts()[0]
    assert url == DRY_RUN
    assert body == {"host": "alpha.test", "path": "/x"}


def test_the_rule_probe_defaults_the_path_to_root(manage_client, fake_api: _FakeClient) -> None:
    _rules_test(manage_client, json={"csrf_token": CSRF, "host": "alpha.test"})

    assert fake_api.posts()[0][1] == {"host": "alpha.test", "path": "/"}


def test_the_rule_probe_adds_a_missing_leading_slash(manage_client, fake_api: _FakeClient) -> None:
    """`path_matches` is exact, so a path without a slash would match nothing."""
    _rules_test(manage_client, json={"csrf_token": CSRF, "host": "alpha.test", "path": "reports"})

    assert fake_api.posts()[0][1]["path"] == "/reports"


def test_a_missing_host_is_a_400_before_any_relay(manage_client, fake_api: _FakeClient) -> None:
    r = _rules_test(manage_client, json={"csrf_token": CSRF, "path": "/x"})

    assert r.status_code == 400
    assert "host" in r.json()["detail"]
    assert fake_api.posts() == []


def test_a_rule_probe_reports_the_match_and_its_warnings(manage_client, monkeypatch) -> None:
    """The shadowing warning is the reason the button exists, so it must arrive."""
    shadowed = {
        "matched_group": "alpha",
        "matched_rule": "/*",
        "action": "none",
        "warnings": [{"rule": "/api/*", "message": "shadowed by /*"}],
    }
    monkeypatch.setattr(
        management_app, "_get_httpx", lambda: _FakeClient(overrides={DRY_RUN: shadowed})
    )

    r = _rules_test(manage_client)

    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "none"
    assert body["matched_group"] == "alpha"
    assert body["warnings"][0]["rule"] == "/api/*", "the warning survives the relay"


# --------------------------------------------------------------------------- #
# The templates
# --------------------------------------------------------------------------- #


def _page(manage_client, path: str, monkeypatch) -> str:
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    r = manage_client.get(path, cookies={"manage_session": SESSION})
    assert r.status_code == 200, r.text
    return r.text


def test_the_routing_page_renders_the_test_controls(manage_client, monkeypatch) -> None:
    html = _page(manage_client, "/manage/routing", monkeypatch)

    assert html.count('class="test-result"') == 3, "one verdict slot per modal"
    assert html.count('title="Test before saving"') == 3
    assert html.count('aria-label="Test before saving"') == 3, "icon-only needs both"
    assert html.count("testDraft(") >= 3, "add-proxy, add-redirect and edit"


def test_the_routing_page_calls_both_new_endpoints(manage_client, monkeypatch) -> None:
    html = _page(manage_client, "/manage/routing", monkeypatch)

    assert "'/manage/routing/test'" in html, "the pre-save probe"
    assert "'/manage/rules/test'" in html, "the gate preview"
    assert "/manage/routing/${rid}/test" in html, "the saved-route test is unchanged"


def test_the_routing_modal_sends_the_csrf_token_as_a_header(manage_client, monkeypatch) -> None:
    html = _page(manage_client, "/manage/routing", monkeypatch)

    assert "'X-CSRF-Token':_csrf" in html
    assert "csrf_token:_csrf" in html


def test_the_rules_page_renders_a_test_control_per_modal(manage_client, monkeypatch) -> None:
    html = _page(manage_client, "/manage/rules/10", monkeypatch)

    assert html.count('title="Test before saving"') == 2, "add and edit"
    assert html.count('aria-label="Test before saving"') == 2
    assert html.count('class="test-result"') == 2


def test_the_rules_page_renders_the_shadowing_verdict(manage_client, monkeypatch) -> None:
    """A warning has to have somewhere to be shown, or the trap stays invisible."""
    html = _page(manage_client, "/manage/rules/10", monkeypatch)

    assert "testRuleDraft(" in html
    assert "shadowed:" in html, "the warning is rendered, not just counted"
    assert "'/manage/rules/test'" in html
    assert "gate.matched_group" in html and "gate.matched_rule" in html


def test_the_rule_modal_pins_a_host_to_test_against(manage_client, monkeypatch) -> None:
    """`/api/dry-run` needs a host, and the modal only has a path."""
    html = _page(manage_client, "/manage/rules/10", monkeypatch)

    assert "_ruleHost()" in html
    assert "probe.example.com" in html, "the default group has no host of its own"
    assert "_ruleGroupDomain" in html


EXTERNAL_HOST = re.compile(r"https?://([a-zA-Z0-9.-]+)")

# Everything the base template and the two pages already loaded before this
# change. The point of the check is the entry that is not here.
ALLOWED_HOSTS = {
    "fonts.googleapis.com",  # base.html, Inter and JetBrains Mono
    "fonts.gstatic.com",  # the font files those rules point at
    "cdnjs.cloudflare.com",  # base.html, Font Awesome
    "cdn.jsdelivr.net",  # base.html, Bootstrap and the audit map
    "portfolio.projectnova.download",  # an example in a routing placeholder
    "testserver",  # the request's own absolute URL in the test client
}


@pytest.mark.parametrize("path", ["/manage/routing", "/manage/rules/10"])
def test_no_new_external_host_appears_on_the_page(manage_client, monkeypatch, path: str) -> None:
    """The modal talks to the panel and nothing else.

    A CDN the base template already loads is not this change's business; a host
    that was not there before is an outbound request from an admin page.
    """
    html = _page(manage_client, path, monkeypatch)
    found = set(EXTERNAL_HOST.findall(html))

    assert not (found - ALLOWED_HOSTS), (
        f"unexpected external host(s): {sorted(found - ALLOWED_HOSTS)}"
    )
    assert "{{ " not in html, "an unrendered template expression reached the page"
