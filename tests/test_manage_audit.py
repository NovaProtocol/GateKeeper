"""The audit page: the map, the aggregation dropdown, and clearing the log.

Three separate claims live here, and they are checked at different levels on
purpose:

* **the map is allowed to draw.** A Leaflet map breaks silently when the tile
  host is missing from `img-src`: the script loads, the container renders, and
  every tile is refused by the browser with nothing in the page to say so. The
  test therefore asserts the tile host in the rendered page **and** in the CSP
  header the same service sends, because a page that references a host its own
  policy blocks is a page that looks broken for a reason nothing on it explains.
* **the aggregation is server-side.** The dropdown is a GET form, so the mode
  travels as a query parameter and the page returns already-counted data: there
  is no client-side arithmetic to get wrong, and the links stay shareable.
* **clearing the log is gated server-side.** The modal is an affordance. The gate
  is the route, which checks the session, the CSRF pair, the origin and the typed
  word before it issues exactly one `DELETE`. A stale tab, a replayed post or a
  script cannot skip it, and these tests exist so it cannot be dropped later.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import management.app as management_app
from shared.geo import GEO_MODES
from shared.jwt import create_manage_token

CSRF = "test-csrf-token"
ORIGIN = "http://testserver"
SESSION = create_manage_token()

API = "http://api:8002"

#: Two countries and an unknown bucket, as the API's `/api/logs/geo` returns it.
GEO_POINTS: list[dict[str, Any]] = [
    {
        "cc": "PH",
        "name": "Philippines",
        "count": 6,
        "lat": 13.0,
        "lon": 122.0,
        "share": 0.6,
        "radius": 21.3,
    },
    {
        "cc": "DE",
        "name": "Germany",
        "count": 3,
        "lat": 51.0,
        "lon": 9.0,
        "share": 0.3,
        "radius": 15.2,
    },
    {
        "cc": None,
        "name": "Unknown",
        "count": 1,
        "lat": None,
        "lon": None,
        "share": 0.1,
        "radius": 0.0,
    },
]

BY_IP: list[dict[str, Any]] = [
    {
        "ip": "203.0.113.10",
        "calls": 6,
        "recent": [
            {
                "ts": "2026-09-17 10:00:00",
                "host": "app.projectnova.download",
                "path": "/reports",
                "action": "auth_success",
                "code_label": "Alice",
                "attempted_code": None,
            }
        ],
        "codes": ["Alice"],
    }
]

TILE_HOST = "tile.openstreetmap.org"


class _FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = b""
        self.headers = headers or {}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Records every relayed call, so "no DELETE was issued" is assertable."""

    def __init__(self, clear_status: int = 200) -> None:
        self.clear_status = clear_status
        self.prune: dict[str, Any] = {"ok": True, "deleted": 4, "remaining": 11}
        self.calls: list[tuple[str, str, Any, dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None, kwargs))
        if url.endswith("/api/logs/geo"):
            return _FakeResponse(200, GEO_POINTS)
        if url.endswith("/api/logs/by-ip"):
            return _FakeResponse(200, BY_IP)
        if url.endswith("/api/logs"):
            return _FakeResponse(200, [], headers={"X-Total-Count": "97"})
        return _FakeResponse(200, [])

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json, kwargs))
        if url.endswith("/api/logs/prune"):
            return _FakeResponse(200, self.prune)
        return _FakeResponse(200, {})

    async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("PUT", url, json, kwargs))
        return _FakeResponse(200, {})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("DELETE", url, None, kwargs))
        return _FakeResponse(self.clear_status, {"ok": self.clear_status < 400})

    def by_method(self, method: str) -> list[tuple[str, str, Any, dict[str, Any]]]:
        return [c for c in self.calls if c[0] == method]


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


def _auth() -> dict[str, str]:
    return {"manage_session": SESSION, "csrf_token": CSRF}


def _page(manage_client: Any, query: str = "") -> str:
    r = manage_client.get(f"/manage/audit{query}", cookies={"manage_session": SESSION})
    assert r.status_code == 200, r.text
    return r.text


def _clear(manage_client: Any, confirm: str | None = "DELETE", **kwargs: Any) -> Any:
    data = kwargs.pop("data", {"csrf_token": CSRF, "confirm": confirm})
    cookies = kwargs.pop("cookies", _auth())
    headers = kwargs.pop("headers", {"Origin": ORIGIN})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        "/manage/logs/clear", data=data, cookies=cookies, headers=headers, **kwargs
    )


# --------------------------------------------------------------------------- #
# The page renders
# --------------------------------------------------------------------------- #


def test_the_page_requires_a_session(manage_client: Any) -> None:
    r = manage_client.get("/manage/audit", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


def test_the_page_renders_the_map_container_and_the_ip_table(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    assert 'id="audit-map"' in html
    assert "203.0.113.10" in html
    assert "Philippines" in html


def test_the_map_container_carries_a_text_summary_so_the_data_is_not_map_only(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """A screen reader and a failed tile fetch both need the answer as text."""
    html = _page(manage_client)

    assert re.search(r'id="audit-map"[^>]*role="img"', html)
    assert re.search(r'id="audit-map"[^>]*aria-label="[^"]*Philippines', html)
    assert "Philippines 6" in html


def test_the_country_totals_are_rendered_as_a_table_too(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    assert "Germany" in html
    assert "Unknown" in html
    assert "60.0%" in html, "the share is rendered for each country"


def test_the_log_row_count_is_shown_from_the_pagination_header(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """An empty table and a cleared table look identical without the number."""
    html = _page(manage_client)

    assert "97" in html


def test_the_page_says_country_level_only(manage_client: Any, fake_api: _FakeClient) -> None:
    html = _page(manage_client)

    assert "CF-IPCountry" in html
    assert "Unknown" in html
    assert "no lookup service" in html


# --------------------------------------------------------------------------- #
# The aggregation dropdown
# --------------------------------------------------------------------------- #


def test_the_dropdown_offers_exactly_the_four_modes(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    options = re.findall(r'<option value="([^"]+)"', html)
    assert options == list(GEO_MODES)


def test_the_selected_mode_is_the_one_marked_selected(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client, "?mode=blocked")

    assert re.search(r'<option value="blocked" selected>', html)
    assert not re.search(r'<option value="views" selected>', html)


def test_the_mode_is_sent_to_the_api(manage_client: Any, fake_api: _FakeClient) -> None:
    _page(manage_client, "?mode=visitors")

    geo = [c for c in fake_api.calls if c[1].endswith("/api/logs/geo")]
    assert len(geo) == 1
    assert geo[0][3]["params"] == {"mode": "visitors"}


@pytest.mark.parametrize("mode", GEO_MODES)
def test_every_mode_propagates(manage_client: Any, fake_api: _FakeClient, mode: str) -> None:
    _page(manage_client, f"?mode={mode}")

    geo = [c for c in fake_api.calls if c[1].endswith("/api/logs/geo")]
    assert geo[0][3]["params"] == {"mode": mode}


@pytest.mark.parametrize("mode", ["", "heatmap", "VIEWS", "by-views"])
def test_an_unusable_mode_falls_back_rather_than_failing_the_page(
    manage_client: Any, fake_api: _FakeClient, mode: str
) -> None:
    html = _page(manage_client, f"?mode={mode}")

    geo = [c for c in fake_api.calls if c[1].endswith("/api/logs/geo")]
    assert geo[0][3]["params"] == {"mode": "views"}
    assert 'id="audit-map"' in html


def test_the_dropdown_is_a_get_form_so_the_view_is_linkable(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    assert re.search(r'<form method="get" action="/manage/audit"', html)
    assert 'name="mode"' in html


# --------------------------------------------------------------------------- #
# The map, the CSP and the library
# --------------------------------------------------------------------------- #


def test_the_page_loads_leaflet_from_the_already_allowed_cdn(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """`script-src` already carries jsdelivr, so this needs no policy change."""
    html = _page(manage_client)

    assert "cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js" in html
    assert "cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css" in html


def test_the_tile_host_is_in_the_page_and_in_the_csp_header(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The claim that matters: the page asks for a host its own policy allows."""
    r = manage_client.get("/manage/audit", cookies={"manage_session": SESSION})
    csp = r.headers["content-security-policy"]

    assert TILE_HOST in r.text
    assert TILE_HOST in csp
    assert "https://*.tile.openstreetmap.org" in csp


def test_the_img_src_directive_is_what_gained_the_tile_host(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """Tiles arrive as `<img>`, so nothing else in the policy is relevant to them."""
    r = manage_client.get("/manage/audit", cookies={"manage_session": SESSION})
    csp = r.headers["content-security-policy"]
    directives = dict(
        part.strip().split(" ", 1) for part in csp.split(";") if " " in part.strip()
    )

    assert TILE_HOST in directives["img-src"]
    assert TILE_HOST not in directives["connect-src"]
    assert TILE_HOST not in directives["script-src"]
    assert TILE_HOST not in directives["style-src"]


def test_the_tile_layer_carries_its_required_attribution(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    assert "openstreetmap.org/copyright" in html
    assert "OpenStreetMap" in html


def test_no_heat_layer_is_loaded(manage_client: Any, fake_api: _FakeClient) -> None:
    """Rejected on purpose: one centroid per country is not a density surface."""
    html = _page(manage_client)

    assert "leaflet.heat" not in html
    assert "L.heatLayer" not in html
    assert "L.circleMarker" in html


def test_the_circle_radius_comes_from_the_server_not_from_javascript(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The aggregation is computed once, in Python, where it can be tested."""
    html = _page(manage_client)

    assert "p.radius" in html
    assert "21.3" in html


def test_the_unknown_bucket_is_not_given_coordinates_in_the_payload(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """It counts in the totals and appears as text; it is never a marker."""
    r = manage_client.get("/manage/audit", cookies={"manage_session": SESSION})
    body = r.text.split('id="audit-map"', 1)[-1]

    assert '"name": "Unknown"' not in body.split("<script>")[-1], "the unknown bucket was plotted"


def test_the_map_script_degrades_to_text_instead_of_an_empty_box(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    assert "audit-map-fallback" in html
    assert "could not be drawn" in html
    assert "typeof L === 'undefined'" in html


def test_a_gateway_with_no_points_renders_the_fallback_and_no_map_script(
    manage_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The state the page is in if `CF-IPCountry` never arrives at all."""

    class _Empty(_FakeClient):
        async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
            self.calls.append(("GET", url, None, kwargs))
            if url.endswith("/api/logs/geo"):
                return _FakeResponse(200, [])
            if url.endswith("/api/logs"):
                return _FakeResponse(200, [], headers={"X-Total-Count": "0"})
            return _FakeResponse(200, [])

    monkeypatch.setattr(management_app, "_get_httpx", lambda: _Empty())

    r = manage_client.get("/manage/audit", cookies={"manage_session": SESSION})
    assert r.status_code == 200
    assert "Nothing to plot yet" in r.text
    assert "No country data recorded yet" in r.text
    assert 'id="audit-map"' not in r.text
    assert "L.map(" not in r.text


def test_an_unreachable_api_does_not_break_the_page(
    manage_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Broken(_FakeClient):
        async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
            raise RuntimeError("connection refused")

    monkeypatch.setattr(management_app, "_get_httpx", lambda: _Broken())

    r = manage_client.get("/manage/audit", cookies={"manage_session": SESSION})
    assert r.status_code == 200
    assert "Nothing to plot yet" in r.text


# --------------------------------------------------------------------------- #
# Clearing the log: the three gates
# --------------------------------------------------------------------------- #


def test_clear_requires_a_session(manage_client: Any, fake_api: _FakeClient) -> None:
    r = _clear(manage_client, cookies=None)

    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")
    assert fake_api.calls == []


def test_clear_rejects_a_missing_csrf_token(manage_client: Any, fake_api: _FakeClient) -> None:
    r = _clear(manage_client, data={"confirm": "DELETE"})

    assert r.status_code == 403
    assert fake_api.by_method("DELETE") == []


def test_clear_rejects_a_mismatched_csrf_token(manage_client: Any, fake_api: _FakeClient) -> None:
    r = _clear(manage_client, data={"csrf_token": "not-the-cookie", "confirm": "DELETE"})

    assert r.status_code == 403
    assert fake_api.by_method("DELETE") == []


def test_clear_rejects_a_cross_origin_request(manage_client: Any, fake_api: _FakeClient) -> None:
    r = _clear(manage_client, headers={"Origin": "http://evil.example.com"})

    assert r.status_code == 403
    assert fake_api.by_method("DELETE") == []


def test_clear_rejects_a_request_with_no_origin_at_all(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """No Origin and no Referer is not same-origin, so it is refused."""
    r = _clear(manage_client, headers={})

    assert r.status_code == 403
    assert fake_api.by_method("DELETE") == []


@pytest.mark.parametrize(
    "confirm",
    [
        pytest.param("", id="empty"),
        pytest.param(None, id="absent"),
        pytest.param("delete", id="lowercase"),
        pytest.param("Delete", id="mixed-case"),
        pytest.param("DELETED", id="suffix"),
        pytest.param("DELETE ALL", id="sentence"),
        pytest.param("PRUNE", id="the-wrong-word"),
        pytest.param(" DELETE", id="leading-space-only-is-trimmed-not-ignored"),
    ],
)
def test_clear_refuses_anything_but_the_exact_word(
    manage_client: Any, fake_api: _FakeClient, confirm: str | None
) -> None:
    """Checked on the server, so the modal is not the gate."""
    r = _clear(manage_client, confirm=confirm)

    if confirm == " DELETE":
        # The word is stripped before comparison, the same as the other typed
        # confirmations; a stray leading space is a keystroke, not a different word.
        assert r.status_code == 200
        return
    assert r.status_code == 403
    assert fake_api.by_method("DELETE") == []


def test_clear_with_the_right_word_relays_exactly_one_delete(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    r = _clear(manage_client)

    assert r.status_code == 200
    deletes = fake_api.by_method("DELETE")
    assert len(deletes) == 1
    assert deletes[0][1] == f"{API}/api/logs/clear"
    assert deletes[0][3]["headers"]["X-Internal-Api-Key"]


def test_clear_reports_what_it_did(manage_client: Any, fake_api: _FakeClient) -> None:
    r = _clear(manage_client)

    assert "Every audit row was deleted" in r.text


def test_clear_survives_a_refusal_from_the_api(
    manage_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal is reported on the page, not turned into a 500."""
    monkeypatch.setattr(management_app, "_get_httpx", lambda: _FakeClient(clear_status=401))

    r = _clear(manage_client)

    assert r.status_code == 200
    assert "Clear failed" in r.text


def test_a_refused_clear_leaves_the_rows_alone(manage_client: Any, fake_api: _FakeClient) -> None:
    """The only assertion that matters about a refusal: nothing happened."""
    _clear(manage_client, confirm="nope")

    assert fake_api.by_method("DELETE") == []
    assert fake_api.by_method("POST") == []


def test_clear_never_touches_the_prune_path(manage_client: Any, fake_api: _FakeClient) -> None:
    _clear(manage_client)

    assert [c for c in fake_api.calls if c[1].endswith("/api/logs/prune")] == []


# --------------------------------------------------------------------------- #
# Prune, from the page that now links to it
# --------------------------------------------------------------------------- #


def test_the_prune_control_is_reachable_from_the_audit_page(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """It sits beside the clear control, which is where an operator looks for it."""
    html = _page(manage_client)

    assert 'href="/manage/settings"' in html
    assert 'action="/manage/logs/prune"' in html
    assert 'name="back" value="audit"' in html


def test_prune_from_the_audit_page_reports_its_count_here(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The count is the point of the button: it has to come back to this page."""
    fake_api.prune = {"ok": True, "deleted": 4, "remaining": 11}

    r = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE", "back": "audit"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert r.status_code == 200
    assert "Deleted 4 audit rows" in r.text
    assert "11 remain" in r.text
    assert 'id="audit-map"' in r.text or "Nothing to plot yet" in r.text


def test_prune_still_reports_its_count_on_the_settings_page(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """Unchanged default: the settings page keeps the control it already had."""
    fake_api.prune = {"ok": True, "deleted": 4, "remaining": 11}

    r = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert r.status_code == 200
    assert "Deleted 4 audit rows" in r.text
    assert "11 remain" in r.text
    assert "Prune audit logs" in r.text


def test_an_unknown_return_target_falls_back_to_the_settings_page(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The field names one of two pages, so it cannot point the response elsewhere."""
    r = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE", "back": "https://evil.example.com"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert r.status_code == 200
    assert "Prune audit logs" in r.text
    assert "evil.example.com" not in r.text


# --------------------------------------------------------------------------- #
# The shipped page is what the previous phase pinned
# --------------------------------------------------------------------------- #


def test_the_rendered_map_is_not_a_second_navigation(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The page grew a card; it did not grow a menu."""
    html = _page(manage_client)

    assert "Manage categories:" not in html


def test_no_stat_card_chrome_reappears(manage_client: Any, fake_api: _FakeClient) -> None:
    """The stat strip replaced the oversized cards in the previous phase."""
    html = _page(manage_client)

    assert 'class="stat-card"' not in html
    assert "stat-strip" in html


def test_every_control_on_the_page_has_a_title_and_an_aria_label(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """A control without both is a control a keyboard or screen-reader user loses."""
    html = _page(manage_client)
    controls = re.findall(r"<(?:input|select|button)\b[^>]*>", html)
    assert controls
    missing = [
        tag
        for tag in controls
        if 'type="hidden"' not in tag
        and "data-dismiss" not in tag
        and ("title=" not in tag or "aria-label=" not in tag)
    ]

    assert missing == []
