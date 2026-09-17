"""Every `/manage/*` page: it renders, it is reachable, and it is not bloat.

This module pins the shape of the panel rather than the behaviour of any one
route, so a later change to the chrome fails here:

* the sidebar's categories are Access, System, Audit in that order, and every
  link it renders resolves instead of 404ing;
* the Warnings page is gone, and the dashboard banner is its replacement: absent
  when there is nothing to report, present when a rule is shadowed;
* the oversized stat cards are gone for good. The complaint was that three
  numbers occupied a card each; the guard is that no template renders
  `class="stat-card"` and no page carries the old inline `max-width:1100px`.
* `/manage/monitoring` still answers, as a redirect, so a bookmark survives the
  rename.

The rendered-DOM proof of the width change lives in `tests/ui/check_layout.py`,
which measures a real browser; these are the cheap guards that fail fast.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import management.app as management_app
from shared.jwt import create_manage_token

SESSION = create_manage_token()

GROUPS: list[dict[str, Any]] = [
    {
        "id": 10,
        "name": "gatekeeper.projectnova.download",
        "domain": "gatekeeper.projectnova.download",
        "display_order": 0,
        "is_default": False,
        "rules_count": 1,
    },
    {
        "id": 12,
        "name": "*.*/*",
        "domain": "*.*/*",
        "display_order": 9999,
        "is_default": True,
        "rules_count": 1,
    },
]

RULES: list[dict[str, Any]] = [
    {
        "id": 1,
        "group_id": 10,
        "path": "/*",
        "action": "access_code",
        "rate_limit": None,
        "display_order": 0,
        "is_default": True,
    }
]

ROUTES: list[dict[str, Any]] = [
    {
        "id": 5,
        "host": "app.projectnova.download",
        "path": "/",
        "route_type": "proxy",
        "upstream": "portfolio-web",
        "port": 8080,
        "redirect_target": None,
        "redirect_code": None,
    }
]

CODES: list[dict[str, Any]] = [
    {
        "id": 3,
        "code": "abcd1234",
        "label": "Alice",
        "display_name": "Alice",
        "active": True,
        "created_at": "2026-01-01 10:00:00",
        "last_accessed": "2026-09-01 12:00:00",
    },
    {
        "id": 4,
        "code": "zzzz9999",
        "label": "Bob",
        "display_name": "Bob",
        "active": False,
        "created_at": "2026-02-02 11:00:00",
        "last_accessed": None,
    },
]

LOGS: list[dict[str, Any]] = [
    {
        "id": 1,
        "ts": "2026-09-17 10:00:00",
        "ip": "203.0.113.5",
        "host": "app.projectnova.download",
        "path": "/reports",
        "action": "auth_success",
    }
]

TOP: list[dict[str, Any]] = [
    {"host": "app.projectnova.download", "path": "/reports", "calls": 12},
    {"host": "app.projectnova.download", "path": "/", "calls": 3},
]

BY_IP: list[dict[str, Any]] = [
    {
        "ip": "203.0.113.5",
        "calls": 12,
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

SETTINGS: list[dict[str, Any]] = [
    {"key": "rate_limit_access_code_per_min", "value": "5", "updated_at": None}
]

API = "http://api:8002"

PAYLOADS: dict[str, Any] = {
    f"{API}/api/groups": GROUPS,
    f"{API}/api/groups/10/rules": RULES,
    f"{API}/api/groups/12/rules": RULES,
    f"{API}/api/routes": ROUTES,
    f"{API}/api/codes": CODES,
    f"{API}/api/logs": LOGS,
    f"{API}/api/logs/top": TOP,
    f"{API}/api/logs/by-ip": BY_IP,
    f"{API}/api/settings": SETTINGS,
    f"{API}/api/warnings": {"groups": [], "rules": []},
    f"{API}/api/backup": {},
}


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = b""
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Answers every relayed call from `PAYLOADS`, with an override per test."""

    def __init__(self, overrides: dict[str, Any] | None = None) -> None:
        self.overrides = overrides or {}
        self.calls: list[tuple[str, str, Any, dict[str, Any]]] = []

    def _payload(self, url: str) -> Any:
        if url in self.overrides:
            return self.overrides[url]
        return PAYLOADS.get(url, [])

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None, kwargs))
        return _FakeResponse(200, self._payload(url))

    async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("PUT", url, json, kwargs))
        return _FakeResponse(200, {})

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json, kwargs))
        return _FakeResponse(200, {})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("DELETE", url, None, kwargs))
        return _FakeResponse(200, {})


def _install(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any] | None = None
) -> _FakeClient:
    client = _FakeClient(overrides)
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


PAGES = [
    pytest.param("/manage", "Recent traffic", id="dashboard"),
    pytest.param("/manage/rules", "Rule Groups", id="rules"),
    pytest.param("/manage/rules/10", "Rules", id="rules-detail"),
    pytest.param("/manage/codes", "Access Codes", id="codes"),
    pytest.param("/manage/routing", "Routing", id="routing"),
    pytest.param("/manage/logs", "Traffic Logs", id="logs"),
    pytest.param("/manage/audit", "Audit", id="audit"),
    pytest.param("/manage/top-pages", "Top Pages", id="top-pages"),
    pytest.param("/manage/settings", "Settings", id="settings"),
    pytest.param("/manage/backup", "Backup", id="backup"),
]


def _get(manage_client, page: str, monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> str:
    _install(monkeypatch, kwargs.pop("overrides", None))
    r = manage_client.get(page, cookies={"manage_session": SESSION})
    assert r.status_code == 200, r.text
    return r.text


SIDEBAR = re.compile(r'<nav class="sidebar">(.*?)</nav>', re.S)


def _sidebar(html: str) -> str:
    found = SIDEBAR.search(html)
    assert found, "no sidebar rendered"
    return found.group(1)


# --------------------------------------------------------------------------- #
# Every page loads
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("page", "heading"), PAGES)
def test_every_page_renders_with_a_session(manage_client, monkeypatch, page, heading) -> None:
    html = _get(manage_client, page, monkeypatch)
    assert heading in html


@pytest.mark.parametrize(("page", "heading"), PAGES)
def test_every_page_redirects_an_anonymous_visitor(manage_client, page, heading) -> None:
    r = manage_client.get(page, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


# --------------------------------------------------------------------------- #
# The sidebar is the navigation, and it is complete
# --------------------------------------------------------------------------- #


def test_sidebar_categories_are_ordered_access_system_audit(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    sidebar = _sidebar(html)
    categories = re.findall(r'<div class="sidebar-cat">([^<]+)</div>', sidebar)
    assert categories == ["Access", "System", "Audit"], categories


def test_sidebar_drops_the_warnings_entry(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    sidebar = _sidebar(html)
    assert "/manage/warnings" not in sidebar
    assert ">Warnings<" not in sidebar
    assert "/manage/audit" in sidebar, "the Audit entry replaces it"


def test_sidebar_links_all_resolve(manage_client, monkeypatch) -> None:
    """No dead entries: every href the sidebar renders answers with a page."""
    html = _get(manage_client, "/manage", monkeypatch)
    hrefs = re.findall(r'<a href="(/manage[^"]*)"', _sidebar(html))
    assert len(hrefs) == 8, hrefs

    for href in hrefs:
        r = manage_client.get(href, cookies={"manage_session": SESSION}, follow_redirects=False)
        assert r.status_code == 200, f"{href} -> {r.status_code}"


def test_the_sidebar_is_the_only_navigation_on_the_dashboard(manage_client, monkeypatch) -> None:
    """The old page repeated the sidebar as a paragraph plus three buttons."""
    html = _get(manage_client, "/manage", monkeypatch)
    assert "Manage categories:" not in html
    content = re.search(r'<div class="main">(.*)</div>\s*</div>\s*<script', html, re.S)
    assert content, "could not isolate the page body"
    assert content.group(1).count('href="/manage/routing"') == 0


# --------------------------------------------------------------------------- #
# Warnings moved from a page to a banner
# --------------------------------------------------------------------------- #


def test_warnings_page_is_gone(manage_client, monkeypatch) -> None:
    _install(monkeypatch)
    r = manage_client.get("/manage/warnings", cookies={"manage_session": SESSION})
    assert r.status_code == 404


def test_warnings_page_template_is_deleted() -> None:
    from pathlib import Path

    templates = Path(management_app.__file__).parent / "templates" / "manage"
    assert not (templates / "warnings.html").exists()
    assert not (templates / "monitoring.html").exists()
    assert (templates / "audit.html").exists()


def test_no_banner_when_nothing_is_shadowed(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    assert "warn-banner" not in html
    assert "shadowed" not in html.lower()


def test_banner_appears_when_a_rule_is_shadowed(manage_client, monkeypatch) -> None:
    """The capability did not vanish with the page, it moved onto the dashboard."""
    overrides = {
        f"{API}/api/warnings": {
            "groups": [{"id": 11, "name": "beta", "reason": "matched by an earlier group"}],
            "rules": [
                {"id": 7, "path": "/docs", "reason": "hidden by /* above it"},
                {"id": 8, "path": "/api", "reason": "hidden by /* above it"},
            ],
        }
    }
    html = _get(manage_client, "/manage", monkeypatch, overrides=overrides)
    assert "warn-banner" in html
    assert "2 shadowed rules" in html
    assert "1 shadowed group" in html
    assert 'href="/manage/rules"' in html, "the banner routes to the page that fixes it"


def test_banner_wording_stays_singular_for_one(manage_client, monkeypatch) -> None:
    overrides = {
        f"{API}/api/warnings": {
            "groups": [],
            "rules": [{"id": 7, "path": "/docs", "reason": "hidden"}],
        }
    }
    html = _get(manage_client, "/manage", monkeypatch, overrides=overrides)
    assert "1 shadowed rule," in html
    assert "1 shadowed rules" not in html


def test_an_unreachable_warnings_endpoint_does_not_break_the_dashboard(
    manage_client, monkeypatch
) -> None:
    """`_api_proxy_get` degrades to `[]`, which must not render as a warning."""
    html = _get(manage_client, "/manage", monkeypatch, overrides={f"{API}/api/warnings": []})
    assert "warn-banner" not in html


# --------------------------------------------------------------------------- #
# The oversized stat cards are gone, and the width is fluid
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("page", "heading"), PAGES)
def test_no_page_renders_an_oversized_stat_card(manage_client, monkeypatch, page, heading) -> None:
    html = _get(manage_client, page, monkeypatch)
    assert 'class="stat-card"' not in html
    assert "stat-number" not in html
    assert "stats-row" not in html


@pytest.mark.parametrize(("page", "heading"), PAGES)
def test_no_page_carries_a_fixed_max_width(manage_client, monkeypatch, page, heading) -> None:
    """The 1100px column was the complaint; width is the stylesheet's business."""
    html = _get(manage_client, page, monkeypatch)
    assert "max-width:1100px" not in html
    assert "max-width:1200px" not in html
    assert "max-width:1400px" not in html
    assert "padding:2rem" not in html


def test_the_stat_strip_is_a_strip_not_a_card(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage/codes", monkeypatch)
    assert 'class="stat-strip"' in html
    labels = re.findall(r'<span class="stat-label">([^<]+)</span>', html)
    assert labels == ["Total codes", "Active", "Inactive"], labels


def test_the_dashboard_reads_its_numbers_from_the_api(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    labels = re.findall(r'<span class="stat-label">([^<]+)</span>', html)
    assert labels[:4] == ["Routes", "Rule groups", "Codes active / total", "Catch-alls"]
    values = re.findall(r'<span class="stat-value">([^<]+)</span>', html)
    assert values == ["1", "2", "1 / 2", "2"], values


def test_the_catch_all_census_walks_every_group(manage_client, monkeypatch) -> None:
    """`rules_count` is not enough: the panel asks each group for its rules."""
    client = _install(monkeypatch)
    manage_client.get("/manage", cookies={"manage_session": SESSION})
    rules_calls = sorted(c[1] for c in client.calls if c[1].endswith("/rules"))
    assert rules_calls == [f"{API}/api/groups/10/rules", f"{API}/api/groups/12/rules"]


def test_the_dashboard_lists_the_recent_traffic_it_fetched(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    assert "Recent traffic" in html
    assert "/reports" in html
    assert "auth_success" in html


def test_the_dashboard_shows_top_pages_with_bars(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    assert "Top pages" in html
    assert 'class="bar-fill"' in html
    widths = re.findall(r'class="bar-fill" style="width:(\d+)%"', html)
    assert widths == ["100", "25"], "bars are scaled against the busiest page"


def test_the_dashboard_shows_code_health(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage", monkeypatch)
    assert "2026-09-01 12:00:00" in html, "the newest last_accessed of any code"


def test_the_dashboard_degrades_to_empty_lists(manage_client, monkeypatch) -> None:
    """Every dashboard payload failing still renders a usable page."""
    paths = (
        f"{API}/api/routes",
        f"{API}/api/groups",
        f"{API}/api/codes",
        f"{API}/api/logs",
        f"{API}/api/logs/top",
    )
    html = _get(manage_client, "/manage", monkeypatch, overrides={path: [] for path in paths})
    assert "No traffic recorded yet." in html
    assert re.search(r'<span class="stat-value">0</span>', html)


def test_a_top_pages_page_with_no_traffic_does_not_divide_by_zero(
    manage_client, monkeypatch
) -> None:
    overrides = {f"{API}/api/logs/top": []}
    html = _get(manage_client, "/manage/top-pages", monkeypatch, overrides=overrides)
    assert "No data" in html


# --------------------------------------------------------------------------- #
# The monitoring rename
# --------------------------------------------------------------------------- #


def test_audit_page_renders_the_per_visitor_view(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage/audit", monkeypatch)
    assert "Audit" in html
    assert "203.0.113.5" in html


def test_monitoring_redirects_to_audit(manage_client, monkeypatch) -> None:
    _install(monkeypatch)
    r = manage_client.get(
        "/manage/monitoring", cookies={"manage_session": SESSION}, follow_redirects=False
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/audit"


def test_the_monitoring_alias_carries_the_query_string_nowhere(manage_client, monkeypatch) -> None:
    """A stable target, so a stale bookmark cannot smuggle options through it."""
    _install(monkeypatch)
    r = manage_client.get(
        "/manage/monitoring?limit=5", cookies={"manage_session": SESSION}, follow_redirects=False
    )
    assert r.headers["Location"] == "/manage/audit"


def test_the_template_under_the_new_name_has_no_old_heading(manage_client, monkeypatch) -> None:
    html = _get(manage_client, "/manage/audit", monkeypatch)
    assert "Monitoring —" not in html


def test_the_warnings_route_is_absent_from_the_app(manage_client, monkeypatch) -> None:
    """404 and not 405: the path is not registered at all any more."""
    _install(monkeypatch)
    for method in ("get", "post"):
        r = getattr(manage_client, method)(
            "/manage/warnings", cookies={"manage_session": SESSION}, follow_redirects=False
        )
        assert r.status_code == 404, method


def test_the_api_still_serves_warnings(manage_client, monkeypatch) -> None:
    """The page died; the keyless primitive the banner reads did not."""
    client = _install(monkeypatch)
    manage_client.get("/manage", cookies={"manage_session": SESSION})
    assert any(call[1] == f"{API}/api/warnings" for call in client.calls)
