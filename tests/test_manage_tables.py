"""Markup pins for the action tables.

Two regressions are worth pinning at the markup level, because both were
invisible in review and one of them shipped in three templates unnoticed:

1. The last cell of a row must stay a table cell. An inline `display:flex` on a
   `<td>` drops it out of the table layout algorithm, so it stops stretching to
   its row's height and its bottom border ends early — the column borders no
   longer meet. The layout belongs on an inner `.actions` wrapper.
2. Every icon-only control in a table row must carry a non-empty `aria-label`.
   Removing the visible word removes the accessible name, so the label has to
   come from somewhere.

The narrow-width behaviour is proven against a real Chromium in
`tests/ui/check_tables.py`; these are the cheap guards that fail fast.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

import management.app as management_app
from shared.jwt import create_manage_token

SESSION = create_manage_token()

RULE_GROUPS: list[dict[str, Any]] = [
    {
        "id": 10,
        "name": "alpha",
        "domain": "alpha.test",
        "display_order": 0,
        "is_default": False,
        "rules_count": 2,
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

GROUP_RULES: list[dict[str, Any]] = [
    {
        "id": 1,
        "group_id": 10,
        "path": "/documentation/*",
        "action": "access_code",
        "rate_limit": None,
        "display_order": 0,
        "is_default": False,
    },
    {
        "id": 2,
        "group_id": 10,
        "path": "/*",
        "action": "none",
        "rate_limit": None,
        "display_order": 1,
        "is_default": True,
    },
]

ROUTES: list[dict[str, Any]] = [
    {
        "id": 5,
        "host": "app.test",
        "path": "/",
        "route_type": "proxy",
        "upstream": "app",
        "port": 8080,
        "redirect_target": None,
        "redirect_code": None,
    },
    {
        "id": 6,
        "host": "old.test",
        "path": "/",
        "route_type": "redirect",
        "upstream": None,
        "port": None,
        "redirect_target": "https://new.test",
        "redirect_code": 302,
    },
]

CODES: list[dict[str, Any]] = [
    {
        "id": 3,
        "code": "abcd1234",
        "label": "Alice",
        "display_name": "Alice",
        "active": True,
        "created_at": "2026-01-01",
        "last_accessed": None,
    }
]


class _FakeResponse:
    def __init__(self, payload: Any = None) -> None:
        self.status_code = 200
        self._payload = payload
        self.text = ""

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    def __init__(self, payloads: dict[str, Any]) -> None:
        self.payloads = payloads

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(self.payloads.get(url, []))

    async def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


RULES_PAGE = {"/api/groups": RULE_GROUPS}
DETAIL_PAGE = {"/api/groups": RULE_GROUPS, "/api/groups/10/rules": GROUP_RULES}
CODES_PAGE = {"/api/codes": CODES}
ROUTING_PAGE = {"/api/routes": ROUTES}

TABLE_PAGES = [
    pytest.param("/manage/rules", RULES_PAGE, id="groups"),
    pytest.param("/manage/rules/10", DETAIL_PAGE, id="rules"),
    pytest.param("/manage/codes", CODES_PAGE, id="codes"),
    pytest.param("/manage/routing", ROUTING_PAGE, id="routing"),
]


def _get(
    manage_client, page: str, monkeypatch: pytest.MonkeyPatch, payloads: dict[str, Any]
) -> str:
    client = _FakeClient({f"http://api:8002{k}": v for k, v in payloads.items()})
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    r = manage_client.get(page, cookies={"manage_session": SESSION})
    assert r.status_code == 200, r.text
    return r.text


def _card_header(html: str) -> str:
    header = re.search(r'<div class="card-header"[^>]*>(.*?)</div>\s*</div>', html, re.S)
    assert header, "no card header found"
    return header.group(1)


def _action_cells(html: str) -> list[str]:
    cells = re.findall(r'<td class="actions-cell"[^>]*>(.*?)</td>', html, re.S)
    assert cells, "no action cell rendered"
    return cells


def _row_controls(html: str) -> list[str]:
    rows = re.findall(r"<tr[^>]*>\s*<td.*?</tr>", html, re.S)
    assert rows, "no rows rendered"
    controls: list[str] = []
    for row in rows:
        cell = re.search(r'<td class="actions-cell"[^>]*>(.*?)</td>', row, re.S)
        if not cell:
            continue
        controls.extend(re.findall(r"<(?:a|button)\b[^>]*>", cell.group(1)))
    return controls


@pytest.mark.parametrize(("page", "payloads"), TABLE_PAGES)
def test_action_cells_are_real_table_cells(manage_client, monkeypatch, page, payloads) -> None:
    html = _get(manage_client, page, monkeypatch, payloads)

    # No inline flex on a <td> anywhere: that is the bug, whatever its spelling.
    inline_flex = r"<td[^>]*style=\"[^\"]*display:\s*flex"
    assert not re.search(inline_flex, html), "flex must not sit on a <td>"

    for cell in _action_cells(html):
        assert '<div class="actions">' in cell, "flex belongs on the inner .actions wrapper"


@pytest.mark.parametrize(("page", "payloads"), TABLE_PAGES)
def test_tables_are_wrapped_in_a_focusable_scroll_region(
    manage_client, monkeypatch, page, payloads
) -> None:
    html = _get(manage_client, page, monkeypatch, payloads)

    wrapper = re.search(r'<div class="table-scroll"([^>]*)>', html)
    assert wrapper, "the table needs its own scroll box inside the clipping card"
    attrs = wrapper.group(1)
    assert 'tabindex="0"' in attrs, "an unfocusable scroll container is an accessibility defect"
    assert 'role="region"' in attrs
    assert re.search(r'aria-label="[^"]+"', attrs), "the scroll region must be named"


@pytest.mark.parametrize(("page", "payloads"), TABLE_PAGES)
def test_every_icon_only_row_control_has_an_accessible_name(
    manage_client, monkeypatch, page, payloads
) -> None:
    html = _get(manage_client, page, monkeypatch, payloads)
    controls = _row_controls(html)

    assert controls, f"no row controls rendered for {page}"
    for control in controls:
        assert re.search(r'aria-label="[^"]+"', control), f"missing aria-label: {control}"
        assert re.search(r'title="[^"]+"', control), f"missing title: {control}"


@pytest.mark.parametrize(("page", "payloads"), TABLE_PAGES)
def test_row_controls_render_no_visible_words(manage_client, monkeypatch, page, payloads) -> None:
    """Icon-only means the glyph is the content, not a glyph plus a label."""
    html = _get(manage_client, page, monkeypatch, payloads)
    for cell in _action_cells(html):
        # Strip the markup; whatever text remains would be a visible word.
        text = re.sub(r"<[^>]+>", "", cell).strip()
        assert text == "", f"visible text left in an icon-only cell: {text!r}"


def test_destructive_row_controls_keep_their_confirm(manage_client, monkeypatch) -> None:
    """Icon-ifying a destructive action must not drop its confirmation."""
    rules_html = _get(manage_client, "/manage/rules", monkeypatch, RULES_PAGE)
    assert "return confirm('Delete group?')" in rules_html

    detail_html = _get(manage_client, "/manage/rules/10", monkeypatch, DETAIL_PAGE)
    assert "return confirm('Delete rule?')" in detail_html

    # Codes: deactivation is reversible, so one confirm is enough. The permanent
    # delete is a separate, typed confirmation checked on the server.
    codes_html = _get(manage_client, "/manage/codes", monkeypatch, CODES_PAGE)
    assert "return switchAction(this, 3, 'Deactivate this code?')" in codes_html
    assert 'id="deleteCodeForm"' in codes_html
    assert 'name="confirm_code"' in codes_html

    routing_html = _get(manage_client, "/manage/routing", monkeypatch, ROUTING_PAGE)
    assert "return confirm('Delete route?')" in routing_html


def test_default_group_and_catch_all_controls_are_disabled_not_hidden(
    manage_client, monkeypatch
) -> None:
    """A hidden control explains nothing; a disabled one carries its reason."""
    rules_html = _get(manage_client, "/manage/rules", monkeypatch, RULES_PAGE)
    assert 'title="The default group cannot be deleted"' in rules_html
    assert 'aria-disabled="true"' in rules_html

    detail_html = _get(manage_client, "/manage/rules/10", monkeypatch, DETAIL_PAGE)
    assert 'title="The catch-all cannot be deleted — delete the group instead"' in detail_html
    # The catch-all's own delete form must be gone, not merely disabled.
    assert 'class="tag tag-inactive">default<' in detail_html


def test_routing_card_header_keeps_the_adjacent_add_labels(manage_client, monkeypatch) -> None:
    """The one exception: two bare `+` glyphs side by side would be identical."""
    html = _get(manage_client, "/manage/routing", monkeypatch, ROUTING_PAGE)
    header = _card_header(html)
    assert "Add Proxy Route" in header
    assert "Add Redirect Route" in header


@pytest.mark.parametrize(
    ("page", "payloads", "word"),
    [
        pytest.param("/manage/rules", RULES_PAGE, "Add Group", id="groups"),
        pytest.param("/manage/rules/10", DETAIL_PAGE, "Add Rule", id="rules"),
        pytest.param("/manage/codes", CODES_PAGE, "Add Code", id="codes"),
    ],
)
def test_single_add_buttons_are_icon_only(manage_client, monkeypatch, page, payloads, word) -> None:
    html = _get(manage_client, page, monkeypatch, payloads)
    header = _card_header(html)

    # The word survives only as the accessible name, never as visible text.
    assert f"</i> {word}" not in header
    assert f'title="{word}"' in header
    assert f'aria-label="{word}"' in header


def test_stylesheet_is_cache_busted(manage_client, monkeypatch) -> None:
    """A stale cached stylesheet would make a correct deploy look broken."""
    html = _get(manage_client, "/manage/rules", monkeypatch, RULES_PAGE)
    assert re.search(r'href="[^"]*manage\.css\?v=2"', html)
