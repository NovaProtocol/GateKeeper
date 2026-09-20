"""Manage-UI order routes and the rules/group table rendering.

The proxy is stubbed: these tests assert that the manage routes gate on
`manage_session`, `csrf_token` and `same_origin`, then issue exactly one `PUT`
to the API with the right body and internal key. What the API does with that
call is covered in `test_api_orders.py`.

The rendering tests assert the two honesty properties the UI promises: real
positions (1, 2, 3…) rather than the sparse `display_order`, and arrows disabled
wherever the API would no-op or refuse — the ends of a list, and the default
group (and its neighbour).
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
        "id": 11,
        "name": "beta",
        "domain": "beta.test",
        "display_order": 1,
        "is_default": False,
        "rules_count": 0,
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
        "path": "/documentation/*",
        "action": "access_code",
        "rate_limit": None,
        "display_order": 0,
        "is_default": False,
    },
    {
        "id": 2,
        "group_id": 10,
        "path": "/api/*",
        "action": "deny",
        "rate_limit": None,
        "display_order": 1,
        "is_default": False,
    },
    {
        "id": 3,
        "group_id": 10,
        "path": "/*",
        "action": "none",
        "rate_limit": None,
        "display_order": 2,
        "is_default": True,
    },
]


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Stand-in for the shared httpx client; records every call it receives."""

    def __init__(
        self,
        get_payloads: dict[str, Any] | None = None,
        put_status: int = 200,
        put_text: str = "",
    ) -> None:
        self.get_payloads = get_payloads or {}
        self.put_status = put_status
        self.put_text = put_text
        self.calls: list[tuple[str, str, Any, dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None, kwargs))
        return _FakeResponse(200, self.get_payloads.get(url, []))

    async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("PUT", url, json, kwargs))
        return _FakeResponse(self.put_status, {"ok": self.put_status < 400}, self.put_text)

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json, kwargs))
        return _FakeResponse(200, {})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("DELETE", url, None, kwargs))
        return _FakeResponse(200, {})


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient(
        get_payloads={
            "http://api:8002/api/groups": RULE_GROUPS,
            "http://api:8002/api/groups/10/rules": RULES,
        }
    )
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


@pytest.fixture()
def refusing_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    """An API that refuses the write, so the refusal path can be asserted."""
    client = _FakeClient(
        get_payloads={
            "http://api:8002/api/groups": RULE_GROUPS,
            "http://api:8002/api/groups/10/rules": RULES,
        },
        put_status=400,
    )
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


def _auth_cookies() -> dict[str, str]:
    return {"manage_session": SESSION, "csrf_token": CSRF}


def _order_controls(html: str) -> list[dict[str, Any]]:
    """Pull (position, up-disabled, down-disabled) out of each rendered row."""
    rows: list[dict[str, Any]] = []
    for row in re.findall(r"<tr\b[^>]*>(.*?)</tr>", html, re.S):
        if 'title="Move up' not in row:
            continue
        position = re.search(r'<span title="display_order (\d+)">(\d+)</span>', row)
        up = re.search(r'title="Move up([^"]*)"([^>]*)>', row)
        down = re.search(r'title="Move down([^"]*)"([^>]*)>', row)
        rows.append(
            {
                "raw_order": position.group(1) if position else None,
                "position": position.group(2) if position else None,
                "up_title": up.group(1) if up else "",
                "down_title": down.group(1) if down else "",
                "up_disabled": "disabled" in (up.group(2) if up else ""),
                "down_disabled": "disabled" in (down.group(2) if down else ""),
            }
        )
    return rows


def test_rule_order_requires_session(manage_client) -> None:
    r = manage_client.post(
        "/manage/rules/1/order",
        data={"csrf_token": CSRF, "direction": "up"},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


def test_group_order_requires_session(manage_client) -> None:
    r = manage_client.post(
        "/manage/groups/10/order",
        data={"csrf_token": CSRF, "direction": "up"},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


def test_rule_order_rejects_missing_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/1/order",
        data={"direction": "up"},
        cookies={"manage_session": SESSION},
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 403
    assert fake_api.calls == []


def test_rule_order_rejects_mismatched_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/1/order",
        data={"csrf_token": "not-the-cookie", "direction": "up"},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 403
    assert fake_api.calls == []


def test_rule_order_rejects_cross_origin(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/1/order",
        data={"csrf_token": CSRF, "direction": "up"},
        cookies=_auth_cookies(),
        headers={"Origin": "http://evil.example.com"},
    )
    assert r.status_code == 403
    assert fake_api.calls == []


def test_rule_order_rejects_bad_direction(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/1/order",
        data={"csrf_token": CSRF, "direction": "sideways"},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 400
    assert fake_api.calls == []


def test_rule_order_proxies_put_to_api(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/7/order",
        data={"csrf_token": CSRF, "direction": "up"},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN, "Referer": "http://testserver/manage/rules/10"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "http://testserver/manage/rules/10"

    assert len(fake_api.calls) == 1
    method, url, payload, kwargs = fake_api.calls[0]
    assert (method, url) == ("PUT", "http://api:8002/api/rules/7/order")
    assert payload == {"direction": "up"}
    assert kwargs["headers"]["X-Internal-Api-Key"] == "test-internal-api-key"


def test_group_order_proxies_put_to_api(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/groups/11/order",
        data={"csrf_token": CSRF, "direction": "down"},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/rules"

    assert len(fake_api.calls) == 1
    method, url, payload, _ = fake_api.calls[0]
    assert (method, url) == ("PUT", "http://api:8002/api/groups/11/order")
    assert payload == {"direction": "down"}


def test_rule_order_redirects_even_when_api_refuses(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal from the API is logged, not surfaced as a broken page."""
    client = _FakeClient(put_status=400, put_text="cannot swap with default")
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = manage_client.post(
        "/manage/rules/1/order",
        data={"csrf_token": CSRF, "direction": "up"},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert client.calls[0][0] == "PUT"


def test_rules_page_disables_the_catch_all_and_keeps_real_positions(
    manage_client, fake_api: _FakeClient
) -> None:
    r = manage_client.get("/manage/rules/10", cookies={"manage_session": SESSION})
    assert r.status_code == 200

    controls = _order_controls(r.text)
    assert [c["position"] for c in controls] == ["1", "2", "3"]
    # The raw sparse display_order survives only as a title attribute.
    assert [c["raw_order"] for c in controls] == ["0", "1", "2"]

    assert controls[0]["up_disabled"] is True
    assert controls[0]["down_disabled"] is False
    # The rule above the catch-all cannot swap down into it, and says why.
    assert controls[1]["up_disabled"] is False
    assert controls[1]["down_disabled"] is True
    assert "the catch-all is below" in controls[1]["down_title"]
    # The catch-all itself is pinned: it cannot move, and nothing can move past it.
    assert controls[2]["up_disabled"] is True
    assert controls[2]["down_disabled"] is True
    assert "the catch-all is forced last" in controls[2]["up_title"]
    assert "the catch-all is forced last" in controls[2]["down_title"]


def test_rules_page_shows_the_default_tag_on_the_catch_all(
    manage_client, fake_api: _FakeClient
) -> None:
    r = manage_client.get("/manage/rules/10", cookies={"manage_session": SESSION})
    assert r.status_code == 200
    assert 'class="tag tag-inactive">default<' in r.text
    assert "forced last" in r.text
    assert "cannot be moved, renamed or deleted" in r.text


def test_rules_page_explains_that_new_rules_land_last(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.get("/manage/rules/10", cookies={"manage_session": SESSION})
    assert r.status_code == 200
    assert "New rules are added" in r.text
    assert "never fire" in r.text


def test_groups_page_disables_arrows_at_the_ends_and_on_default(
    manage_client, fake_api: _FakeClient
) -> None:
    r = manage_client.get("/manage/rules", cookies={"manage_session": SESSION})
    assert r.status_code == 200

    controls = _order_controls(r.text)
    assert [c["position"] for c in controls] == ["1", "2", "3"]

    assert controls[0]["up_disabled"] is True
    assert controls[0]["down_disabled"] is False
    # Neighbour of the pinned default group: down would be refused by the API.
    assert controls[1]["up_disabled"] is False
    assert controls[1]["down_disabled"] is True
    assert "the default group is below" in controls[1]["down_title"]
    # The default group itself never moves, and the tooltip says why.
    assert controls[2]["up_disabled"] is True
    assert controls[2]["down_disabled"] is True
    assert "the default group is pinned last" in controls[2]["up_title"]
    assert "the default group is pinned last" in controls[2]["down_title"]


# --------------------------------------------------------------------------- #
# The status switch: a control, not a route
# --------------------------------------------------------------------------- #


def test_the_rule_status_switch_relays_active_to_the_edit_route(
    manage_client, fake_api: _FakeClient
) -> None:
    """The switch posts to the existing `/manage/rules/{rid}/edit`, nothing new."""
    r = manage_client.post(
        "/manage/rules/1/edit",
        data={"active": "0", "csrf_token": CSRF},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    put = [c for c in fake_api.calls if c[0] == "PUT" and c[1] == "http://api:8002/api/rules/1"]
    assert put, fake_api.calls
    assert put[0][2] == {"active": "0"}, "the switch must post the flag and nothing else"


def test_the_rule_status_switch_relays_an_activation(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/1/edit",
        data={"active": "1", "csrf_token": CSRF},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    put = [c for c in fake_api.calls if c[0] == "PUT" and c[1] == "http://api:8002/api/rules/1"]
    assert put and put[0][2] == {"active": "1"}


def test_an_edit_that_does_not_carry_active_leaves_it_alone(
    manage_client, fake_api: _FakeClient
) -> None:
    """The edit modal must not blank the flag by omitting it."""
    r = manage_client.post(
        "/manage/rules/1/edit",
        data={"path": "/named/*", "action": "none", "csrf_token": CSRF},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    put = [c for c in fake_api.calls if c[0] == "PUT" and c[1] == "http://api:8002/api/rules/1"]
    assert put and "active" not in put[0][2]


def test_the_rule_status_switch_needs_the_csrf_token(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.post(
        "/manage/rules/1/edit",
        data={"active": "0"},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 403


def test_the_rule_status_switch_rejects_a_cross_origin_post(
    manage_client, fake_api: _FakeClient
) -> None:
    r = manage_client.post(
        "/manage/rules/1/edit",
        data={"active": "0", "csrf_token": CSRF},
        cookies=_auth_cookies(),
        headers={"Origin": "https://evil.test"},
        follow_redirects=False,
    )
    assert r.status_code == 403


def test_a_refused_switch_is_logged(manage_client, monkeypatch, refusing_api: _FakeClient) -> None:
    """A switch that silently does nothing would look like a dead control.

    The API refuses switching the catch-all off, and the panel relays that
    refusal into the container log rather than swallowing it — otherwise the
    control just appears broken.
    """
    logged: list[Any] = []
    monkeypatch.setattr(management_app, "_slog", lambda *a, **k: logged.append((a, k)))

    r = manage_client.post(
        "/manage/rules/2/edit",
        data={"active": "0", "csrf_token": CSRF},
        cookies=_auth_cookies(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert r.status_code == 302
    assert any(a and a[0] == "rule_active_refused" for a, _ in logged), logged
