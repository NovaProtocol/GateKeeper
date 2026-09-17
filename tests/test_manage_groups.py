"""Manage-UI group edit route.

The proxy is stubbed, so these assert the route's own contract: it gates on
`manage_session`, `csrf_token` and `same_origin` before touching the API, then
issues exactly one `PUT` carrying only the fields the owner actually filled in.
What the API does with that call is covered in `test_api_groups.py`.

The default-group case is the one that matters: the template disables the domain
input, so the payload must not carry a `domain` key at all — the API's
`cannot change default domain` guard is the backstop, not the only defence.
"""

from __future__ import annotations

from typing import Any

import pytest

import management.app as management_app
from shared.jwt import create_manage_token

CSRF = "test-csrf-token"
ORIGIN = "http://testserver"
SESSION = create_manage_token()

API_GROUPS = "http://api:8002/api/groups"

GROUPS: list[dict[str, Any]] = [
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

    def __init__(self, put_status: int = 200, put_text: str = "") -> None:
        self.put_status = put_status
        self.put_text = put_text
        self.calls: list[tuple[str, str, Any, dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None, kwargs))
        payload = GROUPS if url == API_GROUPS else []
        return _FakeResponse(200, payload)

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
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


def _edit(manage_client, gid: int = 10, **kwargs: Any):
    data = kwargs.pop("data", {"csrf_token": CSRF, "name": "renamed", "domain": "renamed.test"})
    cookies = kwargs.pop("cookies", {"manage_session": SESSION, "csrf_token": CSRF})
    headers = kwargs.pop("headers", {"Origin": ORIGIN})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        f"/manage/groups/{gid}/edit",
        data=data,
        cookies=cookies,
        headers=headers,
        **kwargs,
    )


def test_group_edit_requires_session(manage_client, fake_api: _FakeClient) -> None:
    r = _edit(manage_client, cookies=None)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")
    assert fake_api.calls == []


def test_group_edit_rejects_missing_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _edit(manage_client, data={"name": "renamed"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_group_edit_rejects_mismatched_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _edit(manage_client, data={"csrf_token": "not-the-cookie", "name": "renamed"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_group_edit_rejects_cross_origin(manage_client, fake_api: _FakeClient) -> None:
    r = _edit(manage_client, headers={"Origin": "http://evil.example.com"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_group_edit_proxies_put_to_api(manage_client, fake_api: _FakeClient) -> None:
    r = _edit(
        manage_client,
        gid=10,
        data={"csrf_token": CSRF, "name": "renamed", "domain": "renamed.test"},
        headers={"Origin": ORIGIN, "Referer": "http://testserver/manage/rules"},
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "http://testserver/manage/rules"

    assert len(fake_api.calls) == 1
    method, url, payload, kwargs = fake_api.calls[0]
    assert (method, url) == ("PUT", "http://api:8002/api/groups/10")
    assert payload == {"name": "renamed", "domain": "renamed.test"}
    assert kwargs["headers"]["X-Internal-Api-Key"] == "test-internal-api-key"


def test_group_edit_default_group_sends_name_only(manage_client, fake_api: _FakeClient) -> None:
    """The disabled domain input submits nothing, so renames stay safe."""
    r = _edit(
        manage_client,
        gid=12,
        data={"csrf_token": CSRF, "name": "catch-all"},
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 302

    assert len(fake_api.calls) == 1
    _, url, payload, _ = fake_api.calls[0]
    assert url == "http://api:8002/api/groups/12"
    assert payload == {"name": "catch-all"}
    assert "domain" not in payload


def test_group_edit_omits_blank_fields(manage_client, fake_api: _FakeClient) -> None:
    r = _edit(
        manage_client,
        gid=10,
        data={"csrf_token": CSRF, "name": "", "domain": "  "},
        headers={"Origin": ORIGIN},
    )
    assert r.status_code == 302

    assert len(fake_api.calls) == 1
    _, _, payload, _ = fake_api.calls[0]
    assert payload == {}


def test_group_edit_redirects_even_when_api_refuses(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal is logged, not surfaced as a broken page."""
    client = _FakeClient(put_status=400, put_text="cannot change default domain")
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _edit(manage_client, gid=12, headers={"Origin": ORIGIN})
    assert r.status_code == 302

    assert len(client.calls) == 1
    assert client.calls[0][0] == "PUT"


def test_rules_page_offers_the_group_edit_control(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.get("/manage/rules", cookies={"manage_session": SESSION})
    assert r.status_code == 200

    assert "openEditGroup(10, 'alpha', 'alpha.test', false)" in r.text
    assert "openEditGroup(12, '*.*/*', '*.*/*', true)" in r.text
    assert 'id="editGroupForm"' in r.text
    assert "/manage/groups/'+id+'/edit" in r.text
