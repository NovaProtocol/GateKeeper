"""The manage panel's code routes: deactivate/reactivate and permanent delete.

Two routes are exercised here, and they are not equally dangerous:

* ``/manage/codes/{cid}/active`` is reversible. It relays a single ``PUT`` and
  redirects, and a refusal from the API is logged rather than surfaced.
* ``/manage/codes/{cid}/delete`` removes the row. The modal in the template is
  decoration; the gate that counts is the one in the route, which reads the code
  back from the API and compares it with ``secrets.compare_digest`` before
  issuing the delete. A stale tab, a replayed form post or a script cannot skip
  it, and these tests exist so it cannot be dropped in a later refactor.

Both routes sit behind three gates: ``manage_session``, the double-submit CSRF
cookie/form pair, and ``same_origin``. Each is asserted independently and with
an empty call log, so a gate that stopped short-circuiting fails here.

The final test drives the real management app against the real internal API over
ASGI instead of a stand-in, because the claim it checks (deleting a code nulls
``audit_logs.code_id`` and keeps the row) is a database fact that no amount of
proxy stubbing can prove.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

import management.app as management_app
from api.app import app as api_app
from shared.jwt import create_manage_token
from tests.conftest import TEST_INTERNAL_API_KEY

CSRF = "test-csrf-token"
ORIGIN = "http://testserver"
SESSION = create_manage_token()

API = "http://api:8002"
INTERNAL_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

CODE_ID = 42
CODE_VALUE = "confirm-me-if-you-can"

CODE = {
    "id": CODE_ID,
    "code": CODE_VALUE,
    "label": "Alice",
    "display_name": "Alice",
    "active": True,
    "created_at": "2026-01-01 10:00:00",
    "last_accessed": None,
}


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
    """Records every relayed call so a silent relay is a visible failure."""

    def __init__(self, delete_status: int = 200) -> None:
        self.delete_status = delete_status
        self.calls: list[tuple[str, str, Any, dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None, kwargs))
        if url == f"{API}/api/codes/{CODE_ID}":
            return _FakeResponse(200, CODE)
        return _FakeResponse(200, [CODE])

    async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("PUT", url, json, kwargs))
        return _FakeResponse(200, {"ok": True})

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json, kwargs))
        return _FakeResponse(200, {})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("DELETE", url, None, kwargs))
        return _FakeResponse(self.delete_status, {"ok": self.delete_status < 400})


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


def _auth() -> dict[str, str]:
    return {"manage_session": SESSION, "csrf_token": CSRF}


def _toggle(manage_client, active: bool, **kwargs: Any):
    data = kwargs.pop("data", {"csrf_token": CSRF, "active": "1" if active else "0"})
    cookies = kwargs.pop("cookies", _auth())
    headers = kwargs.pop("headers", {"Origin": ORIGIN})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        f"/manage/codes/{CODE_ID}/active",
        data=data,
        cookies=cookies,
        headers=headers,
        **kwargs,
    )


def _delete(manage_client, confirm: str | None = CODE_VALUE, **kwargs: Any):
    data = kwargs.pop("data", {"csrf_token": CSRF, "confirm_code": confirm})
    cookies = kwargs.pop("cookies", _auth())
    headers = kwargs.pop("headers", {"Origin": ORIGIN})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        f"/manage/codes/{CODE_ID}/delete",
        data=data,
        cookies=cookies,
        headers=headers,
        **kwargs,
    )


def _relayed(client: _FakeClient, method: str) -> list[tuple[str, str, Any, dict[str, Any]]]:
    return [c for c in client.calls if c[0] == method]


# --------------------------------------------------------------------------- #
# Gates on both routes
# --------------------------------------------------------------------------- #


def test_active_requires_session(manage_client, fake_api: _FakeClient) -> None:
    r = _toggle(manage_client, False, cookies=None)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")
    assert fake_api.calls == []


def test_delete_requires_session(manage_client, fake_api: _FakeClient) -> None:
    r = _delete(manage_client, cookies=None)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")
    assert fake_api.calls == []


def test_active_rejects_missing_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _toggle(manage_client, False, data={"active": "0"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_active_rejects_mismatched_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _toggle(manage_client, False, data={"csrf_token": "not-the-cookie", "active": "0"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_delete_rejects_missing_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _delete(manage_client, data={"confirm_code": CODE_VALUE})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_delete_rejects_mismatched_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _delete(manage_client, data={"csrf_token": "not-the-cookie", "confirm_code": CODE_VALUE})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_active_rejects_cross_origin(manage_client, fake_api: _FakeClient) -> None:
    r = _toggle(manage_client, False, headers={"Origin": "http://evil.example.com"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_delete_rejects_cross_origin(manage_client, fake_api: _FakeClient) -> None:
    r = _delete(manage_client, headers={"Origin": "http://evil.example.com"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_both_routes_refuse_a_request_with_no_origin_at_all(
    manage_client, fake_api: _FakeClient
) -> None:
    """No Origin and no Referer is not same-origin, so it is refused."""
    for response in (
        _toggle(manage_client, False, headers={}),
        _delete(manage_client, headers={}),
    ):
        assert response.status_code == 403
    assert fake_api.calls == []


# --------------------------------------------------------------------------- #
# Activate and deactivate
# --------------------------------------------------------------------------- #


def test_deactivate_relays_active_false_and_redirects(manage_client, fake_api: _FakeClient) -> None:
    r = _toggle(manage_client, False)
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/codes"

    calls = _relayed(fake_api, "PUT")
    assert len(calls) == 1
    _, url, payload, kwargs = calls[0]
    assert url == f"{API}/api/codes/{CODE_ID}"
    assert payload == {"active": False}
    assert kwargs["headers"]["X-Internal-Api-Key"] == TEST_INTERNAL_API_KEY


def test_reactivate_relays_active_true(manage_client, fake_api: _FakeClient) -> None:
    r = _toggle(manage_client, True)
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/codes"

    calls = _relayed(fake_api, "PUT")
    assert len(calls) == 1
    assert calls[0][2] == {"active": True}


@pytest.mark.parametrize("raw", ["1", "true", "yes", "TRUE"])
def test_active_accepts_the_spellings_a_checkbox_might_send(
    manage_client, fake_api: _FakeClient, raw: str
) -> None:
    r = _toggle(manage_client, False, data={"csrf_token": CSRF, "active": raw})
    assert r.status_code == 302
    assert _relayed(fake_api, "PUT")[0][2] == {"active": True}


def test_active_redirects_even_when_the_api_refuses(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refusal is logged, not turned into a broken page."""

    class _Refusing(_FakeClient):
        async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
            self.calls.append(("PUT", url, json, kwargs))
            return _FakeResponse(400, None, text="active must be true or false")

    client = _Refusing()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _toggle(manage_client, False)
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/codes"
    assert len(_relayed(client, "PUT")) == 1


def test_active_never_touches_the_delete_route(manage_client, fake_api: _FakeClient) -> None:
    _toggle(manage_client, False)
    assert _relayed(fake_api, "DELETE") == []


# --------------------------------------------------------------------------- #
# Permanent delete
# --------------------------------------------------------------------------- #


def test_delete_with_the_right_code_relays_one_delete(manage_client, fake_api: _FakeClient) -> None:
    r = _delete(manage_client)
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/codes"

    assert [c[1] for c in _relayed(fake_api, "GET")] == [f"{API}/api/codes/{CODE_ID}"]
    deletes = _relayed(fake_api, "DELETE")
    assert len(deletes) == 1
    _, url, _, kwargs = deletes[0]
    assert url == f"{API}/api/codes/{CODE_ID}"
    assert kwargs["headers"]["X-Internal-Api-Key"] == TEST_INTERNAL_API_KEY


@pytest.mark.parametrize(
    "supplied",
    [
        pytest.param("", id="empty"),
        pytest.param(None, id="absent"),
        pytest.param("wrong-code", id="wrong"),
        pytest.param(f" {CODE_VALUE} ", id="padded"),
        pytest.param(CODE_VALUE.upper(), id="wrong-case"),
    ],
)
def test_delete_refuses_anything_but_the_exact_code(
    manage_client, fake_api: _FakeClient, supplied: str | None
) -> None:
    """The comparison happens on the server, so the modal is not the gate."""
    r = _delete(manage_client, confirm=supplied)
    assert r.status_code == 400
    assert _relayed(fake_api, "DELETE") == [], "a refused confirm must not reach the API"


def test_delete_reads_the_code_back_before_comparing(manage_client, fake_api: _FakeClient) -> None:
    """The value compared against is the stored one, never the form's own copy."""
    _delete(manage_client)
    gets = _relayed(fake_api, "GET")
    assert [c[1] for c in gets] == [f"{API}/api/codes/{CODE_ID}"]


def test_delete_reports_a_missing_code_as_404(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_api_proxy_get` answers 404 with an empty list, which is not a code."""

    class _Missing(_FakeClient):
        async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
            self.calls.append(("GET", url, None, kwargs))
            return _FakeResponse(404, [])

    client = _Missing()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _delete(manage_client)
    assert r.status_code == 404
    assert _relayed(client, "DELETE") == []


def test_delete_stops_when_the_code_cannot_be_read_back(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable API fails closed: nothing to compare, nothing deleted.

    `_api_proxy_get` swallows transport errors and answers `[]`, so the route's
    own 502 branch is unreachable through it and the refusal arrives as a 404
    instead. The outcome that matters is the same either way: the delete is not
    issued.
    """

    class _Broken(_FakeClient):
        async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
            raise RuntimeError("no route to host")

    client = _Broken()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _delete(manage_client)
    assert r.status_code in (404, 502)
    assert _relayed(client, "DELETE") == []


def test_delete_surfaces_an_api_refusal(manage_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(delete_status=409)
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _delete(manage_client)
    assert r.status_code == 409
    assert len(_relayed(client, "DELETE")) == 1


def test_codes_page_offers_the_typed_confirmation_field(
    manage_client, fake_api: _FakeClient
) -> None:
    r = manage_client.get("/manage/codes", cookies={"manage_session": SESSION})
    assert r.status_code == 200

    assert 'id="deleteCodeForm"' in r.text
    assert 'name="confirm_code"' in r.text
    # The modal names the code and the script points the form at the row's own
    # delete URL, so the template cannot be pointing at a different code.
    assert 'id="delete-code-shown"' in r.text
    assert re.search(r"/manage/codes/'\+cid\+'/delete", r.text)


# --------------------------------------------------------------------------- #
# End to end: the manage delete against the real API and a real database
# --------------------------------------------------------------------------- #


@pytest.fixture()
def real_api(monkeypatch: pytest.MonkeyPatch) -> Iterator[httpx.AsyncClient]:
    """Relay the manage panel straight into the internal API over ASGI.

    The management app talks to `http://api:8002` with httpx, so pointing that
    same client at the API's ASGI app keeps every hop and every header and drops
    only the socket.
    """
    transport = httpx.ASGITransport(app=api_app)
    client = httpx.AsyncClient(transport=transport, base_url=API, timeout=10.0)
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    yield client


def _create_code(client, code: str = CODE_VALUE) -> dict:
    r = client.post("/api/codes", json={"code": code, "label": "e2e"}, headers=INTERNAL_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()


def _insert_log(client, code_id: int) -> int:
    payload = {
        "ip": "203.0.113.77",
        "host": "codes-e2e.test",
        "path": "/reports",
        "action": "auth_success",
        "code_id": code_id,
    }
    r = client.post("/api/logs", json=payload, headers=INTERNAL_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _log_rows(client) -> list[dict]:
    r = client.get("/api/logs", params={"per_page": 100})
    assert r.status_code == 200, r.text
    return r.json()


def test_delete_through_the_panel_nullifies_the_audit_reference_but_keeps_the_row(
    manage_client, client, real_api
) -> None:
    """The irreversible action, exercised end to end instead of stubbed.

    `client` is requested to guarantee the API's lifespan has seeded the shared
    test database; `real_api` then relays the panel's own requests into it.
    """
    created = _create_code(client)
    log_id = _insert_log(client, created["id"])
    assert next(row for row in _log_rows(client) if row["id"] == log_id)["code_id"] == created["id"]

    r = manage_client.post(
        f"/manage/codes/{created['id']}/delete",
        data={"csrf_token": CSRF, "confirm_code": created["code"]},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"] == "/manage/codes"

    gone = client.get(f"/api/codes/{created['id']}")
    assert gone.status_code == 404, "the code itself is removed"

    row = next(entry for entry in _log_rows(client) if entry["id"] == log_id)
    assert row["code_id"] is None, "the dangling reference is nulled"
    assert row["host"] == "codes-e2e.test"
    assert row["path"] == "/reports"
    assert row["action"] == "auth_success"


def test_a_wrong_code_through_the_panel_leaves_the_row_and_its_logs_alone(
    manage_client, client, real_api
) -> None:
    created = _create_code(client, code=f"{CODE_VALUE}-second")
    log_id = _insert_log(client, created["id"])

    r = manage_client.post(
        f"/manage/codes/{created['id']}/delete",
        data={"csrf_token": CSRF, "confirm_code": "not-the-code"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    assert r.status_code == 400

    assert client.get(f"/api/codes/{created['id']}").status_code == 200, "still there"
    row = next(entry for entry in _log_rows(client) if entry["id"] == log_id)
    assert row["code_id"] == created["id"], "the audit reference is untouched"
