"""The backup page and its proxy routes.

The manage panel never touches the database: it relays to `api:8002` with the
internal key. So these tests drive a recording stand-in for the httpx client and
assert the three gates on every mutating route, the two-step preview/apply
shape, and the honesty the page promises in words — that the file is plaintext,
and that a preview does not write.

The rendering assertions parse real HTML from the template, so a change that
quietly drops the plaintext warning or the disabled-until-confirmed restore
button fails here rather than in review.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

import management.app as management_app
from shared.jwt import create_manage_token

CSRF = "test-csrf-token"
ORIGIN = "http://testserver"
SESSION = create_manage_token()
API = "http://api:8002"

GROUPS = [
    {
        "id": 1,
        "name": "*.*/*",
        "domain": "*.*/*",
        "display_order": 9999,
        "is_default": True,
        "rules_count": 1,
    },
]
RULES = [
    {"id": 1, "group_id": 1, "path": "/*", "action": "access_code", "display_order": 0},
]
ROUTES = [
    {
        "id": 1,
        "host": "example.test",
        "path": "/",
        "route_type": "proxy",
        "upstream": "x",
        "port": 8080,
    }
]
CODES = [{"id": 1, "code": "alpha-code", "label": "alpha", "display_name": "alpha", "active": True}]
SETTINGS = [
    {"key": "backup_exported_at", "value": "2026-09-17T10:00:00Z"},
    {"key": "rate_limit_access_code_per_min", "value": "60"},
]

EXPORT_BODY = {
    "version": 1,
    "created_at": "2026-09-17T10:00:00Z",
    "config": {
        "routes": ROUTES,
        "groups": GROUPS,
        "rules": RULES,
        "codes": CODES,
        "settings": SETTINGS,
    },
    "sig": "a" * 64,
}


class _FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: Any = None,
        text: str = "",
        content: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = content
        self.headers = headers or {}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Records every relayed call and replays canned answers per URL."""

    def __init__(
        self, restore_status: int = 200, restore_body: dict[str, Any] | None = None
    ) -> None:
        self.restore_status = restore_status
        self.restore_body = (
            restore_body
            if restore_body is not None
            else {
                "ok": True,
                "sig": True,
                "reason": "ok",
                "problems": [],
                "counts": {"routes": 1, "groups": 1, "rules": 1, "codes": 1, "settings": 2},
                "detached_logs": {},
            }
        )
        self.calls: list[tuple[str, str, Any, dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None, kwargs))
        if url.endswith("/api/backup"):
            body = json.dumps(EXPORT_BODY, indent=2).encode()
            disposition = "attachment; filename=gatekeeper-config-20260917-100000.json"
            return _FakeResponse(
                200, EXPORT_BODY, content=body, headers={"content-disposition": disposition}
            )
        payload = {
            f"{API}/api/groups": GROUPS,
            f"{API}/api/groups/1/rules": RULES,
            f"{API}/api/routes": ROUTES,
            f"{API}/api/codes": CODES,
            f"{API}/api/settings": SETTINGS,
        }.get(url, [])
        return _FakeResponse(200, payload)

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json, kwargs))
        if url.endswith("/api/backup/restore"):
            return _FakeResponse(self.restore_status, self.restore_body)
        return _FakeResponse(200, {})

    async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("PUT", url, json, kwargs))
        return _FakeResponse(200, {})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("DELETE", url, None, kwargs))
        return _FakeResponse(200, {})


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


def _auth() -> dict[str, str]:
    return {"manage_session": SESSION, "csrf_token": CSRF}


def _upload(blob: Any = EXPORT_BODY, filename: str = "backup.json") -> dict[str, Any]:
    return {"file": (filename, json.dumps(blob).encode(), "application/json")}


def _restore_post(manage_client, **kwargs: Any):
    data = kwargs.pop("data", {"csrf_token": CSRF, "confirm": "REPLACE", "stage": "preview"})
    files = kwargs.pop("files", _upload())
    cookies = kwargs.pop("cookies", _auth())
    headers = kwargs.pop("headers", {"Origin": ORIGIN})
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        "/manage/backup/restore", data=data, files=files, cookies=cookies, headers=headers, **kwargs
    )


# --------------------------------------------------------------------------- #
# Gates
# --------------------------------------------------------------------------- #


def test_backup_page_requires_session(manage_client) -> None:
    r = manage_client.get("/manage/backup", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


def test_download_requires_session(manage_client) -> None:
    r = manage_client.get("/manage/backup/download", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


def test_restore_requires_session(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(manage_client, cookies=None)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")
    assert fake_api.calls == []


def test_restore_rejects_missing_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(manage_client, data={"confirm": "REPLACE", "stage": "apply"})
    assert r.status_code == 403
    assert fake_api.calls == []


def test_restore_rejects_mismatched_csrf(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(
        manage_client, data={"csrf_token": "nope", "confirm": "REPLACE", "stage": "apply"}
    )
    assert r.status_code == 403
    assert fake_api.calls == []


def test_restore_rejects_cross_origin(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(manage_client, headers={"Origin": "http://evil.example.com"})
    assert r.status_code == 403
    assert fake_api.calls == []


@pytest.mark.parametrize("confirm", ["", "replace", "REPL", "REPLACE ME", "DELETE"])
def test_restore_requires_the_exact_confirm_word(
    manage_client, fake_api: _FakeClient, confirm: str
) -> None:
    """Checked on the server, so a crafted post cannot skip the modal."""
    r = _restore_post(
        manage_client, data={"csrf_token": CSRF, "confirm": confirm, "stage": "apply"}
    )
    assert r.status_code == 403
    assert "REPLACE" in r.json()["detail"]
    assert fake_api.calls == []


def test_restore_rejects_an_unknown_stage(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(
        manage_client, data={"csrf_token": CSRF, "confirm": "REPLACE", "stage": "sideways"}
    )
    assert r.status_code == 400
    assert fake_api.calls == []


# --------------------------------------------------------------------------- #
# Relay behaviour
# --------------------------------------------------------------------------- #


def test_download_streams_the_api_blob_unchanged(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.get("/manage/backup/download", cookies={"manage_session": SESSION})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "gatekeeper-config-20260917-100000.json" in r.headers["content-disposition"]
    assert json.loads(r.text) == EXPORT_BODY

    calls = [c for c in fake_api.calls if c[1].endswith("/api/backup")]
    assert len(calls) == 1
    assert calls[0][0] == "GET"
    assert calls[0][3]["headers"]["X-Internal-Api-Key"] == "test-internal-api-key"


def test_download_reports_an_unreachable_api(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Broken(_FakeClient):
        async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
            if url.endswith("/api/backup"):
                raise RuntimeError("no route to host")
            return await super().get(url, **kwargs)

    monkeypatch.setattr(management_app, "_get_httpx", lambda: _Broken())
    r = manage_client.get("/manage/backup/download", cookies={"manage_session": SESSION})
    assert r.status_code == 502


def test_preview_calls_the_dry_run_and_writes_nothing(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(manage_client)
    assert r.status_code == 200

    calls = [c for c in fake_api.calls if c[1].endswith("/api/backup/restore")]
    assert len(calls) == 1
    method, _, payload, kwargs = calls[0]
    assert method == "POST"
    assert kwargs["params"] == {"dry_run": 1}
    assert payload == EXPORT_BODY
    assert kwargs["headers"]["X-Internal-Api-Key"] == "test-internal-api-key"

    assert "Nothing has been written yet" in r.text


def test_apply_calls_the_api_without_the_dry_run_flag(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(
        manage_client, data={"csrf_token": CSRF, "confirm": "REPLACE", "stage": "apply"}
    )
    assert r.status_code == 200

    calls = [c for c in fake_api.calls if c[1].endswith("/api/backup/restore")]
    assert len(calls) == 1
    assert calls[0][3].get("params") is None
    assert "Configuration replaced" in r.text


def test_a_refused_restore_is_shown_as_refused(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _FakeClient(
        restore_status=409,
        restore_body={"ok": False, "sig": False, "reason": "bad-sig", "problems": [], "counts": {}},
    )
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _restore_post(
        manage_client, data={"csrf_token": CSRF, "confirm": "REPLACE", "stage": "apply"}
    )
    assert r.status_code == 200
    assert "bad-sig" in r.text


def test_validation_problems_are_listed(manage_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(
        restore_status=400,
        restore_body={
            "ok": False,
            "sig": True,
            "reason": "invalid-config",
            "problems": ["routes[0]: port must be 1-65535", "groups[0]: name required"],
            "counts": {},
        },
    )
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _restore_post(manage_client)
    assert "routes[0]: port must be 1-65535" in r.text
    assert "groups[0]: name required" in r.text
    assert "invalid-config" in r.text


def test_detached_log_counts_are_shown(manage_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _FakeClient(
        restore_body={
            "ok": True,
            "sig": True,
            "reason": "ok",
            "problems": [],
            "counts": {"routes": 1, "groups": 1, "rules": 1, "codes": 0, "settings": 2},
            "detached_logs": {"code_id": 7},
        }
    )
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    r = _restore_post(
        manage_client, data={"csrf_token": CSRF, "confirm": "REPLACE", "stage": "apply"}
    )
    assert "audit rows detached from code_id: 7" in r.text


def test_a_file_that_is_not_json_is_refused_before_the_api_is_called(
    manage_client, fake_api: _FakeClient
) -> None:
    r = _restore_post(
        manage_client, files={"file": ("backup.json", b"not json at all", "application/json")}
    )
    assert r.status_code == 200
    assert "not a GateKeeper backup" in r.text
    assert [c for c in fake_api.calls if c[1].endswith("/api/backup/restore")] == []


def test_a_json_file_that_is_not_a_backup_is_refused(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(manage_client, files=_upload({"hello": "world"}))
    assert r.status_code == 200
    assert "not a GateKeeper backup" in r.text
    assert [c for c in fake_api.calls if c[1].endswith("/api/backup/restore")] == []


def test_no_file_is_refused(manage_client, fake_api: _FakeClient) -> None:
    r = _restore_post(manage_client, files={"file": ("", b"", "application/json")})
    assert r.status_code == 200
    assert "Choose a backup file first" in r.text
    assert [c for c in fake_api.calls if c[1].endswith("/api/backup/restore")] == []


# --------------------------------------------------------------------------- #
# The page
# --------------------------------------------------------------------------- #


def test_backup_page_renders_both_cards(manage_client, fake_api: _FakeClient) -> None:
    r = manage_client.get("/manage/backup", cookies={"manage_session": SESSION})
    assert r.status_code == 200
    assert "Export" in r.text
    assert "Restore" in r.text
    assert 'href="/manage/backup/download"' in r.text
    assert 'action="/manage/backup/restore"' in r.text
    assert 'enctype="multipart/form-data"' in r.text


def test_backup_page_states_that_the_file_is_plaintext(
    manage_client, fake_api: _FakeClient
) -> None:
    """The one thing an operator must not have to discover for themselves."""
    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    assert "plain text and contains every access code" in html
    assert "does not hide anything" in html
    assert "Store it like a password" in html


def test_backup_page_lists_the_current_counts(manage_client, fake_api: _FakeClient) -> None:
    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    for section in ("routes", "groups", "rules", "codes", "settings"):
        assert re.search(rf"<td>{section}</td><td>\d+</td>", html), section
    assert "Last export taken 2026-09-17T10:00:00Z" in html


def test_backup_page_shows_no_export_taken_yet(
    manage_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _FakeClient()
    original = client.get

    async def get(url: str, **kwargs: Any) -> _FakeResponse:
        if url.endswith("/api/settings"):
            client.calls.append(("GET", url, None, kwargs))
            return _FakeResponse(200, [{"key": "rate_limit_access_code_per_min", "value": "60"}])
        return await original(url, **kwargs)

    monkeypatch.setattr(client, "get", get)
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)

    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    assert "No export has been taken from this panel yet" in html


def test_restore_control_is_disabled_until_file_and_confirmation(
    manage_client, fake_api: _FakeClient
) -> None:
    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    assert re.search(r'id="preview-btn"[^>]*disabled', html)
    assert re.search(r'id="apply-btn"[^>]*disabled', html)
    assert "files.length>0 && confirmField.value.trim()===word" in html


def test_restore_form_carries_both_stages(manage_client, fake_api: _FakeClient) -> None:
    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    assert 'name="stage" value="preview"' in html
    assert 'name="stage" value="apply"' in html
    assert 'name="confirm"' in html
    assert "Type REPLACE to confirm" in html


def test_restore_actions_carry_titles_and_labels(manage_client, fake_api: _FakeClient) -> None:
    """House rule: icon controls keep both, because the glyph carries no name."""
    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    for control in re.findall(
        r"<(?:a|button)[^>]*fa-(?:download|magnifying-glass|rotate-left)[^>]*>", html
    ):
        assert 'title="' in control
        assert 'aria-label="' in control


def test_page_uses_no_oversized_stat_cards(manage_client, fake_api: _FakeClient) -> None:
    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    assert 'class="stat-card"' not in html


def test_page_never_renders_the_secret_key(manage_client, fake_api: _FakeClient) -> None:
    import os

    html = manage_client.get("/manage/backup", cookies={"manage_session": SESSION}).text
    assert os.environ["SECRET_KEY"] not in html
    assert os.environ["INTERNAL_API_KEY"] not in html
    assert os.environ["MANAGE_PASSWORD"] not in html


def test_backup_routes_are_in_the_manage_app(manage_client) -> None:
    paths = {route.path for route in management_app.app.routes}
    assert {"/manage/backup", "/manage/backup/download", "/manage/backup/restore"} <= paths
