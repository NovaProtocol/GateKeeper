"""The settings page: the form, its gates, and the environment panel.

The page is the only place an operator can change `unmatched_action`, maintenance
mode or the session lifetime, so three properties are worth pinning:

* a partial form updates only what was submitted. An unchecked box sends
  nothing, and a field the browser omitted must not be written as blank;
* an invalid value is refused before any `PUT` leaves the panel, so the API's own
  validation is a second line and not the first;
* the environment panel reports a secret's presence and never its value. The
  assertion is that the configured value does not appear in the HTML at all,
  which is the only version of that claim worth making.
"""

from __future__ import annotations

from typing import Any

import pytest

import management.app as management_app
from shared.jwt import create_manage_token
from shared.settings_spec import MAINTENANCE_MODE, SESSION_LIFETIME_HOURS

CSRF = "test-csrf-token"
ORIGIN = "http://testserver"
SESSION = create_manage_token()
API = "http://api:8002"

#: The two values the environment panel must only ever report as present.
FAKE_SECRET_KEY = "secret-key-value-that-must-not-be-rendered-01"
FAKE_INTERNAL_KEY = "internal-key-value-that-must-not-be-rendered-02"

STORED = {
    "rate_limit_access_code_per_min": "60",
    "unmatched_action": "deny",
    SESSION_LIFETIME_HOURS: "36",
    MAINTENANCE_MODE: "true",
    "maintenance_message": "Back at six",
    "log_retention_days": "14",
    "backup_exported_at": "2026-09-17T10:00:00Z",
}


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = ""
        self.content = b""
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    """Records every relayed call, so "no PUT was issued" is assertable."""

    def __init__(self, prune: dict[str, Any] | None = None) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.prune = prune if prune is not None else {"ok": True, "deleted": 4, "remaining": 11}

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, None))
        if url.endswith("/api/settings"):
            rows = [{"key": k, "value": v, "updated_at": None} for k, v in STORED.items()]
            return _FakeResponse(200, rows)
        return _FakeResponse(200, [])

    async def put(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("PUT", url, json))
        return _FakeResponse(200, {"key": url.rsplit("/", 1)[-1], "value": json["value"]})

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("POST", url, json))
        if url.endswith("/api/logs/prune"):
            return _FakeResponse(200, self.prune)
        return _FakeResponse(200, {})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("DELETE", url, None))
        return _FakeResponse(200, {})

    def puts(self) -> dict[str, Any]:
        return {
            url.rsplit("/", 1)[-1]: body["value"]
            for method, url, body in self.calls
            if method == "PUT"
        }


@pytest.fixture()
def fake_api(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(management_app, "_get_httpx", lambda: client)
    return client


@pytest.fixture()
def secrets_in_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", FAKE_SECRET_KEY)
    monkeypatch.setenv("INTERNAL_API_KEY", FAKE_INTERNAL_KEY)


def _auth() -> dict[str, str]:
    return {"manage_session": SESSION, "csrf_token": CSRF}


def _post(manage_client: Any, data: dict[str, Any], **kwargs: Any):
    payload = {"csrf_token": CSRF}
    payload.update(data)
    kwargs.setdefault("follow_redirects", False)
    return manage_client.post(
        "/manage/settings",
        data=payload,
        cookies=kwargs.pop("cookies", _auth()),
        headers=kwargs.pop("headers", {"Origin": ORIGIN}),
        **kwargs,
    )


def _page(manage_client: Any) -> str:
    response = manage_client.get("/manage/settings", cookies=_auth())
    assert response.status_code == 200
    return response.text


# --------------------------------------------------------------------------- #
# Gates
# --------------------------------------------------------------------------- #


def test_the_page_requires_a_session(manage_client: Any) -> None:
    response = manage_client.get("/manage/settings", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].startswith("/manage/login?redirect=")


def test_a_save_requires_a_session(manage_client: Any, fake_api: _FakeClient) -> None:
    response = _post(manage_client, {"rate_limit_access_code_per_min": "70"}, cookies=None)

    assert response.status_code == 302
    assert fake_api.calls == []


def test_a_save_requires_the_csrf_token(manage_client: Any, fake_api: _FakeClient) -> None:
    response = _post(manage_client, {"csrf_token": "", "rate_limit_access_code_per_min": "70"})

    assert response.status_code == 403
    assert fake_api.puts() == {}


def test_a_save_requires_a_same_origin_request(manage_client: Any, fake_api: _FakeClient) -> None:
    response = _post(manage_client, {"rate_limit_access_code_per_min": "70"}, headers={})

    assert response.status_code == 403
    assert fake_api.puts() == {}


# --------------------------------------------------------------------------- #
# The form
# --------------------------------------------------------------------------- #


def test_a_partial_form_writes_only_what_it_sent(manage_client: Any, fake_api: _FakeClient) -> None:
    """The one field posted is the one field written; nothing is blanked.

    The switch is the sharp case: an unchecked box sends no key at all, so it is
    written from its presence. Every other field is left exactly as stored.
    """
    response = _post(manage_client, {"rate_limit_access_code_per_min": "120"})

    assert response.status_code == 302
    assert fake_api.puts() == {"rate_limit_access_code_per_min": "120"}


def test_every_field_in_one_post_becomes_one_put(manage_client: Any, fake_api: _FakeClient) -> None:
    response = _post(
        manage_client,
        {
            "unmatched_action": "deny",
            "rate_limit_access_code_per_min": "90",
            SESSION_LIFETIME_HOURS: "6",
            MAINTENANCE_MODE: "true",
            "maintenance_message": "Back at six",
            "log_retention_days": "30",
        },
    )

    assert response.status_code == 302
    assert fake_api.puts() == {
        "unmatched_action": "deny",
        "rate_limit_access_code_per_min": "90",
        SESSION_LIFETIME_HOURS: "6",
        MAINTENANCE_MODE: "true",
        "maintenance_message": "Back at six",
        "log_retention_days": "30",
    }


def test_an_unchecked_switch_is_written_as_false(manage_client: Any, fake_api: _FakeClient) -> None:
    """The unchecked box still sends `false`, because of the hidden twin it has.

    A browser pairs the hidden field with the checkbox and sends whichever
    applies, so an unchecked switch arrives as `"false"` rather than not
    arriving at all. That is what makes absence meaningful for the other fields.
    """
    response = _post(manage_client, {MAINTENANCE_MODE: "false"})

    assert response.status_code == 302
    assert fake_api.puts()[MAINTENANCE_MODE] == "false"


def test_a_checkbox_on_the_page_has_a_hidden_false_twin(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """Without the twin, an unchecked switch would be indistinguishable from
    a field the form never carried, and the page could never turn it off."""
    html = _page(manage_client)

    assert 'type="hidden" name="maintenance_mode" value="false"' in html


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unmatched_action", "allow"),
        ("rate_limit_access_code_per_min", "0"),
        ("rate_limit_access_code_per_min", "many"),
        (SESSION_LIFETIME_HOURS, "0"),
        (SESSION_LIFETIME_HOURS, "9999"),
        ("maintenance_message", "x" * 201),
        ("log_retention_days", "3"),
    ],
)
def test_an_invalid_value_is_refused_before_anything_is_sent(
    manage_client: Any, fake_api: _FakeClient, field: str, value: str
) -> None:
    """400, and no write at all for the key the panel rejected."""
    response = _post(manage_client, {field: value})

    assert response.status_code == 400
    assert field in response.text
    assert field not in fake_api.puts(), "the API was asked to store a value the panel rejected"


def test_an_invalid_value_does_not_stop_the_valid_ones(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The form reports the failure without silently dropping the rest."""
    response = _post(
        manage_client,
        {"unmatched_action": "allow", "rate_limit_access_code_per_min": "77"},
    )

    assert response.status_code == 400
    assert fake_api.puts() == {"rate_limit_access_code_per_min": "77"}


def test_an_unknown_field_is_never_relayed(manage_client: Any, fake_api: _FakeClient) -> None:
    """A crafted post cannot write a key this panel does not own."""
    response = _post(
        manage_client, {"some_other_key": "anything", "rate_limit_access_code_per_min": "60"}
    )

    assert response.status_code == 302
    assert "some_other_key" not in fake_api.puts()


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def test_the_page_shows_every_manageable_setting(manage_client: Any, fake_api: _FakeClient) -> None:
    html = _page(manage_client)

    for key in (
        "unmatched_action",
        "rate_limit_access_code_per_min",
        SESSION_LIFETIME_HOURS,
        MAINTENANCE_MODE,
        "maintenance_message",
        "log_retention_days",
    ):
        assert f'name="{key}"' in html, f"{key} has no control"


def test_the_page_renders_the_stored_values(manage_client: Any, fake_api: _FakeClient) -> None:
    html = _page(manage_client)

    assert 'value="36"' in html
    assert "checked" in html
    assert "Back at six" in html


def test_the_unmatched_action_offers_exactly_the_accepted_values(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    from shared.gate import UNMATCHED_ACTIONS

    html = _page(manage_client)

    for action in UNMATCHED_ACTIONS:
        assert f'value="{action}"' in html


def test_every_control_carries_a_title_and_an_aria_label(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """A control without both is a control a keyboard or screen-reader user loses."""
    import re

    html = _page(manage_client)
    controls = re.findall(r"<(?:input|select|button)\b[^>]*>", html)
    assert controls
    missing = [
        tag
        for tag in controls
        if 'type="hidden"' not in tag and ("title=" not in tag or "aria-label=" not in tag)
    ]

    assert missing == []


def test_the_environment_panel_never_renders_a_secret(
    manage_client: Any, fake_api: _FakeClient, secrets_in_env: None
) -> None:
    html = _page(manage_client)

    assert FAKE_SECRET_KEY not in html
    assert FAKE_INTERNAL_KEY not in html
    assert "configured" in html
    assert "SECRET_KEY" in html


def test_the_page_names_what_enforces_each_setting(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """The note beside a field is why the value is trustworthy, so it is pinned."""
    html = _page(manage_client)

    assert "resolve_rule_action" in html
    assert "_set_auth_cookie" in html
    assert "_maintenance_response" in html
    assert "prune_audit_logs" in html


def test_the_session_note_states_the_admin_cookie_is_separate(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    html = _page(manage_client)

    assert "manage_session" in html
    assert "8 hours" in html


# --------------------------------------------------------------------------- #
# Prune
# --------------------------------------------------------------------------- #


def test_prune_requires_a_session(manage_client: Any, fake_api: _FakeClient) -> None:
    response = manage_client.post(
        "/manage/logs/prune",
        data={"confirm": "PRUNE"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert fake_api.calls == []


def test_prune_requires_the_csrf_token(manage_client: Any, fake_api: _FakeClient) -> None:
    response = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": "", "confirm": "PRUNE"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert [c for c in fake_api.calls if c[1].endswith("/api/logs/prune")] == []


def test_prune_requires_a_same_origin_request(manage_client: Any, fake_api: _FakeClient) -> None:
    response = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE"},
        cookies=_auth(),
        headers={},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert [c for c in fake_api.calls if c[1].endswith("/api/logs/prune")] == []


@pytest.mark.parametrize("confirm", ["", "prune", "DELETE", "PRUNEX", "Prune"])
def test_prune_refuses_an_unconfirmed_post(
    manage_client: Any, fake_api: _FakeClient, confirm: str
) -> None:
    response = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": confirm},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert [c for c in fake_api.calls if c[1].endswith("/api/logs/prune")] == []


def test_prune_accepts_the_word_with_stray_whitespace(
    manage_client: Any, fake_api: _FakeClient
) -> None:
    """Typed words get trimmed, the same as the restore confirmation."""
    response = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "  PRUNE  "},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert len([c for c in fake_api.calls if c[1].endswith("/api/logs/prune")]) == 1


def test_prune_reports_what_it_deleted(manage_client: Any, fake_api: _FakeClient) -> None:
    response = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Deleted 4 audit rows" in response.text
    assert "11 remain" in response.text
    assert len([c for c in fake_api.calls if c[1].endswith("/api/logs/prune")]) == 1


def test_prune_survives_an_unreachable_api(
    manage_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Broken(_FakeClient):
        async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
            if url.endswith("/api/logs/prune"):
                raise RuntimeError("connection refused")
            return await super().post(url, json, **kwargs)

    monkeypatch.setattr(management_app, "_get_httpx", lambda: _Broken())

    response = manage_client.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE"},
        cookies=_auth(),
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Prune failed" in response.text
