"""Code activation and permanent delete on the internal API.

A code has two different endings and the difference matters:

* **deactivate** (and the older `POST /api/codes/{cid}/revoke`) flips `active`
  and keeps the row, so it can be turned back on. Inactive codes are hidden from
  `GET /api/codes` by default, because a revoked code is noise in the list the
  panel shows.
* **permanent delete** removes the row. Audit rows are history and are never
  deleted: `audit_logs.code_id` is nulled instead, the same policy a backup
  restore applies, so the row survives with its host, path and action intact.

`tests/test_manage_codes.py` covers the confirmation the manage panel enforces
on top of this.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}


def _unique_code() -> str:
    return f"code-{uuid.uuid4().hex[:12]}"


def _create(client, **extra: Any) -> dict:
    payload = {"code": _unique_code(), "label": "codes-test"}
    payload.update(extra)
    r = client.post("/api/codes", json=payload, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()


def _list(client, **params: Any) -> list[dict]:
    r = client.get("/api/codes", params=params or None)
    assert r.status_code == 200, r.text
    return r.json()


def _get(client, cid: int) -> dict:
    r = client.get(f"/api/codes/{cid}")
    assert r.status_code == 200, r.text
    return r.json()


def _names(rows: list[dict]) -> set[str]:
    return {row["code"] for row in rows}


@pytest.fixture(autouse=True)
def _restore_default_group(client):
    """Restore the seeds this module's group churn could disturb.

    The lifespan seed writes into one shared test database, so a module that
    leaves the default group renamed or a catch-all flag moved would leak into
    later modules.
    """
    groups = client.get("/api/groups").json()
    default = next(g for g in groups if g["is_default"])
    original_name = default["name"]
    yield
    default = next(g for g in client.get("/api/groups").json() if g["is_default"])
    if default["name"] != original_name:
        client.put(
            f"/api/groups/{default['id']}",
            json={"name": original_name},
            headers=INTERNAL_KEY_HEADERS,
        )
    for row in client.get(f"/api/groups/{default['id']}/rules").json():
        if row["path"] == "/*" and not row["is_default"]:
            client.put(
                f"/api/rules/{row['id']}",
                json={"action": "access_code"},
                headers=INTERNAL_KEY_HEADERS,
            )


# --------------------------------------------------------------------------- #
# Listing
# --------------------------------------------------------------------------- #


def test_new_codes_are_active_and_listed(client) -> None:
    created = _create(client)
    assert created["id"] in {row["id"] for row in _list(client)}


def test_inactive_codes_are_hidden_unless_asked_for(client) -> None:
    created = _create(client)
    code = created["code"]
    revoked = client.post(f"/api/codes/{created['id']}/revoke", headers=INTERNAL_KEY_HEADERS)
    assert revoked.status_code == 200

    assert code not in _names(_list(client)), "the default list hides inactive codes"
    assert code in _names(_list(client, include_inactive="true")), "the flag shows them"
    assert code in _names(_list(client, include_inactive=True))


def test_include_inactive_accepts_the_variants_a_client_might_send(client) -> None:
    created = _create(client)
    client.post(f"/api/codes/{created['id']}/revoke", headers=INTERNAL_KEY_HEADERS)

    for value in ("true", "True", "1", "yes", True, 1):
        rows = _list(client, include_inactive=value)
        assert created["code"] in _names(rows), f"include_inactive={value!r} hid the code"

    for value in ("false", "0", "no", False, 0):
        rows = _list(client, include_inactive=value)
        assert created["code"] not in _names(rows), f"include_inactive={value!r} showed it"


def test_the_backup_code_row_stays_in_the_default_list(client) -> None:
    """`GET /api/codes` is what the login lookup and the panel both read."""
    assert any(row["code"] == "test-backup-code" for row in _list(client))


# --------------------------------------------------------------------------- #
# Activate and deactivate
# --------------------------------------------------------------------------- #


def test_put_accepts_active_false_and_true(client) -> None:
    created = _create(client)

    r = client.put(
        f"/api/codes/{created['id']}", json={"active": False}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200, r.text
    assert r.json()["active"] is False
    assert _get(client, created["id"])["active"] is False

    r = client.put(
        f"/api/codes/{created['id']}", json={"active": True}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200, r.text
    assert r.json()["active"] is True


def test_put_accepts_the_string_spellings_a_form_sends(client) -> None:
    created = _create(client)
    for raw, expected in (("false", False), ("0", False), ("true", True), ("1", True)):
        r = client.put(
            f"/api/codes/{created['id']}", json={"active": raw}, headers=INTERNAL_KEY_HEADERS
        )
        assert r.status_code == 200, f"{raw!r} -> {r.status_code} {r.text}"
        assert r.json()["active"] is expected, raw


def test_put_refuses_a_nonsense_active_value(client) -> None:
    created = _create(client)
    r = client.put(
        f"/api/codes/{created['id']}",
        json={"active": "maybe"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "active must be true or false"
    assert _get(client, created["id"])["active"] is True, "a refused update changes nothing"


def test_deactivating_and_reactivating_leaves_the_row_alone(client) -> None:
    """Reversible by design: the same id comes back, so history keeps meaning."""
    created = _create(client)
    client.put(f"/api/codes/{created['id']}", json={"active": False}, headers=INTERNAL_KEY_HEADERS)
    client.put(f"/api/codes/{created['id']}", json={"active": True}, headers=INTERNAL_KEY_HEADERS)

    assert _get(client, created["id"])["code"] == created["code"]


def test_active_updates_beside_a_label_change(client) -> None:
    created = _create(client)
    r = client.put(
        f"/api/codes/{created['id']}",
        json={"active": False, "label": "renamed"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["active"] is False
    assert body["label"] == "renamed"


def test_activation_still_requires_the_internal_key(client) -> None:
    created = _create(client)
    r = client.put(f"/api/codes/{created['id']}", json={"active": False})
    assert r.status_code == 401


def test_deactivation_endpoints_are_documented(client) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert "put" in paths["/api/codes/{cid}"]
    assert "delete" in paths["/api/codes/{cid}"]


# --------------------------------------------------------------------------- #
# Permanent delete
# --------------------------------------------------------------------------- #


def _insert_log(client, **extra: Any) -> int:
    payload = {
        "ip": "203.0.113.11",
        "host": "codes.test",
        "path": "/",
        "action": "auth_success",
    }
    payload.update(extra)
    r = client.post("/api/logs", json=payload, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _log(client, log_id: int) -> dict:
    rows = client.get("/api/logs", params={"per_page": 100}).json()
    match = next((row for row in rows if row["id"] == log_id), None)
    assert match is not None, f"audit row {log_id} disappeared"
    return match


def test_delete_removes_the_row_entirely(client) -> None:
    created = _create(client)

    r = client.delete(f"/api/codes/{created['id']}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True

    assert client.get(f"/api/codes/{created['id']}").status_code == 404
    assert created["code"] not in _names(_list(client, include_inactive="true"))


def test_delete_nulls_the_audit_reference_and_keeps_the_row(client) -> None:
    """History is not destroyed by deleting a code the history mentions."""
    created = _create(client)
    log_id = _insert_log(client, code_id=created["id"])
    assert _log(client, log_id)["code_id"] == created["id"]

    r = client.delete(f"/api/codes/{created['id']}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["detached_logs"] >= 1

    row = _log(client, log_id)
    assert row["code_id"] is None
    assert row["host"] == "codes.test"
    assert row["action"] == "auth_success"


def test_delete_leaves_other_codes_audit_rows_alone(client) -> None:
    kept = _create(client)
    doomed = _create(client)
    kept_log = _insert_log(client, code_id=kept["id"])
    _insert_log(client, code_id=doomed["id"])

    removed = client.delete(f"/api/codes/{doomed['id']}", headers=INTERNAL_KEY_HEADERS)
    assert removed.status_code == 200
    assert _log(client, kept_log)["code_id"] == kept["id"]


def test_delete_reports_no_detached_logs_when_there_are_none(client) -> None:
    created = _create(client)
    r = client.delete(f"/api/codes/{created['id']}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    assert r.json()["detached_logs"] == 0


def test_delete_of_an_unknown_code_is_404(client) -> None:
    r = client.delete("/api/codes/9999999", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 404


def test_delete_requires_the_internal_key(client) -> None:
    created = _create(client)
    r = client.delete(f"/api/codes/{created['id']}")
    assert r.status_code == 401
    assert client.get(f"/api/codes/{created['id']}").status_code == 200


def test_delete_works_on_an_inactive_code(client) -> None:
    """Deactivating first is the normal flow, so delete must not require active."""
    created = _create(client)
    client.put(f"/api/codes/{created['id']}", json={"active": False}, headers=INTERNAL_KEY_HEADERS)

    r = client.delete(f"/api/codes/{created['id']}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    assert client.get(f"/api/codes/{created['id']}").status_code == 404


def test_revoking_then_reactivating_still_works(client) -> None:
    """The old kill switch stays, and is still reversible through `PUT`."""
    created = _create(client)
    assert (
        client.post(f"/api/codes/{created['id']}/revoke", headers=INTERNAL_KEY_HEADERS).status_code
        == 200
    )
    assert _get(client, created["id"])["active"] is False

    r = client.put(
        f"/api/codes/{created['id']}", json={"active": True}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200
    assert r.json()["active"] is True
