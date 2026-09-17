"""The mandatory per-group catch-all: the flag, the guards and the backfill.

`Rule.is_default` is what makes the gate's fail-closed invariant safe rather than
lucky. Before it, "every group ends in a `/*` catch-all" was a convention nobody
enforced, and the gate had to assume it. These tests pin the three halves of the
enforcement:

1. **schema and backfill** — the column arrives through the guarded `ALTER
   TABLE`, and the backfill gives every group exactly one flagged catch-all,
   sorted last, with a report showing what moved;
2. **the API guards** — a default rule cannot be deleted, reordered, or renamed,
   and `/*` is reserved for it;
3. **the group lifecycle** — a new group seeds its own catch-all, and deleting
   the group is the one way to remove it.

The backfill runs on real databases in `tests/test_rule_defaults_migration.py`.
"""

from __future__ import annotations

import uuid

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}


def _unique_domain() -> str:
    return f"{uuid.uuid4().hex[:10]}.defaults-test"


def _create_group(client, domain: str | None = None) -> int:
    r = client.post(
        "/api/groups",
        json={"name": f"defaults-{uuid.uuid4().hex[:10]}", "domain": domain or _unique_domain()},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _rules(client, gid: int) -> list[dict]:
    r = client.get(f"/api/groups/{gid}/rules")
    assert r.status_code == 200, r.text
    return r.json()


def _ordered(client, gid: int) -> list[dict]:
    return sorted(_rules(client, gid), key=lambda r: r["display_order"])


def _catch_all(client, gid: int) -> dict:
    return next(r for r in _rules(client, gid) if r["is_default"])


def _add_rule(client, gid: int, path: str, action: str = "none"):
    return client.post(
        f"/api/groups/{gid}/rules",
        json={"path": path, "action": action},
        headers=INTERNAL_KEY_HEADERS,
    )


# --------------------------------------------------------------------------- #
# The seeded invariant
# --------------------------------------------------------------------------- #


def test_every_group_has_exactly_one_default_catch_all_sorted_last(client) -> None:
    groups = client.get("/api/groups").json()
    assert groups, "the lifespan seeds at least one group"

    for group in groups:
        rows = _ordered(client, group["id"])
        flagged = [r for r in rows if r["is_default"]]
        assert len(flagged) == 1, f"group {group['id']}: {len(flagged)} default rules"
        assert flagged[0]["path"] == "/*", f"group {group['id']}: default is not the catch-all"
        assert rows[-1]["is_default"] is True, f"group {group['id']}: catch-all is not last"
        assert [r["display_order"] for r in rows] == list(range(len(rows)))


def test_rule_list_reports_is_default(client) -> None:
    """The panel needs the flag to render its disabled controls."""
    gid = _create_group(client)
    row = _rules(client, gid)[0]
    assert row["path"] == "/*"
    assert row["is_default"] is True


# --------------------------------------------------------------------------- #
# `/*` is reserved
# --------------------------------------------------------------------------- #


def test_creating_a_catch_all_rule_is_refused(client) -> None:
    gid = _create_group(client)
    r = _add_rule(client, gid, "/*", "none")
    assert r.status_code == 400
    assert r.json()["detail"] == "path /* is reserved"


def test_updating_a_rule_to_the_catch_all_path_is_refused(client) -> None:
    gid = _create_group(client)
    rid = _add_rule(client, gid, "/named/*", "none").json()["id"]

    r = client.put(f"/api/rules/{rid}", json={"path": "/*"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400
    assert r.json()["detail"] == "path /* is reserved"
    assert any(r["id"] == rid and r["path"] == "/named/*" for r in _rules(client, gid))


def test_other_paths_are_still_creatable(client) -> None:
    """Reserving `/*` must not reserve `/*`-suffixed paths."""
    gid = _create_group(client)
    for path in ("/", "/api/*", "/*/*", "/x"):
        r = _add_rule(client, gid, path, "none")
        assert r.status_code == 200, f"{path} -> {r.status_code} {r.text}"


# --------------------------------------------------------------------------- #
# Delete and reorder guards
# --------------------------------------------------------------------------- #


def test_deleting_the_default_rule_is_refused(client) -> None:
    gid = _create_group(client)
    rid = _catch_all(client, gid)["id"]

    r = client.delete(f"/api/rules/{rid}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400
    assert r.json()["detail"] == "cannot delete default rule"
    assert any(r["id"] == rid for r in _rules(client, gid))


def test_deleting_a_non_default_rule_still_works(client) -> None:
    gid = _create_group(client)
    rid = _add_rule(client, gid, "/gone/*", "none").json()["id"]

    r = client.delete(f"/api/rules/{rid}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200
    assert not any(row["id"] == rid for row in _rules(client, gid))


def test_reordering_the_default_rule_is_refused(client) -> None:
    gid = _create_group(client)
    _add_rule(client, gid, "/named/*", "none")
    before = [(r["id"], r["display_order"]) for r in _ordered(client, gid)]
    rid = _catch_all(client, gid)["id"]

    for direction in ("up", "down"):
        r = client.put(
            f"/api/rules/{rid}/order",
            json={"direction": direction},
            headers=INTERNAL_KEY_HEADERS,
        )
        assert r.status_code == 400, direction
        assert r.json()["detail"] == "cannot move default rule", direction
    assert [(r["id"], r["display_order"]) for r in _ordered(client, gid)] == before


def test_swapping_with_the_default_rule_is_refused(client) -> None:
    gid = _create_group(client)
    rid = _add_rule(client, gid, "/named/*", "none").json()["id"]
    before = [(r["id"], r["display_order"]) for r in _ordered(client, gid)]

    r = client.put(
        f"/api/rules/{rid}/order",
        json={"direction": "down"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "cannot swap with default rule"
    assert [(r["id"], r["display_order"]) for r in _ordered(client, gid)] == before


def test_renaming_the_default_rule_path_is_refused(client) -> None:
    gid = _create_group(client)
    rid = _catch_all(client, gid)["id"]

    r = client.put(
        f"/api/rules/{rid}", json={"path": "/everything/*"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "cannot change default rule path"
    assert _catch_all(client, gid)["path"] == "/*"


def test_the_default_rule_action_stays_editable(client) -> None:
    """Flipping a group's policy is legitimate; its path and position are not."""
    gid = _create_group(client)
    rid = _catch_all(client, gid)["id"]

    r = client.put(f"/api/rules/{rid}", json={"action": "deny"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    assert _catch_all(client, gid)["action"] == "deny"


def test_the_default_rule_accepts_its_own_path(client) -> None:
    """A no-op path change is what a form submit sends; it must not be refused."""
    gid = _create_group(client)
    rid = _catch_all(client, gid)["id"]

    r = client.put(f"/api/rules/{rid}", json={"path": "/*"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- #
# New groups, and the one sanctioned removal
# --------------------------------------------------------------------------- #


def test_a_new_group_is_seeded_with_a_gating_catch_all(client) -> None:
    """Default to gating: a public group has to be a deliberate `none`."""
    gid = _create_group(client)
    rows = _ordered(client, gid)

    assert len(rows) == 1, f"expected only the seeded catch-all, got {rows}"
    assert rows[0]["path"] == "/*"
    assert rows[0]["action"] == "access_code"
    assert rows[0]["display_order"] == 0
    assert rows[0]["is_default"] is True


def test_a_new_group_refuses_unnamed_paths_until_its_catch_all_is_flipped(client) -> None:
    """The seeded catch-all is what makes the group answer at all."""
    domain = _unique_domain()
    _create_group(client, domain)

    probe = client.post("/api/dry-run", json={"host": domain, "path": "/anything"})
    assert probe.status_code == 200
    assert probe.json()["matched_rule"]["path"] == "/*"
    assert probe.json()["action"] == "access_code"


def test_deleting_the_group_removes_its_catch_all(client) -> None:
    """The sanctioned path: the group goes, its catch-all goes with it."""
    gid = _create_group(client)
    assert _catch_all(client, gid)["is_default"] is True

    r = client.delete(f"/api/groups/{gid}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200

    rows = client.get(f"/api/groups/{gid}/rules")
    assert rows.status_code == 404


def test_new_rules_order_above_the_catch_all(client) -> None:
    """Otherwise a new rule would sit below the catch-all and never fire."""
    gid = _create_group(client)
    first = _add_rule(client, gid, "/one/*", "none").json()["id"]
    second = _add_rule(client, gid, "/two/*", "deny").json()["id"]

    ordered = _ordered(client, gid)
    assert [r["id"] for r in ordered] == [first, second, _catch_all(client, gid)["id"]]
    assert [r["display_order"] for r in ordered] == [0, 1, 2]
