"""Order endpoints on the internal API.

These cover `PUT /api/rules/{rid}/order` and `PUT /api/groups/{gid}/order`
through the real app, so the lifespan seeds are present and the swaps run
against a real database.

The last test is the one that matters operationally: it reproduces the shape of
the live `gatekeeper.projectnova.download` group (a `/*` catch-all sitting above
a narrower rule) and shows that the narrower rule is unreachable until it is
moved up. That is the trap the manage UI's arrows exist to fix.
"""

from __future__ import annotations

import uuid

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}
DEFAULT_DOMAIN = "*.*/*"


def _unique_domain() -> str:
    return f"{uuid.uuid4().hex[:10]}.order-test"


def _create_group(client, domain: str | None = None) -> int:
    name = f"order-test-{uuid.uuid4().hex[:10]}"
    r = client.post(
        "/api/groups",
        json={"name": name, "domain": domain or _unique_domain()},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _create_rule(client, gid: int, path: str, action: str) -> int:
    r = client.post(
        f"/api/groups/{gid}/rules",
        json={"path": path, "action": action},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _rules(client, gid: int) -> list[dict]:
    r = client.get(f"/api/groups/{gid}/rules")
    assert r.status_code == 200
    return r.json()


def _groups(client) -> list[dict]:
    r = client.get("/api/groups")
    assert r.status_code == 200
    return r.json()


def test_rule_order_requires_internal_key(client) -> None:
    gid = _create_group(client)
    rid = _create_rule(client, gid, "/*", "none")
    r = client.put(f"/api/rules/{rid}/order", json={"direction": "up"})
    assert r.status_code == 401


def test_group_order_requires_internal_key(client) -> None:
    gid = _create_group(client)
    r = client.put(f"/api/groups/{gid}/order", json={"direction": "up"})
    assert r.status_code == 401


def test_rule_order_swaps_with_neighbour(client) -> None:
    gid = _create_group(client)
    first = _create_rule(client, gid, "/a/*", "none")
    second = _create_rule(client, gid, "/b/*", "access_code")
    assert [r["id"] for r in _rules(client, gid)] == [first, second]

    r = client.put(
        f"/api/rules/{second}/order",
        json={"direction": "up"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert [r["id"] for r in _rules(client, gid)] == [second, first]


def test_rule_order_up_at_top_is_a_noop(client) -> None:
    gid = _create_group(client)
    first = _create_rule(client, gid, "/a/*", "none")
    _create_rule(client, gid, "/b/*", "none")
    before = [(r["id"], r["display_order"]) for r in _rules(client, gid)]

    r = client.put(
        f"/api/rules/{first}/order",
        json={"direction": "up"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert [(r["id"], r["display_order"]) for r in _rules(client, gid)] == before


def test_rule_order_down_at_bottom_is_a_noop(client) -> None:
    gid = _create_group(client)
    _create_rule(client, gid, "/a/*", "none")
    last = _create_rule(client, gid, "/b/*", "none")
    before = [(r["id"], r["display_order"]) for r in _rules(client, gid)]

    r = client.put(
        f"/api/rules/{last}/order",
        json={"direction": "down"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert [(r["id"], r["display_order"]) for r in _rules(client, gid)] == before


def test_rule_order_rejects_bad_direction(client) -> None:
    gid = _create_group(client)
    rid = _create_rule(client, gid, "/*", "none")
    r = client.put(
        f"/api/rules/{rid}/order",
        json={"direction": "sideways"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "direction must be up|down"


def test_rule_order_unknown_id_is_404(client) -> None:
    r = client.put(
        "/api/rules/999999/order",
        json={"direction": "up"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 404


def test_group_order_swaps_with_neighbour(client) -> None:
    first = _create_group(client)
    second = _create_group(client)
    order = [g["id"] for g in _groups(client) if not g["is_default"]]
    assert order.index(first) < order.index(second)

    r = client.put(
        f"/api/groups/{second}/order",
        json={"direction": "up"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200
    after = [g["id"] for g in _groups(client) if not g["is_default"]]
    assert after.index(second) < after.index(first)


def test_group_order_refuses_the_default_group(client) -> None:
    default = next(g for g in _groups(client) if g["is_default"])
    assert default["domain"] == DEFAULT_DOMAIN
    r = client.put(
        f"/api/groups/{default['id']}/order",
        json={"direction": "up"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "cannot reorder default"


def test_group_order_refuses_to_swap_with_the_default_group(client) -> None:
    """The default group sorts last, so the group above it cannot move down."""
    groups = _groups(client)
    assert groups[-1]["is_default"], "default group is expected to sort last"
    neighbour = groups[-2]
    before = [(g["id"], g["display_order"]) for g in groups]

    r = client.put(
        f"/api/groups/{neighbour['id']}/order",
        json={"direction": "down"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "cannot swap with default"
    assert [(g["id"], g["display_order"]) for g in _groups(client)] == before


def test_new_rule_is_masked_until_it_is_moved_up(client) -> None:
    """The production-shaped trap: a catch-all above a narrower rule wins.

    A rule added through the API lands at ``max + 1``. When the group already
    holds ``/*``, the new rule is matched only after it — and since the gate
    takes the first match, it never fires at all. One ``up`` call fixes it.
    """
    domain = _unique_domain()
    gid = _create_group(client, domain)
    catch_all = _create_rule(client, gid, "/*", "none")
    docs = _create_rule(client, gid, "/documentation/*", "access_code")

    blocked = client.post("/api/dry-run", json={"host": domain, "path": "/documentation/rules/"})
    assert blocked.status_code == 200
    assert blocked.json()["matched_rule"]["id"] == catch_all
    assert blocked.json()["action"] == "none"

    r = client.put(
        f"/api/rules/{docs}/order",
        json={"direction": "up"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200

    fixed = client.post("/api/dry-run", json={"host": domain, "path": "/documentation/rules/"})
    assert fixed.status_code == 200
    assert fixed.json()["matched_rule"]["id"] == docs
    assert fixed.json()["matched_rule"]["path"] == "/documentation/*"
    assert fixed.json()["action"] == "access_code"
