"""The custom-page CRUD endpoints on the internal API.

Run through the real app, so the lifespan-created table and the API's own
validation are the ones under test. Every refusal the plan lists has its own
case, and the partial-`PUT` case is the one that matters operationally: the
panel's toggle posts one field, and it must not blank the body it never showed.
"""

from __future__ import annotations

import uuid

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

BODY = "User-agent: *\nDisallow: /\n"


def _pattern() -> str:
    """A pattern unique to one test, since the column is unique."""
    return f"{uuid.uuid4().hex[:8]}.page-test.example/robots.txt"


def _create(client, pattern: str | None = None, **extra) -> dict:
    payload = {"pattern": pattern or _pattern(), "body": BODY}
    payload.update(extra)
    r = client.post("/api/pages", json=payload, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()


def _pages(client) -> list[dict]:
    r = client.get("/api/pages")
    assert r.status_code == 200
    return r.json()


# --------------------------------------------------------------------------- #
# Read is keyless, writes are not
# --------------------------------------------------------------------------- #


def test_listing_pages_needs_no_key(client) -> None:
    """The gateway reads this on its own cache refresh; it is not a write."""
    assert client.get("/api/pages").status_code == 200


def test_every_write_needs_the_internal_key(client) -> None:
    pid = _create(client)["id"]
    assert client.post("/api/pages", json={"pattern": _pattern(), "body": ""}).status_code == 401
    assert client.put(f"/api/pages/{pid}", json={"body": "x"}).status_code == 401
    assert client.delete(f"/api/pages/{pid}").status_code == 401
    assert client.put(f"/api/pages/{pid}/order", json={"direction": "up"}).status_code == 401


# --------------------------------------------------------------------------- #
# Round trip
# --------------------------------------------------------------------------- #


def test_a_page_round_trips_byte_for_byte(client) -> None:
    pattern = _pattern()
    created = _create(client, pattern)
    assert created["pattern"] == pattern
    assert created["body"] == BODY
    assert created["active"] is True
    assert created["content_type"] == "text/plain; charset=utf-8"

    fetched = next(p for p in _pages(client) if p["id"] == created["id"])
    assert fetched["body"] == BODY

    r = client.delete(f"/api/pages/{created['id']}", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200
    assert all(p["id"] != created["id"] for p in _pages(client))


def test_an_html_body_is_stored_exactly_as_given(client) -> None:
    """No sanitising, no escaping: the owner's bytes, unaltered."""
    html = '<p>moved</p><script>window.location="/";</script>'
    created = _create(client, content_type="text/html; charset=utf-8", body=html)
    assert created["body"] == html
    assert created["content_type"] == "text/html; charset=utf-8"


# --------------------------------------------------------------------------- #
# Refusals, one per rule
# --------------------------------------------------------------------------- #


def test_a_pattern_without_a_slash_is_refused(client) -> None:
    r = client.post("/api/pages", json={"pattern": "robots.txt"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400
    assert "/" in r.json()["detail"]


def test_a_pattern_without_a_host_half_is_refused(client) -> None:
    r = client.post("/api/pages", json={"pattern": "/robots.txt"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400


def test_a_pattern_without_a_path_half_is_refused(client) -> None:
    r = client.post("/api/pages", json={"pattern": "a.test/"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400


def test_a_pattern_with_whitespace_is_refused(client) -> None:
    r = client.post(
        "/api/pages", json={"pattern": "a.test/robot s.txt"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 400


def test_a_pattern_with_a_parent_segment_is_refused(client) -> None:
    r = client.post("/api/pages", json={"pattern": "a.test/../etc"}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400


def test_an_oversize_body_is_refused(client) -> None:
    r = client.post(
        "/api/pages",
        json={"pattern": _pattern(), "body": "x" * (256 * 1024 + 1)},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert "256" in r.json()["detail"]


def test_an_empty_body_is_allowed(client) -> None:
    """A zero-byte page is a legitimate way to swallow a path."""
    created = _create(client, body="")
    assert created["body"] == ""


def test_a_content_type_with_a_line_break_is_refused(client) -> None:
    """It becomes a response header, so this is response splitting."""
    r = client.post(
        "/api/pages",
        json={"pattern": _pattern(), "body": "x", "content_type": "text/plain\r\nX-Evil: 1"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert "line break" in r.json()["detail"]


def test_a_content_type_that_is_not_a_type_is_refused(client) -> None:
    r = client.post(
        "/api/pages",
        json={"pattern": _pattern(), "body": "x", "content_type": "not a type"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400


def test_a_duplicate_pattern_is_a_conflict(client) -> None:
    pattern = _pattern()
    _create(client, pattern)
    r = client.post(
        "/api/pages", json={"pattern": pattern, "body": "other"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 409


# --------------------------------------------------------------------------- #
# Partial update
# --------------------------------------------------------------------------- #


def test_a_put_naming_only_the_body_leaves_the_rest_alone(client) -> None:
    created = _create(client)
    r = client.put(
        f"/api/pages/{created['id']}", json={"body": "changed"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200
    updated = r.json()
    assert updated["body"] == "changed"
    assert updated["pattern"] == created["pattern"]
    assert updated["content_type"] == created["content_type"]


def test_a_put_can_deactivate_a_page(client) -> None:
    created = _create(client)
    r = client.put(
        f"/api/pages/{created['id']}", json={"active": False}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200
    assert r.json()["active"] is False


def test_a_put_renaming_to_a_taken_pattern_is_a_conflict(client) -> None:
    first = _create(client)
    second = _create(client)
    r = client.put(
        f"/api/pages/{second['id']}",
        json={"pattern": first["pattern"]},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 409


def test_a_put_on_a_missing_page_is_a_404(client) -> None:
    assert (
        client.put(
            "/api/pages/999999", json={"body": "x"}, headers=INTERNAL_KEY_HEADERS
        ).status_code
        == 404
    )


# --------------------------------------------------------------------------- #
# Ordering
# --------------------------------------------------------------------------- #


def _orders(client) -> dict[int, int]:
    """`{page id: display_order}` as the API reports it."""
    return {p["id"]: p["display_order"] for p in _pages(client)}


def test_a_new_page_lands_last(client) -> None:
    """A new page appends at `max(display_order) + 1`, so it cannot displace one."""
    first = _create(client)
    second = _create(client)
    orders = _orders(client)
    assert orders[second["id"]] > orders[first["id"]]


def test_the_last_page_cannot_move_down(client) -> None:
    """The ends are no-ops, the contract the rule order endpoint already has."""
    last = max(_pages(client), key=lambda p: (p["display_order"], p["id"]))
    r = client.put(
        f"/api/pages/{last['id']}/order", json={"direction": "down"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert _orders(client)[last["id"]] == last["display_order"]


def test_an_order_direction_that_is_not_up_or_down_is_refused(client) -> None:
    pid = _create(client)["id"]
    r = client.put(
        f"/api/pages/{pid}/order", json={"direction": "sideways"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 400


def test_reordering_moves_a_page_one_visible_position(client) -> None:
    target = _create(client)
    other = _create(client)
    rows_before = [p["id"] for p in _pages(client)]
    assert rows_before.index(target["id"]) < rows_before.index(other["id"])

    r = client.put(
        f"/api/pages/{other['id']}/order", json={"direction": "up"}, headers=INTERNAL_KEY_HEADERS
    )
    assert r.status_code == 200
    rows_after = [p["id"] for p in _pages(client)]
    assert rows_after.index(other["id"]) < rows_after.index(target["id"])
