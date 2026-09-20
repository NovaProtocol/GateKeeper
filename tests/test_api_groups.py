"""Group update endpoint on the internal API.

`PUT /api/groups/{gid}` carries the same validation shape as
`PUT /api/rules/{rid}`: each field is checked only when it is actually present
in the payload, so a pure rename cannot be refused for an unrelated reason.

The default group is special, its domain is the catch-all the gate falls back
to, so it is refused with the same `cannot … default` wording the neighbouring
order and delete endpoints already use. Its *name* stays editable.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}
DEFAULT_DOMAIN = "*.*/*"


def _unique_name() -> str:
    return f"group-test-{uuid.uuid4().hex[:10]}"


def _unique_domain() -> str:
    return f"{uuid.uuid4().hex[:10]}.group-test"


def _create_group(client, name: str | None = None, domain: str | None = None) -> int:
    r = client.post(
        "/api/groups",
        json={"name": name or _unique_name(), "domain": domain or _unique_domain()},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _groups(client) -> list[dict]:
    r = client.get("/api/groups")
    assert r.status_code == 200
    return r.json()


def _group(client, gid: int) -> dict:
    return next(g for g in _groups(client) if g["id"] == gid)


def _default_group(client) -> dict:
    return next(g for g in _groups(client) if g["is_default"])


@pytest.fixture(autouse=True)
def _restore_default_group(client):
    """Undo this module's rename and any catch-all domain it handed out.

    Other modules assert on the plain `*.*/*` default (a group named `*.*/*`
    carrying `/* -> access_code`), so the module that deliberately renames it
    and moves `*.*/*` onto a scratch group has to put both back.
    """
    pre_existing = {g["id"] for g in _groups(client)}
    yield
    default = _default_group(client)
    client.put(
        f"/api/groups/{default['id']}",
        json={"name": DEFAULT_DOMAIN},
        headers=INTERNAL_KEY_HEADERS,
    )
    for g in _groups(client):
        if g["id"] in pre_existing or g["is_default"]:
            continue
        if g["domain"] in ("*.*/*", "*.*"):
            client.put(
                f"/api/groups/{g['id']}",
                json={"domain": _unique_domain()},
                headers=INTERNAL_KEY_HEADERS,
            )


def test_group_update_requires_internal_key(client) -> None:
    gid = _create_group(client)
    r = client.put(f"/api/groups/{gid}", json={"name": _unique_name()})
    assert r.status_code == 401


def test_group_update_renames_and_changes_domain(client) -> None:
    gid = _create_group(client)
    new_name = _unique_name()
    new_domain = _unique_domain()

    r = client.put(
        f"/api/groups/{gid}",
        json={"name": new_name, "domain": new_domain},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == gid
    assert body["name"] == new_name
    assert body["domain"] == new_domain
    assert body["is_default"] is False

    stored = _group(client, gid)
    assert stored["name"] == new_name
    assert stored["domain"] == new_domain


def test_group_update_name_only_leaves_domain_alone(client) -> None:
    """A pure rename sends no `domain`, so it can never trip domain validation."""
    domain = "not a domain!!"
    gid = _create_group(client, domain=domain)
    new_name = _unique_name()

    r = client.put(f"/api/groups/{gid}", json={"name": new_name}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    stored = _group(client, gid)
    assert stored["name"] == new_name
    assert stored["domain"] == domain


def test_group_update_rejects_empty_domain(client) -> None:
    gid = _create_group(client)
    before = _group(client, gid)

    r = client.put(
        f"/api/groups/{gid}",
        json={"domain": "   "},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "domain required"
    assert _group(client, gid)["domain"] == before["domain"]


def test_group_update_rejects_invalid_domain(client) -> None:
    gid = _create_group(client)
    before = _group(client, gid)

    r = client.put(
        f"/api/groups/{gid}",
        json={"domain": "not a domain!!"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "invalid domain"
    assert _group(client, gid)["domain"] == before["domain"]


def test_group_update_rejects_empty_name(client) -> None:
    gid = _create_group(client)
    before = _group(client, gid)

    r = client.put(f"/api/groups/{gid}", json={"name": "  "}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400
    assert r.json()["detail"] == "name required"
    assert _group(client, gid)["name"] == before["name"]


def test_group_update_rejects_duplicate_name(client) -> None:
    first = _create_group(client)
    second = _create_group(client)
    taken = _group(client, first)["name"]

    r = client.put(
        f"/api/groups/{second}",
        json={"name": taken},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "group exists"
    assert _group(client, second)["name"] != taken


def test_group_update_refuses_default_domain_change(client) -> None:
    default = _default_group(client)
    assert default["domain"] == DEFAULT_DOMAIN

    r = client.put(
        f"/api/groups/{default['id']}",
        json={"domain": _unique_domain()},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "cannot change default domain"
    assert _default_group(client)["domain"] == DEFAULT_DOMAIN


def test_group_update_allows_default_rename(client) -> None:
    """The default group's name is editable; only its catch-all domain is fixed."""
    default = _default_group(client)
    new_name = _unique_name()

    r = client.put(
        f"/api/groups/{default['id']}",
        json={"name": new_name},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200, r.text
    stored = _default_group(client)
    assert stored["name"] == new_name
    assert stored["domain"] == DEFAULT_DOMAIN


def test_group_update_accepts_every_live_domain_shape(client) -> None:
    """The house domains the gate actually runs with must survive validation."""
    for domain in (
        "gatekeeper.projectnova.download",
        "projectnova.download",
        "github.projectnova.download",
        "*.*/*",
        "*.*",
    ):
        gid = _create_group(client)
        r = client.put(
            f"/api/groups/{gid}",
            json={"domain": domain},
            headers=INTERNAL_KEY_HEADERS,
        )
        assert r.status_code == 200, f"{domain} -> {r.status_code} {r.text}"
        assert _group(client, gid)["domain"] == domain


def test_group_update_unknown_id_is_404(client) -> None:
    r = client.put(
        "/api/groups/9999999",
        json={"name": _unique_name()},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 404


def test_group_update_is_documented_in_openapi(client) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert "/api/groups/{gid}" in r.json()["paths"]
    assert "put" in r.json()["paths"]["/api/groups/{gid}"]
