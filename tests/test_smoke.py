"""Smoke tests for the current stack.

Each service is exercised through its own ``TestClient`` so the real lifespan
runs — for the API that means the schema is created and the default rule groups
are seeded, which is what the seed assertions below rely on.

The old Flask-era tests here asserted the pre-rewrite forward-auth contract
(``itsdangerous`` tokens, ``gatekeeper.localhost``, Basic auth on ``/manage``).
None of that survives the split into ``api``/``auth-gateway``/``management``, so
they were replaced rather than ported.
"""

from __future__ import annotations

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}


def test_api_health_ok(client) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_gateway_health_ok(gateway_client) -> None:
    r = gateway_client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_management_health_ok(manage_client) -> None:
    r = manage_client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_api_openapi_exposes_expected_routes(client) -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    for expected in (
        "/health",
        "/api/routes",
        "/api/groups",
        "/api/dry-run",
        "/api/rules/{rid}/order",
        "/api/groups/{gid}/order",
        "/api/logs/by-ip",
        "/api/warnings",
    ):
        assert expected in paths, f"{expected} missing from openapi.json"


def test_api_internal_route_rejects_anonymous(client) -> None:
    r = client.put("/api/settings/rate_limit_access_code_per_min", json={"value": "7"})
    assert r.status_code == 401


def test_api_internal_route_accepts_internal_key(client) -> None:
    r = client.put(
        "/api/settings/rate_limit_access_code_per_min",
        json={"value": "7"},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["value"] == "7"


def test_api_seeds_default_rule_group(client) -> None:
    """The lifespan seeds `*.*/*` with a `/* -> access_code` rule."""
    r = client.post("/api/dry-run", json={"host": "unseeded.example.com", "path": "/"})
    assert r.status_code == 200
    body = r.json()
    assert body["matched_group"]["name"] == "*.*/*"
    assert body["matched_rule"]["path"] == "/*"
    assert body["action"] == "access_code"


def test_api_seeds_backup_code(client) -> None:
    r = client.get("/api/codes")
    assert r.status_code == 200
    assert any(row["code"] == "test-backup-code" for row in r.json())


def test_gateway_forward_auth_without_cookie_redirects_to_login(gateway_client) -> None:
    r = gateway_client.get(
        "/api/authz/forward-auth",
        headers={"Host": "portfolio.projectnova.download", "X-Forwarded-Uri": "/private/app"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["Location"].startswith(
        "https://gatekeeper.projectnova.download/login?redirect="
    )


def test_manage_requires_session(manage_client) -> None:
    r = manage_client.get("/manage", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].startswith("/manage/login?redirect=")


def test_manage_login_page_renders(manage_client) -> None:
    r = manage_client.get("/manage/login")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
