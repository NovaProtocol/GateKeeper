import base64

import pytest


@pytest.fixture()
def auth_header():
    creds = base64.b64encode(b"admin:test-manage-password").decode()
    return {"Authorization": f"Basic {creds}"}


def test_forward_auth_without_cookie_redirects_to_login(client):
    resp = client.get("/api/authz/forward-auth")
    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("https://gatekeeper.localhost/?redirect=")


def test_forward_auth_with_valid_code_sets_cookie_and_strips_param(client, valid_code):
    resp = client.get(
        "/api/authz/forward-auth",
        headers={"X-Forwarded-Uri": f"/private/app?access_code={valid_code}"},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/private/app"
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "gatekeeper_token=" in set_cookie
    assert "HttpOnly" in set_cookie


def test_forward_auth_with_valid_cookie_allows(client, app, valid_code):
    from app import serializer

    client.set_cookie("gatekeeper_token", serializer.dumps(valid_code), domain="localhost")
    resp = client.get("/api/authz/forward-auth")
    assert resp.status_code == 200
    assert resp.data == b""


def test_manage_requires_basic_auth(client, auth_header):
    resp = client.get("/manage")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers

    resp = client.get("/manage", headers=auth_header)
    assert resp.status_code == 200
