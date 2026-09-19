"""Session lifetime and maintenance mode, at the gateway's two gate paths.

Three claims, each asserted from the outside:

* **the visitor lifetime moves both halves of the credential.** The cookie's
  ``Max-Age`` and the JWT's ``exp`` are read back and compared, because a cookie
  that outlives its own token fails on the next request and the failure looks
  like a bad code rather than a bad setting;
* **the admin session is not on that dial.** ``manage_session`` is minted by the
  management app with its own lifetime, so the test asserts it does not move,
  which is the whole reason there is a separate setting;
* **maintenance mode covers the site and never the way back in.** On, and every
  host answers 503 while ``/manage`` still renders; off, and the same request
  behaves exactly as before.

The gateway loads its cache and its settings over HTTP from an address that is
unreachable in tests, so both are injected directly. They are module-scoped
state, hence the autouse fixture that saves and restores them.
"""

from __future__ import annotations

import re
import threading
import time
from http.server import ThreadingHTTPServer
from typing import Any
from unittest.mock import patch

import pytest

from shared.jwt import decode_without_verify
from shared.settings_spec import (
    MAINTENANCE_MESSAGE,
    MAINTENANCE_MODE,
    SESSION_LIFETIME_HOURS,
)
from tests.test_gateway_failclosed import (
    HOST,
    _UpstreamHandler,
    _unique_ip,
    gateway_module,
    install_cache,
    make_group,
    make_route,
    proxy,
)


@pytest.fixture(scope="module")
def upstream() -> Any:
    """A real upstream that answers 200, so "was this dialled" is observable.

    Its own instance, not the one in the fail-closed module: that fixture is
    module-scoped, so by the time this file runs it has already been shut down
    and a shared handle would answer 502 in a way that reads like a gateway bug.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _UpstreamHandler.hits.clear()
    yield ("127.0.0.1", server.server_address[1])
    server.shutdown()
    server.server_close()


def install_settings(**values: str) -> None:
    """Pre-seed the gateway's settings cache, so no HTTP call is needed."""
    cache = gateway_module()._SettingCache
    now = time.monotonic()
    for key, value in values.items():
        cache[key] = (now, value)


@pytest.fixture(autouse=True)
def _isolate_gateway_state() -> Any:
    """Save and restore the gateway's module-scoped state around every test.

    The rule cache and the settings cache both outlive a test, so a test that
    seeds one would otherwise be read by the next. The shared ``httpx`` client is
    reset as well: it is closed by the module-scoped client fixture of whichever
    module ran first, so a retained handle would answer 502 on a request the test
    expects to succeed.
    """
    module = gateway_module()
    saved = (
        module._CacheGroups,
        module._CacheRoutes,
        module._CachePages,
        module._CacheTs,
        dict(module._SettingCache),
    )
    _UpstreamHandler.hits.clear()
    module._httpx_client = None
    yield
    module._CacheGroups, module._CacheRoutes, module._CachePages, module._CacheTs = (
        saved[0],
        saved[1],
        saved[2],
        saved[3],
    )
    module._SettingCache.clear()
    module._SettingCache.update(saved[4])
    module._httpx_client = None


def login(client: Any, host: str, code: str = "a-good-code") -> Any:
    """Spend an access code, so the response carries the session cookie."""
    from shared.models import Code

    granted = Code(code=code, label="tester", display_name="tester")
    granted.id = 3

    async def _verify(value: str) -> Any:
        return granted if value == code else None

    async def _rate(_ip: str) -> tuple[bool, int, int]:
        return False, 0, 60

    with (
        patch.object(gateway_module(), "_verify_code_value", _verify),
        patch.object(gateway_module(), "_check_access_code_rate_limited", _rate),
    ):
        return client.get(
            f"/?access_code={code}",
            headers={"X-Forwarded-Host": HOST, "CF-Connecting-IP": _unique_ip()},
            follow_redirects=False,
        )


def cookie_max_age(response: Any, name: str) -> int:
    """The ``Max-Age`` of one ``Set-Cookie`` header, as an int."""
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            match = re.search(r"Max-Age=(\d+)", header)
            assert match, f"no Max-Age on {header!r}"
            return int(match.group(1))
    raise AssertionError(f"{name} was not set: {response.headers.get_list('set-cookie')}")


def cookie_value(response: Any, name: str) -> str:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            return header.split(";", 1)[0].split("=", 1)[1]
    raise AssertionError(f"{name} was not set")


# --------------------------------------------------------------------------- #
# Session lifetime
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("hours", [1, 6, 48, 720])
def test_visitor_lifetime_sets_the_cookie_and_the_token_together(
    gateway_client: Any, hours: int
) -> None:
    install_settings(**{SESSION_LIFETIME_HOURS: str(hours)})
    install_cache([make_group(1, "open", HOST, [("/*", "access_code")])])

    response = login(gateway_client, HOST)

    assert response.status_code == 302
    assert cookie_max_age(response, "gatekeeper_token") == hours * 3600
    claims = decode_without_verify(cookie_value(response, "gatekeeper_token"))
    assert claims is not None
    ttl = claims["exp"] - claims["iat"]
    assert ttl == hours * 3600, "the JWT outlives or underlives its own cookie"


def test_visitor_lifetime_falls_back_to_twelve_hours(gateway_client: Any) -> None:
    """No stored row: the documented default, not an hour and not a year."""
    install_cache([make_group(1, "open", HOST, [("/*", "access_code")])])

    response = login(gateway_client, HOST)

    assert cookie_max_age(response, "gatekeeper_token") == 12 * 3600


@pytest.mark.parametrize("bad", ["0", "721", "-5", "later", "", "1e3"])
def test_a_nonsense_lifetime_cannot_be_acted_on(gateway_client: Any, bad: str) -> None:
    """A row edited outside the panel is normalized, not obeyed."""
    install_settings(**{SESSION_LIFETIME_HOURS: bad})
    install_cache([make_group(1, "open", HOST, [("/*", "access_code")])])

    response = login(gateway_client, HOST)

    assert cookie_max_age(response, "gatekeeper_token") == 12 * 3600


def test_the_admin_session_is_not_on_the_visitor_dial(manage_client: Any) -> None:
    """`manage_session` keeps its own 8h. Extending visitor access must not extend it.

    The two are minted by different apps with different lifetimes; this asserts
    the visitor setting has no route to the admin cookie even at its maximum.
    """
    import os

    os.environ["MANAGE_PASSWORD"] = "test-manage-password"
    response = manage_client.post(
        "/manage/login",
        data={"manage_password": "test-manage-password", "csrf_token": "t"},
        cookies={"csrf_token": "t"},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert cookie_max_age(response, "manage_session") == 8 * 3600


def test_the_visitor_setting_does_not_reach_the_manage_cookie(
    gateway_client: Any, manage_client: Any
) -> None:
    """Set the maximum, then log in to /manage: the admin cookie is unchanged."""
    install_settings(**{SESSION_LIFETIME_HOURS: "720"})
    install_cache([make_group(1, "open", HOST, [("/*", "access_code")])])
    visitor = login(gateway_client, HOST)
    admin = manage_client.post(
        "/manage/login",
        data={"manage_password": "test-manage-password", "csrf_token": "t"},
        cookies={"csrf_token": "t"},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )

    assert cookie_max_age(visitor, "gatekeeper_token") == 720 * 3600
    assert cookie_max_age(admin, "manage_session") == 8 * 3600


# --------------------------------------------------------------------------- #
# Maintenance mode
# --------------------------------------------------------------------------- #


def test_maintenance_refuses_a_normal_host_at_both_paths(
    upstream: Any, gateway_client: Any
) -> None:
    install_settings(**{MAINTENANCE_MODE: "true"})
    install_cache(
        [make_group(1, "open", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
    )

    wildcard = proxy(gateway_client, HOST, "/anything")
    forward = gateway_client.get(
        "/api/authz/forward-auth",
        headers={
            "X-Forwarded-Host": HOST,
            "X-Forwarded-Uri": "/anything",
            "CF-Connecting-IP": _unique_ip(),
        },
        follow_redirects=False,
    )

    assert wildcard.status_code == 503
    assert forward.status_code == 503
    assert _UpstreamHandler.hits == [], "maintenance mode still dialled the upstream"


def test_maintenance_serves_the_themed_page_and_the_notice(
    upstream: Any, gateway_client: Any
) -> None:
    install_settings(**{MAINTENANCE_MODE: "true", MAINTENANCE_MESSAGE: "Back at 18:00 UTC"})
    install_cache([make_group(1, "open", HOST, [("/*", "none")])], [make_route(HOST, *upstream)])

    response = gateway_client.get(
        "/anything",
        headers={
            "X-Forwarded-Host": HOST,
            "Accept": "text/html",
            "CF-Connecting-IP": _unique_ip(),
        },
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "300"
    assert "Down for maintenance" in response.text
    assert "Back at 18:00 UTC" in response.text


def test_the_notice_is_escaped(upstream: Any, gateway_client: Any) -> None:
    install_settings(**{MAINTENANCE_MODE: "true", MAINTENANCE_MESSAGE: "<script>alert(1)</script>"})
    install_cache([make_group(1, "open", HOST, [("/*", "none")])], [make_route(HOST, *upstream)])

    response = gateway_client.get(
        "/x",
        headers={"X-Forwarded-Host": HOST, "Accept": "text/html", "CF-Connecting-IP": _unique_ip()},
        follow_redirects=False,
    )

    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_maintenance_refuses_an_api_caller_with_json(upstream: Any, gateway_client: Any) -> None:
    install_settings(**{MAINTENANCE_MODE: "true"})
    install_cache([make_group(1, "open", HOST, [("/*", "none")])], [make_route(HOST, *upstream)])

    response = gateway_client.get(
        "/x",
        headers={
            "X-Forwarded-Host": HOST,
            "Accept": "application/json",
            "CF-Connecting-IP": _unique_ip(),
        },
        follow_redirects=False,
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "maintenance mode"}


def test_the_manage_page_is_never_maintenance(gateway_client: Any) -> None:
    """The operator must be able to reach the switch that turns it off."""
    install_settings(**{MAINTENANCE_MODE: "true"})
    install_cache([make_group(1, "open", "gatekeeper.projectnova.download", [("/*", "none")])])

    response = gateway_client.get(
        "/manage/settings",
        headers={
            "X-Forwarded-Host": "gatekeeper.projectnova.download",
            "Accept": "text/html",
            "CF-Connecting-IP": _unique_ip(),
        },
        follow_redirects=False,
    )

    assert response.status_code != 503


def test_the_rest_of_the_gatekeeper_host_still_shows_maintenance(
    gateway_client: Any,
) -> None:
    """The exemption is /manage, not the whole host."""
    install_settings(**{MAINTENANCE_MODE: "true"})
    install_cache([make_group(1, "gk", "gatekeeper.projectnova.download", [("/*", "none")])])

    response = gateway_client.get(
        "/documentation/index.html",
        headers={
            "X-Forwarded-Host": "gatekeeper.projectnova.download",
            "CF-Connecting-IP": _unique_ip(),
        },
        follow_redirects=False,
    )

    assert response.status_code == 503


def test_maintenance_off_behaves_exactly_as_before(upstream: Any, gateway_client: Any) -> None:
    install_settings(**{MAINTENANCE_MODE: "false"})
    install_cache(
        [make_group(1, "open", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
    )

    response = proxy(gateway_client, HOST, "/open")

    assert response.status_code == 200
    assert response.text == "upstream-ok"
    assert _UpstreamHandler.hits == ["/open"]


def test_an_unreadable_maintenance_row_reads_as_off(upstream: Any, gateway_client: Any) -> None:
    """The safe fallback is the site staying up, not the site going dark."""
    install_settings(**{MAINTENANCE_MODE: "mostly"})
    install_cache(
        [make_group(1, "open", HOST, [("/*", "none")])],
        [make_route(HOST, *upstream)],
    )

    response = proxy(gateway_client, HOST, "/open")

    assert response.status_code == 200
