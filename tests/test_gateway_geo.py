"""The gateway's half of country capture: read the header, send it on the row.

`shared/geo.py` proves the parsing and `tests/test_api_logs_geo.py` proves the
storage. This is the join between them, and it is the step that would silently do
nothing if it were dropped: a correct resolver nobody calls produces exactly the
same database as a header Cloudflare never sends.

The gateway queues its audit write as a background task that POSTs to `api:8002`,
which is unreachable here, so the transport is replaced with one that records the
payload. That makes the claim checkable without a running API: the body the
gateway *would* send is the value the API would store.

The group in these cases is `access_code`, because that is the path a real visitor
takes: it writes an audit row on every branch, so the country is asserted against
a row that exists. A `none` rule proxies without auditing at all, which would
make a missing country indistinguishable from a missing row.

Three behaviours are load-bearing:

* **the setting is checked before the header is read.** Off means nothing is sent
  at all, which is what makes the switch worth having;
* **a request with no country still audits normally.** Logging must not depend on
  a header whose arrival is unverified, so the absent case is asserted as
  carefully as the present one;
* **both gate paths agree.** `forward_auth` and the wildcard proxy are two
  entries into the same decision, and a country recorded on only one of them
  would produce a map that silently omits half the traffic.
"""

from __future__ import annotations

import time
from typing import Any

from shared.models import Code
from shared.settings_spec import GEO_LOOKUP_ENABLED
from tests.test_gateway_failclosed import (
    _unique_ip,
    gateway_module,
    install_cache,
    make_group,
    make_route,
)

#: The host every case here uses, with a route and an `access_code` group.
HOST = "geo-gateway.test"


class _RecordingResponse:
    status_code = 200
    text = ""

    def json(self) -> dict[str, Any]:
        return {"ok": True}


class _RecordingClient:
    """Captures every audit POST the background task makes.

    The gateway holds one shared client for both auditing and proxying, so a
    `request` is answered too: a test that reached the proxy would otherwise fail
    for a reason that has nothing to do with the claim under test.
    """

    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []

    async def post(self, url: str, json: dict[str, Any] | None = None, **kwargs: Any):
        if url.endswith("/api/logs"):
            self.posts.append(dict(json or {}))
        return _RecordingResponse()

    async def get(self, url: str, **kwargs: Any):
        return _RecordingResponse()


def _install(monkeypatch: Any, action: str = "access_code", **settings: str) -> _RecordingClient:
    """Give the gateway a route, a group and a recording audit transport.

    The settings cache is pre-seeded so no HTTP call is needed to read the
    switch; a value that is not passed takes the gateway's own default, which is
    what it would read from an unavailable API anyway.
    """
    module = gateway_module()
    install_cache(
        [make_group(1, "geo", HOST, [("/*", action)])],
        [make_route(HOST, "127.0.0.1", 9)],
    )
    cache = module._SettingCache
    cache.clear()
    now = time.monotonic()
    cache[GEO_LOOKUP_ENABLED] = (now, settings.get(GEO_LOOKUP_ENABLED, "true"))
    for key, value in settings.items():
        cache[key] = (now, value)
    client = _RecordingClient()
    monkeypatch.setattr(module, "_get_httpx", lambda: client)
    return client


def _forward_headers(country: str | None = "PH", ip: str | None = None) -> dict[str, str]:
    headers = {"X-Forwarded-Host": HOST, "CF-Connecting-IP": ip or _unique_ip()}
    if country is not None:
        headers["CF-IPCountry"] = country
    return headers


def _get(
    gateway_client: Any,
    path: str = "/anything",
    country: str | None = "PH",
    ip: str | None = None,
) -> Any:
    return gateway_client.get(
        path, headers=_forward_headers(country, ip), follow_redirects=False
    )


def _forward_auth(gateway_client: Any, country: str | None = "PH", path: str = "/anything") -> Any:
    headers = _forward_headers(country)
    headers["X-Forwarded-Uri"] = path
    return gateway_client.get("/api/authz/forward-auth", headers=headers, follow_redirects=False)


def _country_on_the_row(client: _RecordingClient) -> str | None:
    """The country the gateway sent, from the last audit POST it made."""
    assert client.posts, "the gateway queued no audit write at all"
    return client.posts[-1].get("country")


def _last_action(client: _RecordingClient) -> str | None:
    return client.posts[-1].get("action") if client.posts else None


# --------------------------------------------------------------------------- #
# The header, end to end through the proxy path
# --------------------------------------------------------------------------- #


def test_a_request_carrying_a_country_sends_that_country(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """The whole capture path in one assertion: header in, row payload out."""
    client = _install(monkeypatch)

    r = _get(gateway_client, country="PH")

    assert r.status_code == 302, r.status_code
    assert _last_action(client) == "no_cookie_redirect"
    assert _country_on_the_row(client) == "PH"


def test_a_request_without_the_country_header_still_audits(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """The unverified premise, asserted as the null it degrades to."""
    client = _install(monkeypatch)

    r = _get(gateway_client, country=None)

    assert r.status_code == 302, r.status_code
    assert client.posts, "the request was not audited at all"
    assert _country_on_the_row(client) is None
    assert client.posts[-1]["ip"], "the visitor address is still recorded"


def test_an_empty_country_header_is_null_not_an_empty_string(
    gateway_client: Any, monkeypatch: Any
) -> None:
    client = _install(monkeypatch)

    _get(gateway_client, country="")

    assert _country_on_the_row(client) is None


def test_a_sentinel_country_is_sent_as_null(gateway_client: Any, monkeypatch: Any) -> None:
    """`XX` means Cloudflare could not tell; it must not become a stored `XX`."""
    client = _install(monkeypatch)

    _get(gateway_client, country="XX")

    assert _country_on_the_row(client) is None


def test_a_tor_country_is_sent_as_null(gateway_client: Any, monkeypatch: Any) -> None:
    client = _install(monkeypatch)

    _get(gateway_client, country="T1")

    assert _country_on_the_row(client) is None


def test_a_garbage_country_is_sent_as_null(gateway_client: Any, monkeypatch: Any) -> None:
    client = _install(monkeypatch)

    _get(gateway_client, country="<script>alert(1)</script>")

    assert _country_on_the_row(client) is None


def test_a_lowercase_country_is_sent_as_null(gateway_client: Any, monkeypatch: Any) -> None:
    """Cloudflare sends uppercase, so lowercase did not come from Cloudflare."""
    client = _install(monkeypatch)

    _get(gateway_client, country="ph")

    assert _country_on_the_row(client) is None


def test_a_whitespace_padded_country_is_trimmed(gateway_client: Any, monkeypatch: Any) -> None:
    client = _install(monkeypatch)

    _get(gateway_client, country="  PH  ")

    assert _country_on_the_row(client) == "PH"


# --------------------------------------------------------------------------- #
# The switch
# --------------------------------------------------------------------------- #


def test_capture_off_sends_nothing_even_when_the_header_is_there(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """The switch is checked first, so off means the header is not read."""
    client = _install(monkeypatch, **{GEO_LOOKUP_ENABLED: "false"})

    _get(gateway_client, country="PH")

    assert client.posts, "capture off must not stop the request being audited"
    assert _country_on_the_row(client) is None


def test_capture_off_still_audits_the_visitor_address(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """Turning capture off is a privacy choice, not a logging outage."""
    client = _install(monkeypatch, **{GEO_LOOKUP_ENABLED: "false"})

    _get(gateway_client, country="PH", ip="203.0.113.77")

    assert client.posts[-1]["ip"] == "203.0.113.77"


def test_capture_off_still_audits_the_action(gateway_client: Any, monkeypatch: Any) -> None:
    client = _install(monkeypatch, **{GEO_LOOKUP_ENABLED: "false"})

    _get(gateway_client, country="PH")

    assert _last_action(client) == "no_cookie_redirect"


def test_an_unreadable_setting_leaves_capture_on(gateway_client: Any, monkeypatch: Any) -> None:
    """The default direction is the recording one, matching the seeded setting."""
    client = _install(monkeypatch, **{GEO_LOOKUP_ENABLED: "perhaps"})

    _get(gateway_client, country="DE")

    assert _country_on_the_row(client) == "DE"


# --------------------------------------------------------------------------- #
# Both gate paths
# --------------------------------------------------------------------------- #


def test_forward_auth_records_the_country(gateway_client: Any, monkeypatch: Any) -> None:
    client = _install(monkeypatch)

    r = _forward_auth(gateway_client, country="PH")

    assert r.status_code == 302, r.status_code
    assert _country_on_the_row(client) == "PH"


def test_both_gate_paths_record_the_same_country(gateway_client: Any, monkeypatch: Any) -> None:
    """Two entries into one decision: a country on only one is a silent hole."""
    client = _install(monkeypatch)

    _get(gateway_client, country="PH")
    via_proxy = _country_on_the_row(client)

    client.posts.clear()
    _forward_auth(gateway_client, country="PH")

    assert via_proxy == _country_on_the_row(client) == "PH"


def test_both_gate_paths_record_the_same_null_without_the_header(
    gateway_client: Any, monkeypatch: Any
) -> None:
    client = _install(monkeypatch)

    _get(gateway_client, country=None)
    via_proxy = _country_on_the_row(client)

    client.posts.clear()
    _forward_auth(gateway_client, country=None)

    assert via_proxy is None
    assert _country_on_the_row(client) is None


# --------------------------------------------------------------------------- #
# The other actions that audit
# --------------------------------------------------------------------------- #


def test_the_country_reaches_the_maintenance_audit_row_too(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """A refused-by-maintenance request is still a visit, with an origin."""
    client = _install(monkeypatch, **{"maintenance_mode": "true"})

    r = _get(gateway_client, country="PH")

    assert r.status_code == 503
    assert client.posts, "the maintenance refusal was not audited"
    assert _last_action(client) == "maintenance_mode"
    assert _country_on_the_row(client) == "PH"


def test_the_country_reaches_a_denied_request_too(gateway_client: Any, monkeypatch: Any) -> None:
    client = _install(monkeypatch, action="deny")

    r = _get(gateway_client, country="PH")

    assert r.status_code == 403
    assert _last_action(client) == "deny"
    assert _country_on_the_row(client) == "PH"


def test_a_login_attempt_gets_its_country_too(gateway_client: Any, monkeypatch: Any) -> None:
    """The access-code path is the one that records who actually came in."""
    module = gateway_module()
    client = _install(monkeypatch)
    granted = Code(code="good-code", label="tester", display_name="tester")
    granted.id = 3

    async def _verify(value: str) -> Any:
        return granted if value == "good-code" else None

    async def _rate(_ip: str) -> tuple[bool, int, int]:
        return False, 0, 60

    monkeypatch.setattr(module, "_verify_code_value", _verify)
    monkeypatch.setattr(module, "_check_access_code_rate_limited", _rate)

    r = _get(gateway_client, path="/?access_code=good-code", country="PH")

    assert r.status_code == 302
    assert _last_action(client) == "access_code_login"
    assert _country_on_the_row(client) == "PH"


def test_a_failed_code_attempt_gets_its_country_too(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """A refused code writes its own row and then the redirect one.

    Both carry the same country, which is the claim: the value is read once per
    request and cannot vary between the rows that request produces.
    """
    module = gateway_module()
    client = _install(monkeypatch)

    async def _verify(_value: str) -> Any:
        return None

    async def _rate(_ip: str) -> tuple[bool, int, int]:
        return False, 0, 60

    monkeypatch.setattr(module, "_verify_code_value", _verify)
    monkeypatch.setattr(module, "_check_access_code_rate_limited", _rate)

    r = _get(gateway_client, path="/?access_code=wrong", country="DE")

    assert r.status_code == 302
    actions = [post.get("action") for post in client.posts]
    assert "access_code_fail" in actions, actions
    assert {post.get("country") for post in client.posts} == {"DE"}, client.posts


def test_the_country_does_not_vary_between_rows_of_one_request(
    gateway_client: Any, monkeypatch: Any
) -> None:
    client = _install(monkeypatch)

    _get(gateway_client, country="US")

    countries = {post.get("country") for post in client.posts}
    assert countries == {"US"}, client.posts


def test_every_audit_payload_carries_the_key_even_when_it_is_null(
    gateway_client: Any, monkeypatch: Any
) -> None:
    """The key is always present, so the API can tell it apart from an old build."""
    client = _install(monkeypatch)

    _get(gateway_client, country=None)

    assert all("country" in post for post in client.posts)
