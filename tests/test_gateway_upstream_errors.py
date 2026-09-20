"""The gateway's themed upstream error pages.

When the application behind a route does not answer, the wildcard proxy used to
return a bare ``JSONResponse`` whatever the caller asked for, so a browser that
hit a stopped container got a line of JSON on a blank page. Both failure modes
also collapsed into one ``except Exception`` and reported ``502``.

Three claims carry this file:

* **the failure classes stay distinct.** Nothing listening is ``502``; something
  that accepted the connection and then went quiet is ``504``. They have
  different causes and different fixes, so a single status for both sends the
  operator looking in the wrong place.
* **content negotiation is honoured.** The same failure gives a browser the
  themed page every other gateway error uses and gives an API caller JSON, via
  the ``wants_html`` branch the rest of the gateway already routes through.
* **the request still fails.** Themed or not, a dead upstream answers an error
  and never a 200, and the status the caller sees is the one in the body.

The upstreams are real: a closed port for the connection failure, and a socket
that accepts and then sleeps for the timeout. A patched transport would only
prove the handler was called.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import httpx
import pytest

from tests.test_gateway_failclosed import (
    HOST,
    _unique_ip,
    gateway_module,
    install_cache,
    make_group,
    make_route,
)

BROWSER = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
API_CALLER = {"Accept": "application/json"}

THEMED_MARKERS = ("<!DOCTYPE html>", 'class="card"', "~/", "Turn back")


def _closed_port() -> int:
    """A port nothing is listening on, so the connect is refused outright."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture(scope="module")
def silent_upstream() -> Any:
    """A socket that accepts and never answers, so the read times out."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    held: list[socket.socket] = []

    def _accept_and_hold() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            held.append(conn)

    thread = threading.Thread(target=_accept_and_hold, daemon=True)
    thread.start()
    yield ("127.0.0.1", server.getsockname()[1])
    server.close()
    for conn in held:
        conn.close()


@pytest.fixture(autouse=True)
def _isolate_gateway_state() -> Any:
    """Save and restore the gateway's module-scoped caches around every test.

    The rule cache is module-level and outlives a test, and ``_httpx_client`` is
    closed by whichever module-scoped client fixture ran first, so a retained
    handle would fail for a reason that has nothing to do with the code here.
    """
    module = gateway_module()
    saved = (
        module._CacheGroups,
        module._CacheRoutes,
        module._CachePages,
        module._CacheTs,
        dict(module._SettingCache),
    )
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


def _serve(client: Any, host: str, upstream: str, port: int, headers: dict[str, str]) -> Any:
    """One public path, routed to ``upstream:port`` with nothing to gate it."""
    install_cache(
        [make_group(1, "portfolio", host, [("/*", "none")])], [make_route(host, upstream, port)]
    )
    return client.get(
        "/anything",
        headers={"X-Forwarded-Host": host, "CF-Connecting-IP": _unique_ip(), **headers},
        follow_redirects=False,
    )


def _assert_themed(response: Any) -> None:
    """The page is the shared gateway error document, not a JSON body."""
    assert response.headers["content-type"].startswith("text/html"), response.headers[
        "content-type"
    ]
    for marker in THEMED_MARKERS:
        assert marker in response.text, marker


# --------------------------------------------------------------------------- #
# 502: nothing is listening
# --------------------------------------------------------------------------- #


def test_a_dead_upstream_gives_a_browser_the_themed_page(gateway_client: Any) -> None:
    response = _serve(gateway_client, HOST, "127.0.0.1", _closed_port(), BROWSER)

    assert response.status_code == 502
    _assert_themed(response)
    assert "Upstream unavailable" in response.text


def test_the_same_failure_gives_an_api_caller_json(gateway_client: Any) -> None:
    """Same route, same dead port, different Accept header."""
    response = _serve(gateway_client, HOST, "127.0.0.1", _closed_port(), API_CALLER)

    assert response.status_code == 502
    body = response.json()
    assert "refused the connection" in body["detail"]
    assert "<!DOCTYPE html>" not in response.text


def test_the_json_body_names_the_upstream_that_failed(gateway_client: Any) -> None:
    port = _closed_port()
    response = _serve(gateway_client, HOST, "127.0.0.1", port, API_CALLER)

    assert f"127.0.0.1:{port}" in response.json()["detail"]


def test_an_unresolvable_upstream_is_also_a_502(gateway_client: Any) -> None:
    """A name that does not resolve raises the same class as a refused connect."""
    response = _serve(gateway_client, HOST, "no-such-container.invalid", 8080, BROWSER)

    assert response.status_code == 502
    _assert_themed(response)


# --------------------------------------------------------------------------- #
# 504: accepted, then silent
# --------------------------------------------------------------------------- #


def _with_short_timeout(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    """Give the gateway a client that gives up quickly, so the test is fast."""
    monkeypatch.setattr(
        gateway_module(),
        "_get_httpx",
        lambda: httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(seconds)),
    )


def test_a_silent_upstream_gives_a_browser_the_themed_page(
    gateway_client: Any, silent_upstream: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _with_short_timeout(monkeypatch, 0.4)
    host, port = silent_upstream

    response = _serve(gateway_client, HOST, host, port, BROWSER)

    assert response.status_code == 504
    _assert_themed(response)
    assert "Upstream timed out" in response.text


def test_a_silent_upstream_gives_an_api_caller_json(
    gateway_client: Any, silent_upstream: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _with_short_timeout(monkeypatch, 0.4)
    host, port = silent_upstream

    response = _serve(gateway_client, HOST, host, port, API_CALLER)

    assert response.status_code == 504
    assert "did not respond in time" in response.json()["detail"]


def test_the_timeout_lands_after_the_connect_succeeded(
    gateway_client: Any, silent_upstream: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The distinction the two statuses rest on, asserted on the same handler.

    ``httpx.ConnectTimeout`` is a ``TimeoutException`` but not a ``ConnectError``,
    so the branch order cannot misclassify it; what this checks is that the silent
    upstream is a *slow* one rather than an unreachable one, which is what makes
    ``504`` the honest answer.
    """
    host, port = silent_upstream
    with httpx.Client(timeout=0.4) as probe, pytest.raises(httpx.TimeoutException) as raised:
        probe.get(f"http://{host}:{port}/")
    assert isinstance(raised.value, httpx.ReadTimeout)
    assert not isinstance(raised.value, httpx.ConnectError)


def test_the_two_failure_modes_get_different_statuses(
    gateway_client: Any, silent_upstream: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    dead = _serve(gateway_client, HOST, "127.0.0.1", _closed_port(), API_CALLER)
    _with_short_timeout(monkeypatch, 0.4)
    host, port = silent_upstream
    silent = _serve(gateway_client, HOST, host, port, API_CALLER)

    assert dead.status_code == 502
    assert silent.status_code == 504
    assert dead.json()["detail"] != silent.json()["detail"]


# --------------------------------------------------------------------------- #
# The catch-all branch keeps its own status
# --------------------------------------------------------------------------- #


def test_an_unexpected_proxy_failure_is_a_themed_502(
    gateway_client: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any other transport failure is still an error page, not a traceback."""

    class _Boom:
        async def request(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("connection closed mid-response")

    monkeypatch.setattr(gateway_module(), "_get_httpx", _Boom)

    response = _serve(gateway_client, HOST, "127.0.0.1", _closed_port(), BROWSER)

    assert response.status_code == 502
    _assert_themed(response)


def test_a_dead_upstream_never_answers_200(gateway_client: Any) -> None:
    """Themed or not, the request failed and the caller must be able to tell."""
    started = time.monotonic()
    dead = _serve(gateway_client, HOST, "127.0.0.1", _closed_port(), BROWSER)

    assert dead.status_code >= 500
    assert time.monotonic() - started < 10.0, "a refused connect should not wait for a timeout"
