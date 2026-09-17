"""`POST /api/routes/test`: probing a draft route before it is saved.

The saved-route endpoint can only answer questions about a route that already
exists, which is the wrong moment for a wrong port: by then it is live. This is
the endpoint behind the modal's Test button, so what it must get right is the
boundary between "the values are invalid" and "the values are valid but nothing
is listening".

Three claims carry the file:

* **an unreachable upstream is a 200.** The probe succeeded; the answer is no. A
  4xx would make the modal render a validation error for a perfectly well-formed
  route, and a caller could not tell a typo from a dead container.
* **invalid input is a 400, and it matches the save.** The validation is shared
  with `create_route`'s rules, so testing a shape and saving it cannot disagree;
  a route the probe accepts must be one the save accepts.
* **the endpoint touches no database.** It is deliberately DB-free, so it cannot
  be used to create, mutate or probe stored rows.
"""

from __future__ import annotations

import socket
import threading
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}


@pytest.fixture(scope="module")
def listener() -> Any:
    """A real socket that accepts connections, on an ephemeral localhost port.

    A real listener rather than a mock, because the claim under test is that the
    probe actually opens a connection: a patched `create_connection` would prove
    only that the code calls the function it was told to call.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    port = server.getsockname()[1]

    def _accept_forever() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.close()

    thread = threading.Thread(target=_accept_forever, daemon=True)
    thread.start()
    yield ("127.0.0.1", port)
    server.close()


def _closed_port() -> int:
    """A port nothing is listening on, so the probe must fail to connect."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _test(client: TestClient, **payload: Any) -> Any:
    return client.post("/api/routes/test", json=payload, headers=INTERNAL)


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #


def test_it_requires_the_internal_key(client: TestClient) -> None:
    r = client.post("/api/routes/test", json={"route_type": "proxy", "upstream": "x", "port": 80})
    assert r.status_code == 401


def test_a_wrong_key_is_refused(client: TestClient) -> None:
    r = client.post(
        "/api/routes/test",
        json={"route_type": "proxy", "upstream": "x", "port": 80},
        headers={"X-Internal-Api-Key": "not-the-key"},
    )
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# A reachable proxy upstream
# --------------------------------------------------------------------------- #


def test_a_reachable_upstream_is_ok(client: TestClient, listener: Any) -> None:
    host, port = listener
    r = _test(client, route_type="proxy", upstream=host, port=port)

    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_the_route_type_defaults_to_proxy(client: TestClient, listener: Any) -> None:
    host, port = listener
    r = _test(client, upstream=host, port=port)

    assert r.status_code == 200
    assert r.json()["ok"] is True


# --------------------------------------------------------------------------- #
# An unreachable upstream is data, not an error
# --------------------------------------------------------------------------- #


def test_a_closed_port_is_a_200_with_ok_false(client: TestClient) -> None:
    """The probe answered; the answer was no. That is not a client error."""
    r = _test(client, route_type="proxy", upstream="127.0.0.1", port=_closed_port())

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["error"]


def test_a_hostname_that_does_not_resolve_is_a_200_with_ok_false(client: TestClient) -> None:
    r = _test(client, route_type="proxy", upstream="no-such-container.invalid", port=8080)

    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_an_unreachable_result_is_not_html(
    client: TestClient,
) -> None:
    """The modal parses this as JSON, so the error path must stay JSON too."""
    r = client.post(
        "/api/routes/test",
        json={"route_type": "proxy", "upstream": "127.0.0.1", "port": _closed_port()},
        headers={**INTERNAL, "Accept": "text/html"},
    )

    assert r.status_code == 200
    assert r.json()["ok"] is False


# --------------------------------------------------------------------------- #
# Validation, mirroring the save
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("port", [0, 70000, -1, 999999])
def test_an_out_of_range_port_is_refused(client: TestClient, port: int) -> None:
    r = _test(client, route_type="proxy", upstream="127.0.0.1", port=port)

    assert r.status_code == 400
    assert "port" in r.json()["detail"]


def test_a_non_numeric_port_is_refused(client: TestClient) -> None:
    r = _test(client, route_type="proxy", upstream="127.0.0.1", port="not-a-number")

    assert r.status_code == 400


def test_a_missing_upstream_is_refused(client: TestClient) -> None:
    r = _test(client, route_type="proxy", upstream="", port=8080)

    assert r.status_code == 400
    assert "upstream" in r.json()["detail"]


def test_an_empty_route_type_is_refused(client: TestClient) -> None:
    """Unlike the save, which silently falls back to proxy, the test refuses.

    A probe is a question asked on purpose; guessing which type was meant would
    answer a question nobody asked.
    """
    r = _test(client, route_type="nonsense", upstream="127.0.0.1", port=8080)

    assert r.status_code == 400
    assert "route_type" in r.json()["detail"]


def test_an_empty_body_is_refused(client: TestClient) -> None:
    r = client.post("/api/routes/test", json={}, headers=INTERNAL)

    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Redirect targets
# --------------------------------------------------------------------------- #


def test_a_path_redirect_needs_no_resolution(client: TestClient) -> None:
    r = _test(client, route_type="redirect", redirect_target="/newpath")

    assert r.status_code == 200
    assert r.json()["note"] == "redirect path ok"


def test_a_url_redirect_to_a_real_host_is_ok(client: TestClient) -> None:
    r = _test(client, route_type="redirect", redirect_target="https://localhost/")

    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_a_url_redirect_to_a_bad_host_is_ok_false(client: TestClient) -> None:
    r = _test(client, route_type="redirect", redirect_target="https://nope.invalid/")

    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_an_empty_redirect_target_is_refused(client: TestClient) -> None:
    r = _test(client, route_type="redirect", redirect_target="")

    assert r.status_code == 400
    assert "redirect_target" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# It does not touch the database
# --------------------------------------------------------------------------- #


def test_the_draft_probe_writes_nothing(client: TestClient, listener: Any) -> None:
    """Called repeatedly, the route list must be exactly what it was."""
    before = client.get("/api/routes").json()
    host, port = listener
    for _ in range(3):
        _test(client, route_type="proxy", upstream=host, port=port)
        _test(client, route_type="redirect", redirect_target="/somewhere")
    after = client.get("/api/routes").json()

    assert [r["id"] for r in after] == [r["id"] for r in before]


def test_a_probe_with_a_host_that_a_route_could_use_does_not_create_one(
    client: TestClient, listener: Any
) -> None:
    """A payload carrying save-shaped fields must not be mistaken for a save."""
    host, port = listener
    before = len(client.get("/api/routes").json())
    _test(
        client, route_type="proxy", host="should-not-exist.test", upstream=host, port=port, path="/"
    )

    assert len(client.get("/api/routes").json()) == before


# --------------------------------------------------------------------------- #
# The saved-route test now shares the probe
# --------------------------------------------------------------------------- #


def test_the_saved_route_test_agrees_with_the_draft_probe(
    client: TestClient, listener: Any
) -> None:
    """Two entry points, one probe: they must not disagree about a pair."""
    host, port = listener
    created = client.post(
        "/api/routes",
        json={
            "host": "agree.test",
            "path": "/",
            "route_type": "proxy",
            "upstream": host,
            "port": port,
        },
        headers=INTERNAL,
    )
    assert created.status_code == 200, created.text
    rid = created.json()["id"]

    saved = client.post(f"/api/routes/{rid}/test", headers=INTERNAL)
    draft = _test(client, route_type="proxy", upstream=host, port=port)

    assert saved.status_code == 200
    assert saved.json()["ok"] == draft.json()["ok"] is True
    assert saved.json().get("latency") == draft.json().get("latency")


def test_the_saved_route_test_still_reports_ok_false_for_a_dead_port(
    client: TestClient,
) -> None:
    port = _closed_port()
    created = client.post(
        "/api/routes",
        json={
            "host": "dead.test",
            "path": "/",
            "route_type": "proxy",
            "upstream": "127.0.0.1",
            "port": port,
        },
        headers=INTERNAL,
    )
    rid = created.json()["id"]

    r = client.post(f"/api/routes/{rid}/test", headers=INTERNAL)

    assert r.status_code == 200
    assert r.json()["ok"] is False
