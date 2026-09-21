"""The shape of ``caddy/Caddyfile``, and the routing bug it once carried.

The gateway's caddy is the wildcard ingress for ``*.projectnova.download``. Its
``/documentation/*`` handler serves *this* service's docs, which is only correct
on GateKeeper's own hosts. Written as a bare ``handle /documentation/*`` the
matcher applies to every host, so the handler won the prefix for each project
and served GateKeeper's docs at, for example,
``github.projectnova.download/documentation/`` instead of that project's own.

The project caddies each carry their own ``/documentation/*`` handler, reached
through the gate over the DB route. That is why the wildcard handler has to be
host-scoped and let everything else fall through to the catch-all.

These are text assertions against the Caddyfile rather than a live request: the
``docker`` CLI is not available in the test environment, and the failure mode is
a missing matcher clause, which the text captures exactly. The live behaviour was
verified separately by adapting the config with ``caddy adapt`` and by serving a
request per hostname.
"""

from __future__ import annotations

import re
from pathlib import Path

CADDYFILE = Path(__file__).resolve().parent.parent / "caddy" / "Caddyfile"

#: The hosts whose ``/documentation/`` is this service's own.
GATEKEEPER_HOSTS = (
    "gatekeeper.projectnova.download",
    "projectnova.download",
    "gatekeeper",
    "localhost",
)


def _src() -> str:
    return CADDYFILE.read_text()


def test_the_docs_handler_is_host_scoped():
    """A bare ``handle /documentation/*`` would serve these docs to every host."""
    src = _src()

    assert "@gatekeeper_docs {" in src, (
        "the /documentation/* handler needs a named matcher so it stops at "
        "GateKeeper's own hosts"
    )
    assert "handle /documentation/* {" not in src, (
        "a bare handle on /documentation/* matches every host and shadows each "
        "project's own docs"
    )
    assert "handle @gatekeeper_docs {" in src


def test_the_matcher_names_every_gatekeeper_host():
    src = _src()

    matcher = re.search(r"@gatekeeper_docs \{(.*?)\}", src, re.S)
    assert matcher, "matcher block not found"
    body = matcher.group(1)

    host_line = re.search(r"host (.+)", body)
    assert host_line, "the matcher must constrain by host"
    named = host_line.group(1).split()

    for host in GATEKEEPER_HOSTS:
        assert host in named, f"{host} missing from the host matcher"

    assert "path /documentation/*" in body, "the matcher must still constrain the path"


def test_the_docs_handler_still_strips_the_prefix_inside_a_route():
    """Both halves of the earlier fix have to survive.

    ``handle`` rather than ``handle_path`` keeps the prefix for ``forward_auth``
    so a ``/documentation/*`` rule can match; the ``route`` block then strips it
    only on the way upstream. Written as bare siblings Caddy sorts ``uri`` ahead
    of ``forward_auth`` and the gate goes blind to the prefix again.
    """
    src = _src()

    assert "handle_path /documentation" not in src
    assert "route {" in src
    assert "uri strip_prefix /documentation" in src
    assert "forward_auth gatekeeper_auth:8001" in src

    # The strip must sit after the auth call, inside the same route block.
    route = src.index("route {")
    auth = src.index("forward_auth", route)
    strip = src.index("uri strip_prefix", route)
    upstream = src.index("reverse_proxy gatekeeper_documentation", route)
    assert auth < strip < upstream


def test_the_catch_all_still_proxies_through_the_gate():
    """Whatever the docs matcher does not claim must reach the gate, not a 404."""
    src = _src()

    catch_all = src.rindex("handle {")
    tail = src[catch_all:]
    assert "reverse_proxy gatekeeper_auth:8001" in tail


def test_health_is_answered_locally():
    """The tunnel's health probe must not depend on the gate being up."""
    src = _src()

    assert "handle /health {" in src
    assert "respond" in src
