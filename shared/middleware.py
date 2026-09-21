"""Shared HTTP middleware for every GateKeeper service.

Kept in one module so the three services carry the same request-id handling and
the same cache policy. A service that needs different behaviour should subclass
rather than copy, which is how the three copies drifted before.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# Production cache lifespans, in seconds. Tuning one is a one-line edit here
# plus a redeploy; they are deliberately not env vars. `_HTML_MAX_AGE` is short
# because this is the gateway: its HTML is a verdict about one visitor, not a
# document. The documentation service uses 300 for its own HTML, which is built
# once and changes on deploy.
_STATIC_MAX_AGE = 86400
_HTML_MAX_AGE = 60
_MISC_MAX_AGE = 3600

# Debug value: forbids any cache from storing the response at all, so gated
# bytes never rest on shared infrastructure while developing.
_NO_STORE = "no-store"

# GateKeeper sits in front of everything, and most of what it serves is a
# verdict about one specific visitor. Only its own static assets are shared.
_STATIC_PREFIX = "/static/"
_MISC_PATHS = frozenset({"/health"})

# Paths whose response is a decision about this visitor, never a shared artifact.
_NEVER_CACHE_PREFIXES = ("/api/", "/manage", "/login", "/logout", "/api/authz/")

# What a control-plane response always carries, whatever the upstream said and
# whatever the deployment type is.
_PRIVATE_NO_STORE = "private, no-store"

# Directives that already restrict a response to one visitor (`private`) or
# forbid storing it at all (`no-store`). Anything else, including a bare
# `max-age`, is shared-cacheable and is replaced on a response the gate decided.
_VISITOR_SCOPED = ("private", "no-store")


def _public_max_age(seconds: int) -> str:
    return f"public, max-age={seconds}"


def _cache_control_for(path: str) -> str:
    if path.startswith(_STATIC_PREFIX):
        return _public_max_age(_STATIC_MAX_AGE)
    if path in _MISC_PATHS:
        return _public_max_age(_MISC_MAX_AGE)
    if path.startswith(_NEVER_CACHE_PREFIXES):
        # A gating verdict cached by a shared proxy would be served to the wrong
        # visitor. This is the one mistake that would break the gate itself, so
        # the answer is always no-store regardless of deployment type.
        return _PRIVATE_NO_STORE
    return f"private, max-age={_HTML_MAX_AGE}"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attach a request id, echo it, and log the request."""

    def __init__(self, app, log=None) -> None:
        super().__init__(app)
        self._log = log

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = rid
        if self._log is not None:
            self._log("request", method=request.method, path=request.url.path, request_id=rid)
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        return resp


def enforce_private_cache_control(response: Response) -> None:
    """Keep a response the gate decided out of every shared cache, in place.

    The invariant this enforces:

        A response may be ``public``-cacheable only when the path is ungated
        (the gate resolved ``action == "none"``) **and** the upstream chose
        that header itself.

    A gate that decides a request is a gate that answers one visitor. If that
    answer says ``public`` and it is a perfect fit for a shared cache, the cache
    stores it against the URL alone and serves it to the next visitor, who has
    proved nothing. Any header that does not already restrict the response to a
    single visitor (``private``) or forbid storing it (``no-store``) is replaced
    with ``private, no-store``. A bare ``max-age`` counts as shared-cacheable,
    because that is what HTTP says it means, so it is replaced too.

    Called only on responses the gate produced, or on proxied responses whose
    request the gate decided (any action other than ``none``). It is NOT called
    on the ungated pass-through, which is what lets a project publish a
    deliberately public asset through a ``none`` rule: NovaProtocol's
    ``/public/*`` SVG badges are exactly that case, and they must keep the
    ``public`` header a shared cache needs to store them.
    """
    value = response.headers.get("Cache-Control")
    if value and any(directive in value for directive in _VISITOR_SCOPED):
        return
    response.headers["Cache-Control"] = _PRIVATE_NO_STORE


class CacheControlMiddleware(BaseHTTPMiddleware):
    """Set Cache-Control per deployment type.

    Order, and it matters:

    1. Control-plane paths (``/api/``, ``/manage``, ``/login``, ``/logout``,
       ``/api/authz/``) always get ``private, no-store``, in both modes and
       whatever the upstream sent. A cacheable verdict is the one way this
       middleware could break the gate it sits in front of.
    2. Debug caches nothing. With ``is_debug`` set, anything shared-cacheable is
       replaced with ``no-store``, so a deliberately ``public`` value never
       survives into a development deployment. A value that already forbids
       storage is kept verbatim, so the gate's own verdict passes through
       unchanged.
    3. In production, a response that already carries a ``Cache-Control`` header
       keeps it. The upstream knows its own content and its own decision to
       publish; a path-class default is not a reason to overrule it.
    4. In production, only a response with no header is given the path class's
       lifespan.

    Rule 3 is safe only because the gate demotes a shared-cacheable header on
    every request it decided; see :func:`enforce_private_cache_control`.
    """

    def __init__(self, app, is_debug: bool) -> None:
        super().__init__(app)
        self.is_debug = is_debug

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        response = await call_next(request)
        if path.startswith(_NEVER_CACHE_PREFIXES):
            response.headers["Cache-Control"] = _PRIVATE_NO_STORE
            return response
        if self.is_debug:
            # `DEPLOYMENT_TYPE=debug` disables caching outright: nothing this
            # service hands out may be stored, whatever the upstream asked for.
            # Every lifespan below is a production behaviour. The control-plane
            # branch above already returned, and a value that itself forbids
            # storage is kept verbatim; anything else, including a deliberately
            # `public` one, is replaced.
            value = response.headers.get("Cache-Control")
            if not value or not any(d in value for d in _VISITOR_SCOPED):
                response.headers["Cache-Control"] = _NO_STORE
            return response
        if "Cache-Control" in response.headers:
            return response
        response.headers["Cache-Control"] = _cache_control_for(path)
        return response
