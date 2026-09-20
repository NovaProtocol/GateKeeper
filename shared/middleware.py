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
# plus a redeploy; they are deliberately not env vars.
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
        return "private, no-store"
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


class CacheControlMiddleware(BaseHTTPMiddleware):
    """Set Cache-Control per deployment type: no-store in debug, lifespans otherwise.

    A response that already carries a Cache-Control header keeps it, so a route
    that sets its own policy is never overridden here.
    """

    def __init__(self, app, is_debug: bool) -> None:
        super().__init__(app)
        self.is_debug = is_debug

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if self.is_debug:
            response.headers["Cache-Control"] = _NO_STORE
        elif "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = _cache_control_for(request.url.path)
        return response
