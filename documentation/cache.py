"""Cache-Control policy for the documentation service.

Kept local because this image does not carry the shared package. The policy is
the same as the application services so a docs page and an app page agree.
"""

from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# Production cache lifespans, in seconds. Tuning one is a one-line edit here
# plus a redeploy; they are deliberately not env vars.
_STATIC_MAX_AGE = 86400
_HTML_MAX_AGE = 300
_MISC_MAX_AGE = 3600

# Debug value: forbids any cache from storing the response at all.
_NO_STORE = "no-store"

_STATIC_PREFIX = "/static/"
_API_PREFIXES = ("/api/",)
_MISC_PATHS = frozenset({"/health", "/api/health"})


def _public_max_age(seconds: int) -> str:
    return f"public, max-age={seconds}"


def _cache_control_for(path: str) -> str:
    if path.startswith(_STATIC_PREFIX):
        return _public_max_age(_STATIC_MAX_AGE)
    if path.startswith(_API_PREFIXES):
        # Per-visitor and often gated. Never let a shared cache hold it.
        return "private, no-store"
    if path in _MISC_PATHS:
        return _public_max_age(_MISC_MAX_AGE)
    return f"private, max-age={_HTML_MAX_AGE}"


def is_debug_deployment() -> bool:
    return os.environ.get("DEPLOYMENT_TYPE", "").lower() in ("debug", "true", "1", "yes")


class CacheControlMiddleware(BaseHTTPMiddleware):
    """Set Cache-Control per deployment type: no-store in debug, lifespans otherwise.

    A response that already carries a Cache-Control header keeps it.
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
