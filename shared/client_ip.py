"""Resolve the real visitor IP behind the Cloudflare tunnel.

Cloudflare stamps ``CF-Connecting-IP`` with the visitor address at the edge and
cloudflared forwards it untouched, so on this stack that header is the
authoritative source.

``X-Forwarded-For`` is **not** usable here and is the reason the audit log used
to fill up with ``172.18.x.x``: cloudflared does not set it on the origin dial,
so Caddy's ``reverse_proxy`` fills it with the immediate peer — the cloudflared
container's own bridge address. Every visitor then collapsed into one identity,
which also meant the per-IP rate limiter throttled the whole internet as if it
were a single caller.

Trust model: only the tunnel may reach the origin. ``gatekeeper_caddy`` is the
sole member of ``cloudflared-tunnel`` besides cloudflared itself, and its port
is loopback-bound, so an inbound request cannot arrive from anywhere but
Cloudflare. These headers are plain strings — if the origin ever becomes
directly reachable, they are forgeable and only the peer address is
trustworthy.
"""

from __future__ import annotations

from starlette.requests import Request

# Ordered by trustworthiness for this deployment.
_VISITOR_HEADERS = ("CF-Connecting-IP", "True-Client-IP", "X-Real-IP")

# audit_logs.ip is String(64); truncate rather than fail the insert.
_MAX_LEN = 64


def _first(value: str) -> str:
    """Take the left-most entry of a comma list and bound its length."""
    return value.split(",")[0].strip()[:_MAX_LEN]


def get_client_ip(request: Request) -> str:
    """Return the visitor address, falling back to progressively weaker hints."""
    for header in _VISITOR_HEADERS:
        value = _first(request.headers.get(header, ""))
        if value:
            return value

    forwarded = _first(request.headers.get("X-Forwarded-For", ""))
    if forwarded:
        return forwarded

    peer = request.client.host if request.client else ""
    return peer[:_MAX_LEN] or "0.0.0.0"
