"""The security headers every HTML response under the gateway carries.

Two services serve HTML on this stack and both set these headers, so the values
live here rather than in either of them. On a proxied response the gateway's copy
is the one a browser receives: it buffers the upstream response and writes its
own headers over it. Two copies of a header that must agree therefore do not stay
equal, and the copy that wins is the gateway's, which is how the audit map lost
its tile hosts while the management service was still sending them.

The policy is the union of what both services load and nothing else. Each
directive names the hosts that serve it, so widening the policy shows up as a
diff in this file rather than as a missing header nobody notices until a page
breaks silently.
"""

from __future__ import annotations

from typing import Any

#: Everything both services load: Bootstrap and Font Awesome as scripts and
#: styles, Inter and JetBrains Mono from Google Fonts, the Cloudflare Web
#: Analytics beacon as a script, and OpenStreetMap raster tiles as images for
#: the audit map's Leaflet layer (jsdelivr is in `img-src` because Leaflet
#: resolves its own default marker images relative to the script URL).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
    "https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com "
    "https://static.cloudflareinsights.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
    "https://stackpath.bootstrapcdn.com https://fonts.googleapis.com "
    "https://cdnjs.cloudflare.com; "
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data: https://cdn.jsdelivr.net "
    "https://tile.openstreetmap.org https://*.tile.openstreetmap.org; "
    "connect-src 'self'; "
    "frame-src 'self' https://*.projectnova.download "
    "https://portfolio.projectnova.download; "
    "frame-ancestors 'self' https://portfolio.projectnova.download "
    "https://*.projectnova.download"
)

#: The three headers set together on every response, as one unit. `nosniff` and
#: `Referrer-Policy` were already identical in both services; keeping them beside
#: the policy stops the next edit from reaching only one of the two.
SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}


def apply_security_headers(response: Any) -> None:
    """Write the site-wide security headers onto a response, in place.

    Called by the CSP middleware of both services, so the header a browser
    receives is this file's value whichever service produced the body.
    """
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
