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

#: Everything the gated sites load: Bootstrap and Font Awesome as scripts and
#: styles, Inter and JetBrains Mono from Google Fonts, the Cloudflare Web
#: Analytics beacon as a script, and OpenStreetMap raster tiles as images for
#: the audit map's Leaflet layer.
#:
#: jsdelivr appears in four directives because four different things arrive from
#: it: Leaflet resolves its marker images relative to the script URL (`img-src`),
#: MathQuill serves Symbola as a webfont and MathJax serves its CHTML fonts the
#: same way (`font-src`), and the kits are loaded as scripts and styles. It is
#: listed per directive on purpose, so removing one shows up as its own diff.
#:
#: `connect-src` names api.github.com because MkDocs renders a source card on
#: every documentation page that fetches the repository's stars, forks and latest
#: release from it. Without the host the card stays blank and each page logs a
#: CSP violation, which is how this was noticed.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
    "https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com "
    "https://cdn.projectnova.download https://static.cloudflareinsights.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
    "https://stackpath.bootstrapcdn.com https://fonts.googleapis.com "
    "https://cdnjs.cloudflare.com https://cdn.projectnova.download; "
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com "
    "https://cdn.jsdelivr.net https://cdn.projectnova.download; "
    "img-src 'self' data: https://cdn.jsdelivr.net "
    "https://fastapi.tiangolo.com "
    "https://cdn.projectnova.download "
    "https://tile.openstreetmap.org https://*.tile.openstreetmap.org; "
    "connect-src 'self' https://api.github.com; "
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
