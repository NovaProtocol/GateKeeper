"""Shared error page helper — GateKeeper dark theme.

Used by both auth-gateway and management so every 404/403 is themed
consistently. House tokens: --bg-primary #0a0a0f, --bg-card #1a1a28,
--border #2a2a3e, --accent #64ffda, Inter + JetBrains Mono.
"""
from __future__ import annotations

import html

try:
    from fastapi import Request as _Request  # type: ignore[import-not-found]
except Exception:
    _Request = object  # type: ignore[assignment]


def wants_html(request: _Request) -> bool:  # type: ignore[no-untyped-def]
    """Return True if the client prefers HTML over JSON.

    Browsers send Accept: text/html. API/monitoring sends
    application/json. We keep JSON for programmatic callers to
    preserve backward compat for detail checks.
    """
    try:
        accept = (request.headers.get("accept") or "").lower()
        if "text/html" in accept:
            return True
        # X-Requested-With is a common AJAX marker
        if request.headers.get("x-requested-with"):
            # if it explicitly asked for json, stay json
            if "application/json" in accept or "json" in accept:
                return False
        # fallback: if accept is empty or */* assume browser when
        # not explicitly json, but we keep json for empty to avoid
        # breaking health checks that assert {"detail": ...}
        if not accept or accept.strip() in ("*/*", ""):
            return False
        return False
    except Exception:
        return False


def _apex_fallback(apex: str) -> str:
    return apex or "projectnova.download"


def render_error_html(
    *,
    status: int,
    title: str,
    message: str,
    detail: str | None = None,
    host: str | None = None,
    path: str | None = None,
    request_id: str | None = None,
    apex: str = "projectnova.download",
    subtitle: str | None = None,
    extra_html: str = "",
) -> str:
    """Return a standalone HTML document for the given error."""
    apex = _apex_fallback(apex)
    # escape all user-controlled values
    esc_title = html.escape(title)
    esc_message = html.escape(message)
    esc_detail = html.escape(detail) if detail else ""
    esc_host = html.escape((host or "")[:253])
    esc_path = html.escape((path or "")[:512])
    esc_req = html.escape((request_id or "")[:64])
    esc_apex = html.escape(apex)
    # host+path line
    host_path_line = ""
    if esc_host or esc_path:
        hp = esc_host
        if esc_path:
            hp = f"{esc_host}{esc_path}" if esc_host else esc_path
        # truncate display
        if len(hp) > 80:
            hp = hp[:77] + "…"
        host_path_line = f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:.72rem;color:var(--text-secondary);margin-top:.75rem;word-break:break-all">{hp}</div>'
    detail_line = ""
    if esc_detail:
        detail_line = f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:.7rem;color:var(--text-secondary);margin-top:.5rem;opacity:.85">{esc_detail}</div>'
    req_line = ""
    if esc_req:
        req_line = f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:.65rem;color:var(--text-secondary);margin-top:.6rem;opacity:.6">request_id: {esc_req}</div>'
    subtitle_html = ""
    if subtitle:
        subtitle_html = f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:.7rem;letter-spacing:.08em;text-transform:uppercase;color:var(--accent);margin-bottom:.6rem">{html.escape(subtitle)}</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{status} — {esc_title} · GateKeeper</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{{--bg-primary:#0a0a0f;--bg-card:#1a1a28;--bg-secondary:#12121a;--border:#2a2a3e;--text-primary:#e8e8f0;--text-secondary:#8888a0;--accent:#64ffda;--accent-dim:rgba(100,255,218,.1);--danger:#f87171}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg-primary);color:var(--text-primary);min-height:100vh}}
.header{{background:rgba(10,10,15,.85);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between}}
.header-title{{font-size:1.15rem;font-weight:700;letter-spacing:-.02em}}
.header-title span{{color:var(--accent)}}
.header-badge{{font-family:'JetBrains Mono',monospace;font-size:.7rem;color:var(--text-secondary);background:var(--bg-card);padding:.3rem .7rem;border-radius:6px;border:1px solid var(--border)}}
.card{{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden;max-width:640px;width:100%}}
.btn-accent{{display:inline-flex;align-items:center;gap:.5rem;background:var(--accent);color:var(--bg-primary);font-weight:700;padding:.7rem 1.6rem;border-radius:8px;text-decoration:none;font-size:.9rem}}
.btn-accent:hover{{opacity:.9}}
.btn-ghost{{display:inline-flex;align-items:center;gap:.5rem;background:transparent;color:var(--text-secondary);border:1px solid var(--border);padding:.65rem 1.4rem;border-radius:8px;text-decoration:none;font-size:.9rem;margin-left:.6rem}}
.btn-ghost:hover{{border-color:var(--text-secondary);color:var(--text-primary)}}
</style>
</head>
<body>
<header class="header">
  <div class="header-title">~/<span>gatekeeper</span></div>
  <span class="header-badge">{esc_apex}</span>
</header>
<div style="min-height:calc(100vh - 56px);display:flex;align-items:center;justify-content:center;padding:2rem;background:var(--bg-primary)">
  <div class="card">
    <div style="padding:2.5rem;text-align:center">
      {subtitle_html}
      <div style="font-family:'JetBrains Mono',monospace;font-size:.75rem;color:var(--accent);margin-bottom:.75rem;letter-spacing:.08em;text-transform:uppercase">{status} — {esc_title}</div>
      <h1 style="font-size:1.45rem;font-weight:800;margin-bottom:.6rem;line-height:1.3">{esc_title}</h1>
      <p style="color:var(--text-secondary);font-size:.95rem;line-height:1.6;margin-bottom:1.5rem">{esc_message}</p>
      {extra_html}
      {detail_line}
      {host_path_line}
      {req_line}
      <div style="margin-top:1.75rem">
        <a href="https://gatekeeper.{esc_apex}/" class="btn-accent"><i class="fa-solid fa-arrow-rotate-left"></i> Turn back</a>
        <a href="#" onclick="history.back();return false;" class="btn-ghost"><i class="fa-solid fa-arrow-left"></i> Go back</a>
      </div>
    </div>
  </div>
</div>
</body>
</html>
"""


def render_maintenance_html(
    *,
    message: str = "",
    host: str | None = None,
    apex: str = "projectnova.download",
) -> str:
    """The page every gated host answers with while maintenance mode is on.

    Deliberately the same document as every other gateway error: an outage is the
    worst moment to make a visitor learn a second layout. ``message`` is the
    operator's own notice; it is escaped here and never rendered raw.
    """
    note = message.strip() if message else ""
    extra = (
        '<p style="color:var(--text-secondary);font-size:.9rem;line-height:1.6;margin:1rem 0 0">'
        f"{html.escape(note)}</p>"
        if note
        else ""
    )
    return render_error_html(
        status=503,
        title="Down for maintenance",
        message=(
            "The gateway is being updated. Nothing is wrong with your connection, "
            "and this page will load again shortly."
        ),
        host=host,
        apex=apex,
        subtitle="maintenance",
        extra_html=extra,
    )
