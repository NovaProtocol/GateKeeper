from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import secrets

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from shared.jwt import create_access_token, create_custom_token, verify_access_token, verify_custom_token

from shared.error_pages import render_error_html, render_maintenance_html, wants_html
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from shared.client_ip import get_client_ip
from shared.config import get_config
from shared.csp import apply_security_headers
from shared.gate import DEFAULT_UNMATCHED_ACTION, find_group_rule, resolve_rule_action
from shared.geo import get_country
from shared.models import Code, CustomPage, Route, Rule, RuleGroup
from shared.pages import pattern_matches
from shared.rule_defaults import DEFAULT_ACTIVE_READING
from shared.security import apex_domain as shared_apex_domain
from shared.security import host_matches, mask_code, verify_custom_password
from shared.settings_spec import (
    GEO_LOOKUP_ENABLED,
    MAINTENANCE_MESSAGE,
    MAINTENANCE_MODE,
    SESSION_LIFETIME_HOURS,
    as_bool,
    as_int,
    default_int,
    default_value,
)

try:
    import structlog

    structlog.configure(
        processors=[structlog.processors.JSONRenderer()] if hasattr(structlog.processors, "JSONRenderer") else [],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )

    def _slog(msg: str, **kw: Any) -> None:
        structlog.get_logger().info(msg, **kw)

except Exception:
    logging.basicConfig(level=logging.INFO)

    def _slog(msg: str, **kw: Any) -> None:
        logging.getLogger("auth-gateway").info("%s %s", msg, kw)

try:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    def _key_func(request: Request) -> str:
        return get_client_ip(request)

    limiter = Limiter(key_func=_key_func, default_limits=[])

    _has_slowapi = True
except Exception:
    _has_slowapi = False

    class _DummyLimiter:
        def limit(self, *a: Any, **kw: Any):  # type: ignore[no-untyped-def]
            def dec(fn):  # type: ignore[no-untyped-def]
                return fn

            return dec

        def __call__(self, *a: Any, **kw: Any) -> Any:
            return None

    limiter = _DummyLimiter()  # type: ignore[assignment]
    RateLimitExceeded = Exception  # type: ignore[assignment,misc]
    SlowAPIMiddleware = None  # type: ignore[assignment]

_CacheGroups: list[RuleGroup] | None = None
_CacheRoutes: list[Route] | None = None
_CachePages: list[CustomPage] | None = None
_CacheTs: float = 0.0
_CacheLock = asyncio.Lock()
CACHE_TTL = 5.0

_httpx_client: httpx.AsyncClient | None = None


def _get_httpx() -> httpx.AsyncClient:
    global _httpx_client
    if _httpx_client is None:
        _httpx_client = httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(30.0))
    return _httpx_client


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = rid
        _slog("request", method=request.method, path=request.url.path, host=request.headers.get("X-Forwarded-Host") or request.headers.get("Host"), request_id=rid)
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        return resp


class ProxyFixMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        x_proto = request.headers.get("X-Forwarded-Proto")
        x_host = request.headers.get("X-Forwarded-Host")
        if x_proto:
            request.scope["scheme"] = x_proto.split(",")[0].strip()
        if x_host:
            h = x_host.split(",")[0].strip()
            request.headers.__dict__.get("_list", [])
            request.scope["server"] = (h.split(":")[0], 443 if request.scope.get("scheme") == "https" else 80)
        return await call_next(request)


class CSPMiddleware(BaseHTTPMiddleware):
    """The site-wide security headers, including on proxied responses.

    This service proxies every gated request, so the headers written here are the
    ones a browser receives even when the upstream set its own: the values come
    from :mod:`shared.csp`, which the management service applies too. Holding a
    second copy here is what let the two drift apart and silently drop the tile
    hosts the audit map needs.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        resp = await call_next(request)
        apply_security_headers(resp)
        return resp


def _error_response(  # type: ignore[no-untyped-def]
    request: Request,
    status: int,
    title: str,
    message: str,
    detail: str | None,
    host: str | None,
    path: str | None,
    request_id: str | None,
    apex: str,
) -> Response:
    from fastapi.responses import HTMLResponse as _HR, JSONResponse as _JR

    if wants_html(request):
        html = render_error_html(
            status=status,
            title=title,
            message=message,
            detail=detail,
            host=host,
            path=path,
            request_id=request_id,
            apex=apex,
        )
        return _HR(content=html, status_code=status, headers={"Content-Type": "text/html; charset=utf-8"})
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return _JR(status_code=status, content={"detail": detail or message})
    return Response(status_code=status, content=detail or message)


def _apex_from_host(host: str) -> str:
    return shared_apex_domain(host)


def _current_apex(request: Request, host: str | None = None) -> str:
    if host is None:
        host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
        host = host.split(",")[0].strip().split(":")[0].lower()
    return _apex_from_host(host)


def _safe_redirect_target(target: str, apex: str) -> bool:
    parts = urlsplit(target)
    if not parts.scheme and not parts.netloc:
        return target.startswith("/")
    if parts.scheme in ("http", "https") and parts.netloc:
        h = parts.netloc.split(":")[0].lower()
        return h == apex or h.endswith("." + apex)
    return False


def same_origin(request: Request, apex: str | None = None) -> bool:
    origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
    if not origin:
        return False
    host = urlsplit(origin).hostname or ""
    host = host.lower()
    cur_host = (request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")).split(",")[0].strip().split(":")[0].lower()
    if apex is None:
        apex = _apex_from_host(cur_host)
    return host == cur_host or host == apex or host.endswith("." + apex)


def _get_ip(request: Request) -> str:
    """Visitor address, not the tunnel's — see :mod:`shared.client_ip`."""
    return get_client_ip(request)


def _get_forwarded_host(request: Request) -> str:
    h = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
    h = h.split(",")[0].strip().split(":")[0].lower()
    return h


def _get_forwarded_uri(request: Request) -> str:
    uri = request.headers.get("X-Forwarded-Uri", "")
    if uri:
        return uri
    q = ("?" + request.url.query) if request.url.query else ""
    return request.url.path + q


def _get_forwarded_proto(request: Request) -> str:
    p = request.headers.get("X-Forwarded-Proto", "")
    if p:
        if "https" in p.lower():
            return "https"
        return p.split(",")[0].strip().lower()
    cf = request.headers.get("CF-Visitor", "")
    if "https" in cf.lower():
        return "https"
    if request.headers.get("X-Forwarded-Host") and request.headers.get("Cf-Ray"):
        return "https"
    return request.url.scheme


def _get_access_code_param(request: Request) -> tuple[str | None, str, str]:
    xf_uri = request.headers.get("X-Forwarded-Uri", "")
    if xf_uri:
        parts = urlsplit(xf_uri)
        qs = parse_qsl(parts.query, keep_blank_values=True)
        for k, v in qs:
            if k == "access_code":
                return v.strip() or None, parts.path, parts.query
        return None, parts.path, parts.query
    path = request.url.path
    qs = request.url.query
    for k, v in parse_qsl(qs, keep_blank_values=True):
        if k == "access_code":
            return v.strip() or None, path, qs
    return None, path, qs


def _strip_access_code(uri: str) -> str:
    parts = urlsplit(uri)
    qs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "access_code"]
    return urlunsplit(("", "", parts.path, urlencode(qs), parts.fragment))


def _api_headers() -> dict[str, str]:
    cfg = get_config()
    h: dict[str, str] = {"Content-Type": "application/json"}
    if cfg.INTERNAL_API_KEY:
        h["X-Internal-Api-Key"] = cfg.INTERNAL_API_KEY
    return h


def _api_base() -> str:
    import os
    return os.environ.get("API_HTTP_ADDR", "http://api:8002")


async def _load_caches() -> tuple[list[Route], list[RuleGroup], list[CustomPage]]:
    global _CacheRoutes, _CacheGroups, _CachePages, _CacheTs
    now = time.monotonic()
    if (
        _CacheRoutes is not None
        and _CacheGroups is not None
        and _CachePages is not None
        and (now - _CacheTs) < CACHE_TTL
    ):
        return _CacheRoutes, _CacheGroups, _CachePages
    async with _CacheLock:
        now2 = time.monotonic()
        if (
            _CacheRoutes is not None
            and _CacheGroups is not None
            and _CachePages is not None
            and (now2 - _CacheTs) < CACHE_TTL
        ):
            return _CacheRoutes, _CacheGroups, _CachePages
        try:
            base = _api_base()
            client = _get_httpx()
            hdr = _api_headers()
            # fetch routes + groups via API (X-Internal-Api-Key on net-api)
            r_resp = await client.get(f"{base}/api/routes", headers=hdr, timeout=2.0)
            r_resp.raise_for_status()
            r_json = r_resp.json()
            routes: list[Route] = []
            for row in r_json if isinstance(r_json, list) else []:
                rr = Route(host=row.get("host", ""), path=row.get("path", "/"), route_type=row.get("route_type", "proxy"), upstream=row.get("upstream"), port=row.get("port"), redirect_target=row.get("redirect_target"), redirect_code=row.get("redirect_code"))
                rr.id = row.get("id", 0)  # type: ignore[attr-defined]
                routes.append(rr)
            g_resp = await client.get(f"{base}/api/groups", headers=hdr, timeout=2.0)
            g_resp.raise_for_status()
            g_json = g_resp.json()
            groups: list[RuleGroup] = []
            # groups endpoint returns without rules; fetch rules per group
            for grow in g_json if isinstance(g_json, list) else []:
                gr = RuleGroup(name=grow.get("name", ""), domain=grow.get("domain", ""), display_order=grow.get("display_order", 0), is_default=bool(grow.get("is_default", False)))
                gr.id = grow.get("id", 0)  # type: ignore[attr-defined]
                try:
                    rr_resp = await client.get(f"{base}/api/groups/{gr.id}/rules", headers=hdr, timeout=2.0)
                    if rr_resp.status_code == 200:
                        for rrow in rr_resp.json():
                            rule = Rule(group_id=gr.id, path=rrow.get("path", "/"), action=rrow.get("action", "access_code"), display_order=rrow.get("display_order", 0))
                            rule.id = rrow.get("id", 0)  # type: ignore[attr-defined]
                            # The gateway never touches the database, so this is the
                            # only way the switch reaches the gate. A missing field
                            # reads as active: an old API that does not send it must
                            # not be able to silence every rule.
                            rule.active = rrow.get("active", DEFAULT_ACTIVE_READING) is not False  # type: ignore[attr-defined]
                            rule.custom_password_hash = None  # type: ignore[attr-defined]
                            rule.custom_password_salt = None  # type: ignore[attr-defined]
                            # need hash for custom_password param check — fetch via direct rule lookup not exposed; keep verify via api
                            gr.rules.append(rule)
                except Exception:
                    pass
                groups.append(gr)
            p_resp = await client.get(f"{base}/api/pages", headers=hdr, timeout=2.0)
            p_resp.raise_for_status()
            p_json = p_resp.json()
            pages: list[CustomPage] = []
            for prow in p_json if isinstance(p_json, list) else []:
                page = CustomPage(
                    pattern=prow.get("pattern", ""),
                    body=prow.get("body", ""),
                    content_type=prow.get("content_type") or "text/plain; charset=utf-8",
                    active=bool(prow.get("active", True)),
                    display_order=prow.get("display_order", 0),
                )
                page.id = prow.get("id", 0)  # type: ignore[attr-defined]
                pages.append(page)
        except Exception as e:
            _slog("cache_load_failed", error=str(e))
            if _CacheRoutes is not None and _CacheGroups is not None and _CachePages is not None:
                return _CacheRoutes, _CacheGroups, _CachePages
            # Nothing readable means "no page matched", never "some page
            # matched": an unreadable page list must not be able to serve a body.
            return [], [], []
        _CacheRoutes = routes
        _CacheGroups = groups
        _CachePages = pages
        _CacheTs = time.monotonic()
        return routes, groups, pages


def _find_group_rule(
    host: str, path: str, groups: list[RuleGroup]
) -> tuple[RuleGroup | None, Rule | None]:
    """Host/rule resolution, delegated to :func:`shared.gate.find_group_rule`."""
    return find_group_rule(host, path, groups)


_SETTING_TTL = 60.0
_SettingCache: dict[str, tuple[float, str]] = {}


async def _get_setting(key: str, default: str) -> str:
    """Read one setting from the API, cached briefly, falling back to ``default``.

    Every default on this path is the gating reading, so an unreachable API can
    only ever make the gateway stricter. The fallback is cached too: a settings
    outage must not put a 2s round trip in front of every request.
    """
    now = time.monotonic()
    hit = _SettingCache.get(key)
    if hit and (now - hit[0]) < _SETTING_TTL:
        return hit[1]
    try:
        base = _api_base()
        client = _get_httpx()
        resp = await client.get(f"{base}/api/settings/{key}", headers=_api_headers(), timeout=2.0)
        if resp.status_code == 200:
            val = str(resp.json().get("value") or "").strip()
            if val:
                _SettingCache[key] = (now, val)
                return val
    except Exception:
        pass
    _SettingCache[key] = (now, default)
    return default


async def _resolve_action(grp: RuleGroup | None, rule: Rule | None) -> str:
    """The action governing this request, shared by both gate paths.

    The setting is only consulted when nothing matched at all, so the common
    case costs no extra call.
    """
    if rule is not None or grp is not None:
        return resolve_rule_action(grp, rule, DEFAULT_UNMATCHED_ACTION)
    unmatched = await _get_setting("unmatched_action", DEFAULT_UNMATCHED_ACTION)
    return resolve_rule_action(None, None, unmatched)


async def _setting_int(key: str) -> int:
    """A stored integer setting, read through the shared reader.

    The stored value is re-read through :func:`shared.settings_spec.read_value`
    so a row edited by hand, or restored from an older backup, is normalized the
    same way the write path would have. The cached default comes from the same
    table, so a settings outage cannot produce a lifetime the panel refuses.
    """
    fallback = default_int(key)
    raw = await _get_setting(key, str(fallback))
    return as_int(key, raw)


async def _setting_bool(key: str) -> bool:
    raw = await _get_setting(key, default_value(key))
    return as_bool(key, raw)


async def _visitor_country(request: Request) -> str | None:
    """The visitor's country, or ``None`` when capture is off or absent.

    The switch is checked first so turning it off stops the header being read at
    all, and the header read never raises: `geo_lookup_enabled` defaults to on
    because an unreadable row must not be able to make the gateway stop
    recording where visitors came from.
    """
    if not await _setting_bool(GEO_LOOKUP_ENABLED):
        return None
    return get_country(request)


#: Hosts where the maintenance switch must never apply to, because they are how
#: the operator turns it back off. Matched on the hostname, ignoring any port.
_MANAGE_HOSTS = ("gatekeeper", "gatekeeper.projectnova.download", "localhost", "127.0.0.1")


def _is_maintenance_exempt(host: str, path: str) -> bool:
    """Whether this request is how the operator gets back into the panel.

    The exemption is both a host and a path condition: on the gatekeeper host
    only `/manage` and `/manage/login` are spared, so the rest of that site still
    shows the maintenance page like everything else.
    """
    hostname = (host or "").split(",")[0].strip().split(":")[0].lower()
    if hostname not in _MANAGE_HOSTS:
        return False
    p = path if path.startswith("/") else "/" + path
    return p == "/manage" or p.startswith("/manage/")


async def _maintenance_response(
    request: Request, host: str, path: str, apex: str
) -> Response | None:
    """The themed 503 while maintenance mode is on, or ``None`` to carry on.

    Checked before rule dispatch, so the switch says the same thing on every host
    rather than depending on which rule happens to match. `/manage` on the
    gatekeeper host is exempt, because a maintenance switch that also hides the
    page that turns it off is a foot-gun.
    """
    if _is_maintenance_exempt(host, path):
        return None
    if not await _setting_bool(MAINTENANCE_MODE):
        return None
    message = await _get_setting(MAINTENANCE_MESSAGE, "")
    if wants_html(request):
        html = render_maintenance_html(message=message, host=host, apex=apex)
        return HTMLResponse(
            content=html,
            status_code=503,
            headers={"Content-Type": "text/html; charset=utf-8", "Retry-After": "300"},
        )
    return JSONResponse(
        status_code=503,
        content={"detail": "maintenance mode"},
        headers={"Retry-After": "300"},
    )


#: The paths on a manage host that are how the operator gets back into the
#: panel, and therefore the paths a custom page may never answer for.
_CONTROL_PLANE_PATHS = ("/", "/login", "/logout", "/manage", "/static")
_CONTROL_PLANE_PREFIXES = ("/manage", "/static")


def _is_control_plane(host: str, path: str, apex: str) -> bool:
    """Whether this request is the operator's way in, not a page's to swallow.

    Custom pages sit below the control plane in priority, and this is what makes
    that true rather than assumed. `/health` and `/api/authz/forward-auth` need
    no entry here — Caddy answers `/health` at the site level and the wildcard
    refuses `/api/authz/forward-auth` before this point — and `/logout` is a real
    route registered ahead of the wildcard. What is **not** ahead of the wildcard
    is `/login`, the gatekeeper host's `/` and the panel's own `/static/*`: they
    are served by the wildcard proxy into `gatekeeper_management`, so without
    this predicate a pattern like `gatekeeper.projectnova.download/*` would
    swallow the login page and the stylesheet it loads with it — the panel would
    answer while rendering unstyled, which is the same lockout by another route.

    Narrow on purpose: only the manage hosts and the apex, and only the paths
    that reach the panel. `/robots.txt` on the gatekeeper host stays the
    owner's to intercept, and a project host's own `/static/*` is untouched
    because this predicate is false for every non-manage host.
    """
    hostname = (host or "").split(",")[0].strip().split(":")[0].lower()
    if hostname not in _MANAGE_HOSTS and hostname != apex:
        return False
    p = path if path.startswith("/") else "/" + path
    if p in _CONTROL_PLANE_PATHS:
        return True
    return any(p.startswith(prefix + "/") for prefix in _CONTROL_PLANE_PREFIXES)


def _find_page(host: str, path: str, pages: list[CustomPage]) -> CustomPage | None:
    """The first active page whose pattern matches, in the gate's own order.

    Order is ``(display_order, id)`` ascending and the first match is the only
    match: nothing merges, nothing cascades, and the number the panel shows is
    the position the gate consults. A page whose ``active`` **is** ``False`` is
    skipped before its pattern is even read.
    """
    for page in sorted(pages, key=lambda p: (p.display_order, p.id)):
        if page.active is False:
            continue
        if pattern_matches(page.pattern, host, path):
            return page
    return None


async def _queue_page_audit(
    request: Request,
    background_tasks: BackgroundTasks,
    host: str,
    path: str,
    ip: str,
    req_id: str,
    grp: RuleGroup | None,
    rule: Rule | None,
) -> None:
    """One audit row per request answered by a custom page.

    Shaped like :func:`_queue_maintenance_audit`, with the rule that allowed the
    page carried in `rule_group_id` / `rule_id` because that is the interesting
    fact, and `matched_action="custom_page"` as the greppable marker that a page
    (rather than a rule) produced the body.
    """
    _queue_audit(
        background_tasks,
        host=host,
        path=path,
        ip=ip,
        country=await _visitor_country(request),
        action="custom_page",
        matched_action="custom_page",
        rule_group_id=grp.id if grp else None,
        rule_id=rule.id if rule else None,
        code_id=None,
        request_id=req_id,
        user_agent=request.headers.get("User-Agent"),
        referer=request.headers.get("Referer"),
        latency_ms=None,
        method=request.method,
        status_code=200,
        attempted_code=None,
    )


async def _queue_maintenance_audit(
    request: Request,
    background_tasks: BackgroundTasks,
    host: str,
    path: str,
    ip: str,
    req_id: str,
) -> None:
    """One audit row per refused-by-maintenance request, same shape as the rest.

    Without this the switch is invisible in the audit trail, which is exactly the
    kind of gap that makes an operator distrust the page.
    """
    _queue_audit(
        background_tasks,
        host=host,
        path=path,
        ip=ip,
        country=await _visitor_country(request),
        action="maintenance_mode",
        matched_action="maintenance_mode",
        rule_group_id=None,
        rule_id=None,
        code_id=None,
        request_id=req_id,
        user_agent=request.headers.get("User-Agent"),
        referer=request.headers.get("Referer"),
        latency_ms=None,
        method=request.method,
        status_code=503,
        attempted_code=None,
    )


def _find_route(host: str, path: str, routes: list[Route]) -> Route | None:
    hl = host.lower().split(":")[0]
    if not path.startswith("/"):
        path = "/" + path
    candidates: list[Route] = []
    for r in routes:
        if not (host_matches(r.host, hl) or r.host.lower() == hl):
            continue
        rp = (r.path or "/").strip() or "/"
        if rp == "/" or rp == "/*":
            candidates.append(r)
        elif rp.endswith("/*"):
            prefix = rp[:-1]
            if path == prefix.rstrip("/") or path.startswith(prefix):
                candidates.append(r)
        else:
            if path == rp or path.startswith(rp.rstrip("/") + "/"):
                candidates.append(r)
            elif rp == path:
                candidates.append(r)
    if not candidates:
        return None
    candidates.sort(key=lambda x: len((x.path or "/").strip() or "/"), reverse=True)
    return candidates[0]


async def _verify_code_value(code_val: str) -> Code | None:
    if not code_val:
        return None
    try:
        base = _api_base()
        client = _get_httpx()
        resp = await client.post(f"{base}/api/auth/verify-code", json={"code": code_val}, headers=_api_headers(), timeout=2.0)
        if resp.status_code != 200:
            return None
        data = resp.json()
        c = Code(code=code_val, label=data.get("label"), display_name=data.get("display_name"))
        c.id = data.get("code_id", 0)  # type: ignore[attr-defined]
        c.active = True  # type: ignore[attr-defined]
        return c
    except Exception:
        return None


_RateLimitCache: dict[str, Any] = {"value": 5, "ts": 0.0}


async def _check_access_code_rate_limited(ip: str) -> tuple[bool, int, int]:
    if not ip or ip == "0.0.0.0":
        return False, 0, 5
    try:
        base = _api_base()
        client = _get_httpx()
        # cache settings value for 10s to avoid extra call if check-rate-limit already does it, but we just call check directly
        resp = await client.post(f"{base}/api/auth/check-rate-limit", json={"ip": ip}, headers=_api_headers(), timeout=2.0)
        if resp.status_code == 200:
            d = resp.json()
            allowed = bool(d.get("allowed", True))
            return (not allowed), int(d.get("count", 0)), int(d.get("limit", 5))
    except Exception:
        pass
    return False, 0, 5


async def _audit_log_async(
    host: str,
    path: str,
    ip: str,
    action: str,
    matched_action: str | None,
    rule_group_id: int | None,
    rule_id: int | None,
    code_id: int | None,
    request_id: str,
    user_agent: str | None,
    referer: str | None,
    latency_ms: int | None = None,
    method: str | None = None,
    status_code: int | None = None,
    attempted_code: str | None = None,
    country: str | None = None,
) -> None:
    payload = {
        "ts": __import__("datetime").datetime.utcnow().isoformat(),
        "host": host,
        "path": path,
        "ip": ip,
        "country": country,
        "action": action,
        "matched_action": matched_action,
        "rule_group_id": rule_group_id,
        "rule_id": rule_id,
        "code_id": code_id,
        "request_id": request_id,
        "user_agent": (user_agent or "")[:512],
        "referer": (referer or "")[:1024],
        "latency_ms": latency_ms,
        "method": (method or "")[:10] or None,
        "status_code": status_code,
        "attempted_code": mask_code(attempted_code) if attempted_code else None,
    }
    try:
        cfg = get_config()
        url = "http://api:8002/api/logs"
        hdr: dict[str, str] = {"Content-Type": "application/json"}
        if cfg.INTERNAL_API_KEY:
            hdr["X-Internal-Api-Key"] = cfg.INTERNAL_API_KEY
        client = _get_httpx()
        try:
            resp = await client.post(url, json=payload, headers=hdr, timeout=2.0)
            if 200 <= resp.status_code < 300:
                return
        except Exception:
            pass
    except Exception:
        pass
    # audit fallback removed — API-only DB; api:8002 is sole writer (internal:true)


def _queue_audit(background_tasks: BackgroundTasks, **kw: Any) -> None:
    background_tasks.add_task(_audit_log_async, **kw)


def _set_auth_cookie(resp: Response, code: Code, apex: str, lifetime_hours: int | None = None) -> None:
    if lifetime_hours is None:
        lifetime_hours = default_int(SESSION_LIFETIME_HOURS)
    token = create_access_token(code.id, code.display_name or code.label or "User", expires_hours=lifetime_hours)
    resp.set_cookie(
        key="gatekeeper_token",
        value=token,
        domain=f".{apex}",
        path="/",
        httponly=True,
        samesite="lax",
        secure=True,
        max_age=lifetime_hours * 3600,
    )


def _clear_auth_cookie(resp: Response, apex: str) -> None:
    resp.delete_cookie(key="gatekeeper_token", domain=f".{apex}", path="/")
    # also clear without domain for host-only fallback
    resp.delete_cookie(key="gatekeeper_token", path="/")


async def _code_from_jwt(token: str) -> Code | None:
    data = verify_access_token(token)
    if not data:
        return None
    cid = data.get("cid")
    if cid is None:
        return None
    # API-only: verify via cid endpoint (X-Internal-Api-Key on net-api)
    try:
        base = _api_base()
        client = _get_httpx()
        resp = await client.post(f"{base}/api/auth/verify-code-id", json={"cid": int(cid)}, headers=_api_headers(), timeout=2.0)
        if resp.status_code != 200:
            return None
        jd = resp.json()
        c = Code(code=jd.get("code", ""), label=jd.get("label"), display_name=jd.get("display_name"))
        c.id = jd.get("code_id", int(cid))  # type: ignore[attr-defined]
        c.active = True  # type: ignore[attr-defined]
        if not c.code:
            c.code = str(cid)
        return c
    except Exception:
        return None


def _set_custom_cookie(resp: Response, rule_id: int, apex: str, lifetime_hours: int | None = None) -> None:
    if lifetime_hours is None:
        lifetime_hours = default_int(SESSION_LIFETIME_HOURS)
    token = create_custom_token(rule_id, expires_hours=lifetime_hours)
    resp.set_cookie(key=f"gatekeeper_custom_{rule_id}", value=token, domain=f".{apex}", path="/", httponly=True, samesite="lax", secure=True, max_age=lifetime_hours * 3600)


def _has_valid_custom_cookie(request: Request, rule: Rule) -> bool:
    raw = request.cookies.get(f"gatekeeper_custom_{rule.id}")
    if not raw:
        raw = request.headers.get("X-Custom-Password", "")
        if raw and rule.custom_password_hash and rule.custom_password_salt:
            try:
                return verify_custom_password(raw, rule.custom_password_hash, rule.custom_password_salt)
            except Exception:
                return False
        return False
    if verify_custom_token(raw, rule.id):
        return True
    # header fallback already checked; allow X-Custom-Password header as password
    hdr = request.headers.get("X-Custom-Password", "")
    if hdr and rule.custom_password_hash and rule.custom_password_salt:
        try:
            return verify_custom_password(hdr, rule.custom_password_hash, rule.custom_password_salt)
        except Exception:
            return False
    return False


def _check_custom_password_param(request: Request, rule: Rule) -> bool:
    if not rule.custom_password_hash or not rule.custom_password_salt:
        return False
    xf_uri = request.headers.get("X-Forwarded-Uri", "")
    params: list[tuple[str, str]] = []
    if xf_uri:
        params = parse_qsl(urlsplit(xf_uri).query)
    else:
        params = list(request.query_params.items())
    for k, v in params:
        if k in ("custom_password", "customPassword", "password"):
            if verify_custom_password(v, rule.custom_password_hash, rule.custom_password_salt):
                return True
    hdr = request.headers.get("X-Custom-Password", "")
    if hdr and verify_custom_password(hdr, rule.custom_password_hash, rule.custom_password_salt):
        return True
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    yield
    global _httpx_client
    if _httpx_client is not None:
        try:
            await _httpx_client.aclose()
        except Exception:
            pass


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(RequestIDMiddleware)  # type: ignore[arg-type]
    app.add_middleware(ProxyFixMiddleware)  # type: ignore[arg-type]
    app.add_middleware(CSPMiddleware)  # type: ignore[arg-type]

    if _has_slowapi and SlowAPIMiddleware is not None:
        app.state.limiter = limiter
        app.add_middleware(SlowAPIMiddleware)  # type: ignore[arg-type]

        @app.exception_handler(RateLimitExceeded)  # type: ignore[arg-type]
        async def _rate_handler(request: Request, exc: RateLimitExceeded):  # type: ignore[no-untyped-def]
            return JSONResponse(status_code=429, content={"detail": "rate limited"})

    @app.exception_handler(HTTPException)  # type: ignore[arg-type]
    async def _http_exc_handler(request: Request, exc: HTTPException):  # type: ignore[no-untyped-def]
        status = getattr(exc, "status_code", 500)
        detail = getattr(exc, "detail", str(exc))
        if status in (403, 404):
            title = "Access denied" if status == 403 else "End of the road"
            message = (
                "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway."
                if status == 403
                else "You've reached the end of the road. This page doesn't exist on gatekeeper. Check the URL or return to the gateway."
            )
            host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
            path = request.url.path
            try:
                apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
            except Exception:
                apex = "projectnova.download"
            req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
            return _error_response(request, status, title, message, str(detail), host, path, req_id, apex)
        return JSONResponse(status_code=status, content={"detail": str(detail)})

    @app.exception_handler(404)  # type: ignore[arg-type]
    async def _not_found_handler(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
        path = request.url.path
        try:
            apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
        except Exception:
            apex = "projectnova.download"
        req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
        return _error_response(
            request,
            404,
            "End of the road",
            "You've reached the end of the road. This page doesn't exist on gatekeeper. Check the URL or return to the gateway.",
            "not found",
            host,
            path,
            req_id,
            apex,
        )

    @app.exception_handler(403)  # type: ignore[arg-type]
    async def _forbidden_handler(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
        path = request.url.path
        try:
            apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
        except Exception:
            apex = "projectnova.download"
        req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
        detail = getattr(exc, "detail", "forbidden") if hasattr(exc, "detail") else "forbidden"
        return _error_response(
            request,
            403,
            "Access denied",
            "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
            str(detail),
            host,
            path,
            req_id,
            apex,
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    def _clear_gatekeeper_cookie(resp: Response, apex: str) -> None:
        resp.delete_cookie(key="gatekeeper_token", domain=f".{apex}", path="/")
        resp.delete_cookie(key="gatekeeper_token", path="/")

    @app.get("/logout")
    async def logout_get(request: Request) -> Response:
        host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
        apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
        referer = request.headers.get("Referer", "")
        target = "/login"
        if referer:
            try:
                rh = (urlsplit(referer).hostname or "").lower()
                if rh == host or rh.endswith("." + apex):
                    target = "/login?redirect=/"
            except Exception:
                pass
        resp = RedirectResponse(url=target, status_code=302)
        _clear_gatekeeper_cookie(resp, apex)
        return resp

    @app.post("/logout")
    @limiter.limit("10/minute")
    async def logout_post(request: Request) -> Response:
        host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
        apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
        if request.method == "POST" and not same_origin(request, apex):
            ct = (await request.form()).get("csrf_token") if request.headers.get("content-type", "").startswith("application/x-www-form") else None
            if ct is None or not secrets.compare_digest(str(ct), request.cookies.get("csrf_token", "")):
                # still clear but require origin — fail closed with 403
                return JSONResponse(status_code=403, content={"detail": "Cross-site request rejected"})
        resp = RedirectResponse(url="/login", status_code=302)
        _clear_gatekeeper_cookie(resp, apex)
        return resp

    @app.get("/api/authz/forward-auth")
    @limiter.limit("100/minute")
    async def forward_auth(request: Request, background_tasks: BackgroundTasks, response: Response) -> Response:
        t0 = time.monotonic()
        host = _get_forwarded_host(request)
        uri = _get_forwarded_uri(request)
        proto = _get_forwarded_proto(request)
        path = urlsplit(uri).path or "/"
        if not path.startswith("/"):
            path = "/" + path
        apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
        routes, groups, _pages = await _load_caches()
        # Audited like any other request: a maintenance refusal that leaves no
        # row would make the switch invisible in the log it is explained by.
        maintenance = await _maintenance_response(request, host, path, apex)
        if maintenance is not None:
            await _queue_maintenance_audit(
                request,
                background_tasks,
                host,
                path,
                _get_ip(request),
                getattr(request.state, "request_id", uuid.uuid4().hex),
            )
            return maintenance
        grp, rule = _find_group_rule(host, path, groups)
        action = await _resolve_action(grp, rule)
        # The audit row carries the action that actually governed the request, so
        # a fallback is distinguishable from a policy that allowed the request.
        matched_action = action if rule is None else rule.action
        ip = _get_ip(request)
        req_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        # Read once per request: the header is the same on every audit row a
        # request writes, and the setting lookup is cached.
        country = await _visitor_country(request)

        async def _log(action: str, code_id: int | None = None, status_code: int | None = None, attempted_code: str | None = None) -> None:
            lat = int((time.monotonic() - t0) * 1000)
            _queue_audit(
                background_tasks,
                host=host,
                path=path,
                ip=ip,
                country=country,
                action=action,
                matched_action=matched_action,
                rule_group_id=grp.id if grp else None,
                rule_id=rule.id if rule else None,
                code_id=code_id,
                request_id=req_id,
                user_agent=request.headers.get("User-Agent"),
                referer=request.headers.get("Referer"),
                latency_ms=lat,
                method=request.method,
                status_code=status_code,
                attempted_code=attempted_code,
            )

        if rule is None:
            # Nothing matched. `grp is not None` means the group's catch-all is
            # missing, which resolve_rule_action always answers with a refusal;
            # `grp is None` follows the unmatched_action setting.
            if action == "deny":
                await _log("deny", status_code=403)
                return _error_response(
                    request,
                    403,
                    "Access denied",
                    "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
                    "denied: unmatched request",
                    host,
                    path,
                    req_id,
                    apex,
                )
            if action == "none":
                await _log("none_gate", status_code=200)
                return Response(status_code=200)
            # access_code: fall through to the cookie / ?access_code= checks below.

        if rule and rule.action == "deny":
            await _log("deny")
            return _error_response(
                request,
                403,
                "Access denied",
                "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
                "denied by rule",
                host,
                path,
                req_id,
                apex,
            )
        if rule and rule.action == "none":
            await _log("none_gate")
            return Response(status_code=200)

        if rule and rule.action == "custom_password":
            if _has_valid_custom_cookie(request, rule):
                await _log("custom_password_cookie")
                return Response(status_code=200)
            if _check_custom_password_param(request, rule):
                resp = Response(status_code=200)
                _set_custom_cookie(resp, rule.id, apex, await _setting_int(SESSION_LIFETIME_HOURS))
                await _log("custom_password_login")
                return resp
            cpass = request.query_params.get("custom_password") or request.headers.get("X-Custom-Password")
            if cpass and rule.custom_password_hash and rule.custom_password_salt and verify_custom_password(cpass, rule.custom_password_hash, rule.custom_password_salt):
                resp = Response(status_code=200)
                _set_custom_cookie(resp, rule.id, apex, await _setting_int(SESSION_LIFETIME_HOURS))
                await _log("custom_password_login")
                return resp
            await _log("custom_password_required")
            target = quote(f"https://{host}{uri}", safe="")
            return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)

        token = request.cookies.get("gatekeeper_token")
        if token:
            cres = await _code_from_jwt(token)
            if cres:
                await _log("auth_success", code_id=cres.id)
                return Response(status_code=200)

        access_code, _ac_path, _ac_qs = _get_access_code_param(request)
        if access_code:
            # rate-limit access_code tries per minute per IP (tries/min setting)
            limited, cnt, lim = await _check_access_code_rate_limited(ip)
            if limited:
                await _log("access_code_rate_limited", status_code=429, attempted_code=access_code)
                return JSONResponse(status_code=429, content={"detail": f"rate limited {cnt}/{lim} per minute"})
            cres = await _verify_code_value(access_code)
            if cres:
                clean = _strip_access_code(uri)
                if not clean.startswith("/"):
                    clean = "/" + clean
                loc = clean if clean else "/"
                resp = RedirectResponse(url=loc, status_code=302)
                _set_auth_cookie(resp, cres, apex, await _setting_int(SESSION_LIFETIME_HOURS))
                await _log("access_code_login", code_id=cres.id, status_code=302, attempted_code=access_code)
                return resp
            await _log("access_code_fail", status_code=401, attempted_code=access_code)

        await _log("no_cookie_redirect", status_code=302)
        target = quote(f"https://{host}{uri}", safe="")
        return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)

    hop_by_hop = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }

    async def _proxy_to_upstream(request: Request, background_tasks: BackgroundTasks) -> Response:
        t0 = time.monotonic()
        host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
        raw_path = request.url.path
        raw_qs = request.url.query
        full_uri = raw_path + (("?" + raw_qs) if raw_qs else "")
        proto = _get_forwarded_proto(request)
        apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
        routes, groups, pages = await _load_caches()
        maintenance = await _maintenance_response(request, host, raw_path, apex)
        if maintenance is not None:
            ip = _get_ip(request)
            req_id = getattr(request.state, "request_id", uuid.uuid4().hex)
            await _queue_maintenance_audit(request, background_tasks, host, raw_path, ip, req_id)
            return maintenance
        grp, rule = _find_group_rule(host, raw_path, groups)
        action = await _resolve_action(grp, rule)
        matched_action = action if rule is None else rule.action
        ip = _get_ip(request)
        req_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        country = await _visitor_country(request)
        code_id: int | None = None
        need_custom_cookie = False
        custom_cookie_rule: Rule | None = None

        async def _log(action: str, code_id: int | None = None, status_code: int | None = None, attempted_code: str | None = None) -> None:
            lat = int((time.monotonic() - t0) * 1000)
            _queue_audit(
                background_tasks,
                host=host,
                path=raw_path,
                ip=ip,
                country=country,
                action=action,
                matched_action=matched_action,
                rule_group_id=grp.id if grp else None,
                rule_id=rule.id if rule else None,
                code_id=code_id,
                request_id=req_id,
                user_agent=request.headers.get("User-Agent"),
                referer=request.headers.get("Referer"),
                latency_ms=lat,
                method=request.method,
                status_code=status_code,
                attempted_code=attempted_code,
            )

        if action == "deny":
            await _log("deny", status_code=403)
            return _error_response(
                request,
                403,
                "Access denied",
                "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
                "denied by rule" if rule else "denied: unmatched request",
                host,
                raw_path,
                req_id,
                apex,
            )
        if action == "none":
            # A custom page is served from here and nowhere else. This branch is
            # the one path where the gate has already decided the request may
            # pass, so `deny` / `custom_password` / `access_code` never reach the
            # check below and the feature cannot open a gate that was closed.
            page = None
            if request.method in ("GET", "HEAD") and not _is_control_plane(host, raw_path, apex):
                page = _find_page(host, raw_path, pages)
            if page is not None:
                await _queue_page_audit(
                    request, background_tasks, host, raw_path, ip, req_id, grp, rule
                )
                # The stored bytes, whole, with the stored content type. Nothing
                # escaped, sanitised or sniffed, and no header added beyond what
                # the response type requires.
                return Response(content=page.body.encode("utf-8"), media_type=page.content_type)
        elif action == "custom_password" and rule is not None:
            ok = False
            need_custom_cookie = False
            if _has_valid_custom_cookie(request, rule):
                ok = True
                await _log("custom_password_cookie")
            elif _check_custom_password_param(request, rule):
                ok = True
                need_custom_cookie = True
                custom_cookie_rule = rule
                await _log("custom_password_login")
            if not ok:
                token = request.cookies.get("gatekeeper_token")
                if token:
                    cres = await _code_from_jwt(token)
                    if cres:
                        ok = True
            if not ok:
                await _log("custom_password_required")
                target = quote(f"https://{host}{full_uri}", safe="")
                if not _safe_redirect_target(f"https://gatekeeper.{apex}/", apex):
                    return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)
                return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)
        else:
            # access_code. Reached by a matching rule, and by the fallback when
            # nothing matched but the action is not deny/none.
            authed = False
            code_id: int | None = None
            token = request.cookies.get("gatekeeper_token")
            if token:
                cres = await _code_from_jwt(token)
                if cres:
                    authed = True
                    code_id = cres.id
            if not authed:
                ac, _, _ = _get_access_code_param(request)
                if ac:
                    limited, cnt, lim = await _check_access_code_rate_limited(ip)
                    if limited:
                        await _log("access_code_rate_limited", status_code=429, attempted_code=ac)
                        return JSONResponse(status_code=429, content={"detail": f"rate limited {cnt}/{lim} per minute"})
                    cres = await _verify_code_value(ac)
                    if cres:
                        clean = _strip_access_code(full_uri)
                        if not clean.startswith("/"):
                            clean = "/" + clean
                        loc = clean if clean else "/"
                        resp = RedirectResponse(url=loc, status_code=302)
                        _set_auth_cookie(resp, cres, apex, await _setting_int(SESSION_LIFETIME_HOURS))
                        await _log("access_code_login", code_id=cres.id, status_code=302, attempted_code=ac)
                        return resp
                    await _log("access_code_fail", status_code=401, attempted_code=ac)
            if not authed:
                # Never proxy unauthenticated: nothing reached a rule that
                # allows the request, so send the visitor to the login page.
                await _log("no_cookie_redirect", status_code=302)
                target = quote(f"https://{host}{full_uri}", safe="")
                return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)
            await _log("auth_success", code_id=code_id, status_code=200)

        route = _find_route(host, raw_path, routes)
        if not route and host in ("gatekeeper.projectnova.download", "projectnova.download", "gatekeeper", "localhost"):
            route = Route(host=host, path="/", route_type="proxy", upstream="gatekeeper_management", port=8003)
        if not route:
            await _log("route_not_found")
            return _error_response(
                request,
                404,
                "End of the road",
                "You've reached the end of the road. This host isn't routed on the gateway. Check the subdomain or go back.",
                "no route for host",
                host,
                raw_path,
                req_id,
                apex,
            )
        if (route.route_type or "proxy") == "redirect":
            target = (route.redirect_target or "/").strip()
            code = route.redirect_code or 302
            if code not in (301, 302, 307, 308):
                code = 302
            clean_qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in parse_qsl(raw_qs, keep_blank_values=True) if k not in ("access_code", "custom_password", "customPassword", "password"))
            if target.startswith("http://") or target.startswith("https://"):
                loc = target
                if clean_qs and "?" not in loc:
                    loc += "?" + clean_qs
                elif clean_qs:
                    loc += "&" + clean_qs if "?" in loc else "?" + clean_qs
            else:
                if not target.startswith("/"):
                    target = "/" + target
                loc = f"https://{host}{target}"
                if clean_qs:
                    loc += "?" + clean_qs if "?" not in target else "&" + clean_qs
            await _log("redirect", code_id=code_id)
            resp = RedirectResponse(url=loc, status_code=code)
            if need_custom_cookie and custom_cookie_rule:
                _set_custom_cookie(resp, custom_cookie_rule.id, apex, await _setting_int(SESSION_LIFETIME_HOURS))
            return resp

        clean_qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in parse_qsl(raw_qs, keep_blank_values=True) if k not in ("access_code", "custom_password", "customPassword", "password"))
        upstream_url = f"http://{route.upstream}:{route.port}{raw_path}"
        if clean_qs:
            upstream_url += "?" + clean_qs

        body = await request.body()
        headers = {k.lower(): v for k, v in request.headers.items() if k.lower() not in hop_by_hop and not k.lower().startswith("x-forwarded-")}
        headers["x-forwarded-for"] = ip
        headers["x-forwarded-host"] = host
        headers["x-forwarded-proto"] = proto
        headers["x-request-id"] = req_id
        headers["host"] = f"{route.upstream}:{route.port}"

        client = _get_httpx()
        try:
            rp = await client.request(request.method, upstream_url, headers=headers, content=body, follow_redirects=False)
        except httpx.ConnectError as e:
            # The upstream container is not answering. A browser gets the themed
            # page every other gateway error uses; an API caller still gets JSON.
            # `_error_response` already branches on `wants_html`, so the only
            # thing that changes here is which of the two it is asked to build.
            _slog("proxy_unreachable", upstream=route.upstream, port=route.port, error=str(e))
            return _error_response(
                request,
                502,
                "Upstream unavailable",
                "The application behind this address is not responding. It may be restarting, "
                "or its container may not be running.",
                f"{route.upstream}:{route.port} refused the connection",
                host,
                raw_path,
                req_id,
                apex,
            )
        except httpx.TimeoutException as e:
            # A distinct status from ConnectError, because "nothing is listening"
            # and "it accepted the connection and went quiet" are different
            # problems with different fixes. Both used to collapse into the one
            # `except Exception` below and report 502.
            _slog("proxy_timeout", upstream=route.upstream, port=route.port, error=str(e))
            return _error_response(
                request,
                504,
                "Upstream timed out",
                "The application behind this address accepted the connection but did not "
                "answer in time. It may be under load or stuck.",
                f"{route.upstream}:{route.port} did not respond in time",
                host,
                raw_path,
                req_id,
                apex,
            )
        except Exception as e:
            _slog("proxy_error", error=str(e))
            return _error_response(
                request,
                502,
                "Upstream unavailable",
                "The gateway could not complete the request to the application behind this "
                "address.",
                "proxy error",
                host,
                raw_path,
                req_id,
                apex,
            )

        resp_headers = {k: v for k, v in rp.headers.items() if k.lower() not in hop_by_hop}
        if "content-encoding" in resp_headers:
            resp_headers.pop("content-encoding", None)

        async def _stream():  # type: ignore[no-untyped-def]
            async for chunk in rp.aiter_bytes():
                yield chunk

        if rp.headers.get("content-length") and int(rp.headers.get("content-length", "0")) < 1024 * 1024 * 2:
            content = rp.content
            await rp.aclose()
            resp = Response(content=content, status_code=rp.status_code, headers=resp_headers)
            if need_custom_cookie and custom_cookie_rule:
                _set_custom_cookie(resp, custom_cookie_rule.id, apex, await _setting_int(SESSION_LIFETIME_HOURS))
            return resp
        resp2 = StreamingResponse(_stream(), status_code=rp.status_code, headers=resp_headers, background=BackgroundTaskWrapper(rp))
        if need_custom_cookie and custom_cookie_rule:
            _set_custom_cookie(resp2, custom_cookie_rule.id, apex, await _setting_int(SESSION_LIFETIME_HOURS))
        return resp2

    class BackgroundTaskWrapper:  # type: ignore[no-redef]
        def __init__(self, rp: httpx.Response) -> None:
            self.rp = rp

        async def __call__(self) -> None:
            try:
                await self.rp.aclose()
            except Exception:
                pass

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    @limiter.limit("100/minute")
    async def wildcard(request: Request, full_path: str, background_tasks: BackgroundTasks) -> Response:  # type: ignore[no-untyped-def]
        if request.url.path == "/health" or request.url.path == "/api/authz/forward-auth":
            host = _get_forwarded_host(request) or request.headers.get("Host", "").split(":")[0].lower()
            path = request.url.path
            try:
                apex = _apex_from_host(host) if host else _apex_from_host(request.headers.get("Host", ""))
            except Exception:
                apex = "projectnova.download"
            req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
            return _error_response(
                request,
                404,
                "End of the road",
                "You've reached the end of the road. This page doesn't exist on gatekeeper. Check the URL or return to the gateway.",
                "not found",
                host,
                path,
                req_id,
                apex,
            )
        return await _proxy_to_upstream(request, background_tasks)

    return app


app = create_app()

if __name__ == "__main__":
    import granian  # type: ignore[import-not-found]

    granian.run("app:app", host="0.0.0.0", port=8001, interface="asgi")
