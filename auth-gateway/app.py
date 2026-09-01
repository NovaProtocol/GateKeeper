from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from itsdangerous import BadSignature, URLSafeSerializer

from shared.error_pages import render_error_html, wants_html
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from shared.config import get_config
from shared.db import get_sessionmaker
from shared.models import ApiKey, AuditLog, Code, Route, Rule, RuleGroup
from shared.security import apex_domain as shared_apex_domain
from shared.security import hash_api_key, host_matches, path_matches, verify_custom_password

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
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware

    def _key_func(request: Request) -> str:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return get_remote_address(request)

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
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
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
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    cip = request.client.host if request.client else ""
    return cip or "0.0.0.0"


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


def _get_api_key_value(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        v = auth[7:].strip()
        if v:
            return v
    v = request.headers.get("X-Api-Key") or request.headers.get("x-api-key")
    if v:
        return v.strip()
    v = request.query_params.get("api_key") or request.query_params.get("apiKey")
    if v:
        return v.strip()
    xf_uri = request.headers.get("X-Forwarded-Uri", "")
    if xf_uri:
        qs = urlsplit(xf_uri).query
        for k, val in parse_qsl(qs):
            if k in ("api_key", "apiKey", "x-api-key"):
                return val.strip()
    return None


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


def _api_key_allows(api_key: ApiKey, host: str, path: str) -> bool:
    mode = (api_key.mode or "none").lower()
    if mode == "none":
        return True
    wl_raw = api_key.whitelist
    bl_raw = api_key.blacklist

    def _parse(raw: Any) -> list[str]:
        if not raw:
            return []
        if isinstance(raw, list):
            return [str(x).strip() for x in raw if str(x).strip()]
        try:
            j = json.loads(raw)
            if isinstance(j, list):
                return [str(x).strip() for x in j if str(x).strip()]
        except Exception:
            pass
        return [s.strip() for s in str(raw).split(",") if s.strip()]

    host_path = f"{host}{path}"

    def _glob_match(pattern: str, target_host: str, target_path: str) -> bool:
        if "/" in pattern:
            ph, pp = pattern.split("/", 1)
            pp = "/" + pp
        else:
            ph, pp = pattern, "/*"
        return host_matches(ph, target_host) and path_matches(pp, target_path)

    if mode == "whitelist":
        wl = _parse(wl_raw)
        if not wl:
            return False
        for pat in wl:
            if _glob_match(pat, host, path) or _glob_match(pat, host_path, path):
                if pat == "*.*/*" or pat == "*.*":
                    return True
                if "/" in pat:
                    h, _ = pat.split("/", 1)
                    if host_matches(h, host):
                        return True
                    if host_matches(pat.split("/")[0], host_path):
                        return True
                if _glob_match(pat, host, path):
                    return True
        for pat in wl:
            if _glob_match(pat, host, path):
                return True
        return False
    if mode == "blacklist":
        bl = _parse(bl_raw)
        for pat in bl:
            if _glob_match(pat, host, path):
                return False
        return True
    return True


async def _load_caches() -> tuple[list[Route], list[RuleGroup]]:
    global _CacheRoutes, _CacheGroups, _CacheTs
    now = time.monotonic()
    if _CacheRoutes is not None and _CacheGroups is not None and (now - _CacheTs) < CACHE_TTL:
        return _CacheRoutes, _CacheGroups
    async with _CacheLock:
        now2 = time.monotonic()
        if _CacheRoutes is not None and _CacheGroups is not None and (now2 - _CacheTs) < CACHE_TTL:
            return _CacheRoutes, _CacheGroups
        try:
            sm = get_sessionmaker()
            async with sm() as s:
                rres = await s.execute(select(Route))
                routes = list(rres.scalars().all())
                gres = await s.execute(select(RuleGroup).options(selectinload(RuleGroup.rules)).order_by(RuleGroup.display_order))
                groups = list(gres.scalars().all())
        except Exception as e:
            _slog("cache_load_failed", error=str(e))
            if _CacheRoutes is not None and _CacheGroups is not None:
                return _CacheRoutes, _CacheGroups
            return [], []
        _CacheRoutes = routes
        _CacheGroups = groups
        _CacheTs = time.monotonic()
        return routes, groups


def _find_group_rule(host: str, path: str, groups: list[RuleGroup]) -> tuple[RuleGroup | None, Rule | None]:
    groups_sorted = sorted(groups, key=lambda g: g.display_order)
    for g in groups_sorted:
        if not host_matches(g.domain, host):
            continue
        rules_sorted = sorted(g.rules, key=lambda r: r.display_order)
        for r in rules_sorted:
            if path_matches(r.path, path):
                return g, r
        break
    return None, None


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
        sm = get_sessionmaker()
        async with sm() as s:
            res = await s.execute(select(Code).where(Code.code == code_val, Code.active == True))  # noqa: E712
            row = res.scalars().first()
            if row:
                try:
                    row.last_accessed = __import__("datetime").datetime.utcnow()  # type: ignore[attr-defined]
                    await s.commit()
                except Exception:
                    pass
            return row
    except Exception:
        return None


async def _verify_api_key_value(key_val: str) -> ApiKey | None:
    if not key_val:
        return None
    try:
        sm = get_sessionmaker()
        async with sm() as s:
            res = await s.execute(select(ApiKey).where(ApiKey.active == True))  # noqa: E712
            for k in res.scalars().all():
                exp = hash_api_key(key_val, k.salt)
                if __import__("hmac").compare_digest(exp, k.key_hash):
                    if k.expires_at is not None:
                        import datetime as dt

                        now = dt.datetime.utcnow()
                        ea = k.expires_at
                        if ea.tzinfo is not None:
                            ea = ea.replace(tzinfo=None)
                        if ea < now:
                            return None
                    try:
                        import datetime as dt

                        k.last_used = dt.datetime.utcnow()  # type: ignore[attr-defined]
                        await s.commit()
                    except Exception:
                        pass
                    return k
            return None
    except Exception:
        return None


async def _audit_log_async(
    host: str,
    path: str,
    ip: str,
    action: str,
    matched_action: str | None,
    rule_group_id: int | None,
    rule_id: int | None,
    code_id: int | None,
    api_key_id: int | None,
    request_id: str,
    user_agent: str | None,
    referer: str | None,
    latency_ms: int | None = None,
) -> None:
    payload = {
        "ts": __import__("datetime").datetime.utcnow().isoformat(),
        "host": host,
        "path": path,
        "ip": ip,
        "action": action,
        "matched_action": matched_action,
        "rule_group_id": rule_group_id,
        "rule_id": rule_id,
        "code_id": code_id,
        "api_key_id": api_key_id,
        "request_id": request_id,
        "user_agent": (user_agent or "")[:512],
        "referer": (referer or "")[:1024],
        "latency_ms": latency_ms,
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
    try:
        sm = get_sessionmaker()
        async with sm() as s:
            import datetime as dt

            al = AuditLog(
                ip=ip,
                host=host,
                path=path,
                action=action,
                matched_action=matched_action,
                rule_group_id=rule_group_id,
                rule_id=rule_id,
                code_id=code_id,
                api_key_id=api_key_id,
                request_id=request_id,
                user_agent=(user_agent or "")[:512],
                referer=(referer or "")[:1024],
                latency_ms=latency_ms,
                ts=dt.datetime.utcnow(),
            )
            s.add(al)
            await s.commit()
    except Exception as e:
        _slog("audit_direct_failed", error=str(e))


def _queue_audit(background_tasks: BackgroundTasks, **kw: Any) -> None:
    background_tasks.add_task(_audit_log_async, **kw)


def _cookie_serializer() -> URLSafeSerializer:
    cfg = get_config()
    return URLSafeSerializer(cfg.SECRET_KEY, salt="cookie")


def _set_auth_cookie(resp: Response, code_val: str, apex: str) -> None:
    ser = _cookie_serializer()
    token = ser.dumps(code_val)
    resp.set_cookie(
        key="gatekeeper_token",
        value=token,
        domain=f".{apex}",
        path="/",
        httponly=True,
        samesite="lax",
        secure=True,
    )


def _set_custom_cookie(resp: Response, rule_id: int, apex: str) -> None:
    ser = URLSafeSerializer(get_config().SECRET_KEY, salt=f"custom-{rule_id}")
    token = ser.dumps("ok")
    resp.set_cookie(
        key=f"gatekeeper_custom_{rule_id}",
        value=token,
        domain=f".{apex}",
        path="/",
        httponly=True,
        samesite="lax",
        secure=True,
    )


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
    try:
        ser = URLSafeSerializer(get_config().SECRET_KEY, salt=f"custom-{rule.id}")
        ser.loads(raw)
        return True
    except Exception:
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
        routes, groups = await _load_caches()
        grp, rule = _find_group_rule(host, path, groups)
        matched_action = rule.action if rule else None
        ip = _get_ip(request)
        req_id = getattr(request.state, "request_id", uuid.uuid4().hex)

        async def _log(action: str, code_id: int | None = None, api_key_id: int | None = None) -> None:
            lat = int((time.monotonic() - t0) * 1000)
            _queue_audit(
                background_tasks,
                host=host,
                path=path,
                ip=ip,
                action=action,
                matched_action=matched_action,
                rule_group_id=grp.id if grp else None,
                rule_id=rule.id if rule else None,
                code_id=code_id,
                api_key_id=api_key_id,
                request_id=req_id,
                user_agent=request.headers.get("User-Agent"),
                referer=request.headers.get("Referer"),
                latency_ms=lat,
            )

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
                _set_custom_cookie(resp, rule.id, apex)
                await _log("custom_password_login")
                return resp
            cpass = request.query_params.get("custom_password") or request.headers.get("X-Custom-Password")
            if cpass and rule.custom_password_hash and rule.custom_password_salt and verify_custom_password(cpass, rule.custom_password_hash, rule.custom_password_salt):
                resp = Response(status_code=200)
                _set_custom_cookie(resp, rule.id, apex)
                await _log("custom_password_login")
                return resp
            await _log("custom_password_required")
            target = quote(f"https://{host}{uri}", safe="")
            return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)

        token = request.cookies.get("gatekeeper_token")
        if token:
            try:
                ser = _cookie_serializer()
                code_val = ser.loads(token)
                cres = await _verify_code_value(code_val)
                if cres:
                    await _log("auth_success", code_id=cres.id)
                    return Response(status_code=200)
            except (BadSignature, Exception):
                pass

        access_code, _ac_path, _ac_qs = _get_access_code_param(request)
        if access_code:
            cres = await _verify_code_value(access_code)
            if cres:
                clean = _strip_access_code(uri)
                if not clean.startswith("/"):
                    clean = "/" + clean
                loc = clean if clean else "/"
                resp = RedirectResponse(url=loc, status_code=302)
                _set_auth_cookie(resp, access_code, apex)
                await _log("access_code_login", code_id=cres.id)
                return resp

        api_key_val = _get_api_key_value(request)
        if api_key_val:
            k = await _verify_api_key_value(api_key_val)
            if k:
                if _api_key_allows(k, host, path):
                    await _log("api_key_success", api_key_id=k.id)
                    return Response(status_code=200)
                await _log("api_key_blacklisted", api_key_id=k.id)
                return _error_response(
                    request,
                    403,
                    "Access denied",
                    "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
                    "api key not allowed for this endpoint",
                    host,
                    path,
                    req_id,
                    apex,
                )

        await _log("no_cookie_redirect")
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
        routes, groups = await _load_caches()
        grp, rule = _find_group_rule(host, raw_path, groups)
        matched_action = rule.action if rule else None
        ip = _get_ip(request)
        req_id = getattr(request.state, "request_id", uuid.uuid4().hex)
        code_id: int | None = None
        api_key_id: int | None = None
        need_custom_cookie = False
        custom_cookie_rule: Rule | None = None

        async def _log(action: str, code_id: int | None = None, api_key_id: int | None = None) -> None:
            lat = int((time.monotonic() - t0) * 1000)
            _queue_audit(
                background_tasks,
                host=host,
                path=raw_path,
                ip=ip,
                action=action,
                matched_action=matched_action,
                rule_group_id=grp.id if grp else None,
                rule_id=rule.id if rule else None,
                code_id=code_id,
                api_key_id=api_key_id,
                request_id=req_id,
                user_agent=request.headers.get("User-Agent"),
                referer=request.headers.get("Referer"),
                latency_ms=lat,
            )

        if rule and rule.action == "deny":
            await _log("deny")
            return _error_response(
                request,
                403,
                "Access denied",
                "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
                "denied",
                host,
                raw_path,
                req_id,
                apex,
            )
        if rule and rule.action == "none":
            pass
        elif rule and rule.action == "custom_password":
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
                    try:
                        code_val = _cookie_serializer().loads(token)
                        cres = await _verify_code_value(code_val)
                        if cres:
                            ok = True
                    except Exception:
                        pass
            if not ok:
                await _log("custom_password_required")
                target = quote(f"https://{host}{full_uri}", safe="")
                if not _safe_redirect_target(f"https://gatekeeper.{apex}/", apex):
                    return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)
                return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)
        elif rule is None or (rule and rule.action == "access_code"):
            authed = False
            code_id: int | None = None
            api_key_id: int | None = None
            token = request.cookies.get("gatekeeper_token")
            if token:
                try:
                    code_val = _cookie_serializer().loads(token)
                    cres = await _verify_code_value(code_val)
                    if cres:
                        authed = True
                        code_id = cres.id
                except Exception:
                    pass
            if not authed:
                ac, _, _ = _get_access_code_param(request)
                if ac:
                    cres = await _verify_code_value(ac)
                    if cres:
                        clean = _strip_access_code(full_uri)
                        if not clean.startswith("/"):
                            clean = "/" + clean
                        loc = clean if clean else "/"
                        resp = RedirectResponse(url=loc, status_code=302)
                        _set_auth_cookie(resp, ac, apex)
                        await _log("access_code_login", code_id=cres.id)
                        return resp
            if not authed:
                ak = _get_api_key_value(request)
                if ak:
                    k = await _verify_api_key_value(ak)
                    if k and _api_key_allows(k, host, raw_path):
                        authed = True
                        api_key_id = k.id
                    elif k:
                        await _log("api_key_blacklisted", api_key_id=k.id)
                        return _error_response(
                            request,
                            403,
                            "Access denied",
                            "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway.",
                            "api key not allowed",
                            host,
                            raw_path,
                            req_id,
                            apex,
                        )
            if not authed:
                if rule is None:
                    pass
                else:
                    await _log("no_cookie_redirect")
                    target = quote(f"https://{host}{full_uri}", safe="")
                    return RedirectResponse(url=f"https://gatekeeper.{apex}/login?redirect={target}", status_code=302)
            if authed:
                await _log("auth_success", code_id=code_id, api_key_id=api_key_id)
            else:
                await _log("none_gate")

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
            await _log("redirect", code_id=code_id, api_key_id=api_key_id)
            resp = RedirectResponse(url=loc, status_code=code)
            if need_custom_cookie and custom_cookie_rule:
                _set_custom_cookie(resp, custom_cookie_rule.id, apex)
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
        except httpx.ConnectError:
            return JSONResponse(status_code=502, content={"detail": "upstream unreachable"})
        except Exception as e:
            _slog("proxy_error", error=str(e))
            return JSONResponse(status_code=502, content={"detail": "proxy error"})

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
                _set_custom_cookie(resp, custom_cookie_rule.id, apex)
            return resp
        resp2 = StreamingResponse(_stream(), status_code=rp.status_code, headers=resp_headers, background=BackgroundTaskWrapper(rp))
        if need_custom_cookie and custom_cookie_rule:
            _set_custom_cookie(resp2, custom_cookie_rule.id, apex)
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
