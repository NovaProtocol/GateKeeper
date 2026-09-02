from __future__ import annotations

import logging
import secrets
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from shared.config import get_config
from shared.db import get_sessionmaker
from shared.models import Code
from shared.error_pages import render_error_html, wants_html
from shared.security import apex_domain as shared_apex, mask_code

try:
    import structlog

    structlog.configure(
        processors=[structlog.processors.JSONRenderer()] if hasattr(structlog.processors, "JSONRenderer") else [],  # type: ignore[attr-defined]
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),  # type: ignore[attr-defined]
    )

    def _slog(msg: str, **kw: Any) -> None:
        structlog.get_logger().info(msg, **kw)

except Exception:
    logging.basicConfig(level=logging.INFO)

    def _slog(msg: str, **kw: Any) -> None:
        logging.getLogger("management").info("%s %s", msg, kw)

try:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.middleware import SlowAPIMiddleware
    from slowapi.util import get_remote_address

    def _key_func(request: Request) -> str:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return get_remote_address(request)

    limiter = Limiter(key_func=_key_func, default_limits=[])
    _has_slowapi = True
except Exception:

    class _DummyLimiter:
        def limit(self, *a: Any, **kw: Any):  # type: ignore[no-untyped-def]
            def dec(fn):  # type: ignore[no-untyped-def]
                return fn

            return dec

    limiter = _DummyLimiter()  # type: ignore[assignment]
    RateLimitExceeded = Exception  # type: ignore[assignment,misc]
    SlowAPIMiddleware = None  # type: ignore[assignment]
    _has_slowapi = False

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

_httpx_client: httpx.AsyncClient | None = None


def _get_httpx() -> httpx.AsyncClient:
    global _httpx_client
    if _httpx_client is None:
        _httpx_client = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
    return _httpx_client


def _cookie_serializer() -> URLSafeSerializer:
    cfg = get_config()
    return URLSafeSerializer(cfg.SECRET_KEY, salt="cookie")


def _apex_from_request(request: Request) -> str:
    host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
    host = host.split(",")[0].strip().split(":")[0].lower()
    return shared_apex(host) if host else "projectnova.download"


def _derive_login_host(redirect_target: str, apex: str) -> str:
    """Hostname only, no path — validated against apex to avoid display injection."""
    try:
        th = (urlsplit(redirect_target).hostname or "").lower()
        if th and (th == apex or th.endswith("." + apex)):
            return th
    except Exception:
        pass
    return apex


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
        apex = shared_apex(cur_host) if cur_host else "projectnova.download"
    return host == cur_host or host == apex or host.endswith("." + apex)


def _get_csrf_token(request: Request) -> str:
    tok = request.cookies.get("csrf_token")
    if tok:
        return tok
    return secrets.token_urlsafe(32)


def _verify_csrf(request: Request, form_token: str | None) -> bool:
    cookie_token = request.cookies.get("csrf_token")
    if not cookie_token or not form_token:
        return False
    return secrets.compare_digest(cookie_token, form_token)


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
                    import datetime as dt

                    row.last_accessed = dt.datetime.utcnow()  # type: ignore[attr-defined]
                    await s.commit()
                except Exception:
                    pass
            return row
    except Exception:
        return None


async def _get_authenticated_code(request: Request) -> Code | None:
    token = request.cookies.get("gatekeeper_token")
    if not token:
        return None
    try:
        val = _cookie_serializer().loads(token)
    except (BadSignature, Exception):
        return None
    return await _verify_code_value(val)


def _display_name(code: Code) -> str:
    return code.display_name or code.label or "User"


def _masked(code: str) -> str:
    return mask_code(code)


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = rid
        _slog("request", method=request.method, path=request.url.path, request_id=rid)
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
            request.scope["server"] = (h.split(":")[0], 443 if request.scope.get("scheme") == "https" else 80)
        return await call_next(request)


class CSPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'; frame-src 'self' https://*.projectnova.download https://portfolio.projectnova.download; frame-ancestors 'self' https://portfolio.projectnova.download https://*.projectnova.download"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return resp


async def _require_manage_auth(request: Request) -> Response | None:
    """Check manage_session cookie. Returns redirect Response if unauthenticated, None if OK."""
    cfg = get_config()
    pw = cfg.MANAGE_PASSWORD
    if not pw:
        raise HTTPException(status_code=500, detail="MANAGE_PASSWORD not configured")
    token = request.cookies.get("manage_session")
    if not token:
        return _manage_auth_redirect(request)
    try:
        val = _cookie_serializer().loads(token)
        if not secrets.compare_digest(str(val), "manage-ok"):
            return _manage_auth_redirect(request)
    except (BadSignature, Exception):
        return _manage_auth_redirect(request)
    if request.method == "POST" and not same_origin(request):
        raise HTTPException(status_code=403, detail="Cross-site request rejected")
    return None


def _manage_auth_redirect(request: Request) -> Response:
    """Return a redirect to /manage/login or a 401 JSON for API callers."""
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept:
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    redirect_target = quote(request.url.path, safe="")
    return RedirectResponse(url=f"/manage/login?redirect={redirect_target}", status_code=302)


def _api_headers() -> dict[str, str]:
    cfg = get_config()
    h: dict[str, str] = {"Content-Type": "application/json"}
    if cfg.INTERNAL_API_KEY:
        h["X-Internal-Api-Key"] = cfg.INTERNAL_API_KEY
    return h


async def _api_proxy_get(path: str, params: dict[str, Any] | None = None) -> Any:
    url = f"http://api:8002{path}"
    client = _get_httpx()
    try:
        r = await client.get(url, headers=_api_headers(), params=params, timeout=5.0)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return r.json()
    except Exception as e:
        _slog("api_proxy_failed", path=path, error=str(e))
        return []


async def _api_proxy_post(path: str, payload: dict[str, Any]) -> Any:
    url = f"http://api:8002{path}"
    client = _get_httpx()
    r = await client.post(url, json=payload, headers=_api_headers(), timeout=5.0)
    return r


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

    def _mgmt_error_response(  # type: ignore[no-untyped-def]
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
        return _JR(status_code=status, content={"detail": detail or message})

    @app.exception_handler(HTTPException)  # type: ignore[arg-type]
    async def _mgmt_http_exc(request: Request, exc: HTTPException):  # type: ignore[no-untyped-def]
        status = getattr(exc, "status_code", 500)
        detail = getattr(exc, "detail", str(exc))
        if status in (403, 404):
            title = "Access denied" if status == 403 else "End of the road"
            message = (
                "This page is denied by gateway rules. If you believe this is an error, contact the admin or return to the gateway."
                if status == 403
                else "You've reached the end of the road. This page doesn't exist on gatekeeper. Check the URL or return to the gateway."
            )
            host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
            host = host.split(",")[0].strip().split(":")[0].lower()
            path = request.url.path
            try:
                apex = shared_apex(host) if host else _apex_from_request(request)
            except Exception:
                apex = "projectnova.download"
            req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
            return _mgmt_error_response(request, status, title, message, str(detail), host, path, req_id, apex)
        return JSONResponse(status_code=status, content={"detail": str(detail)})

    @app.exception_handler(404)  # type: ignore[arg-type]
    async def _mgmt_not_found(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
        host = host.split(",")[0].strip().split(":")[0].lower()
        path = request.url.path
        try:
            apex = shared_apex(host) if host else _apex_from_request(request)
        except Exception:
            apex = "projectnova.download"
        req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
        return _mgmt_error_response(
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
    async def _mgmt_forbidden(request: Request, exc: Exception):  # type: ignore[no-untyped-def]
        host = request.headers.get("X-Forwarded-Host") or request.headers.get("Host", "")
        host = host.split(",")[0].strip().split(":")[0].lower()
        path = request.url.path
        try:
            apex = shared_apex(host) if host else _apex_from_request(request)
        except Exception:
            apex = "projectnova.download"
        req_id = getattr(getattr(request, "state", object()), "request_id", None) or request.headers.get("X-Request-ID") or ""
        detail = getattr(exc, "detail", "forbidden") if hasattr(exc, "detail") else "forbidden"
        return _mgmt_error_response(
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

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _set_auth_cookie(resp: Response, code_val: str, apex: str) -> None:
        token = _cookie_serializer().dumps(code_val)
        resp.set_cookie(key="gatekeeper_token", value=token, domain=f".{apex}", path="/", httponly=True, samesite="lax", secure=True)

    def _set_manage_session_cookie(resp: Response) -> None:
        token = _cookie_serializer().dumps("manage-ok")
        resp.set_cookie(key="manage_session", value=token, path="/manage", httponly=True, samesite="lax", secure=True, max_age=8 * 3600)

    def _clear_manage_session_cookie(resp: Response) -> None:
        resp.delete_cookie(key="manage_session", path="/manage")

    @app.get("/manage/login", response_class=HTMLResponse)
    @limiter.limit("10/minute")
    async def manage_login_get(request: Request) -> Response:
        redirect_target = request.query_params.get("redirect", "/manage")
        if not redirect_target.startswith("/manage"):
            redirect_target = "/manage"
        csrf = _get_csrf_token(request)
        resp = templates.TemplateResponse(request, "manage_login.html", {"request": request, "redirect": redirect_target, "error": None, "csrf_token": csrf})
        if not request.cookies.get("csrf_token"):
            resp.set_cookie(key="csrf_token", value=csrf, path="/", samesite="lax", secure=True)
        return resp

    @app.post("/manage/login", response_class=HTMLResponse)
    @limiter.limit("10/minute")
    async def manage_login_post(request: Request) -> Response:
        form = await request.form()
        password = str(form.get("manage_password") or "").strip()
        redirect_target = str(form.get("redirect") or "/manage")
        csrf_token = str(form.get("csrf_token") or "")
        if not redirect_target.startswith("/manage"):
            redirect_target = "/manage"
        if not same_origin(request):
            csrf_ok = _verify_csrf(request, csrf_token)
            if not csrf_ok:
                return templates.TemplateResponse(request, "manage_login.html", {"request": request, "redirect": redirect_target, "error": "Cross-site request rejected", "csrf_token": _get_csrf_token(request)}, status_code=403)
        if not _verify_csrf(request, csrf_token):
            return templates.TemplateResponse(request, "manage_login.html", {"request": request, "redirect": redirect_target, "error": "Invalid CSRF token", "csrf_token": _get_csrf_token(request)}, status_code=403)
        cfg = get_config()
        if not password or not secrets.compare_digest(password, cfg.MANAGE_PASSWORD or ""):
            return templates.TemplateResponse(request, "manage_login.html", {"request": request, "redirect": redirect_target, "error": "Invalid management password", "csrf_token": _get_csrf_token(request)}, status_code=401)
        resp = RedirectResponse(url=redirect_target, status_code=302)
        _set_manage_session_cookie(resp)
        return resp

    @app.get("/manage/logout")
    async def manage_logout(request: Request) -> Response:
        resp = RedirectResponse(url="/manage/login", status_code=302)
        _clear_manage_session_cookie(resp)
        return resp

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def landing(request: Request) -> Response:
        code = await _get_authenticated_code(request)
        if not code:
            redirect = quote(str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""), safe="")
            return RedirectResponse(url=f"/login?redirect={redirect}", status_code=302)
        name = _display_name(code)
        masked = _masked(code.code)
        csrf = _get_csrf_token(request)
        resp = templates.TemplateResponse(request, "landing.html", {"request": request, "name": name, "masked_code": masked, "code": code, "csrf_token": csrf})
        if not request.cookies.get("csrf_token"):
            resp.set_cookie(key="csrf_token", value=csrf, path="/", samesite="lax", secure=True)
        return resp

    @app.get("/login", response_class=HTMLResponse)
    @limiter.limit("5/minute")
    async def login_get(request: Request) -> Response:
        code = await _get_authenticated_code(request)
        if code:
            apex = _apex_from_request(request)
            target = request.query_params.get("redirect", "/")
            if not _safe_redirect_target(target, apex):
                target = "/"
            return RedirectResponse(url=target, status_code=302)
        csrf = _get_csrf_token(request)
        redirect_target = request.query_params.get("redirect", "/")
        is_custom = False
        custom_host = ""
        try:
            from urllib.parse import urlsplit as _us
            from shared.security import host_matches as _hm2, path_matches as _pm2
            from sqlalchemy import select as _sel2
            from shared.models import RuleGroup as _RG2, Rule as _R2
            tp = _us(redirect_target)
            th = (tp.hostname or "").lower()
            tpa = tp.path or "/"
            if th:
                sm2 = get_sessionmaker()
                async with sm2() as s2:
                    gres = await s2.execute(_sel2(_RG2).order_by(_RG2.display_order))
                    for g in gres.scalars().all():
                        if not _hm2(g.domain, th):
                            continue
                        rres = await s2.execute(_sel2(_R2).where(_R2.group_id == g.id).order_by(_R2.display_order))
                        for r in rres.scalars().all():
                            if _pm2(r.path, tpa) and r.action == "custom_password":
                                is_custom = True
                                custom_host = th
                                break
                        break
        except Exception:
            pass
        # derive login_host for non-custom case (hostname only, no path)
        _apex_for_host = _apex_from_request(request)
        login_host = _derive_login_host(redirect_target, _apex_for_host)
        resp = templates.TemplateResponse(request, "login.html", {"request": request, "error": None, "redirect": redirect_target, "csrf_token": csrf, "is_custom": is_custom, "custom_host": custom_host, "login_host": login_host})
        if not request.cookies.get("csrf_token"):
            resp.set_cookie(key="csrf_token", value=csrf, path="/", samesite="lax", secure=True)
        return resp

    async def _handle_login_post(request: Request) -> Response:
        form = await request.form()
        code_val = str(form.get("access_code") or form.get("code") or form.get("custom_password") or "").strip()
        redirect_target = str(form.get("redirect") or request.query_params.get("redirect") or "/")
        csrf_token = str(form.get("csrf_token") or "")
        apex = _apex_from_request(request)
        # host for error renders (hostname only, validated against apex)
        login_host_err = _derive_login_host(redirect_target, apex)
        if not same_origin(request, apex):
            csrf_ok = _verify_csrf(request, csrf_token)
            if not csrf_ok:
                return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Cross-site request rejected", "redirect": redirect_target, "csrf_token": _get_csrf_token(request), "is_custom": False, "custom_host": "", "login_host": login_host_err}, status_code=403)
        if not _verify_csrf(request, csrf_token):
            return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid CSRF token", "redirect": redirect_target, "csrf_token": _get_csrf_token(request), "is_custom": False, "custom_host": "", "login_host": login_host_err}, status_code=403)
        if not code_val:
            return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Access code required", "redirect": redirect_target, "csrf_token": _get_csrf_token(request), "is_custom": False, "custom_host": "", "login_host": login_host_err}, status_code=400)
        row = await _verify_code_value(code_val)
        if row:
            if not _safe_redirect_target(redirect_target, apex):
                redirect_target = "/"
            resp = RedirectResponse(url=redirect_target, status_code=302)
            _set_auth_cookie(resp, code_val, apex)
            return resp
        try:
            from urllib.parse import urlsplit as _urlsplit
            from shared.security import host_matches as _hm, path_matches as _pm, verify_custom_password as _vcp
            from sqlalchemy import select as _select
            from shared.models import RuleGroup as _RG, Rule as _R
            target_parts = _urlsplit(redirect_target)
            thost = (target_parts.hostname or "").lower() or _apex_from_request(request).lower()
            tpath = target_parts.path or "/"
            if not thost:
                thost = _apex_from_request(request)
            sm = get_sessionmaker()
            async with sm() as s:
                gres = await s.execute(_select(_RG).order_by(_RG.display_order))
                for g in gres.scalars().all():
                    if not _hm(g.domain, thost):
                        continue
                    rres = await s.execute(_select(_R).where(_R.group_id == g.id).order_by(_R.display_order))
                    for r in rres.scalars().all():
                        if r.action == "custom_password" and r.custom_password_hash and r.custom_password_salt and _pm(r.path, tpath):
                            if _vcp(code_val, r.custom_password_hash, r.custom_password_salt):
                                from itsdangerous import URLSafeSerializer as _Ser
                                ser = _Ser(get_config().SECRET_KEY, salt=f"custom-{r.id}")
                                tok = ser.dumps("ok")
                                if not _safe_redirect_target(redirect_target, apex):
                                    redirect_target = "/"
                                resp = RedirectResponse(url=redirect_target, status_code=302)
                                resp.set_cookie(key=f"gatekeeper_custom_{r.id}", value=tok, domain=f".{apex}", path="/", httponly=True, samesite="lax", secure=True)
                                return resp
        except Exception:
            pass
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid code", "redirect": redirect_target, "csrf_token": _get_csrf_token(request), "is_custom": False, "custom_host": "", "login_host": _derive_login_host(redirect_target, apex)}, status_code=401)

    @app.post("/", response_class=HTMLResponse)
    @limiter.limit("5/minute")
    async def login_post_root(request: Request) -> Response:
        return await _handle_login_post(request)

    @app.post("/login", response_class=HTMLResponse)
    @limiter.limit("5/minute")
    async def login_post(request: Request) -> Response:
        return await _handle_login_post(request)

    async def _render_manage(request: Request, template: str, ctx: dict[str, Any] | None = None) -> Response:
        auth_resp = await _require_manage_auth(request)
        if auth_resp is not None:
            return auth_resp
        csrf = _get_csrf_token(request)
        base_ctx: dict[str, Any] = {"request": request, "csrf_token": csrf}
        if ctx:
            base_ctx.update(ctx)
        resp = templates.TemplateResponse(request, template, base_ctx)
        if not request.cookies.get("csrf_token"):
            resp.set_cookie(key="csrf_token", value=csrf, path="/", samesite="lax", secure=True)
        return resp

    @app.get("/manage", response_class=HTMLResponse)
    async def manage_dashboard(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        routes = await _api_proxy_get("/api/routes")
        groups = await _api_proxy_get("/api/groups")
        codes = await _api_proxy_get("/api/codes")
        warnings = await _api_proxy_get("/api/warnings")
        api_keys = await _api_proxy_get("/api/keys")
        stats = {"routes": len(routes) if isinstance(routes, list) else 0, "groups": len(groups) if isinstance(groups, list) else 0, "codes": len(codes) if isinstance(codes, list) else 0, "api_keys": len(api_keys) if isinstance(api_keys, list) else 0}
        return await _render_manage(request, "manage/dashboard.html", {"stats": stats, "routes": routes if isinstance(routes, list) else [], "groups": groups if isinstance(groups, list) else [], "codes": codes if isinstance(codes, list) else [], "warnings": warnings})

    @app.get("/manage/routing", response_class=HTMLResponse)
    async def manage_routing(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        routes = await _api_proxy_get("/api/routes")
        if not isinstance(routes, list):
            routes = []
        return await _render_manage(request, "manage/routing.html", {"routes": routes})

    @app.post("/manage/routing", response_class=HTMLResponse)
    async def manage_routing_create(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        host = str(form.get("host") or "").strip().lower()
        if not host:
            sub = str(form.get("subdomain") or "").strip().lower()
            dom = str(form.get("domain") or "").strip().lower()
            if dom:
                host = f"{sub}.{dom}" if sub else dom
        path = str(form.get("path") or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        route_type = str(form.get("route_type") or "proxy").strip().lower()
        if route_type == "redirect":
            target = str(form.get("redirect_target") or "").strip()
            code = str(form.get("redirect_code") or "302").strip() or "302"
            if host and target:
                try:
                    await _api_proxy_post("/api/routes", {"host": host, "path": path, "route_type": "redirect", "redirect_target": target, "redirect_code": int(code)})
                except Exception as e:
                    _slog("routing_create_failed", error=str(e))
        else:
            upstream = str(form.get("upstream") or "").strip()
            port = str(form.get("port") or form.get("port_visible") or "8080").strip() or "8080"
            try:
                p = int(port)
            except Exception:
                p = 8080
            if host and upstream and 1 <= p <= 65535:
                try:
                    await _api_proxy_post("/api/routes", {"host": host, "path": path, "route_type": "proxy", "upstream": upstream, "port": p})
                except Exception as e:
                    _slog("routing_create_failed", error=str(e))
        return RedirectResponse(url="/manage/routing", status_code=302)

    @app.post("/manage/routing/{rid}/edit", response_class=HTMLResponse)
    async def manage_routing_edit(request: Request, rid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        host = str(form.get("host") or "").strip().lower()
        if not host:
            sub = str(form.get("subdomain") or "").strip().lower()
            dom = str(form.get("domain") or "").strip().lower()
            if dom:
                host = f"{sub}.{dom}" if sub else dom
            else:
                for k in ("edit-redirect-host", "edit-host"):
                    v = str(form.get(k) or "").strip().lower()
                    if v:
                        host = v
                        break
        path = str(form.get("path") or "/").strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        route_type = str(form.get("route_type") or "proxy").strip().lower()
        payload: dict[str, Any] = {"host": host, "path": path, "route_type": route_type}
        if route_type == "redirect":
            payload["redirect_target"] = str(form.get("redirect_target") or "").strip()
            payload["redirect_code"] = str(form.get("redirect_code") or "302").strip() or "302"
        else:
            payload["upstream"] = str(form.get("upstream") or "").strip()
            payload["port"] = str(form.get("port") or form.get("port_visible") or "8080").strip() or "8080"
        try:
            client = _get_httpx()
            await client.put(f"http://api:8002/api/routes/{rid}", json=payload, headers=_api_headers(), timeout=5.0)
        except Exception as e:
            _slog("routing_edit_failed", error=str(e))
        return RedirectResponse(url="/manage/routing", status_code=302)

    @app.post("/manage/routing/{rid}/delete", response_class=HTMLResponse)
    async def manage_routing_delete(request: Request, rid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        try:
            client = _get_httpx()
            await client.delete(f"http://api:8002/api/routes/{rid}", headers=_api_headers(), timeout=5.0)
        except Exception:
            pass
        return RedirectResponse(url="/manage/routing", status_code=302)

    @app.post("/manage/routing/{rid}/test")
    async def manage_routing_test(request: Request, rid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        token = str(form.get("csrf_token") or request.headers.get("X-CSRF-Token") or "")
        if not _verify_csrf(request, token):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        result: dict[str, Any] = {}
        try:
            client = _get_httpx()
            r = await client.post(f"http://api:8002/api/routes/{rid}/test", headers=_api_headers(), timeout=5.0)
            result = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"ok": r.status_code == 200}
        except Exception as e:
            result = {"ok": False, "error": str(e)}
        if "application/json" in request.headers.get("Accept", ""):
            return JSONResponse(result)
        routes = await _api_proxy_get("/api/routes")
        return await _render_manage(request, "manage/routing.html", {"routes": routes if isinstance(routes, list) else [], "test_result": result, "tested_id": rid})

    @app.get("/manage/rules", response_class=HTMLResponse)
    async def manage_rules(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        groups = await _api_proxy_get("/api/groups")
        if not isinstance(groups, list):
            groups = []
        return await _render_manage(request, "manage/rules.html", {"groups": groups})

    @app.post("/manage/groups", response_class=HTMLResponse)
    async def manage_groups_create(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        name = str(form.get("name") or "").strip()
        domain = str(form.get("domain") or "").strip()
        if name and domain:
            try:
                await _api_proxy_post("/api/groups", {"name": name, "domain": domain})
            except Exception as e:
                _slog("group_create_failed", error=str(e))
        return RedirectResponse(url="/manage/rules", status_code=302)

    @app.post("/manage/groups/{gid}/delete", response_class=HTMLResponse)
    async def manage_groups_delete(request: Request, gid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        try:
            client = _get_httpx()
            await client.delete(f"http://api:8002/api/groups/{gid}", headers=_api_headers(), timeout=5.0)
        except Exception:
            pass
        return RedirectResponse(url="/manage/rules", status_code=302)

    @app.post("/manage/groups/{gid}/rules", response_class=HTMLResponse)
    async def manage_rules_create(request: Request, gid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        path = str(form.get("path") or "").strip()
        action = str(form.get("action") or "").strip()
        payload: dict[str, Any] = {"path": path, "action": action}
        if action == "custom_password":
            payload["custom_password"] = str(form.get("custom_password") or "").strip()
        try:
            await _api_proxy_post(f"/api/groups/{gid}/rules", payload)
        except Exception as e:
            _slog("rule_create_failed", error=str(e))
        return RedirectResponse(url=f"/manage/rules/{gid}", status_code=302)

    @app.post("/manage/rules/{rid}/delete", response_class=HTMLResponse)
    async def manage_rules_delete(request: Request, rid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        try:
            client = _get_httpx()
            await client.delete(f"http://api:8002/api/rules/{rid}", headers=_api_headers(), timeout=5.0)
        except Exception:
            pass
        referer = request.headers.get("Referer") or "/manage/rules"
        return RedirectResponse(url=referer, status_code=302)

    @app.post("/manage/rules/{rid}/edit", response_class=HTMLResponse)
    async def manage_rules_edit(request: Request, rid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        path = str(form.get("path") or "").strip()
        action = str(form.get("action") or "").strip()
        payload: dict[str, Any] = {}
        if path:
            payload["path"] = path
        if action:
            payload["action"] = action
            if action == "custom_password":
                pwd = str(form.get("custom_password") or "").strip()
                if pwd:
                    payload["custom_password"] = pwd
        try:
            client = _get_httpx()
            await client.put(f"http://api:8002/api/rules/{rid}", json=payload, headers=_api_headers(), timeout=5.0)
        except Exception as e:
            _slog("rule_edit_failed", error=str(e))
        referer = request.headers.get("Referer") or "/manage/rules"
        return RedirectResponse(url=referer, status_code=302)

    @app.get("/manage/rules/{gid}", response_class=HTMLResponse)
    async def manage_rules_detail(request: Request, gid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        groups = await _api_proxy_get("/api/groups")
        rules = await _api_proxy_get(f"/api/groups/{gid}/rules")
        cur = next((g for g in groups if isinstance(groups, list) and g.get("id") == gid), None) if isinstance(groups, list) else None
        return await _render_manage(request, "manage/rules_detail.html", {"group": cur, "rules": rules if isinstance(rules, list) else [], "gid": gid})

    @app.get("/manage/codes", response_class=HTMLResponse)
    async def manage_codes(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        codes = await _api_proxy_get("/api/codes")
        if not isinstance(codes, list):
            codes = []
        return await _render_manage(request, "manage/codes.html", {"codes": codes})

    @app.post("/manage/codes", response_class=HTMLResponse)
    async def manage_codes_create(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        label = str(form.get("label") or "").strip() or None
        code = str(form.get("code") or "").strip()
        if not code:
            raise HTTPException(status_code=400, detail="Access code required")
        payload: dict[str, Any] = {"code": code}
        if label:
            payload["label"] = label
            payload["display_name"] = label
        try:
            r = await _api_proxy_post("/api/codes", payload)
            if r.status_code >= 400:
                raise HTTPException(status_code=400, detail=r.text)
        except HTTPException:
            raise
        except Exception as e:
            _slog("codes_create_failed", error=str(e))
            raise HTTPException(status_code=400, detail=str(e))
        return RedirectResponse(url="/manage/codes", status_code=302)

    @app.post("/manage/codes/{cid}/revoke", response_class=HTMLResponse)
    async def manage_codes_revoke(request: Request, cid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        try:
            client = _get_httpx()
            await client.post(f"http://api:8002/api/codes/{cid}/revoke", headers=_api_headers(), timeout=5.0)
        except Exception:
            pass
        return RedirectResponse(url="/manage/codes", status_code=302)

    @app.post("/manage/codes/{cid}/edit", response_class=HTMLResponse)
    async def manage_codes_edit(request: Request, cid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        label = str(form.get("label") or "").strip() or None
        code = str(form.get("code") or "").strip() or None
        payload: dict[str, Any] = {}
        if label is not None:
            payload["label"] = label
            payload["display_name"] = label
        if code:
            payload["code"] = code
        if payload:
            try:
                client = _get_httpx()
                await client.put(f"http://api:8002/api/codes/{cid}", json=payload, headers=_api_headers(), timeout=5.0)
            except Exception as e:
                _slog("codes_edit_failed", error=str(e))
        return RedirectResponse(url="/manage/codes", status_code=302)

    @app.get("/manage/logs", response_class=HTMLResponse)
    async def manage_logs(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        params: dict[str, Any] = {}
        for k in ("ip", "host", "action", "endpoint", "from", "to", "page", "per_page"):
            v = request.query_params.get(k)
            if v:
                params[k] = v
        logs = await _api_proxy_get("/api/logs", params)
        if not isinstance(logs, list):
            logs = []
        return await _render_manage(request, "manage/logs.html", {"logs": logs, "filters": params})

    @app.get("/manage/top-pages", response_class=HTMLResponse)
    async def manage_top_pages(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        top = await _api_proxy_get("/api/logs/top", {"limit": 20})
        if not isinstance(top, list):
            top = []
        max_calls = max((x.get("calls", 0) for x in top), default=1)
        for x in top:
            x["percent"] = int((x.get("calls", 0) / max_calls * 100)) if max_calls else 0
        return await _render_manage(request, "manage/top_pages.html", {"pages": top})

    @app.get("/manage/warnings", response_class=HTMLResponse)
    async def manage_warnings(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        warnings = await _api_proxy_get("/api/warnings")
        if not isinstance(warnings, dict):
            warnings = {"groups": [], "rules": []}
        return await _render_manage(request, "manage/warnings.html", {"warnings": warnings})

    @app.get("/manage/settings", response_class=HTMLResponse)
    async def manage_settings(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        return await _render_manage(request, "manage/settings.html", {})

    @app.get("/manage/backup", response_class=HTMLResponse)
    async def manage_backup(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        return await _render_manage(request, "manage/backup.html", {})

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("management.app:app", host="0.0.0.0", port=8003, reload=get_config().is_debug)
