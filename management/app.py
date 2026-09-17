from __future__ import annotations

import json
import logging
import os
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
import jwt
from shared.jwt import create_access_token, create_custom_token, create_manage_token, decode_without_verify, verify_access_token, verify_custom_token, verify_manage_token
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from shared.client_ip import get_client_ip
from shared.config import get_config
from shared.models import Code
from shared.error_pages import render_error_html, wants_html
from shared.security import apex_domain as shared_apex, mask_code
from shared.settings_spec import (
    LOG_RETENTION_DAYS,
    MANAGE_FIELDS,
    default_value,
    validate_value,
)

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

    def _key_func(request: Request) -> str:
        return get_client_ip(request)

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


def _jwt_secret() -> str:
    return get_config().SECRET_KEY


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


def _api_headers() -> dict[str, str]:
    cfg = get_config()
    h: dict[str, str] = {"Content-Type": "application/json"}
    if cfg.INTERNAL_API_KEY:
        h["X-Internal-Api-Key"] = cfg.INTERNAL_API_KEY
    return h


def _api_base() -> str:
    import os
    return os.environ.get("API_HTTP_ADDR", "http://api:8002")


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


async def _verify_code_by_id(cid: int) -> Code | None:
    try:
        base = _api_base()
        client = _get_httpx()
        resp = await client.post(f"{base}/api/auth/verify-code-id", json={"cid": cid}, headers=_api_headers(), timeout=2.0)
        if resp.status_code != 200:
            return None
        data = resp.json()
        # data has code_id/label/display_name
        c = Code(code=data.get("code", ""), label=data.get("label"), display_name=data.get("display_name"))
        c.id = data.get("code_id", cid)  # type: ignore[attr-defined]
        c.active = True  # type: ignore[attr-defined]
        if not c.code:
            # fetch via /api/codes/{id} is public but need code value for mask — fetch from data["code"] if present
            # if api didn't return code, keep label/display_name
            c.code = "***"
        return c
    except Exception:
        return None


async def _get_authenticated_code(request: Request) -> Code | None:
    token = request.cookies.get("gatekeeper_token")
    if not token:
        return None
    data = verify_access_token(token)
    if not data:
        return None
    cid = data.get("cid")
    if cid is None:
        return None
    return await _verify_code_by_id(int(cid))


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
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com https://cdnjs.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self'; frame-src 'self' https://*.projectnova.download https://portfolio.projectnova.download; frame-ancestors 'self' https://portfolio.projectnova.download https://*.projectnova.download"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return resp


async def _require_manage_auth(request: Request) -> Response | None:
    """Check manage_session JWT. Returns redirect Response if unauthenticated, None if OK."""
    cfg = get_config()
    pw = cfg.MANAGE_PASSWORD
    if not pw:
        raise HTTPException(status_code=500, detail="MANAGE_PASSWORD not configured")
    token = request.cookies.get("manage_session")
    if not token:
        return _manage_auth_redirect(request)
    data = verify_manage_token(token)
    if not data:
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


async def _api_proxy_put(path: str, payload: dict[str, Any]) -> Any:
    url = f"http://api:8002{path}"
    client = _get_httpx()
    r = await client.put(url, json=payload, headers=_api_headers(), timeout=5.0)
    return r


#: The word an operator types before a configuration replace goes ahead.
RESTORE_CONFIRM = "REPLACE"

#: The word an operator types before audit rows are deleted.
PRUNE_CONFIRM = "PRUNE"

#: Counts shown on the backup page, keyed the same way the export is.
BACKUP_SECTIONS = ("routes", "groups", "rules", "codes", "settings")


def _submitted_settings(form: Any) -> dict[str, str]:
    """The submitted form as `{key: value}` for keys this panel owns.

    The last occurrence of a key wins, which is what makes a checkbox usable: the
    template puts a hidden `false` before the box, so a browser sends `false` when
    it is unchecked and `false,true` when it is checked, and the later value is
    the one that reflects the operator's decision.

    A key the browser did not send at all is left out entirely, so a partial form
    cannot blank a setting it never showed. Keys outside `MANAGE_FIELDS` are
    dropped, so a crafted post cannot reach a setting this page does not own.
    """
    out: dict[str, str] = {}
    for key in MANAGE_FIELDS:
        try:
            values = form.getlist(key)
        except AttributeError:  # a plain dict, as in the unit tests
            raw = form.get(key)
            values = [] if raw is None else [raw]
        if not values:
            continue
        out[key] = str(values[-1])
    return out


def _environment_panel() -> dict[str, Any]:
    """Read-only facts about the running process.

    A secret is reported only as configured or not: reading the value to report
    anything richer would put it in this process for a question a boolean
    already answers, and it would then be one template mistake away from the
    page.
    """
    config = get_config()
    return {
        "deployment_type": config.DEPLOYMENT_TYPE,
        "db_backend": config.db_url.split("://", 1)[0].split("+", 1)[0].lower() or "sqlite",
        "db_is_override": bool(config.DATABASE_URL),
        "internal_api_key_set": bool(config.INTERNAL_API_KEY),
        "secret_key_set": bool(config.SECRET_KEY),
    }


def _retention_source(stored: dict[str, str]) -> str:
    """Where the retention window actually comes from, in the panel's words."""
    if LOG_RETENTION_DAYS in stored:
        return "stored setting"
    return "LOG_RETENTION_DAYS environment variable" if os.environ.get("LOG_RETENTION_DAYS") else "built-in default"


async def _settings_context(errors: list[str] | None = None) -> dict[str, Any]:
    """Everything the settings page renders: current values and the environment."""
    settings = await _api_proxy_get("/api/settings")
    if not isinstance(settings, list):
        settings = []
    stored = {str(s.get("key")): str(s.get("value")) for s in settings if isinstance(s, dict)}
    environment = _environment_panel()
    environment["log_retention_source"] = _retention_source(stored)
    return {
        "values": {key: stored.get(key, default_value(key)) for key in MANAGE_FIELDS},
        "errors": errors or [],
        "environment": environment,
        "stored_keys": sorted(stored),
        "confirm_word": PRUNE_CONFIRM,
    }


async def _backup_context(
    verdict: dict[str, Any] | None = None,
    stage: str = "",
    error: str = "",
) -> dict[str, Any]:
    """What the backup page renders: current counts and the last export time."""
    counts = {section: 0 for section in BACKUP_SECTIONS}
    groups = await _api_proxy_get("/api/groups")
    counts["groups"] = len(groups) if isinstance(groups, list) else 0
    rules = 0
    if isinstance(groups, list):
        for g in groups:
            rows = await _api_proxy_get(f"/api/groups/{g.get('id')}/rules")
            if isinstance(rows, list):
                rules += len(rows)
    counts["rules"] = rules
    for section, path in (("routes", "/api/routes"), ("codes", "/api/codes")):
        rows = await _api_proxy_get(path)
        counts[section] = len(rows) if isinstance(rows, list) else 0
    settings = await _api_proxy_get("/api/settings")
    counts["settings"] = len(settings) if isinstance(settings, list) else 0
    last_export = None
    if isinstance(settings, list):
        last_export = next(
            (s.get("value") for s in settings if s.get("key") == "backup_exported_at"), None
        )
    return {
        "counts": counts,
        "last_export": last_export,
        "verdict": verdict,
        "stage": stage,
        "error": error,
        "confirm_word": RESTORE_CONFIRM,
    }


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

    def _set_auth_cookie(resp: Response, code: Code, apex: str) -> None:
        token = create_access_token(code.id, code.display_name or code.label or "User")
        resp.set_cookie(key="gatekeeper_token", value=token, domain=f".{apex}", path="/", httponly=True, samesite="lax", secure=True, max_age=43200)

    def _set_auth_cookie_raw(resp: Response, code: Code, apex: str) -> None:
        _set_auth_cookie(resp, code, apex)

    def _set_manage_session_cookie(resp: Response) -> None:
        token = create_manage_token()
        resp.set_cookie(key="manage_session", value=token, path="/manage", httponly=True, samesite="lax", secure=True, max_age=8 * 3600)

    def _clear_auth_cookie(resp: Response, apex: str) -> None:
        resp.delete_cookie(key="gatekeeper_token", domain=f".{apex}", path="/")
        resp.delete_cookie(key="gatekeeper_token", path="/")

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

    @app.get("/logout")
    async def gate_logout_get(request: Request) -> Response:
        apex = _apex_from_request(request)
        resp = RedirectResponse(url="/login", status_code=302)
        _clear_auth_cookie(resp, apex)
        return resp

    @app.post("/logout")
    @limiter.limit("10/minute")
    async def gate_logout_post(request: Request) -> Response:
        apex = _apex_from_request(request)
        form = await request.form() if request.headers.get("content-type", "").startswith("application/x-www-form") else {}
        tok = str(form.get("csrf_token") if hasattr(form, "get") else "" or "")
        if request.method == "POST" and not same_origin(request, apex):
            if not _verify_csrf(request, tok):
                return JSONResponse(status_code=403, content={"detail": "Cross-site request rejected"})
        if tok and not _verify_csrf(request, tok):
            return JSONResponse(status_code=403, content={"detail": "Invalid CSRF"})
        resp = RedirectResponse(url="/login", status_code=302)
        _clear_auth_cookie(resp, apex)
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
        # expiry hint for status card
        exp_label = "12h"
        try:
            tok = request.cookies.get("gatekeeper_token", "")
            payload = decode_without_verify(tok) if tok else None
            exp = payload.get("exp") if payload else None
            if exp:
                import datetime as _dt
                exp_dt = _dt.datetime.fromtimestamp(int(exp), tz=_dt.timezone.utc)
                delta = exp_dt - _dt.datetime.now(_dt.timezone.utc)
                hrs = max(0, int(delta.total_seconds() // 3600))
                mins = max(0, int((delta.total_seconds() % 3600) // 60))
                if hrs > 0:
                    exp_label = f"{hrs}h {mins}m" if mins else f"{hrs}h"
                else:
                    exp_label = f"{mins}m"
        except Exception:
            pass
        apex = _apex_from_request(request)
        resp = templates.TemplateResponse(request, "landing.html", {"request": request, "name": name, "masked_code": masked, "code": code, "csrf_token": csrf, "exp_label": exp_label, "apex": apex})
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
            tp = _us(redirect_target)
            th = (tp.hostname or "").lower()
            tpa = tp.path or "/"
            if th:
                # API-only: ask api to check custom rule via verify-custom (best-effort, no code yet)
                # for login page decoration we do a lightweight probe: try verify-custom with dummy code
                # Instead fetch groups via API and check locally without DB
                base = _api_base()
                client = _get_httpx()
                g_resp = await client.get(f"{base}/api/groups", headers=_api_headers(), timeout=2.0)
                if g_resp.status_code == 200:
                    from shared.security import host_matches as _hm2, path_matches as _pm2
                    for grow in g_resp.json():
                        if not _hm2(grow.get("domain", ""), th):
                            continue
                        gid = grow.get("id")
                        r_resp = await client.get(f"{base}/api/groups/{gid}/rules", headers=_api_headers(), timeout=2.0)
                        if r_resp.status_code == 200:
                            for rrow in r_resp.json():
                                if _pm2(rrow.get("path", "/"), tpa) and rrow.get("action") == "custom_password":
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
            _set_auth_cookie(resp, row, apex)
            return resp
        try:
            from urllib.parse import urlsplit as _urlsplit
            target_parts = _urlsplit(redirect_target)
            thost = (target_parts.hostname or "").lower() or _apex_from_request(request).lower()
            tpath = target_parts.path or "/"
            if not thost:
                thost = _apex_from_request(request)
            base = _api_base()
            client = _get_httpx()
            vresp = await client.post(f"{base}/api/auth/verify-custom", json={"code": code_val, "host": thost, "path": tpath}, headers=_api_headers(), timeout=2.0)
            if vresp.status_code == 200:
                rid = vresp.json().get("rule_id")
                tok = create_custom_token(int(rid))
                if not _safe_redirect_target(redirect_target, apex):
                    redirect_target = "/"
                resp = RedirectResponse(url=redirect_target, status_code=302)
                resp.set_cookie(key=f"gatekeeper_custom_{rid}", value=tok, domain=f".{apex}", path="/", httponly=True, samesite="lax", secure=True, max_age=43200)
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

    async def _render_manage(request: Request, template: str, ctx: dict[str, Any] | None = None, status_code: int = 200) -> Response:
        auth_resp = await _require_manage_auth(request)
        if auth_resp is not None:
            return auth_resp
        csrf = _get_csrf_token(request)
        base_ctx: dict[str, Any] = {"request": request, "csrf_token": csrf}
        if ctx:
            base_ctx.update(ctx)
        resp = templates.TemplateResponse(request, template, base_ctx, status_code=status_code)
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
        codes = await _api_proxy_get("/api/codes", {"include_inactive": "true"})
        warnings = await _api_proxy_get("/api/warnings")
        recent = await _api_proxy_get("/api/logs", {"per_page": 10})
        top = await _api_proxy_get("/api/logs/top", {"limit": 5})

        routes = routes if isinstance(routes, list) else []
        groups = groups if isinstance(groups, list) else []
        codes = codes if isinstance(codes, list) else []
        recent = recent if isinstance(recent, list) else []
        top = top if isinstance(top, list) else []

        active_codes = [c for c in codes if c.get("active")]
        # `/api/groups` reports only `rules_count`, so the catch-all census needs
        # one rules call per group. The panel already does this on the backup
        # page for the same reason, and the group count is small.
        catch_alls = 0
        for g in groups:
            rows = await _api_proxy_get(f"/api/groups/{g.get('id')}/rules")
            if isinstance(rows, list):
                catch_alls += sum(1 for r in rows if r.get("path") == "/*")
        last_used = max(
            (str(c.get("last_accessed")) for c in codes if c.get("last_accessed")),
            default=None,
        )
        stats = {
            "routes": len(routes),
            "groups": len(groups),
            "codes_total": len(codes),
            "codes_active": len(active_codes),
            "codes_inactive": len(codes) - len(active_codes),
            "catch_alls": catch_alls,
        }
        max_calls = max((x.get("calls", 0) for x in top), default=0)
        for x in top:
            x["percent"] = int(x.get("calls", 0) / max_calls * 100) if max_calls else 0
        return await _render_manage(
            request,
            "manage/dashboard.html",
            {
                "stats": stats,
                "warnings": warnings,
                "recent": recent,
                "top": top,
                "last_used": last_used,
            },
        )

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

    @app.post("/manage/rules/{rid}/order", response_class=HTMLResponse)
    async def manage_rules_order(request: Request, rid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        direction = str(form.get("direction") or "").strip().lower()
        if direction not in ("up", "down"):
            raise HTTPException(status_code=400, detail="direction must be up|down")
        referer = request.headers.get("Referer") or "/manage/rules"
        try:
            r = await _api_proxy_put(f"/api/rules/{rid}/order", {"direction": direction})
            if r.status_code >= 400:
                _slog(
                    "rule_order_refused",
                    rid=rid,
                    direction=direction,
                    status=r.status_code,
                    detail=r.text[:200],
                )
        except Exception as e:
            _slog("rule_order_failed", rid=rid, direction=direction, error=str(e))
        return RedirectResponse(url=referer, status_code=302)

    @app.post("/manage/groups/{gid}/edit", response_class=HTMLResponse)
    async def manage_groups_edit(request: Request, gid: int) -> Response:
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
        payload: dict[str, Any] = {}
        if name:
            payload["name"] = name
        if domain:
            payload["domain"] = domain
        referer = request.headers.get("Referer") or "/manage/rules"
        try:
            r = await _api_proxy_put(f"/api/groups/{gid}", payload)
            if r.status_code >= 400:
                _slog(
                    "group_edit_refused",
                    gid=gid,
                    status=r.status_code,
                    detail=r.text[:200],
                )
        except Exception as e:
            _slog("group_edit_failed", gid=gid, error=str(e))
        return RedirectResponse(url=referer, status_code=302)

    @app.post("/manage/groups/{gid}/order", response_class=HTMLResponse)
    async def manage_groups_order(request: Request, gid: int) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        direction = str(form.get("direction") or "").strip().lower()
        if direction not in ("up", "down"):
            raise HTTPException(status_code=400, detail="direction must be up|down")
        referer = request.headers.get("Referer") or "/manage/rules"
        try:
            r = await _api_proxy_put(f"/api/groups/{gid}/order", {"direction": direction})
            if r.status_code >= 400:
                _slog(
                    "group_order_refused",
                    gid=gid,
                    direction=direction,
                    status=r.status_code,
                    detail=r.text[:200],
                )
        except Exception as e:
            _slog("group_order_failed", gid=gid, direction=direction, error=str(e))
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
        include_inactive = str(request.query_params.get("include_inactive") or "").lower() in (
            "1",
            "true",
            "yes",
        )
        codes = await _api_proxy_get(
            "/api/codes", params={"include_inactive": "true"} if include_inactive else None
        )
        if not isinstance(codes, list):
            codes = []
        active_codes = await _api_proxy_get("/api/codes")
        active_count = len(active_codes) if isinstance(active_codes, list) else 0
        return await _render_manage(
            request,
            "manage/codes.html",
            {
                "codes": codes,
                "include_inactive": include_inactive,
                "active_count": active_count,
                "inactive_count": max(len(codes) - active_count, 0),
            },
        )

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

    @app.post("/manage/codes/{cid}/active", response_class=HTMLResponse)
    async def manage_codes_active(request: Request, cid: int) -> Response:
        """Deactivate or reactivate a code. Reversible, so one confirm is enough."""
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        active = str(form.get("active") or "").strip().lower() in ("1", "true", "yes")
        try:
            r = await _api_proxy_put(f"/api/codes/{cid}", {"active": active})
            if r.status_code >= 400:
                _slog("codes_active_refused", cid=cid, status=r.status_code, detail=r.text[:200])
        except Exception as e:
            _slog("codes_active_failed", cid=cid, error=str(e))
        return RedirectResponse(url="/manage/codes", status_code=302)

    @app.post("/manage/codes/{cid}/delete", response_class=HTMLResponse)
    async def manage_codes_delete(request: Request, cid: int) -> Response:
        """Permanently delete a code, confirmed against the stored value.

        The typed confirmation is checked here, against the code read back from
        the API, and only then is the delete issued. A modal alone would be
        decoration: it cannot stop a stale tab, a replayed form post or a
        script, and this is the one action with nothing behind it.
        """
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        supplied = str(form.get("confirm_code") or "")
        try:
            current = await _api_proxy_get(f"/api/codes/{cid}")
        except Exception as e:
            _slog("codes_delete_lookup_failed", cid=cid, error=str(e))
            raise HTTPException(status_code=502, detail="could not read the code") from e
        if not isinstance(current, dict) or current.get("code") is None:
            raise HTTPException(status_code=404, detail="not found")
        if not secrets.compare_digest(supplied, str(current["code"])):
            _slog("codes_delete_refused", cid=cid, reason="confirm mismatch")
            raise HTTPException(status_code=400, detail="confirm_code does not match")
        try:
            client = _get_httpx()
            r = await client.delete(
                f"http://api:8002/api/codes/{cid}", headers=_api_headers(), timeout=5.0
            )
            if r.status_code >= 400:
                _slog("codes_delete_refused", cid=cid, status=r.status_code, detail=r.text[:200])
                raise HTTPException(status_code=r.status_code, detail="delete refused")
        except HTTPException:
            raise
        except Exception as e:
            _slog("codes_delete_failed", cid=cid, error=str(e))
            raise HTTPException(status_code=502, detail="delete failed") from e
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
        for k in ("ip", "host", "action", "endpoint", "from", "to", "page", "per_page", "code"):
            v = request.query_params.get(k)
            if v:
                params[k] = v
        accept = request.headers.get("accept", "").lower()
        is_json = request.query_params.get("format") == "json" or "application/json" in accept
        if is_json:
            client = _get_httpx()
            r = await client.get("http://api:8002/api/logs", params=params, headers=_api_headers(), timeout=5.0)
            try:
                body = r.json()
            except Exception:
                body = []
            return JSONResponse({"logs": body if isinstance(body, list) else [], "total": int(r.headers.get("X-Total-Count", "0") or "0")})
        logs = await _api_proxy_get("/api/logs", params)
        if not isinstance(logs, list):
            logs = []
        return await _render_manage(request, "manage/logs.html", {"logs": logs, "filters": params})

    @app.get("/manage/audit", response_class=HTMLResponse)
    async def manage_audit(request: Request) -> Response:
        """Per-visitor view: which IP saw which pages, with which code."""
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        limit = request.query_params.get("limit", "50")
        data = await _api_proxy_get("/api/logs/by-ip", {"limit": limit})
        if not isinstance(data, list):
            data = []
        return await _render_manage(request, "manage/audit.html", {"items": data})

    @app.get("/manage/monitoring", response_class=HTMLResponse)
    async def manage_monitoring_alias(request: Request) -> Response:
        """The old address, kept as a redirect so existing bookmarks still land."""
        return RedirectResponse(url="/manage/audit", status_code=302)

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

    @app.get("/manage/settings", response_class=HTMLResponse)
    async def manage_settings(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        return await _render_manage(request, "manage/settings.html", await _settings_context())

    @app.post("/manage/settings", response_class=HTMLResponse)
    async def manage_settings_post(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        # One `PUT` per changed field, and only for keys this panel owns. A field
        # the browser did not send is left alone, so a partial form cannot blank
        # a setting it never showed.
        errors: list[str] = []
        for key, raw in _submitted_settings(form).items():
            try:
                value = validate_value(key, raw)
            except ValueError as e:
                errors.append(f"{key}: {e}")
                continue
            await _api_proxy_put(f"/api/settings/{key}", {"value": value})
        if errors:
            ctx = await _settings_context()
            ctx["errors"] = errors
            return await _render_manage(request, "manage/settings.html", ctx, status_code=400)
        return RedirectResponse(url="/manage/settings", status_code=302)

    @app.post("/manage/logs/prune", response_class=HTMLResponse)
    async def manage_logs_prune(request: Request) -> Response:
        """Delete audit rows past the retention window, on demand.

        The only way to prune without restarting the API, and it always asks for
        the confirmation word first: this deletes history with no undo.
        """
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        if str(form.get("confirm") or "").strip() != PRUNE_CONFIRM:
            raise HTTPException(status_code=403, detail=f"Type {PRUNE_CONFIRM} to confirm")
        client = _get_httpx()
        try:
            r = await client.post("http://api:8002/api/logs/prune", headers=_api_headers(), timeout=60.0)
            verdict = r.json()
        except Exception as e:
            _slog("logs_prune_failed", error=str(e))
            verdict = {"ok": False, "detail": "prune failed"}
        if not isinstance(verdict, dict):
            verdict = {"ok": False, "detail": "prune failed"}
        ctx = await _settings_context()
        ctx["prune"] = verdict
        return await _render_manage(request, "manage/settings.html", ctx)

    @app.get("/manage/backup", response_class=HTMLResponse)
    async def manage_backup(request: Request) -> Response:
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        return await _render_manage(request, "manage/backup.html", await _backup_context())

    @app.get("/manage/backup/download")
    async def manage_backup_download(request: Request) -> Response:
        """Stream the API's signed export straight through, byte for byte."""
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        client = _get_httpx()
        try:
            r = await client.get("http://api:8002/api/backup", headers=_api_headers(), timeout=30.0)
        except Exception as e:
            _slog("backup_download_failed", error=str(e))
            raise HTTPException(status_code=502, detail="backup export failed") from e
        if r.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"backup export failed ({r.status_code})")
        disposition = r.headers.get("content-disposition")
        fallback = "attachment; filename=gatekeeper-config.json"
        headers = {"Content-Disposition": disposition or fallback}
        return Response(content=r.content, media_type="application/json", headers=headers)

    @app.post("/manage/backup/restore", response_class=HTMLResponse)
    async def manage_backup_restore(request: Request) -> Response:
        """Two-step restore: preview the verdict, then apply it."""
        _auth = await _require_manage_auth(request)
        if _auth is not None:
            return _auth
        form = await request.form()
        if not _verify_csrf(request, str(form.get("csrf_token") or "")):
            raise HTTPException(status_code=403, detail="Invalid CSRF")
        if not same_origin(request):
            raise HTTPException(status_code=403, detail="Cross-site")
        if str(form.get("confirm") or "").strip() != RESTORE_CONFIRM:
            raise HTTPException(status_code=403, detail=f"Type {RESTORE_CONFIRM} to confirm")
        stage = str(form.get("stage") or "preview").strip().lower()
        if stage not in ("preview", "apply"):
            raise HTTPException(status_code=400, detail="stage must be preview or apply")
        upload = form.get("file")
        raw = await upload.read() if upload is not None and hasattr(upload, "read") else b""
        if not raw:
            return await _render_manage(
                request,
                "manage/backup.html",
                await _backup_context(error="Choose a backup file first"),
            )
        try:
            blob = json.loads(raw.decode("utf-8"))
        except Exception:
            blob = None
        if not isinstance(blob, dict) or "config" not in blob:
            return await _render_manage(
                request,
                "manage/backup.html",
                await _backup_context(error="That file is not a GateKeeper backup"),
            )
        client = _get_httpx()
        try:
            r = await client.post(
                "http://api:8002/api/backup/restore",
                params={"dry_run": 1} if stage == "preview" else None,
                json=blob,
                headers=_api_headers(),
                timeout=30.0,
            )
            verdict = r.json()
        except Exception as e:
            _slog("backup_restore_failed", error=str(e))
            verdict = {
                "ok": False,
                "sig": False,
                "problems": ["The API could not be reached"],
                "counts": {},
            }
        _slog("backup_restore", stage=stage, ok=verdict.get("ok"))
        return await _render_manage(
            request, "manage/backup.html", await _backup_context(verdict=verdict, stage=stage)
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("management.app:app", host="0.0.0.0", port=8003, reload=get_config().is_debug)
