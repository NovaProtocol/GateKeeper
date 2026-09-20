from __future__ import annotations

import csv
import datetime as dt
import io
import json
import logging
import secrets
import socket
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from shared.backup import SECTIONS, apply_backup, build_backup, config_warnings
from shared.backup import validate as validate_backup
from shared.backup import verify as verify_backup
from shared.config import get_config
from shared.middleware import CacheControlMiddleware
from shared.db import Base, get_db, get_engine, get_sessionmaker
from shared.gate import _is_active as rule_is_active
from shared.geo import (
    BLOCKED_ACTIONS,
    DEFAULT_GEO_MODE,
    GEO_MODES,
    build_points,
    normalize_country,
)
from shared.models import AuditLog, Code, CustomPage, Route, Rule, RuleGroup, Setting
from shared.pages import (
    DEFAULT_PAGE_CONTENT_TYPE as pages_default_content_type,
)
from shared.pages import (
    PAGE_BODY_MAX as pages_body_max,
)
from shared.pages import validate_content_type, validate_pattern
from shared.rule_defaults import (
    CATCH_ALL,
    add_is_default_column,
    add_rule_active_column,
    apply_rule_defaults,
    invariant_problems,
)
from shared.rule_defaults import DEFAULT_ACTION as DEFAULT_CATCH_ALL_ACTION
from shared.rule_defaults import load as rule_defaults_load
from shared.settings_spec import (
    LOG_RETENTION_DAYS,
    MANAGE_FIELDS,
    RETENTION_MAX,
    RETENTION_MIN,
    SETTING_SPECS,
    as_int,
    default_value,
    validate_value,
)
from shared.security import (
    hash_custom_password,
    host_matches,
    is_valid_host,
    path_matches,
)

try:
    import structlog

    def _log(msg: str, **kw: Any) -> None:
        structlog.get_logger().info(msg, **kw)

    structlog.configure(
        processors=[structlog.processors.JSONRenderer()] if hasattr(structlog.processors, "JSONRenderer") else [],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )
except Exception:
    logging.basicConfig(level=logging.INFO)

    def _log(msg: str, **kw: Any) -> None:
        logging.getLogger("api").info("%s %s", msg, kw)


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = rid
        _log("request", method=request.method, path=request.url.path, request_id=rid)
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        return resp


async def _require_internal(x_internal_api_key: str | None = Header(default=None, alias="X-Internal-Api-Key")) -> None:
    cfg = get_config()
    if cfg.INTERNAL_API_KEY and x_internal_api_key != cfg.INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="invalid internal api key")


def _glob_to_like(pat: str) -> str:
    pat = pat.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return pat.replace("*", "%").replace("?", "_")


def _sample_host(domain: str) -> str:
    d = domain.split("/")[0].strip()
    if d in ("*.*", "*.*/*"):
        return "foo.example.com"
    if d.startswith("*."):
        return "test." + d[2:]
    return d


def _sample_path(path: str) -> str:
    if path.endswith("/*"):
        p = path[:-2] or "/"
        return p.rstrip("/") + "/x" if p != "/" else "/x"
    return path


def probe_upstream(upstream: str | None, port: int | None, timeout: float = 2.0) -> dict[str, Any]:
    """Is something listening on ``upstream:port``? Answered, never raised.

    Shared by the saved-route test and the pre-save test so the two cannot drift
    into giving different verdicts about the same pair. A refusal is data, not an
    error: the caller is asking a question and "no" is a valid answer, which is
    why the caller returns 200 with ``ok: false`` rather than a 4xx.

    The probe is a TCP connect and nothing more. It sends no request, reads no
    response and does not distinguish one service from another, so it can say
    "something is listening there" and never "that is the right application".
    """
    if not upstream:
        return {"ok": False, "error": "no upstream"}
    try:
        probe_port = int(port) if port is not None else 0
    except (TypeError, ValueError):
        return {"ok": False, "error": "port must be a number"}
    if not (1 <= probe_port <= 65535):
        return {"ok": False, "error": "port must be 1-65535"}
    try:
        sock = socket.create_connection((upstream, probe_port), timeout=timeout)
        sock.close()
        return {"ok": True, "latency": "reachable"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def probe_redirect_target(target: str | None) -> dict[str, Any]:
    """Can a redirect target be used? A URL needs a resolvable host, a path does not.

    Same shape and the same "never raise" contract as :func:`probe_upstream`, and
    shared with the saved-route variant for the same reason.
    """
    text = (target or "").strip()
    if not text:
        return {"ok": False, "error": "no target"}
    if text.startswith("http://") or text.startswith("https://"):
        try:
            from urllib.parse import urlsplit

            host = urlsplit(text).hostname or ""
            if host:
                socket.getaddrinfo(host, None)
            return {"ok": True, "note": "redirect target ok"}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": True, "note": "redirect path ok"}


def validate_route_shape(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise and validate a route payload, for the pre-save probe.

    Mirrors ``create_route``'s rules so the test button refuses the same shapes
    the save would, and returns the same normalised fields. Raising the same
    ``HTTPException`` codes means the modal reports a validation failure and a
    save failure identically, which is the point of testing before saving.
    """
    route_type = str(payload.get("route_type", "proxy")).strip().lower()
    if route_type not in ("proxy", "redirect"):
        raise HTTPException(status_code=400, detail="route_type must be proxy or redirect")
    if route_type == "proxy":
        upstream = str(payload.get("upstream", "")).strip()
        if not upstream:
            raise HTTPException(status_code=400, detail="upstream (container name) required")
        raw_port = payload.get("port", 8080)
        try:
            port = int(str(raw_port).strip() or 8080)
        except Exception:
            # The ValueError is not the useful part of this; the caller is told
            # what is wrong with the port instead.
            raise HTTPException(status_code=400, detail="port must be a number") from None
        if not (1 <= port <= 65535):
            raise HTTPException(status_code=400, detail="port must be 1-65535")
        return {"route_type": "proxy", "upstream": upstream, "port": port}
    target = str(payload.get("redirect_target", "")).strip()
    if not target:
        raise HTTPException(status_code=400, detail="redirect_target required")
    return {"route_type": "redirect", "redirect_target": target}


def _parse_active(raw: Any) -> bool | None:
    """Read an `active` payload value. Returns None when it is not one.

    Accepts booleans and the `true`/`false`/`1`/`0` spellings, as strings or
    numbers, with the same leniency `PUT /api/codes/{cid}` already has: the panel
    posts a form value, other callers send JSON, and every spelling has to reach
    the same column. Anything else is refused rather than guessed at.
    """
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str) and raw.strip().lower() in ("true", "false", "1", "0"):
        return raw.strip().lower() in ("true", "1")
    if isinstance(raw, int):
        return bool(raw)
    return None


def _guard_catch_all_active(obj: Rule, active: bool | None) -> None:
    """Refuse switching the catch-all off.

    Sits beside `cannot delete default rule` / `cannot move default rule` /
    `cannot change default rule path`, and for the same reason: the catch-all is
    the group's fallback decision. Deactivating it would leave every path in the
    group that a narrower rule does not name refused, so one switch could make a
    whole host answer nothing. `invariant_problems` reports the state if it ever
    arrives by another route; this is what stops it being produced here.
    """
    if active is False and obj.is_default:
        raise HTTPException(status_code=400, detail="the catch-all cannot be deactivated")


def _shadowed_warnings(groups: list[RuleGroup]) -> dict[str, Any]:
    groups_sorted = sorted(groups, key=lambda g: g.display_order)
    shadowed_groups: list[dict[str, Any]] = []
    shadowed_rules: list[dict[str, Any]] = []
    for idx, g in enumerate(groups_sorted):
        if g.is_default:
            continue
        sh: RuleGroup | None = None
        for j in range(idx):
            ug = groups_sorted[j]
            if host_matches(ug.domain, _sample_host(g.domain)):
                has_catch = any(r.path == "/*" for r in ug.rules)
                if has_catch:
                    sh = ug
                    break
        if sh:
            shadowed_groups.append({"id": g.id, "name": g.name, "shadowed_by": sh.id, "reason": f"host covered by {sh.name} /*"})
    for g in groups_sorted:
        rules_sorted = sorted(g.rules, key=lambda r: r.display_order)
        for i, r in enumerate(rules_sorted):
            for j in range(i):
                ur = rules_sorted[j]
                # An inactive rule shadows nothing: it is skipped by resolution,
                # so the rule below it still fires. Reporting one as a shadow is
                # the false alarm this list exists to avoid. The subject is still
                # checked, though, an inactive rule that *is* shadowed cannot
                # take effect even after it is switched back on, which is worth
                # knowing.
                if not rule_is_active(ur):
                    continue
                if path_matches(ur.path, _sample_path(r.path)) or ur.path == "/*":
                    shadowed_rules.append({"id": r.id, "path": r.path, "group_id": g.id, "shadowed_by": ur.id, "reason": f"shadowed by {ur.path}"})
                    break
    for sg in shadowed_groups:
        gid = sg["id"]
        for r in next((x.rules for x in groups_sorted if x.id == gid), []):
            if not any(sr["id"] == r.id for sr in shadowed_rules):
                shadowed_rules.append({"id": r.id, "path": r.path, "group_id": gid, "shadowed_by": sg["shadowed_by"], "reason": "group shadowed"})
    return {"groups": shadowed_groups, "rules": shadowed_rules}


#: The response type a page carries unless it says otherwise, and the largest body
#: it may carry. Both are read from :mod:`shared.pages` so the endpoint, the
#: backup validator and the gateway cannot drift apart about either.
DEFAULT_PAGE_CONTENT_TYPE = pages_default_content_type
PAGE_BODY_MAX = pages_body_max


def _validate_page_pattern(pattern: str) -> None:
    """Refuse a pattern that cannot describe a URL, naming the reason."""
    try:
        validate_pattern(pattern)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def _validate_page_content_type(content_type: str) -> None:
    """A response type, and never a header injection.

    It becomes a response header, so a CR or LF in it is response splitting
    rather than a formatting mistake. The shape check keeps a typo out of the
    stored value; `nosniff` makes the stored value authoritative downstream.
    """
    try:
        validate_content_type(content_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


def _validate_page_body(body: str) -> None:
    if len(body) > PAGE_BODY_MAX:
        raise HTTPException(
            status_code=400,
            detail=(
                f"body must be {PAGE_BODY_MAX // 1024} KiB "
                f"({PAGE_BODY_MAX} characters) or fewer"
            ),
        )


def _page_json(p: Any) -> dict[str, Any]:
    """One page as the API reports it, in the gate's own field names."""
    return {
        "id": p.id,
        "pattern": p.pattern,
        "body": p.body,
        "content_type": p.content_type or DEFAULT_PAGE_CONTENT_TYPE,
        "active": bool(p.active),
        "display_order": p.display_order,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    }


def _parse_dt(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            continue
    return None


def _migrate_audit(sync_conn: Any) -> None:
    """Add the audit columns a live table may be missing, guarded and idempotent.

    Module level rather than a closure inside the lifespan so the same function
    the app runs at boot can be run against a throwaway database in a test. The
    pattern is unchanged from the original inline version: `PRAGMA table_info`
    first, then `ALTER TABLE ... ADD COLUMN` only for what is absent, inside a
    `try/except` that never stops the API from starting.

    No backfill. A row written before a column existed keeps a NULL in it, which
    is honest: for `country` it means "recorded before this was captured", and
    inventing a value from the address would be a guess stored as a record.
    """
    try:
        res = sync_conn.execute(text("PRAGMA table_info(audit_logs)"))
        cols = {row[1] for row in res.fetchall()}
        if "method" not in cols:
            sync_conn.execute(text("ALTER TABLE audit_logs ADD COLUMN method VARCHAR(10)"))
        if "status_code" not in cols:
            sync_conn.execute(text("ALTER TABLE audit_logs ADD COLUMN status_code INTEGER"))
        if "attempted_code" not in cols:
            sync_conn.execute(text("ALTER TABLE audit_logs ADD COLUMN attempted_code VARCHAR(64)"))
        # Country only, and no backfill: rows written before this column existed
        # stay NULL and are reported as Unknown.
        if "country" not in cols:
            sync_conn.execute(text("ALTER TABLE audit_logs ADD COLUMN country VARCHAR(2)"))
        if "ip" in cols:
            sync_conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_logs_ip ON audit_logs (ip)"))
        if "action" in cols:
            sync_conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs (action)")
            )
        # Re-read rather than testing the set above: `cols` predates the ALTER, so
        # on the first boot it does not yet contain `country` and the index would
        # silently not be created until the next restart.
        added = {
            row[1]
            for row in sync_conn.execute(text("PRAGMA table_info(audit_logs)")).fetchall()
        }
        if "country" in added:
            sync_conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_audit_logs_country ON audit_logs (country)")
            )
    except Exception:
        pass
    try:
        sync_conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS settings "
                "(key VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL, "
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
            )
        )
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        def _migrate_routes(sync_conn):  # type: ignore[no-untyped-def]
            try:
                res = sync_conn.execute(text("PRAGMA table_info(routes)"))
                rows = res.fetchall()
                cols = {row[1]: row for row in rows}
                need_rebuild = False
                if "path" not in cols:
                    sync_conn.execute(text("ALTER TABLE routes ADD COLUMN path VARCHAR(1024) DEFAULT '/'"))
                if "route_type" not in cols:
                    sync_conn.execute(text("ALTER TABLE routes ADD COLUMN route_type VARCHAR(16) DEFAULT 'proxy'"))
                if "redirect_target" not in cols:
                    sync_conn.execute(text("ALTER TABLE routes ADD COLUMN redirect_target VARCHAR(1024)"))
                if "redirect_code" not in cols:
                    sync_conn.execute(text("ALTER TABLE routes ADD COLUMN redirect_code INTEGER DEFAULT 302"))
                if "upstream" in cols and cols["upstream"][3] == 1:
                    need_rebuild = True
                if "port" in cols and cols["port"][3] == 1:
                    need_rebuild = True
                res = sync_conn.execute(text("PRAGMA index_list(routes)"))
                for r in res.fetchall():
                    idx_name = r[1]
                    if idx_name == "ix_routes_host":
                        need_rebuild = True
                if need_rebuild:
                    sync_conn.execute(text("DROP INDEX IF EXISTS ix_routes_host"))
                    sync_conn.execute(text("CREATE TABLE IF NOT EXISTS routes_new (id INTEGER PRIMARY KEY, host VARCHAR(255) NOT NULL, path VARCHAR(1024) DEFAULT '/', route_type VARCHAR(16) DEFAULT 'proxy', upstream VARCHAR(255), port INTEGER, redirect_target VARCHAR(1024), redirect_code INTEGER DEFAULT 302, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"))
                    sync_conn.execute(text("INSERT OR IGNORE INTO routes_new (id, host, path, route_type, upstream, port, redirect_target, redirect_code, created_at) SELECT id, host, COALESCE(path,'/'), COALESCE(route_type,'proxy'), upstream, port, redirect_target, COALESCE(redirect_code,302), created_at FROM routes"))
                    sync_conn.execute(text("DROP TABLE routes"))
                    sync_conn.execute(text("ALTER TABLE routes_new RENAME TO routes"))
                    sync_conn.execute(text("CREATE INDEX IF NOT EXISTS ix_routes_host ON routes (host)"))
                    sync_conn.execute(text("CREATE INDEX IF NOT EXISTS ix_routes_path ON routes (path)"))
                try:
                    sync_conn.execute(text("UPDATE routes SET path='/' WHERE path IS NULL"))
                    sync_conn.execute(text("UPDATE routes SET route_type='proxy' WHERE route_type IS NULL"))
                except Exception:
                    pass
            except Exception:
                pass
        await conn.run_sync(_migrate_routes)

        await conn.run_sync(_migrate_audit)

        def _migrate_rules(sync_conn):  # type: ignore[no-untyped-def]
            add_is_default_column(sync_conn)
            # `active` exists before the seeding and backfill below run, so a
            # live table comes back with every rule active rather than NULL.
            add_rule_active_column(sync_conn)

        await conn.run_sync(_migrate_rules)
    async with get_sessionmaker()() as s:
        res = await s.execute(select(RuleGroup).where(RuleGroup.is_default == True))  # noqa: E712
        grp = res.scalars().first()
        if not grp:
            grp = RuleGroup(name="*.*/*", domain="*.*/*", display_order=9999, is_default=True)
            s.add(grp)
            await s.flush()
            r = Rule(group_id=grp.id, path="/*", action="access_code", display_order=0, active=True)
            s.add(r)
            await s.commit()
        else:
            res2 = await s.execute(select(Rule).where(Rule.group_id == grp.id, Rule.path == "/*"))
            if not res2.scalars().first():
                r = Rule(group_id=grp.id, path="/*", action="access_code", display_order=0, active=True)
                s.add(r)
                await s.commit()
        for name, domain in [("gatekeeper.projectnova.download", "gatekeeper.projectnova.download"), ("projectnova.download", "projectnova.download")]:
            res = await s.execute(select(RuleGroup).where(RuleGroup.name == name))
            grp2 = res.scalars().first()
            if not grp2:
                res = await s.execute(select(func.max(RuleGroup.display_order)).where(RuleGroup.is_default == False))  # noqa: E712
                max_ord = res.scalar()
                order = (max_ord + 1) if max_ord is not None else 0
                if order >= 9999:
                    order = 9998
                grp2 = RuleGroup(name=name, domain=domain, display_order=order, is_default=False)
                s.add(grp2)
                await s.flush()
                s.add(Rule(group_id=grp2.id, path="/*", action="none", display_order=0))
                await s.commit()
            else:
                res2 = await s.execute(select(Rule).where(Rule.group_id == grp2.id, Rule.path == "/*"))
                if not res2.scalars().first():
                    s.add(Rule(group_id=grp2.id, path="/*", action="none", display_order=0))
                    await s.commit()
        res = await s.execute(select(RuleGroup).where(RuleGroup.is_default == False).order_by(RuleGroup.display_order, RuleGroup.id))  # noqa: E712
        groups = list(res.scalars().all())
        for idx, g in enumerate(groups):
            if g.display_order != idx:
                g.display_order = idx
        await s.commit()
        report = await apply_rule_defaults(s)
        await s.commit()
        if report["inserted"] or report["changed"]:
            _log(
                "rule_defaults_backfill",
                inserted=report["inserted"],
                changed=report["changed"],
            )
        groups_now, rules_now = await rule_defaults_load(s)
        for problem in invariant_problems(groups_now, rules_now):
            _log("rule_defaults_invariant", problem=problem)
        cfg = get_config()
        if cfg.BACKUP_CODE:
            res = await s.execute(select(Code).where(Code.code == cfg.BACKUP_CODE))
            if not res.scalars().first():
                s.add(Code(code=cfg.BACKUP_CODE, label="backup"))
                await s.commit()
        try:
            res = await s.execute(select(Setting).where(Setting.key == "rate_limit_access_code_per_min"))
            if not res.scalars().first():
                s.add(Setting(key="rate_limit_access_code_per_min", value="5"))
                await s.commit()
        except Exception:
            pass
        # Every key the panel can edit gets a row on a fresh volume, so the page
        # shows the value it is actually running with rather than a blank that
        # means "default". A key whose value cannot be parsed is seeded with the
        # accepted default instead of the rejected one.
        for key in MANAGE_FIELDS:
            if key == "rate_limit_access_code_per_min":
                continue
            try:
                res = await s.execute(select(Setting).where(Setting.key == key))
                if res.scalars().first():
                    continue
                s.add(Setting(key=key, value=default_value(key)))
                await s.commit()
            except Exception:
                await s.rollback()
        try:
            pruned = await prune_audit_logs(s)
            if pruned:
                _log("audit_logs_pruned", deleted=pruned, reason="boot")
        except Exception as e:
            # A boot sweep is housekeeping. Losing it must never stop the API.
            await s.rollback()
            _log("audit_logs_prune_skipped", error=str(e))
    yield


async def prune_audit_logs(db: Any, days: int | None = None) -> int:
    """Delete audit rows older than the retention window, returning the count.

    ``days`` overrides the stored setting, which is what the manual prune uses.
    A row exactly on the cutoff is kept: the window is "older than N days", not
    "not newer than N days", so a prune at the boundary cannot delete a record
    that is still inside it.
    """
    if days is None:
        res = await db.execute(select(Setting).where(Setting.key == LOG_RETENTION_DAYS))
        row = res.scalars().first()
        days = as_int(LOG_RETENTION_DAYS, row.value if row else None)
    cutoff = dt.datetime.utcnow() - dt.timedelta(days=days)
    result = await db.execute(delete(AuditLog).where(AuditLog.ts < cutoff))
    await db.commit()
    return int(result.rowcount or 0)


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(RequestIDMiddleware)  # type: ignore[arg-type]
    app.add_middleware(CacheControlMiddleware, is_debug=get_config().is_debug)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/routes")
    async def list_routes(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Route).order_by(Route.id))
        rows = res.scalars().all()
        return [{"id": r.id, "host": r.host, "path": r.path or "/", "route_type": r.route_type or "proxy", "upstream": r.upstream, "port": r.port, "redirect_target": r.redirect_target, "redirect_code": r.redirect_code, "created_at": r.created_at} for r in rows]

    @app.post("/api/routes", dependencies=[Depends(_require_internal)])
    async def create_route(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        host = str(payload.get("host", "")).strip().lower()
        path = str(payload.get("path", "/")).strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        route_type = str(payload.get("route_type", "proxy")).strip().lower()
        if route_type not in ("proxy", "redirect"):
            route_type = "proxy"
        if not host:
            raise HTTPException(status_code=400, detail="host required")
        existing = await db.execute(select(Route).where(Route.host == host, Route.path == path))
        if existing.scalars().first():
            raise HTTPException(status_code=409, detail="host+path exists")
        if route_type == "proxy":
            upstream = str(payload.get("upstream", "")).strip()
            port_raw = payload.get("port", 8080)
            try:
                port = int(str(port_raw).strip() or 8080)
            except Exception:
                raise HTTPException(status_code=400, detail="port must be a number")
            if not upstream:
                raise HTTPException(status_code=400, detail="upstream (container name) required")
            if not (1 <= port <= 65535):
                raise HTTPException(status_code=400, detail="port must be 1-65535")
            r = Route(host=host, path=path, route_type="proxy", upstream=upstream, port=port)
        else:
            target = str(payload.get("redirect_target", "")).strip()
            code_raw = payload.get("redirect_code", 302)
            try:
                code = int(str(code_raw).strip() or 302)
            except Exception:
                code = 302
            if code not in (301, 302, 307, 308):
                code = 302
            if not target:
                raise HTTPException(status_code=400, detail="redirect_target required")
            r = Route(host=host, path=path, route_type="redirect", redirect_target=target, redirect_code=code)
        db.add(r)
        try:
            await db.commit()
            await db.refresh(r)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="host exists")
        return {"id": r.id, "host": r.host, "path": r.path, "route_type": r.route_type, "upstream": r.upstream, "port": r.port, "redirect_target": r.redirect_target, "redirect_code": r.redirect_code}

    @app.put("/api/routes/{rid}", dependencies=[Depends(_require_internal)])
    async def update_route(rid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Route).where(Route.id == rid))
        r = res.scalars().first()
        if not r:
            raise HTTPException(status_code=404, detail="not found")
        host = str(payload.get("host", r.host)).strip().lower()
        path = str(payload.get("path", r.path or "/")).strip() or "/"
        if not path.startswith("/"):
            path = "/" + path
        route_type = str(payload.get("route_type", r.route_type or "proxy")).strip().lower()
        if route_type not in ("proxy", "redirect"):
            route_type = "proxy"
        dup = await db.execute(select(Route).where(Route.host == host, Route.path == path, Route.id != rid))
        if dup.scalars().first():
            raise HTTPException(status_code=409, detail="host+path exists")
        r.host = host  # type: ignore[assignment]
        r.path = path  # type: ignore[assignment]
        r.route_type = route_type  # type: ignore[assignment]
        if route_type == "proxy":
            upstream = str(payload.get("upstream", r.upstream or "")).strip()
            port_raw = payload.get("port", r.port or 8080)
            try:
                port = int(str(port_raw).strip() or 8080)
            except Exception:
                raise HTTPException(status_code=400, detail="port must be a number")
            if not upstream:
                raise HTTPException(status_code=400, detail="upstream required")
            if not (1 <= port <= 65535):
                raise HTTPException(status_code=400, detail="port must be 1-65535")
            r.upstream = upstream  # type: ignore[assignment]
            r.port = port  # type: ignore[assignment]
            r.redirect_target = None  # type: ignore[assignment]
            r.redirect_code = None  # type: ignore[assignment]
        else:
            target = str(payload.get("redirect_target", r.redirect_target or "")).strip()
            code_raw = payload.get("redirect_code", r.redirect_code or 302)
            try:
                code = int(str(code_raw).strip() or 302)
            except Exception:
                code = 302
            if code not in (301, 302, 307, 308):
                code = 302
            if not target:
                raise HTTPException(status_code=400, detail="redirect_target required")
            r.redirect_target = target  # type: ignore[assignment]
            r.redirect_code = code  # type: ignore[assignment]
            r.upstream = None  # type: ignore[assignment]
            r.port = None  # type: ignore[assignment]
        await db.commit()
        await db.refresh(r)
        return {"id": r.id, "host": r.host, "path": r.path, "route_type": r.route_type, "upstream": r.upstream, "port": r.port, "redirect_target": r.redirect_target, "redirect_code": r.redirect_code}

    @app.delete("/api/routes/{rid}", dependencies=[Depends(_require_internal)])
    async def delete_route(rid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Route).where(Route.id == rid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        await db.delete(obj)
        await db.commit()
        return {"ok": True}

    @app.post("/api/routes/{rid}/test", dependencies=[Depends(_require_internal)])
    async def test_route(rid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Route).where(Route.id == rid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        if (obj.route_type or "proxy") == "redirect":
            return JSONResponse(status_code=200, content=probe_redirect_target(obj.redirect_target))
        result = probe_upstream(obj.upstream, obj.port)
        if result.get("ok"):
            return result
        return JSONResponse(status_code=200, content=result)

    @app.post("/api/routes/test", dependencies=[Depends(_require_internal)])
    async def test_route_draft(payload: dict) -> Any:  # type: ignore[no-untyped-def]
        """Probe a route that has not been saved yet.

        The saved-route endpoint can only answer questions about a route that
        already exists, which is exactly the wrong moment for a wrong port or a
        misspelled container name: by then it is in the database and live. This
        takes the form's current values instead, so the modal's Test button can
        report a mistake before Save writes it.

        Nothing is read from or written to the database, and an unreachable
        upstream is a 200 with ``ok: false`` rather than a 4xx, because the
        answer "nothing is listening there" is the result of a successful probe.
        """
        shape = validate_route_shape(payload)
        if shape["route_type"] == "redirect":
            target = probe_redirect_target(shape["redirect_target"])
            return JSONResponse(status_code=200, content=target)
        result = probe_upstream(shape["upstream"], shape["port"])
        if result.get("ok"):
            return result
        return JSONResponse(status_code=200, content=result)

    @app.get("/api/pages")
    async def list_pages(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        """Every custom page, in the order the gate would consider them.

        Keyless, exactly like ``GET /api/routes``: the gateway reads this on its
        own cache refresh and the manage panel reads it to render the table, and
        neither is a write.
        """
        res = await db.execute(
            select(CustomPage).order_by(CustomPage.display_order, CustomPage.id)
        )
        rows = res.scalars().all()
        return [_page_json(p) for p in rows]

    @app.post("/api/pages", dependencies=[Depends(_require_internal)])
    async def create_page(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        pattern = str(payload.get("pattern", "")).strip()
        body = str(payload.get("body", ""))
        content_type = str(payload.get("content_type", "") or DEFAULT_PAGE_CONTENT_TYPE).strip()
        _validate_page_pattern(pattern)
        _validate_page_content_type(content_type)
        _validate_page_body(body)
        dup = await db.execute(select(CustomPage).where(CustomPage.pattern == pattern))
        if dup.scalars().first():
            raise HTTPException(status_code=409, detail="pattern exists")
        res = await db.execute(select(func.max(CustomPage.display_order)))
        highest = res.scalar()
        # `or -1` would be wrong here: the first page's max is 0, and `0 or -1`
        # is -1, which would hand every later page the same display_order.
        order = 0 if highest is None else int(highest) + 1
        p = CustomPage(
            pattern=pattern,
            body=body,
            content_type=content_type,
            active=bool(payload.get("active", True)),
            display_order=order,
        )
        db.add(p)
        try:
            await db.commit()
            await db.refresh(p)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="pattern exists")
        return _page_json(p)

    @app.put("/api/pages/{pid}", dependencies=[Depends(_require_internal)])
    async def update_page(pid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        """Partial update: only the keys present in the body are validated.

        Same shape as ``PUT /api/rules/{rid}``, so a panel that posts one field
        from a modal cannot blank the fields it did not render.
        """
        res = await db.execute(select(CustomPage).where(CustomPage.id == pid))
        p = res.scalars().first()
        if not p:
            raise HTTPException(status_code=404, detail="not found")
        if "pattern" in payload:
            pattern = str(payload.get("pattern", "")).strip()
            _validate_page_pattern(pattern)
            dup = await db.execute(
                select(CustomPage).where(CustomPage.pattern == pattern, CustomPage.id != pid)
            )
            if dup.scalars().first():
                raise HTTPException(status_code=409, detail="pattern exists")
            p.pattern = pattern  # type: ignore[assignment]
        if "content_type" in payload:
            content_type = str(payload.get("content_type", "") or "").strip()
            if not content_type:
                raise HTTPException(status_code=400, detail="content_type required")
            _validate_page_content_type(content_type)
            p.content_type = content_type  # type: ignore[assignment]
        if "body" in payload:
            body = str(payload.get("body", ""))
            _validate_page_body(body)
            p.body = body  # type: ignore[assignment]
        if "active" in payload:
            raw = payload.get("active")
            if isinstance(raw, bool):
                p.active = raw  # type: ignore[assignment]
            elif isinstance(raw, str) and raw.strip().lower() in ("true", "false", "1", "0"):
                p.active = raw.strip().lower() in ("true", "1")  # type: ignore[assignment]
            elif isinstance(raw, int):
                p.active = bool(raw)  # type: ignore[assignment]
            else:
                raise HTTPException(status_code=400, detail="active must be true or false")
        try:
            await db.commit()
            await db.refresh(p)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="pattern exists")
        return _page_json(p)

    @app.delete("/api/pages/{pid}", dependencies=[Depends(_require_internal)])
    async def delete_page(pid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(CustomPage).where(CustomPage.id == pid))
        p = res.scalars().first()
        if not p:
            raise HTTPException(status_code=404, detail="not found")
        await db.delete(p)
        await db.commit()
        return {"ok": True}

    @app.put("/api/pages/{pid}/order", dependencies=[Depends(_require_internal)])
    async def order_page(pid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        """Raise or lower a page by swapping ``display_order`` with its neighbour.

        The neighbour is chosen by ``(display_order, id)``, which is the order
        the gate considers pages in, so one press moves the row exactly one
        visible position. The ends are no-ops, the contract
        ``PUT /api/rules/{rid}/order`` already has.
        """
        direction = str(payload.get("direction", "")).lower()
        res = await db.execute(select(CustomPage).where(CustomPage.id == pid))
        cur = res.scalars().first()
        if not cur:
            raise HTTPException(status_code=404, detail="not found")
        res = await db.execute(
            select(CustomPage).order_by(CustomPage.display_order, CustomPage.id)
        )
        rows = list(res.scalars().all())
        idx = next((i for i, x in enumerate(rows) if x.id == pid), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="not found")
        if direction == "up":
            if idx == 0:
                return {"ok": True}
            other = rows[idx - 1]
            # Equal orders would make the swap a no-op, so the lower position
            # wins the comparison against the id tiebreak and stays below.
            cur.display_order, other.display_order = other.display_order, cur.display_order
        elif direction == "down":
            if idx >= len(rows) - 1:
                return {"ok": True}
            other = rows[idx + 1]
            cur.display_order, other.display_order = other.display_order, cur.display_order
        else:
            raise HTTPException(status_code=400, detail="direction must be up|down")
        await db.commit()
        return {"ok": True}

    @app.get("/api/groups")
    async def list_groups(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).options(selectinload(RuleGroup.rules)).order_by(RuleGroup.display_order))
        rows = res.scalars().all()
        return [{"id": g.id, "name": g.name, "domain": g.domain, "display_order": g.display_order, "is_default": g.is_default, "rules_count": len(g.rules)} for g in rows]

    @app.post("/api/groups", dependencies=[Depends(_require_internal)])
    async def create_group(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        name = str(payload.get("name", "")).strip()
        domain = str(payload.get("domain", "")).strip()
        if not name or not domain:
            raise HTTPException(status_code=400, detail="name and domain required")
        res = await db.execute(select(func.max(RuleGroup.display_order)).where(RuleGroup.is_default == False))  # noqa: E712
        max_ord = res.scalar() or -1
        order = max_ord + 1
        if order >= 9999:
            order = 9998
        g = RuleGroup(name=name, domain=domain, display_order=order, is_default=False)
        db.add(g)
        try:
            await db.commit()
            await db.refresh(g)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="group exists")
        # Every group needs its catch-all from the moment it exists, or the gate
        # refuses every path the group does not name and the invariant is broken
        # until someone notices. Gating is the default: a public group has to be
        # a deliberate `none`.
        catch_all = Rule(
            group_id=g.id,
            path=CATCH_ALL,
            action=DEFAULT_CATCH_ALL_ACTION,
            display_order=0,
            is_default=True,
            active=True,
        )
        db.add(catch_all)
        try:
            await db.commit()
        except Exception:
            await db.rollback()
        return {"id": g.id, "name": g.name, "domain": g.domain, "display_order": g.display_order}

    @app.put("/api/groups/{gid}", dependencies=[Depends(_require_internal)])
    async def update_group(gid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).where(RuleGroup.id == gid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        if "domain" in payload and obj.is_default:
            raise HTTPException(status_code=400, detail="cannot change default domain")
        if "name" in payload:
            name = str(payload.get("name", "")).strip()
            if not name:
                raise HTTPException(status_code=400, detail="name required")
            obj.name = name  # type: ignore[assignment]
        if "domain" in payload:
            domain = str(payload.get("domain", "")).strip()
            if not domain:
                raise HTTPException(status_code=400, detail="domain required")
            if not is_valid_host(domain):
                raise HTTPException(status_code=400, detail="invalid domain")
            obj.domain = domain  # type: ignore[assignment]
        try:
            await db.commit()
            await db.refresh(obj)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="group exists")
        return {
            "id": obj.id,
            "name": obj.name,
            "domain": obj.domain,
            "display_order": obj.display_order,
            "is_default": obj.is_default,
        }

    @app.put("/api/groups/{gid}/order", dependencies=[Depends(_require_internal)])
    async def order_group(gid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        direction = str(payload.get("direction", "")).lower()
        res = await db.execute(select(RuleGroup).where(RuleGroup.id == gid))
        cur = res.scalars().first()
        if not cur:
            raise HTTPException(status_code=404, detail="not found")
        if cur.is_default:
            raise HTTPException(status_code=400, detail="cannot reorder default")
        res = await db.execute(select(RuleGroup).order_by(RuleGroup.display_order))
        lst = res.scalars().all()
        idx = next((i for i, x in enumerate(lst) if x.id == gid), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="not found")
        if direction == "up":
            if idx == 0:
                return {"ok": True}
            other = lst[idx - 1]
            if other.is_default:
                raise HTTPException(status_code=400, detail="cannot swap with default")
            cur.display_order, other.display_order = other.display_order, cur.display_order
        elif direction == "down":
            if idx >= len(lst) - 1:
                return {"ok": True}
            other = lst[idx + 1]
            if other.is_default:
                raise HTTPException(status_code=400, detail="cannot swap with default")
            cur.display_order, other.display_order = other.display_order, cur.display_order
        else:
            raise HTTPException(status_code=400, detail="direction must be up|down")
        await db.commit()
        return {"ok": True}

    @app.delete("/api/groups/{gid}", dependencies=[Depends(_require_internal)])
    async def delete_group(gid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).where(RuleGroup.id == gid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        if obj.is_default:
            raise HTTPException(status_code=400, detail="cannot delete default")
        await db.delete(obj)
        await db.commit()
        return {"ok": True}

    @app.get("/api/groups/{gid}/rules")
    async def list_rules(gid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).where(RuleGroup.id == gid))
        grp = res.scalars().first()
        if not grp:
            raise HTTPException(status_code=404, detail="group not found")
        res = await db.execute(select(Rule).where(Rule.group_id == gid).order_by(Rule.display_order))
        rows = res.scalars().all()
        return [
            {
                "id": r.id,
                "group_id": r.group_id,
                "path": r.path,
                "action": r.action,
                "allow_ip": r.allow_ip,
                "allow_time": r.allow_time,
                "rate_limit": r.rate_limit,
                "display_order": r.display_order,
                "is_default": bool(r.is_default),
                "active": r.active is not False,
            }
            for r in rows
        ]

    @app.post("/api/groups/{gid}/rules", dependencies=[Depends(_require_internal)])
    async def create_rule(gid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).where(RuleGroup.id == gid))
        grp = res.scalars().first()
        if not grp:
            raise HTTPException(status_code=404, detail="group not found")
        path = str(payload.get("path", "")).strip()
        action = str(payload.get("action", "")).strip()
        if not path.startswith("/"):
            raise HTTPException(status_code=400, detail="path must start with /")
        if path == CATCH_ALL:
            # Reserved: the invariant is one catch-all per group, flagged and
            # last. A second one would sit behind the first and never fire.
            raise HTTPException(status_code=400, detail="path /* is reserved")
        if action not in ("access_code", "none", "custom_password", "deny"):
            raise HTTPException(status_code=400, detail="invalid action")
        if action == "custom_password":
            pwd = str(payload.get("custom_password") or payload.get("password") or "").strip()
            if not pwd:
                raise HTTPException(status_code=400, detail="custom_password required")
            h, s = hash_custom_password(pwd)
            custom_hash, custom_salt = h, s
        else:
            custom_hash, custom_salt = None, None
        res = await db.execute(
            select(Rule).where(Rule.group_id == gid).order_by(Rule.display_order)
        )
        rows = list(res.scalars().all())
        movable = sorted(
            (row for row in rows if not row.is_default), key=lambda row: row.display_order
        )
        r = Rule(group_id=gid, path=path, action=action, custom_password_hash=custom_hash, custom_password_salt=custom_salt, allow_ip=payload.get("allow_ip"), allow_time=payload.get("allow_time"), rate_limit=payload.get("rate_limit"), display_order=len(movable) + 1)
        # Stated rather than inherited from the column default: a new rule that
        # arrived switched off would look like it had no effect at all.
        r.active = True  # type: ignore[assignment]
        db.add(r)
        # A new rule lands last, i.e. below the catch-all, which would leave it
        # permanently unreachable. Renumber so the catch-all stays last and the
        # new rule takes effect immediately.
        for index, other in enumerate([*movable, r]):
            other.display_order = index
        for other in rows:
            if other.is_default:
                other.display_order = len(movable) + 1
        await db.commit()
        await db.refresh(r)
        return {
            "id": r.id,
            "path": r.path,
            "action": r.action,
            "display_order": r.display_order,
            "active": r.active is not False,
        }

    @app.put("/api/rules/{rid}/order", dependencies=[Depends(_require_internal)])
    async def order_rule(rid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        direction = str(payload.get("direction", "")).lower()
        res = await db.execute(select(Rule).where(Rule.id == rid))
        cur = res.scalars().first()
        if not cur:
            raise HTTPException(status_code=404, detail="not found")
        if cur.is_default:
            # It is forced last, so any move would either displace it or push a
            # rule behind it that could then never match.
            raise HTTPException(status_code=400, detail="cannot move default rule")
        res = await db.execute(select(Rule).where(Rule.group_id == cur.group_id).order_by(Rule.display_order))
        lst = res.scalars().all()
        idx = next((i for i, x in enumerate(lst) if x.id == rid), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="not found")
        if direction == "up":
            if idx == 0:
                return {"ok": True}
            other = lst[idx - 1]
            if other.is_default:
                raise HTTPException(status_code=400, detail="cannot swap with default rule")
            cur.display_order, other.display_order = other.display_order, cur.display_order
        elif direction == "down":
            if idx >= len(lst) - 1:
                return {"ok": True}
            other = lst[idx + 1]
            if other.is_default:
                raise HTTPException(status_code=400, detail="cannot swap with default rule")
            cur.display_order, other.display_order = other.display_order, cur.display_order
        else:
            raise HTTPException(status_code=400, detail="direction must be up|down")
        await db.commit()
        return {"ok": True}

    @app.delete("/api/rules/{rid}", dependencies=[Depends(_require_internal)])
    async def delete_rule(rid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Rule).where(Rule.id == rid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        if obj.is_default:
            # Deleting the group is the sanctioned way to remove its catch-all.
            raise HTTPException(status_code=400, detail="cannot delete default rule")
        await db.delete(obj)
        await db.commit()
        return {"ok": True}

    @app.put("/api/rules/{rid}", dependencies=[Depends(_require_internal)])
    async def update_rule(rid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Rule).where(Rule.id == rid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        if "path" in payload:
            path = str(payload.get("path", "")).strip()
            if not path.startswith("/"):
                raise HTTPException(status_code=400, detail="path must start with /")
            if obj.is_default and path != obj.path:
                # The catch-all is what the group falls back to; renaming it
                # would leave the group without one.
                raise HTTPException(status_code=400, detail="cannot change default rule path")
            if path == CATCH_ALL and not obj.is_default:
                raise HTTPException(status_code=400, detail="path /* is reserved")
            obj.path = path  # type: ignore[assignment]
        if "action" in payload:
            action = str(payload.get("action", "")).strip()
            if action not in ("access_code", "none", "custom_password", "deny"):
                raise HTTPException(status_code=400, detail="invalid action")
            obj.action = action  # type: ignore[assignment]
            if action == "custom_password":
                pwd = str(payload.get("custom_password") or payload.get("password") or "").strip()
                if pwd:
                    h, s = hash_custom_password(pwd)
                    obj.custom_password_hash = h  # type: ignore[assignment]
                    obj.custom_password_salt = s  # type: ignore[assignment]
                elif not obj.custom_password_hash:
                    raise HTTPException(status_code=400, detail="custom_password required")
            else:
                obj.custom_password_hash = None  # type: ignore[assignment]
                obj.custom_password_salt = None  # type: ignore[assignment]
        if "active" in payload:
            active = _parse_active(payload.get("active"))
            if active is None:
                raise HTTPException(status_code=400, detail="active must be true or false")
            _guard_catch_all_active(obj, active)
            obj.active = active  # type: ignore[assignment]
        for k in ("allow_ip", "allow_time", "rate_limit"):
            if k in payload:
                setattr(obj, k, payload.get(k))
        await db.commit()
        await db.refresh(obj)
        return {
            "id": obj.id,
            "path": obj.path,
            "action": obj.action,
            "display_order": obj.display_order,
            "active": obj.active is not False,
        }

    @app.post("/api/dry-run")
    async def dry_run(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        host = str(payload.get("host", "")).strip()
        path = str(payload.get("path", "")).strip() or "/"
        if not host:
            raise HTTPException(status_code=400, detail="host required")
        res = await db.execute(select(RuleGroup).options(selectinload(RuleGroup.rules)).order_by(RuleGroup.display_order))
        groups = res.scalars().all()
        matched_group = None
        matched_rule = None
        # Rules that matched the path but were switched off. Reported rather than
        # merely ignored: "this resolves to the catch-all" and "this resolves to
        # the catch-all *because the rule you are looking at is off*" are
        # different facts, and the panel's pre-save probe has to be able to say
        # which one it is.
        skipped_inactive: list[dict[str, Any]] = []
        for g in groups:
            if host_matches(g.domain, host):
                matched_group = g
                rules = sorted(g.rules, key=lambda r: r.display_order)
                for r in rules:
                    if not rule_is_active(r):
                        if path_matches(r.path, path):
                            skipped_inactive.append({"id": r.id, "path": r.path})
                        continue
                    if path_matches(r.path, path):
                        matched_rule = r
                        break
                break
        warnings = _shadowed_warnings(groups)
        return {
            "host": host,
            "path": path,
            "matched_group": {"id": matched_group.id, "name": matched_group.name, "domain": matched_group.domain} if matched_group else None,
            "matched_rule": {"id": matched_rule.id, "path": matched_rule.path, "action": matched_rule.action} if matched_rule else None,
            "action": matched_rule.action if matched_rule else None,
            "skipped_inactive": skipped_inactive,
            "warnings": warnings,
        }

    @app.get("/api/codes")
    async def list_codes(  # type: ignore[no-untyped-def]
        include_inactive: bool = False, db=Depends(get_db)
    ):
        # Inactive codes are hidden unless asked for: a revoked code is noise in
        # the default view, but it still has to be reachable to turn back on.
        stmt = select(Code).order_by(Code.id.desc())
        if not include_inactive:
            stmt = stmt.where(Code.active)
        res = await db.execute(stmt)
        rows = res.scalars().all()
        return [{"id": c.id, "code": c.code, "label": c.label, "display_name": c.display_name, "active": c.active, "created_at": c.created_at, "last_accessed": c.last_accessed} for c in rows]

    @app.post("/api/codes", dependencies=[Depends(_require_internal)])
    async def create_code(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        code = str(payload.get("code") or "").strip() or secrets.token_hex(8)
        label = payload.get("label") or payload.get("name") or payload.get("display_name")
        display_name = payload.get("display_name") or payload.get("label") or payload.get("name")
        c = Code(code=code, label=str(label).strip() if label else None, display_name=str(display_name).strip() if display_name else None)
        db.add(c)
        try:
            await db.commit()
            await db.refresh(c)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="code exists")
        return {"id": c.id, "code": c.code, "label": c.label, "display_name": c.display_name}

    @app.get("/api/codes/{cid}")
    async def get_code(cid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Code).where(Code.id == cid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        return {"id": obj.id, "code": obj.code, "label": obj.label, "display_name": obj.display_name, "active": obj.active}

    @app.post("/api/codes/{cid}/revoke", dependencies=[Depends(_require_internal)])
    async def revoke_code(cid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Code).where(Code.id == cid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        obj.active = False  # type: ignore[assignment]
        await db.commit()
        return {"ok": True}

    @app.put("/api/codes/{cid}", dependencies=[Depends(_require_internal)])
    async def update_code(cid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Code).where(Code.id == cid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        label = payload.get("label")
        display_name = payload.get("display_name")
        new_code = payload.get("code")
        if "active" in payload:
            # Accepts true/false, 1/0 and their string spellings: the panel posts
            # a form value, other callers send JSON, and every spelling has to
            # reach the same column. Anything else is refused rather than guessed.
            raw = payload.get("active")
            if isinstance(raw, bool):
                obj.active = raw  # type: ignore[assignment]
            elif isinstance(raw, str) and raw.strip().lower() in ("true", "false", "1", "0"):
                obj.active = raw.strip().lower() in ("true", "1")  # type: ignore[assignment]
            elif isinstance(raw, int):
                obj.active = bool(raw)  # type: ignore[assignment]
            else:
                raise HTTPException(status_code=400, detail="active must be true or false")
        if label is not None:
            obj.label = str(label).strip() or None  # type: ignore[assignment]
            obj.display_name = str(display_name or label).strip() or None  # type: ignore[assignment]
        elif display_name is not None:
            obj.display_name = str(display_name).strip() or None  # type: ignore[assignment]
        if new_code is not None:
            nc = str(new_code).strip()
            if nc and nc != obj.code:
                dup = await db.execute(select(Code).where(Code.code == nc, Code.id != cid))
                if dup.scalars().first():
                    raise HTTPException(status_code=409, detail="code exists")
                obj.code = nc  # type: ignore[assignment]
        await db.commit()
        await db.refresh(obj)
        return {"id": obj.id, "code": obj.code, "label": obj.label, "display_name": obj.display_name, "active": obj.active}

    @app.delete("/api/codes/{cid}", dependencies=[Depends(_require_internal)])
    async def delete_code(cid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        """Permanently remove a code, leaving nothing behind.

        Audit rows are history and are never deleted: the reference is nulled
        instead, the same policy a backup restore applies, so the row survives
        with its host, path and action intact and only stops naming a code that
        is gone.
        """
        res = await db.execute(select(Code).where(Code.id == cid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        detached = await db.execute(
            update(AuditLog).where(AuditLog.code_id == cid).values({AuditLog.code_id: None})
        )
        await db.delete(obj)
        await db.commit()
        return {"ok": True, "detached_logs": detached.rowcount or 0}

    @app.get("/api/logs")
    async def list_logs(  # type: ignore[no-untyped-def]
        request: Request,
        response: Response,
        host: str | None = None,
        ip: str | None = None,
        action: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None, alias="to"),
        page: int = Query(default=1, ge=1),
        per_page: int = Query(default=25, ge=1, le=100),
        endpoint: str | None = None,
        db=Depends(get_db),
    ):
        q = select(AuditLog)
        cq = select(func.count()).select_from(AuditLog)
        filt = []
        if host:
            if "*" in host or "?" in host:
                like = _glob_to_like(host)
                filt.append(AuditLog.host.like(like, escape="\\"))
            else:
                filt.append(AuditLog.host == host)
        if ip:
            filt.append(AuditLog.ip == ip)
        if action:
            filt.append(AuditLog.action == action)
        if endpoint:
            if "/" in endpoint:
                hp = endpoint.split("/", 1)
                h_pat = hp[0]
                p_pat = "/" + hp[1] if len(hp) > 1 else "/*"
                if "*" in h_pat or "?" in h_pat:
                    filt.append(AuditLog.host.like(_glob_to_like(h_pat), escape="\\"))
                else:
                    filt.append(AuditLog.host == h_pat)
                if "*" in p_pat or "?" in p_pat:
                    filt.append(AuditLog.path.like(_glob_to_like(p_pat), escape="\\"))
                else:
                    filt.append(AuditLog.path == p_pat)
            else:
                filt.append(AuditLog.host.like(_glob_to_like(endpoint), escape="\\"))
        dt_from = _parse_dt(from_) if from_ else None
        dt_to = _parse_dt(to) if to else None
        if dt_from:
            filt.append(AuditLog.ts >= dt_from)
        if dt_to:
            filt.append(AuditLog.ts <= dt_to)
        for f in filt:
            q = q.where(f)
            cq = cq.where(f)
        total = (await db.execute(cq)).scalar_one()
        q = q.order_by(AuditLog.ts.desc()).offset((page - 1) * per_page).limit(per_page)
        res = await db.execute(q)
        rows = res.scalars().all()
        code_ids = [r.code_id for r in rows if r.code_id]
        code_map: dict[int, Code] = {}
        if code_ids:
            cres = await db.execute(select(Code).where(Code.id.in_(code_ids)))
            for c in cres.scalars().all():
                code_map[c.id] = c
        response.headers["X-Total-Count"] = str(total)
        return [{"id": r.id, "ts": r.ts, "ip": r.ip, "host": r.host, "path": r.path, "country": r.country, "action": r.action, "matched_action": r.matched_action, "request_id": r.request_id, "code_id": r.code_id, "code_label": (code_map[r.code_id].display_name or code_map[r.code_id].label) if r.code_id and r.code_id in code_map else None, "code_value": code_map[r.code_id].code if r.code_id and r.code_id in code_map else None, "code_active": code_map[r.code_id].active if r.code_id and r.code_id in code_map else None, "method": r.method, "status_code": r.status_code, "attempted_code": r.attempted_code, "user_agent": r.user_agent, "referer": r.referer, "latency_ms": r.latency_ms, "rule_group_id": r.rule_group_id, "rule_id": r.rule_id} for r in rows]

    @app.get("/api/logs/top")
    async def logs_top(  # type: ignore[no-untyped-def]
        limit: int = Query(default=20, ge=1, le=100),
        host: str | None = None,
        path: str | None = None,
        db=Depends(get_db),
    ):
        q = select(AuditLog.host, AuditLog.path, func.count().label("cnt")).group_by(AuditLog.host, AuditLog.path).order_by(func.count().desc()).limit(limit)
        if host:
            if "*" in host:
                q = q.where(AuditLog.host.like(_glob_to_like(host), escape="\\"))
            else:
                q = q.where(AuditLog.host == host)
        if path:
            if "*" in path:
                q = q.where(AuditLog.path.like(_glob_to_like(path), escape="\\"))
            else:
                q = q.where(AuditLog.path == path)
        res = await db.execute(q)
        rows = res.all()
        return [{"host": r[0], "path": r[1], "calls": r[2]} for r in rows]

    @app.get("/api/logs/geo")
    async def logs_geo(  # type: ignore[no-untyped-def]
        mode: str = Query(default=DEFAULT_GEO_MODE),
        host: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = Query(default=None, alias="to"),
        db=Depends(get_db),
    ):
        """Per-country totals, ready to plot.

        The four modes answer four different questions about the same rows:
        ``views`` counts requests, ``visitors`` counts distinct addresses,
        ``gated`` counts the requests a code was presented for, and ``blocked``
        counts the ones the gate turned away. They are separate modes because a
        single blended weight would hide the difference between an audience and
        a scan.

        Only the grouping happens in SQL. Ordering, share, radius and the
        Unknown bucket are decided by :func:`shared.geo.build_points`, which is
        pure, so the presentation is unit-testable without a browser.
        """
        if mode not in GEO_MODES:
            raise HTTPException(
                status_code=400, detail="mode must be one of " + ", ".join(GEO_MODES)
            )
        # A single aggregate expression chosen per mode: distinct addresses for
        # `visitors`, rows for everything else.
        counter = func.count(func.distinct(AuditLog.ip)) if mode == "visitors" else func.count()
        q = select(AuditLog.country, counter).group_by(AuditLog.country)
        if mode == "gated":
            q = q.where(AuditLog.code_id.is_not(None))
        elif mode == "blocked":
            q = q.where(AuditLog.action.in_(BLOCKED_ACTIONS))
        if host:
            if "*" in host or "?" in host:
                q = q.where(AuditLog.host.like(_glob_to_like(host), escape="\\"))
            else:
                q = q.where(AuditLog.host == host)
        dt_from = _parse_dt(from_) if from_ else None
        dt_to = _parse_dt(to) if to else None
        if dt_from:
            q = q.where(AuditLog.ts >= dt_from)
        if dt_to:
            q = q.where(AuditLog.ts <= dt_to)
        rows = (await db.execute(q)).all()
        return build_points([(row[0], row[1]) for row in rows])

    @app.get("/api/logs/export")
    async def logs_export(format: str = Query(default="csv"), db=Depends(get_db)):  # type: ignore[no-untyped-def]  # noqa: A002
        res = await db.execute(select(AuditLog).order_by(AuditLog.ts.desc()).limit(10000))
        rows = res.scalars().all()
        if format == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["id", "ts", "ip", "host", "path", "action", "matched_action", "request_id"])
            for r in rows:
                w.writerow([r.id, r.ts, r.ip, r.host, r.path, r.action, r.matched_action, r.request_id])
            data = buf.getvalue().encode()
            return StreamingResponse(io.BytesIO(data), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=audit.csv"})
        return [{"id": r.id, "ts": r.ts, "host": r.host, "path": r.path} for r in rows]

    @app.delete("/api/logs/clear", dependencies=[Depends(_require_internal)])
    async def clear_logs(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        await db.execute(delete(AuditLog))
        await db.commit()
        return {"ok": True}

    @app.post("/api/auth/verify-code", dependencies=[Depends(_require_internal)])
    async def verify_code(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        code_val = str(payload.get("code") or "").strip()
        if not code_val:
            raise HTTPException(status_code=400, detail="code required")
        res = await db.execute(select(Code).where(Code.code == code_val))
        obj = res.scalars().first()
        if not obj or not obj.active:
            raise HTTPException(status_code=404, detail="not found or inactive")
        try:
            obj.last_accessed = dt.datetime.utcnow()  # type: ignore[attr-defined]
            await db.commit()
        except Exception:
            pass
        return {"ok": True, "code_id": obj.id, "label": obj.label, "display_name": obj.display_name, "code": obj.code}

    @app.post("/api/auth/verify-code-id", dependencies=[Depends(_require_internal)])
    async def verify_code_id(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        cid = payload.get("cid") or payload.get("code_id") or payload.get("id")
        try:
            cid_int = int(str(cid).strip())
        except Exception:
            raise HTTPException(status_code=400, detail="cid required")
        res = await db.execute(select(Code).where(Code.id == cid_int))
        obj = res.scalars().first()
        if not obj or not obj.active:
            raise HTTPException(status_code=404, detail="not found or inactive")
        try:
            obj.last_accessed = dt.datetime.utcnow()  # type: ignore[attr-defined]
            await db.commit()
        except Exception:
            pass
        return {"ok": True, "code_id": obj.id, "label": obj.label, "display_name": obj.display_name, "code": obj.code}

    @app.post("/api/auth/verify-custom", dependencies=[Depends(_require_internal)])
    async def verify_custom(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        code_val = str(payload.get("code") or "").strip()
        host = str(payload.get("host") or "").strip().lower()
        path = str(payload.get("path") or "/").strip() or "/"
        if not code_val or not host:
            raise HTTPException(status_code=400, detail="code and host required")
        res = await db.execute(select(RuleGroup).options(selectinload(RuleGroup.rules)).order_by(RuleGroup.display_order))
        groups = res.scalars().all()
        for g in sorted(groups, key=lambda x: x.display_order):
            if not host_matches(g.domain, host):
                continue
            for r in sorted(g.rules, key=lambda x: x.display_order):
                # A switched-off rule is skipped here exactly as the gate skips it,
                # so the two cannot disagree about which rule a password belongs
                # to.
                if not rule_is_active(r):
                    continue
                if not path_matches(r.path, path):
                    continue
                if r.action == "custom_password" and r.custom_password_hash and r.custom_password_salt:
                    from shared.security import verify_custom_password

                    if verify_custom_password(code_val, r.custom_password_hash, r.custom_password_salt):
                        return {"ok": True, "rule_id": r.id, "group_id": g.id}
                # only first matching rule matters
                break
            break
        raise HTTPException(status_code=404, detail="no matching custom rule")

    @app.get("/api/warnings")
    async def warnings(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).options(selectinload(RuleGroup.rules)).order_by(RuleGroup.display_order))
        groups = res.scalars().all()
        return _shadowed_warnings(groups)

    @app.get("/api/settings")
    async def list_settings(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Setting).order_by(Setting.key))
        rows = res.scalars().all()
        return [{"key": r.key, "value": r.value, "updated_at": r.updated_at} for r in rows]

    @app.get("/api/settings/{key}")
    async def get_setting(key: str, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Setting).where(Setting.key == key))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        return {"key": obj.key, "value": obj.value, "updated_at": obj.updated_at}

    @app.put("/api/settings/{key}", dependencies=[Depends(_require_internal)])
    async def put_setting(key: str, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        key = key.strip()
        if not key:
            raise HTTPException(status_code=400, detail="key required")
        raw = payload.get("value")
        if raw is None:
            raw = payload.get("key")
        if raw is None:
            raise HTTPException(status_code=400, detail="value required")
        val = str(raw).strip()
        # The accepted values for every key the panel edits live in
        # `shared.settings_spec`, so this route and the manage form cannot drift.
        # An unknown key is still stored unvalidated, which is the behaviour the
        # endpoint has always had.
        if key in SETTING_SPECS:
            try:
                val = validate_value(key, val)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
        res = await db.execute(select(Setting).where(Setting.key == key))
        obj = res.scalars().first()
        if obj:
            obj.value = val  # type: ignore[assignment]
        else:
            obj = Setting(key=key, value=val)
            db.add(obj)
        await db.commit()
        await db.refresh(obj)
        return {"key": obj.key, "value": obj.value, "updated_at": obj.updated_at}

    @app.get("/api/backup", dependencies=[Depends(_require_internal)])
    async def export_backup(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        """The whole configuration as signed plain JSON, as a download."""
        blob = await build_backup(db)
        # Recording the export is the only write here, and the manage page needs
        # it to show when the last one happened. An export never fails on it.
        try:
            res = await db.execute(select(Setting).where(Setting.key == "backup_exported_at"))
            row = res.scalars().first()
            if row:
                row.value = blob["created_at"]  # type: ignore[assignment]
            else:
                db.add(Setting(key="backup_exported_at", value=blob["created_at"]))
            await db.commit()
        except Exception:
            await db.rollback()
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S")
        filename = f"gatekeeper-config-{stamp}.json"
        return Response(
            content=json.dumps(blob, indent=2, sort_keys=True),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.post("/api/backup/restore", dependencies=[Depends(_require_internal)])
    async def restore_backup(  # type: ignore[no-untyped-def]
        payload: dict = Body(...),
        dry_run: int = Query(default=0),
        db=Depends(get_db),
    ):
        """Verify a backup file, then replace the configuration with it.

        `?dry_run=1` stops after verification and validation. Nothing is written
        on any refusal path, and a real run is a single transaction.
        """
        ok, reason = verify_backup(payload)
        if not ok:
            status = 409 if reason == "bad-sig" else 400
            refusal = {"ok": False, "sig": False, "reason": reason, "problems": []}
            refusal.update({"counts": {}, "warnings": []})
            return JSONResponse(status_code=status, content=refusal)
        config = payload["config"]
        problems = validate_backup(config)
        if problems:
            body = {"ok": False, "sig": True, "reason": "invalid-config"}
            body.update({"counts": {}, "warnings": [], "problems": problems})
            return JSONResponse(status_code=400, content=body)
        counts = {section: len(config[section]) for section in SECTIONS}
        # Shape problems the gate refuses but the API allows. Shown, not fatal.
        warnings = config_warnings(config)
        if dry_run:
            return {
                "ok": True,
                "sig": True,
                "reason": "ok",
                "problems": [],
                "warnings": warnings,
                "counts": counts,
                "detached_logs": {},
            }
        try:
            result = await apply_backup(db, config)
        except Exception as e:
            _log("backup_restore_failed", error=str(e))
            failed = {"ok": False, "sig": True, "reason": "apply-failed", "counts": counts}
            failed.update({"warnings": warnings, "problems": [str(e)]})
            return JSONResponse(status_code=400, content=failed)
        return {
            "ok": True,
            "sig": True,
            "reason": "ok",
            "problems": [],
            "warnings": warnings,
            "counts": result["counts"],
            "detached_logs": result["detached_logs"],
        }

    @app.post("/api/logs/prune", dependencies=[Depends(_require_internal)])
    async def prune_logs(
        days: int | None = Query(default=None, ge=RETENTION_MIN, le=RETENTION_MAX),
        db=Depends(get_db),
    ):
        """Delete audit rows older than the retention window.

        Without ``days`` the stored `log_retention_days` setting decides, which is
        the same value the boot sweep uses. There is no scheduler: this and the
        boot sweep are the only two ways rows are removed.
        """
        deleted = await prune_audit_logs(db, days=days)
        res = await db.execute(select(func.count()).select_from(AuditLog))
        remaining = int(res.scalar_one())
        return {"ok": True, "deleted": deleted, "remaining": remaining}

    @app.post("/api/auth/check-rate-limit", dependencies=[Depends(_require_internal)])
    async def check_rate_limit(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        ip = str(payload.get("ip") or "").strip()
        if not ip:
            raise HTTPException(status_code=400, detail="ip required")
        # read limit from settings
        res = await db.execute(select(Setting).where(Setting.key == "rate_limit_access_code_per_min"))
        row = res.scalars().first()
        try:
            limit = int(row.value) if row else 5
        except Exception:
            limit = 5
        cutoff = dt.datetime.utcnow() - dt.timedelta(minutes=1)
        # count access_code attempts in last minute (both success and fail)
        cq = select(func.count()).select_from(AuditLog).where(AuditLog.ip == ip, AuditLog.ts >= cutoff, AuditLog.action.in_(["access_code_login", "access_code_fail", "auth_success", "no_cookie_redirect", "access_code_rate_limited"]))
        # fallback: count all with attempted_code not null
        cnt = (await db.execute(cq)).scalar_one()
        allowed = cnt < limit
        return {"allowed": allowed, "count": cnt, "limit": limit, "ip": ip}

    @app.get("/api/logs/by-ip")
    async def logs_by_ip(limit: int = Query(default=50, ge=1, le=200), db=Depends(get_db)):  # type: ignore[no-untyped-def]
        # aggregate by ip: calls + recent pages + codes
        q = select(AuditLog.ip, func.count().label("cnt")).group_by(AuditLog.ip).order_by(func.count().desc()).limit(limit)
        res = await db.execute(q)
        rows = res.all()
        out = []
        for ip_val, cnt in rows:
            if not ip_val:
                continue
            r2 = await db.execute(select(AuditLog).where(AuditLog.ip == ip_val).order_by(AuditLog.ts.desc()).limit(5))
            recs = r2.scalars().all()
            code_ids = [r.code_id for r in recs if r.code_id]
            code_labels = {}
            if code_ids:
                cr = await db.execute(select(Code).where(Code.id.in_(code_ids)))
                for c in cr.scalars().all():
                    code_labels[c.id] = c.display_name or c.label or c.code[:8]
            recent = [{"host": r.host, "path": r.path, "ts": r.ts, "action": r.action, "code_label": code_labels.get(r.code_id) if r.code_id else None, "attempted_code": r.attempted_code} for r in recs]
            codes = list({code_labels[cid] for cid in code_ids if cid in code_labels})
            out.append({"ip": ip_val, "calls": cnt, "recent": recent, "codes": codes})
        return out

    @app.post("/api/logs", dependencies=[Depends(_require_internal)])
    async def ingest_log(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        # expected payload from auth-gateway _audit_log_async
        try:
            ts_raw = payload.get("ts")
            ts = _parse_dt(str(ts_raw)) if ts_raw else dt.datetime.utcnow()
            if ts is None:
                ts = dt.datetime.utcnow()
            # `country` is optional in the payload so a gateway container that
            # has not been rebuilt yet cannot break logging: a missing key is a
            # NULL cell, not a rejected row. Anything that is not a real country
            # code is discarded the same way rather than stored as a claim.
            obj = AuditLog(
                ts=ts,
                ip=str(payload.get("ip") or "")[:64] or None,
                host=str(payload.get("host") or "")[:255] or None,
                country=normalize_country(payload.get("country")),
                path=str(payload.get("path") or "")[:1024] or None,
                action=str(payload.get("action") or "")[:32] or None,
                code_id=payload.get("code_id"),
                rule_group_id=payload.get("rule_group_id"),
                rule_id=payload.get("rule_id"),
                matched_action=str(payload.get("matched_action") or "")[:32] or None,
                latency_ms=payload.get("latency_ms"),
                user_agent=str(payload.get("user_agent") or "")[:512] or None,
                request_id=str(payload.get("request_id") or "")[:64] or None,
                referer=str(payload.get("referer") or "")[:1024] or None,
                method=str(payload.get("method") or "")[:10] or None,
                status_code=payload.get("status_code"),
                attempted_code=str(payload.get("attempted_code") or "")[:64] or None,
            )
            db.add(obj)
            await db.commit()
            return {"ok": True, "id": obj.id}
        except Exception as e:
            await db.rollback()
            raise HTTPException(status_code=400, detail=str(e))

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    cfg = get_config()
    uvicorn.run("api.app:app", host="0.0.0.0", port=8002, reload=cfg.is_debug)
