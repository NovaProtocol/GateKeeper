from __future__ import annotations

import asyncio
import csv
import datetime as dt
import io
import json
import logging
import secrets
import socket
import string
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import String, Text, delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from starlette.middleware.base import BaseHTTPMiddleware

from shared.config import get_config
from shared.db import Base, get_db, get_engine, get_sessionmaker
from shared.models import ApiKey, AuditLog, Code, Route, Rule, RuleGroup
from shared.security import hash_api_key, hash_custom_password, host_matches, path_matches

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
                if path_matches(ur.path, _sample_path(r.path)) or ur.path == "/*":
                    shadowed_rules.append({"id": r.id, "path": r.path, "group_id": g.id, "shadowed_by": ur.id, "reason": f"shadowed by {ur.path}"})
                    break
    for sg in shadowed_groups:
        gid = sg["id"]
        for r in next((x.rules for x in groups_sorted if x.id == gid), []):
            if not any(sr["id"] == r.id for sr in shadowed_rules):
                shadowed_rules.append({"id": r.id, "path": r.path, "group_id": gid, "shadowed_by": sg["shadowed_by"], "reason": "group shadowed"})
    return {"groups": shadowed_groups, "rules": shadowed_rules}


def _parse_dt(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            continue
    return None


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
    async with get_sessionmaker()() as s:
        res = await s.execute(select(RuleGroup).where(RuleGroup.name == "*.*/*"))
        grp = res.scalars().first()
        if not grp:
            grp = RuleGroup(name="*.*/*", domain="*.*/*", display_order=9999, is_default=True)
            s.add(grp)
            await s.flush()
            r = Rule(group_id=grp.id, path="/*", action="access_code", display_order=0)
            s.add(r)
            await s.commit()
        else:
            res2 = await s.execute(select(Rule).where(Rule.group_id == grp.id, Rule.path == "/*"))
            if not res2.scalars().first():
                r = Rule(group_id=grp.id, path="/*", action="access_code", display_order=0)
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
        cfg = get_config()
        if cfg.BACKUP_CODE:
            res = await s.execute(select(Code).where(Code.code == cfg.BACKUP_CODE))
            if not res.scalars().first():
                s.add(Code(code=cfg.BACKUP_CODE, label="backup"))
                await s.commit()
    yield


def create_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)
    app.add_middleware(RequestIDMiddleware)  # type: ignore[arg-type]

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
            target = (obj.redirect_target or "").strip()
            if not target:
                return JSONResponse(status_code=200, content={"ok": False, "error": "no target"})
            if target.startswith("http://") or target.startswith("https://"):
                try:
                    from urllib.parse import urlsplit
                    host = urlsplit(target).hostname or ""
                    if host:
                        socket.getaddrinfo(host, None)
                    return {"ok": True, "note": "redirect target ok"}
                except Exception as e:
                    return JSONResponse(status_code=200, content={"ok": False, "error": str(e)})
            else:
                return {"ok": True, "note": "redirect path ok"}
        try:
            sock = socket.create_connection((obj.upstream, obj.port), timeout=2)
            sock.close()
            return {"ok": True, "latency": "reachable"}
        except Exception as e:
            return JSONResponse(status_code=200, content={"ok": False, "error": str(e)})

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
        return {"id": g.id, "name": g.name, "domain": g.domain, "display_order": g.display_order}

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
        return [{"id": r.id, "group_id": r.group_id, "path": r.path, "action": r.action, "allow_ip": r.allow_ip, "allow_time": r.allow_time, "rate_limit": r.rate_limit, "display_order": r.display_order} for r in rows]

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
        res = await db.execute(select(func.max(Rule.display_order)).where(Rule.group_id == gid))
        max_ord = res.scalar()
        order = (max_ord + 1) if max_ord is not None else 0
        r = Rule(group_id=gid, path=path, action=action, custom_password_hash=custom_hash, custom_password_salt=custom_salt, allow_ip=payload.get("allow_ip"), allow_time=payload.get("allow_time"), rate_limit=payload.get("rate_limit"), display_order=order)
        db.add(r)
        await db.commit()
        await db.refresh(r)
        return {"id": r.id, "path": r.path, "action": r.action, "display_order": r.display_order}

    @app.put("/api/rules/{rid}/order", dependencies=[Depends(_require_internal)])
    async def order_rule(rid: int, payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        direction = str(payload.get("direction", "")).lower()
        res = await db.execute(select(Rule).where(Rule.id == rid))
        cur = res.scalars().first()
        if not cur:
            raise HTTPException(status_code=404, detail="not found")
        res = await db.execute(select(Rule).where(Rule.group_id == cur.group_id).order_by(Rule.display_order))
        lst = res.scalars().all()
        idx = next((i for i, x in enumerate(lst) if x.id == rid), None)
        if idx is None:
            raise HTTPException(status_code=404, detail="not found")
        if direction == "up":
            if idx == 0:
                return {"ok": True}
            other = lst[idx - 1]
            cur.display_order, other.display_order = other.display_order, cur.display_order
        elif direction == "down":
            if idx >= len(lst) - 1:
                return {"ok": True}
            other = lst[idx + 1]
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
        for k in ("allow_ip", "allow_time", "rate_limit"):
            if k in payload:
                setattr(obj, k, payload.get(k))
        await db.commit()
        await db.refresh(obj)
        return {"id": obj.id, "path": obj.path, "action": obj.action, "display_order": obj.display_order}

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
        for g in groups:
            if host_matches(g.domain, host):
                matched_group = g
                rules = sorted(g.rules, key=lambda r: r.display_order)
                for r in rules:
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
            "warnings": warnings,
        }

    @app.get("/api/codes")
    async def list_codes(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(Code).order_by(Code.id.desc()))
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

    @app.get("/api/keys")
    async def list_keys(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(ApiKey).order_by(ApiKey.id.desc()))
        rows = res.scalars().all()
        return [{"id": k.id, "key_prefix": k.key_prefix, "label": k.label, "display_name": k.display_name, "active": k.active, "mode": k.mode, "whitelist": k.whitelist, "blacklist": k.blacklist, "expires_at": k.expires_at, "last_used": k.last_used} for k in rows]

    @app.post("/api/keys", dependencies=[Depends(_require_internal)])
    async def create_key(payload: dict, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        raw = str(payload.get("key") or "").strip() or secrets.token_urlsafe(16)[:16]
        if len(raw) < 8 or len(raw) > 64:
            raise HTTPException(status_code=400, detail="key must be 8-64 chars")
        label = payload.get("label")
        mode = str(payload.get("mode") or "none").strip()
        if mode not in ("none", "whitelist", "blacklist"):
            raise HTTPException(status_code=400, detail="invalid mode")
        whitelist = payload.get("whitelist")
        blacklist = payload.get("blacklist")
        if isinstance(whitelist, list):
            whitelist = json.dumps(whitelist)
        if isinstance(blacklist, list):
            blacklist = json.dumps(blacklist)
        expires_at = payload.get("expires_at")
        exp_dt = _parse_dt(str(expires_at)) if expires_at else None
        salt = secrets.token_hex(32)
        h = hash_api_key(raw, salt)
        prefix = raw[:4] + "***" + raw[-4:] if len(raw) > 8 else raw[:2] + "***" + raw[-2:]
        k = ApiKey(key_hash=h, key_prefix=prefix, salt=salt, label=str(label).strip() if label else None, display_name=str(payload.get("display_name") or label).strip() if (label or payload.get("display_name")) else None, mode=mode, whitelist=whitelist, blacklist=blacklist, expires_at=exp_dt)
        db.add(k)
        try:
            await db.commit()
            await db.refresh(k)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="key exists")
        return {"id": k.id, "key": raw, "key_prefix": prefix, "label": k.label, "mode": k.mode}

    @app.post("/api/keys/{kid}/revoke", dependencies=[Depends(_require_internal)])
    async def revoke_key(kid: int, db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(ApiKey).where(ApiKey.id == kid))
        obj = res.scalars().first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")
        obj.active = False  # type: ignore[assignment]
        await db.commit()
        return {"ok": True}

    @app.get("/api/keys/dice")
    async def dice(len: int = Query(default=8, ge=4, le=64)) -> dict[str, str]:  # noqa: A002
        alphabet = string.ascii_letters + string.digits
        return {"dice": "".join(secrets.choice(alphabet) for _ in range(len))}

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
        api_key_ids = [r.api_key_id for r in rows if r.api_key_id]
        code_map: dict[int, Code] = {}
        api_key_map: dict[int, ApiKey] = {}
        if code_ids:
            cres = await db.execute(select(Code).where(Code.id.in_(code_ids)))
            for c in cres.scalars().all():
                code_map[c.id] = c
        if api_key_ids:
            kres = await db.execute(select(ApiKey).where(ApiKey.id.in_(api_key_ids)))
            for k in kres.scalars().all():
                api_key_map[k.id] = k
        response.headers["X-Total-Count"] = str(total)
        return [{"id": r.id, "ts": r.ts, "ip": r.ip, "host": r.host, "path": r.path, "action": r.action, "matched_action": r.matched_action, "request_id": r.request_id, "code_id": r.code_id, "api_key_id": r.api_key_id, "code_label": (code_map[r.code_id].display_name or code_map[r.code_id].label) if r.code_id and r.code_id in code_map else None, "code_value": code_map[r.code_id].code if r.code_id and r.code_id in code_map else None, "code_active": code_map[r.code_id].active if r.code_id and r.code_id in code_map else None, "api_key_label": (api_key_map[r.api_key_id].display_name or api_key_map[r.api_key_id].label) if r.api_key_id and r.api_key_id in api_key_map else None, "api_key_active": api_key_map[r.api_key_id].active if r.api_key_id and r.api_key_id in api_key_map else None} for r in rows]

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

    @app.get("/api/warnings")
    async def warnings(db=Depends(get_db)):  # type: ignore[no-untyped-def]
        res = await db.execute(select(RuleGroup).options(selectinload(RuleGroup.rules)).order_by(RuleGroup.display_order))
        groups = res.scalars().all()
        return _shadowed_warnings(groups)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    cfg = get_config()
    uvicorn.run("api.app:app", host="0.0.0.0", port=8002, reload=cfg.is_debug)
