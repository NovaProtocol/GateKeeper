# Architecture

## Stack

| Layer | Choice |
|-------|--------|
| Runtime | Python 3.14-slim, Granian (ASGI) |
| Framework | FastAPI modular — `shared/` + 3 services, not a Flask monolith |
| Cookie | `PyJWT HS256` (`SECRET_KEY`, `iss=gatekeeper`, `aud=projectnova.download`, `exp 12h`) |
| DB | SQLAlchemy 2 async — `aiosqlite` (SQLite WAL) or `aiomysql` (MySQL 8.4). File `gatekeeper.db` at `DB_DIR=/data` |
| Docs | MkDocs Material 1.6.1 on `:8005`, FastAPI + granian, USER appuser |
| Proxy | Caddy 2 on `:7000` — wildcard `*.projectnova.download` → `forward_auth gatekeeper_auth:8001` → DB Route lookup |

## 7-Service Topology

```
project/
├── caddy/Caddyfile                 # :7000 wildcard, handle /health, /documentation/*, catch-all (no phpmyadmin)
├── caddy/Dockerfile                # caddy:2-alpine
├── shared/
│   ├── config.py                   # pydantic-settings: SECRET_KEY, MANAGE_PASSWORD, DATABASE_URL, INTERNAL_API_KEY, DEPLOYMENT_TYPE, BACKUP_CODE
│   ├── jwt.py                      # PyJWT HS256 iss=gatekeeper aud=projectnova.download exp 12h/8h/12h + jti
│   ├── models.py                   # 6 tables + settings + audit_logs (routes, rule_groups, rules, codes, settings, audit_logs with method/status_code/attempted_code)
│   ├── security.py                 # pbkdf2_hmac sha512 100k, host_matches, path_matches, mask_code, apex_domain
│   ├── error_pages.py              # wants_html, render_error_html (dark theme)
│   └── db.py                       # create_async_engine, async_sessionmaker, get_db() — imported only by api:8002 (net-data)
├── auth-gateway/app.py             # :8001 — RequestID, ProxyFix, CSP, slowapi, forward_auth + wildcard proxy (net-api → api:8002, no DB)
├── api/app.py                      # :8002 + :50051 gRPC — lifespan create_all + migrations + seed (net-data sole writer)
├── management/app.py               # :8003 — Jinja2 + StaticFiles, /manage/* UI (net-api → api:8002, no DB)
├── documentation/                  # MkDocs site (this site)
└── compose.yaml                    # 6 services (caddy, auth-gateway, api, management, mysql-db, documentation), gatekeeper_data + mysql_data
```

### Compose Services

| Service | Build | Expose | Networks |
|---------|-------|--------|----------|
| caddy | `caddy/Dockerfile` | `127.0.0.1:7000:7000` | default, gatekeeper, cloudflared-tunnel, gatekeeper_dynamic, net-data |
| auth-gateway | `auth-gateway/Dockerfile` | 8001 | default, net-api (`internal:true`), gatekeeper_dynamic — no `net-data`, no `gatekeeper_data:/data`, no `shared/db.py` |
| api | `api/Dockerfile` | 8002, 50051 | net-api (`internal:true`), net-data (`internal:true`), gatekeeper_dynamic — sole `shared/db.py` owner (`gatekeeper_data:/data` + `mysql_data`) |
| management | `management/Dockerfile` | 8003 | default, net-api (`internal:true`) — no `net-data`, no `shared/db.py` |
| mysql-db | `mysql:8.4` | 3306 | net-data (`internal:true`) |
| documentation | `documentation/Dockerfile` | 8005 | default |

All healthchecks: `python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:<port>/health')"`.

## Data Model (6 tables + settings)

| Table | Key columns |
|-------|-------------|
| `routes` | `host, path, route_type(proxy|redirect), upstream, port, redirect_target, redirect_code` |
| `rule_groups` | `name unique, domain, display_order, is_default` |
| `rules` | `group_id, path, action(access_code|none|custom_password|deny), custom_password_hash/salt, allow_ip, allow_time, rate_limit, display_order` |
| `codes` | `code unique, label, display_name, active, last_accessed` |
| `settings` | `key PK, value, updated_at` — e.g. `rate_limit_access_code_per_min` |
| `audit_logs` | `ts, ip, host, path, action, code_id, rule_group_id, rule_id, method, status_code, attempted_code, latency_ms, request_id, user_agent, referer` |

`allow_ip / allow_time / rate_limit` on `rules` are **reserved** (stored, not enforced on hot path).

### DB Init

`api/app.py:lifespan` runs `create_all`, then `ALTER TABLE` migrations (try/except), seeds default `*.*/*` group (`/* → access_code`), public groups `gatekeeper.projectnova.download` + `projectnova.download` (`/* → none`), and `BACKUP_CODE` if set. Reseats `display_order` so `*.*/*` stays bottom.

## Auth Flow (summary)

```
Browser → Caddy :7000 → Auth Gateway :8001 /api/authz/forward-auth
  ├─ Rule lookup: RuleGroups ASC display_order → host_matches → Rules ASC → path_matches → first wins
  ├─ 200 / 302 / 403 per rule action
  └─ on pass: longest-path Route match → proxy to upstream or redirect
```

Cache: in-memory `RuleGroup+Route` polled every `CACHE_TTL=5s` under `asyncio.Lock` via `GET http://api:8002/api/routes|groups|rules` (`X-Internal-Api-Key` on `net-api` `internal:true`) — only `api:8002` imports `shared/db.py`. Code verification is `POST /api/auth/verify-*` on `net-api`. Audit via `BackgroundTasks → POST http://api:8002/api/logs` (`X-Internal-Api-Key` `internal:true`) + rate-limit `POST /api/auth/check-rate-limit {ip}` for `?access_code=` tries/min; `POST /api/routes/{id}/test` `socket.create_connection((upstream,port))` needs `api` on `gatekeeper_dynamic` to reach `portfolio_main:8000` etc.

## Networks

```
default, net-api (internal), net-data (internal),
gatekeeper_dynamic (external gatekeeper_dynamic),
gatekeeper (external gatekeeper_default),
cloudflared-tunnel (external cloudflared-tunnel_default)
```

Caddy terminates TLS at Cloudflare Tunnel; after tunnel, traffic is plain HTTP on `cloudflared-tunnel_default`. Only Caddy joins the public networks; apps stay internal.

## Ports

| Port | Service |
|------|---------|
| 7000 | Caddy (only published, loopback) |
| 8001 | Auth Gateway |
| 8002 | API (REST) + 50051 gRPC |
| 8003 | Management UI |
| 8005 | Docs |
| 3306 | MySQL (internal) |
