# GateKeeper

FastAPI gateway that protects every web app on one apex domain behind a signed access-code cookie. Caddy `forward_auth` is the only gate — apps hold zero auth code and zero GateKeeper secrets.

**Stack:** Python 3.14 · FastAPI + Granian · SQLAlchemy 2 (async) · MySQL 8.4 / SQLite · Caddy 2 · PyJWT · Docker Compose

## Services

| Service | Container | Port | Purpose | Network |
|---------|-----------|------|---------|---------|
| **Caddy** | `gatekeeper_caddy` | `:7000` (127.0.0.1) | Wildcard ingress + forward_auth | `gatekeeper_dynamic`, `cloudflared-tunnel` |
| **Auth Gateway** | `gatekeeper_auth` | `:8001` | forward_auth + wildcard proxy | `gatekeeper_dynamic`, `net-api` |
| **API** | `gatekeeper_api` | `:8002` + `:50051` (gRPC) | DB owner, CRUD, gRPC LogAuth | `net-api`, `net-data` |
| **Management** | `gatekeeper_management` | `:8003` | Admin UI (Jinja + CSRF) | `net-api` |
| **MySQL** | `gatekeeper_db` | `:3306` | Primary store | `net-data` |
| **Documentation** | `gatekeeper_phpmyadmin` | `:80` | DB UI (gated) | `net-data` |
| **Documentation** | `gatekeeper_documentation` | `:8005` | MkDocs (FastAPI + granian) | `default` |

Shared layer `shared/` holds `config.py` (pydantic-settings), `db.py` (async engine), `models.py` (7 tables), `security.py` (pbkdf2, host/path match), `error_pages.py`.

```mermaid
graph TB
    TUN["Cloudflare Tunnel / Browser"] --> CADDY["Caddy :7000<br/>wildcard"]
    CADDY --> AUTH["Auth Gateway :8001<br/>forward_auth + proxy"]
    AUTH --> API["API :8002 / :50051<br/>DB + gRPC"]
    AUTH --> MGMT["Management :8003<br/>Jinja UI"]
    AUTH --> DB[("MySQL / SQLite<br/>gatekeeper.db")]
    AUTH --> COOKIE["gatekeeper_token<br/>HttpOnly Lax Secure<br/>.apex"]
    CADDY --> DOC["Docs :8005<br/>FastAPI/granian"]
```

```
Request → Caddy → Auth Gateway /api/authz/forward-auth
                    ├─ valid gatekeeper_token     → 200 → proxy to Route upstream
                    ├─ valid ?access_code=        → 302 + Set-Cookie (apex)
                    ├─ valid custom_password/API key → 200 (per rule)
                    └─ neither                    → 302 → https://gatekeeper.<apex>/login?redirect=<original>
```

## Quick Links

| Link | Description |
|------|-------------|
| [Getting Started](getting-started.md) | Env vars, run locally + in Docker |
| [Architecture](architecture.md) | 7-service layout, DB, networks |
| [Auth Flow](auth-flow.md) | forward_auth, magic links, rule dispatch |
| [Cookie Contract](cookie-contract.md) | gatekeeper_token + siblings |
| [Management UI](manage-panel.md) | /manage/login, dashboard, CSRF |
| [Caddy Integration](caddy-integration.md) | Wildcard + per-app gating |
| [Docker](docker.md) | Images, compose, healthchecks |
| [Routes](routes.md) | DB-driven host→upstream |
| [Rules](rules.md) | Groups, actions, shadowing |
| [API Keys](api-keys.md) | Generation, transports, modes |
| [Logs & Warnings](logs.md) | Audit, top pages, dry-run |

## House Reference

Follows `agent_stuff/reference/`: `fastapi/` (routers, Granian), `docker/` (slim, loopback, external nets), `gatekeeper/` (single cookie, forward_auth, apex deduction), `conventions/docs-readme.md` (tracked `documentation/` MkDocs Material 1.6.1 on 8005).
