# GateKeeper

FastAPI gateway that protects web apps through a reverse-proxy gate. A signed, non-expiring access-code cookie (`gatekeeper_token`) on the apex domain is the primary credential; per-rule custom passwords and API keys cover special cases. All traffic enters via Caddy `:7000` (wildcard `*.projectnova.download`).

## How it works

```
Request → Caddy :7000 → Auth Gateway :8001 /api/authz/forward-auth
                          ├─ valid gatekeeper_token        → 200 → proxy to Route upstream
                          ├─ valid ?access_code=           → 302 + Set-Cookie (stripped)
                          ├─ valid custom_password/API key → 200
                          └─ neither                       → 302 → https://gatekeeper.<apex>/login?redirect=<original>
```

Any gated URL can carry `?access_code=<code>` as a magic link — stripped after setting the cookie.

**Stack:** Python 3.14 · FastAPI + Granian · SQLAlchemy 2 (async) · MySQL 8.4 / SQLite · Caddy 2 · PyJWT

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Caddy | 7000 | Wildcard ingress, forward_auth |
| Auth Gateway | 8001 | forward_auth + wildcard proxy |
| API | 8002 + 50051 (gRPC) | DB owner, CRUD, LogAuth |
| Management | 8003 | Admin UI |
| MySQL | 3306 | Store |
| Documentation | 8005 | MkDocs (gated) |
| Documentation | 8005 | MkDocs |

## Quick Start

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export MANAGE_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export DEPLOYMENT_TYPE=production
docker compose up -d
```

Visit `https://gatekeeper.projectnova.download/` (login) or `/manage/login` for admin.

## Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | yes | Signing key |
| `MANAGE_PASSWORD` | yes | `/manage/login` password |
| `DEPLOYMENT_TYPE` | yes | `debug` or `production` |
| `INTERNAL_API_KEY` | no | Protects `POST /api/*` |
| `DATABASE_URL` | no | `mysql+aiomysql://` or `sqlite+aiosqlite://` |
| `BACKUP_CODE` | no | Seeded backup code |
| `DB_DIR` | no | `/data` in container |

## Routes

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /`, `POST /`, `GET /login`, `POST /login` | — | Login (sets `gatekeeper_token`) |
| `GET /api/authz/forward-auth` | — | Caddy forward_auth (200/302/403) |
| `GET /manage/login`, `POST /manage/login` | — | Management login (sets `manage_session`) |
| `GET /manage/logout` | manage | Clear session |
| `GET /manage`, `/routing`, `/rules`, `/codes`, `/logs`, `/top-pages`, `/warnings` | manage | Admin pages |
| `GET /api/routes`, `/groups`, `/rules`, `/codes`, `/keys`, `/logs` | internal/api key | REST API |

## Domain Adaptation

No hardcoded domains. Cookie domain is last two labels of host (`.example.com`). Fallback is `portfolio.<apex>`. `?redirect=` hosts validated against apex.
