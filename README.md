# GateKeeper

FastAPI gateway that protects web apps through a reverse-proxy gate. A signed, expiring 12h JWT cookie (`gatekeeper_token` `PyJWT HS256` `iss=gatekeeper` `aud=projectnova.download` `exp 12h` `jti`) on the apex domain is the primary credential; `manage_session` (`8h` `Path /manage`) and per-rule `gatekeeper_custom_{id}` (`12h` `rid`) share the same `SECRET_KEY` (`Field(min_length=32)`). `codes.active=0` revokes instantly via `api:8002` (`internal:true` `X-Internal-Api-Key`). `settings.rate_limit_access_code_per_min` rate-limits `?access_code=` tries/min. All traffic enters via Caddy `:7000` (wildcard `*.projectnova.download`).

## How it works

```
Request → Caddy :7000 → Auth Gateway :8001 /api/authz/forward-auth
                          ├─ valid gatekeeper_token        → 200 → proxy to Route upstream
                          ├─ valid ?access_code=           → 302 + Set-Cookie (stripped)
                          ├─ valid custom_password → 200
                          ├─ group matched, no rule matched → 302 → login (always)
                          └─ no group matched              → `unmatched_action` (default 302)
```

Any gated URL can carry `?access_code=<code>` as a magic link — stripped after setting the cookie.

Rule resolution and the unmatched-request decision live in `shared/gate.py` and are used by **both** gate paths, so `forward_auth` and the wildcard proxy cannot reach different verdicts about the same request. A host that is in no rule group follows `settings.unmatched_action`: `access_code` (default, redirect to login), `deny` (403), or `none` (proxy without auth). A group that matched the host with no matching rule is always refused, whatever the setting says.

Every group carries exactly one `/*` catch-all (`rules.is_default`), forced last, and the API refuses to delete, reorder or rename it: `/*` is a reserved path and deleting the group is the only way to remove its catch-all. A group created through `POST /api/groups` seeds one with `action=access_code`, because gating is the default. The boot backfill in `shared/rule_defaults.py` establishes and reports the invariant on an existing database.

**Stack:** Python 3.14 · FastAPI + Granian · SQLAlchemy 2 (async) · MySQL 8.4 / SQLite · Caddy 2 · PyJWT

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Caddy | 7000 | Wildcard ingress, forward_auth |
| Auth Gateway | 8001 | forward_auth + wildcard proxy |
| API | 8002 | DB owner, CRUD |
| Management | 8003 | Admin UI |
| MySQL | 3306 | Store |
| Documentation | 8005 | MkDocs (gated) |

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
| `GET /manage`, `/routing`, `/rules`, `/codes`, `/logs`, `/audit`, `/top-pages`, `/settings` | manage | Admin pages |
| `GET /manage/monitoring` | manage | `302` alias to `/manage/audit`, kept so old bookmarks land |
| `GET /manage/backup`, `/manage/backup/download`, `POST /manage/backup/restore` | manage | Configuration export and restore (`confirm=REPLACE`, `stage=preview\|apply`) |
| `POST /manage/groups/{gid}/order`, `POST /manage/rules/{rid}/order` | manage | Reorder rule groups and rules up/down (refused on the pinned default group and catch-all) |
| `POST /manage/codes/{cid}/active`, `POST /manage/codes/{cid}/delete` | manage | Activate/deactivate a code, or delete it permanently against a typed `confirm_code` |
| `POST /manage/groups/{gid}/edit`, `POST /manage/rules/{rid}/edit` | manage | Edit a rule group (`name`, `domain`) or a rule (`path`, `action`) |
| `GET /api/routes`, `/groups`, `/rules`, `/codes`, `/logs`, `/settings`, `/warnings` | internal (`X-Internal-Api-Key` on `net-api`) | REST API (`/api/codes` hides inactive rows unless `?include_inactive=true`) |
| `PUT /api/groups/{gid}`, `PUT /api/rules/{rid}` | internal (`X-Internal-Api-Key`) | Update a group or rule; each field is validated only when present in the body |
| `PUT /api/codes/{cid}`, `DELETE /api/codes/{cid}` | internal (`X-Internal-Api-Key`) | Activate/deactivate a code (`active`, booleans or `"true"`/`"false"`/`"1"`/`"0"`); `DELETE` removes it permanently and nulls `audit_logs.code_id` |
| `PUT /api/settings/{key}` | internal (`X-Internal-Api-Key`) | Update a setting; `rate_limit_access_code_per_min` is `1..1000`, `unmatched_action` is `access_code`/`deny`/`none` |
| `GET /api/backup`, `POST /api/backup/restore` | internal (`X-Internal-Api-Key`) | Export the configuration as signed plain JSON; restore it (`?dry_run=1` verifies without writing) |

## Domain Adaptation

No hardcoded domains. Cookie domain is last two labels of host (`.example.com`). Fallback is `portfolio.<apex>`. `?redirect=` hosts validated against apex.

## Backup

Rules, groups, routes, codes and settings live only in the database volume, with no git history and no migration to undo. `/manage/backup` exports them as signed plain JSON and restores them from the same page.

The signature (`HMAC-SHA256` over the canonicalised `config`, keyed by `SECRET_KEY`) proves the file came from this deployment and has not been altered. **It does not hide anything**: the file is plain text and contains every access code, so store it like a password. Restoring replaces all five sections in one transaction; audit references that no longer resolve are nulled rather than deleted.
