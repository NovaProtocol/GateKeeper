# GateKeeper

FastAPI gateway that protects web apps through a reverse-proxy gate. A signed, expiring JWT cookie (`gatekeeper_token` `PyJWT HS256` `iss=gatekeeper` `aud=projectnova.download` `exp` = `session_lifetime_hours`, default 12h, `jti`) on the apex domain is the primary credential; `manage_session` (`8h` `Path /manage`) and per-rule `gatekeeper_custom_{id}` (`session_lifetime_hours`) share the same `SECRET_KEY` (`Field(min_length=32)`). `codes.active=0` revokes instantly via `api:8002` (`internal:true` `X-Internal-Api-Key`). `settings.rate_limit_access_code_per_min` rate-limits `?access_code=` tries/min. All traffic enters via Caddy `:7000` (wildcard `*.projectnova.download`).

## How it works

```
Request → Caddy :7000 → Auth Gateway :8001 /api/authz/forward-auth
                          ├─ maintenance_mode on           → 503 (manage hosts exempt)
                          ├─ valid gatekeeper_token        → 200 → proxy to Route upstream
                          ├─ valid ?access_code=           → 302 + Set-Cookie (stripped)
                          ├─ valid custom_password → 200
                          ├─ rule action `none` + a matching custom page → the page body
                          ├─ group matched, no rule matched → 302 → login (always)
                          └─ no group matched              → `unmatched_action` (default 302)
```

Any gated URL can carry `?access_code=<code>` as a magic link — stripped after setting the cookie.

Rule resolution and the unmatched-request decision live in `shared/gate.py` and are used by **both** gate paths, so `forward_auth` and the wildcard proxy cannot reach different verdicts about the same request. A host that is in no rule group follows `settings.unmatched_action`: `access_code` (default, redirect to login), `deny` (403), or `none` (proxy without auth). A group that matched the host with no matching rule is always refused, whatever the setting says.

Every group carries exactly one `/*` catch-all (`rules.is_default`), forced last, and the API refuses to delete, reorder or rename it: `/*` is a reserved path and deleting the group is the only way to remove its catch-all. A group created through `POST /api/groups` seeds one with `action=access_code`, because gating is the default. The boot backfill in `shared/rule_defaults.py` establishes and reports the invariant on an existing database.

Behaviour an operator can change while the gateway runs lives in the `settings` table, described once in `shared/settings_spec.py`: `unmatched_action`, `rate_limit_access_code_per_min`, `session_lifetime_hours`, `maintenance_mode`, `maintenance_message`, `log_retention_days` and `geo_lookup_enabled`. All seven are editable on `/manage/settings`, which also shows a read-only environment panel (`DEPLOYMENT_TYPE`, database backend, and whether the two secrets are configured, as presence only). The visitor cookie's lifetime is `session_lifetime_hours`; `manage_session` keeps its own fixed `8h` and deliberately does not follow it. Maintenance mode serves a themed `503` on every gated host while keeping `/manage` reachable, so the switch cannot lock the operator out. Retention prunes at API startup and on demand, with no scheduler.

`/manage/audit` shows where visitors came from, next to the per-visitor table. `audit_logs.country` is a two-letter code read from `CF-IPCountry` by `shared/geo.py`, gated by `geo_lookup_enabled`, country level only: no city, no coordinates from a visitor's own address, no lookup service. `GET /api/logs/geo?mode=views|visitors|gated|blocked` aggregates it and the page draws radius-scaled circle markers rather than a heat layer, because one centroid per country is not a density surface. Whether cloudflared forwards `CF-IPCountry` to the origin is not yet verified; if it does not, every row stores `NULL` and the page reports `Unknown` instead of failing.

When a route's upstream fails, the gateway keeps the two causes apart: `502` when nothing is listening and `504` when the connection was accepted and went quiet. Both go through the same `_error_response` helper as every other gateway error, so a browser gets the themed page and an `Accept: application/json` caller gets JSON with the upstream and port named.

GateKeeper can also answer a request itself. A **custom page** is a body matched by a `host-glob/path-glob` pattern (`*.projectnova.download/robots.txt`), with a priority, ▲/▼ reordering and a deactivate switch on `/manage/pages`. Pages sit below GateKeeper's own control plane and are served **only** where the governing rule's action is `none`, so a page cannot open a gate that was closed: the check runs inside the `none` branch and every gating action is untouched. `*` crosses `/` rather than stopping at it, the stored bytes are served unmodified, and `X-Content-Type-Options: nosniff` makes the stored content type authoritative — so an HTML body must not be labelled `text/plain`. Docs: [Custom Pages](documentation/docs/custom-pages.md).

Routing and Rules each have a **Test before saving** button in their add and edit modals. It asks the server about the values currently typed, without saving: `POST /api/routes/test` connects to the named upstream and port, and `POST /api/dry-run` reports which rule would win and whether the path is shadowed. Reachability means something is listening, not that it is the right application.

`Content-Security-Policy`, `X-Content-Type-Options` and `Referrer-Policy` are defined once, in `shared/csp.py`, and applied by a `CSPMiddleware` in both `auth-gateway/app.py` and `management/app.py`; neither service holds a header value of its own. A response from the management service reaches a browser through the gateway, which writes its own headers over the upstream's, so a second copy there is a replacement for the management service's policy rather than a fallback. The two had drifted and the gateway's stale `img-src` refused the audit map's OpenStreetMap tiles, which is why the value now lives in one file. Docs: [Architecture § Security headers](documentation/docs/architecture.md).

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
| `LOG_RETENTION_DAYS` | no | Seeds the `log_retention_days` setting on a fresh volume (default `30`) |

## Routes

| Route | Auth | Purpose |
|-------|------|---------|
| `GET /`, `POST /`, `GET /login`, `POST /login` | — | Login (sets `gatekeeper_token`) |
| `GET /api/authz/forward-auth` | — | Caddy forward_auth (200/302/403) |
| `GET /manage/login`, `POST /manage/login` | — | Management login (sets `manage_session`) |
| `GET /manage/logout` | manage | Clear session |
| `GET /manage`, `/routing`, `/rules`, `/codes`, `/pages`, `/logs`, `/audit`, `/top-pages`, `/settings` | manage | Admin pages |
| `GET /manage/monitoring` | manage | `302` alias to `/manage/audit`, kept so old bookmarks land |
| `POST /manage/logs/prune` | manage | Delete audit rows past the retention window (`confirm=PRUNE`); `back=audit` renders the count on the Audit page instead of the settings page |
| `POST /manage/logs/clear` | manage | Delete every audit row (`confirm=DELETE`), checked on the server alongside CSRF and `same_origin` |
| `GET /manage/backup`, `/manage/backup/download`, `POST /manage/backup/restore` | manage | Configuration export and restore (`confirm=REPLACE`, `stage=preview\|apply`) |
| `POST /manage/groups/{gid}/order`, `POST /manage/rules/{rid}/order` | manage | Reorder rule groups and rules up/down (refused on the pinned default group and catch-all) |
| `POST /manage/codes/{cid}/active`, `POST /manage/codes/{cid}/delete` | manage | Activate/deactivate a code, or delete it permanently against a typed `confirm_code` |
| `POST /manage/groups/{gid}/edit`, `POST /manage/rules/{rid}/edit` | manage | Edit a rule group (`name`, `domain`) or a rule (`path`, `action`) |
| `POST /manage/routing/test`, `POST /manage/rules/test` | manage | Test the values currently typed into a route or rule modal before saving (`{ok, note}` / the gate's verdict); write nothing |
| `POST /manage/pages`, `POST /manage/pages/{pid}/edit`, `/{pid}/active`, `/{pid}/order`, `/{pid}/delete` | manage | Create, edit, toggle, reorder or delete a custom page |
| `POST /api/pages`, `PUT /api/pages/{pid}`, `DELETE /api/pages/{pid}`, `PUT /api/pages/{pid}/order` | internal (`X-Internal-Api-Key`) | Custom-page writes; `PUT` is partial, and the order endpoint no-ops at the ends |
| `GET /api/routes`, `/groups`, `/rules`, `/codes`, `/pages`, `/logs`, `/settings`, `/warnings` | internal (`X-Internal-Api-Key` on `net-api`) | REST API (`/api/codes` hides inactive rows unless `?include_inactive=true`; `/api/pages` is keyless like `/api/routes`) |
| `POST /api/routes/test` | internal (`X-Internal-Api-Key`) | Probe a route that has not been saved yet: `{route_type, upstream, port, redirect_target}`; a dead upstream is `200` with `ok: false`, a bad shape is `400`. Shares its probe with `POST /api/routes/{rid}/test` |
| `PUT /api/groups/{gid}`, `PUT /api/rules/{rid}` | internal (`X-Internal-Api-Key`) | Update a group or rule; each field is validated only when present in the body |
| `PUT /api/codes/{cid}`, `DELETE /api/codes/{cid}` | internal (`X-Internal-Api-Key`) | Activate/deactivate a code (`active`, booleans or `"true"`/`"false"`/`"1"`/`"0"`); `DELETE` removes it permanently and nulls `audit_logs.code_id` |
| `PUT /api/settings/{key}` | internal (`X-Internal-Api-Key`) | Update a setting, validated per key in `shared/settings_spec.py`: `unmatched_action` is `access_code`/`deny`/`none`, `rate_limit_access_code_per_min` is `1..1000`, `session_lifetime_hours` is `1..720`, `maintenance_mode` is `true`/`false`, `maintenance_message` is at most 200 characters, `log_retention_days` is `7..3650`, `geo_lookup_enabled` is `true`/`false` |
| `GET /api/logs/geo` | none | Per-country totals (`mode=views|visitors|gated|blocked`, default `views`; optional `host`, `from`, `to`) with centroids and a marker radius; `null` country rows are reported as `Unknown` |
| `POST /api/logs/prune` | internal (`X-Internal-Api-Key`) | Delete audit rows older than the retention window; `?days=` overrides the stored setting |
| `GET /api/backup`, `POST /api/backup/restore` | internal (`X-Internal-Api-Key`) | Export the configuration as signed plain JSON; restore it (`?dry_run=1` verifies without writing) |

## Domain Adaptation

No hardcoded domains. Cookie domain is last two labels of host (`.example.com`). Fallback is `portfolio.<apex>`. `?redirect=` hosts validated against apex.

## Backup

Rules, groups, routes, codes, settings and custom pages live only in the database volume, with no git history and no migration to undo. `/manage/backup` exports them as signed plain JSON and restores them from the same page.

The signature (`HMAC-SHA256` over the canonicalised `config`, keyed by `SECRET_KEY`) proves the file came from this deployment and has not been altered. **It does not hide anything**: the file is plain text and contains every access code, so store it like a password. Restoring replaces the whole configuration in one transaction; audit references that no longer resolve are nulled rather than deleted. `pages` is an optional section, so a file written before custom pages existed still validates and restores.
