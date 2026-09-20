# Architecture

## Stack

| Layer | Choice |
|-------|--------|
| Runtime | Python 3.14-slim, Granian (ASGI) |
| Framework | FastAPI modular, `shared/` + 3 services, not a Flask monolith |
| Cookie | `PyJWT HS256` (`SECRET_KEY`, `iss=gatekeeper`, `aud=projectnova.download`, `exp` = `session_lifetime_hours`, default 12h) |
| DB | SQLAlchemy 2 async, `aiosqlite` (SQLite WAL) or `aiomysql` (MySQL 8.4). File `gatekeeper.db` at `DB_DIR=/data` |
| Docs | MkDocs Material 1.6.1 on `:8005`, FastAPI + granian, USER appuser |
| Proxy | Caddy 2 on `:7000`, wildcard `*.projectnova.download` → `gatekeeper_auth:8001` → DB Route lookup |

## 6-Service Topology

```
project/
├── caddy/Caddyfile # :7000 wildcard, handle /health, /documentation/*, catch-all (no phpmyadmin)
├── caddy/Dockerfile # caddy:2-alpine
├── shared/
│ ├── config.py # pydantic-settings: SECRET_KEY, MANAGE_PASSWORD, DATABASE_URL, INTERNAL_API_KEY, DEPLOYMENT_TYPE, BACKUP_CODE
│ ├── jwt.py # PyJWT HS256 iss=gatekeeper aud=projectnova.download exp configurable/8h/configurable + jti
│ ├── csp.py # the site-wide security headers (CONTENT_SECURITY_POLICY, SECURITY_HEADERS, apply_security_headers)
│ ├── models.py # 7 tables + settings + audit_logs (routes, rule_groups, rules, codes, custom_pages, settings, audit_logs with method/status_code/attempted_code/country)
│ ├── settings_spec.py # the settings table: accepted values, defaults, fallback direction
│ ├── security.py # pbkdf2_hmac sha512 100k, host_matches, path_matches, mask_code, apex_domain
│ ├── pages.py # custom-page patterns: split_pattern, glob_match, sample_from_pattern
│ ├── gate.py # rule dispatch + the unmatched-request decision (find_group_rule, resolve_rule_action)
│ ├── geo.py # country resolution from CF-IPCountry + the static centroid table (country level only)
│ ├── backup.py # signed plain-JSON export/restore of the config tables (HMAC-SHA256 over `config`)
│ ├── rule_defaults.py # boot backfill: exactly one `/*` catch-all per group, forced last
│ ├── error_pages.py # wants_html, render_error_html, render_maintenance_html (dark theme)
│ └── db.py # create_async_engine, async_sessionmaker, get_db(), imported only by api:8002 (net-data)
├── auth-gateway/app.py # :8001, RequestID, ProxyFix, CSP, slowapi, wildcard proxy (net-api → api:8002, no DB)
├── api/app.py # :8002, lifespan create_all + migrations + seed (net-data sole writer)
├── management/app.py # :8003, Jinja2 + StaticFiles, /manage/* UI (net-api → api:8002, no DB)
├── documentation/ # MkDocs site (this site)
└── compose.yaml # 6 services (caddy, auth-gateway, api, management, mysql-db, documentation), gatekeeper_data + mysql_data
```

### Compose Services

| Service | Build | Expose | Networks |
|---------|-------|--------|----------|
| caddy | `caddy/Dockerfile` | `127.0.0.1:7000:7000` | default, gatekeeper (owned), sole tunnel ingress, no `net-data` |
| auth-gateway | `auth-gateway/Dockerfile` | 8001 | default, net-api (`internal:true`), gatekeeper (owned), no `net-data`, no `gatekeeper_data:/data`, no `shared/db.py` |
| api | `api/Dockerfile` | 8002 | net-api (`internal:true`), net-data (`internal:true`), gatekeeper (owned), sole `shared/db.py` owner (`gatekeeper_data:/data` + `mysql_data`) |
| management | `management/Dockerfile` | 8003 | default, net-api (`internal:true`), no `net-data`, no `shared/db.py` |
| mysql-db | `mysql:8.4` | 3306 | net-data (`internal:true`) |
| documentation | `documentation/Dockerfile` | 8005 | default |

All healthchecks: `python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:<port>/health')"`.

## Data Model (7 tables + settings)

| Table | Key columns |
|-------|-------------|
| `routes` | `host, path, route_type(proxy|redirect), upstream, port, redirect_target, redirect_code` |
| `rule_groups` | `name unique, domain, display_order, is_default` |
| `rules` | `group_id, path, action(access_code|none|custom_password|deny), custom_password_hash/salt, allow_ip, allow_time, rate_limit, display_order, is_default, active` |
| `codes` | `code unique, label, display_name, active, last_accessed` |
| `custom_pages` | `pattern unique (host-glob/path-glob), body, content_type, active, display_order, created_at, updated_at` |
| `settings` | `key PK, value, updated_at`. Keys the panel edits: `unmatched_action` (`access_code`/`deny`/`none`), `rate_limit_access_code_per_min` (1..1000), `session_lifetime_hours` (1..720), `maintenance_mode` (`true`/`false`), `maintenance_message` (≤200 chars), `log_retention_days` (7..3650), `geo_lookup_enabled` (`true`/`false`). The accepted values, defaults and fallback direction for each live in `shared/settings_spec.py`, which the API validator, both reader services and the manage form all read |
| `audit_logs` | `ts, ip, host, path, action, code_id, rule_group_id, rule_id, method, status_code, attempted_code, country, latency_ms, request_id, user_agent, referer` |

`audit_logs.country` is a two-character code resolved from `CF-IPCountry` by `shared/geo.py`, or `NULL` when the header is absent, a Cloudflare sentinel, or not a country code. It is added to a live table by the guarded `ALTER TABLE ... ADD COLUMN` block in `api/app.py:_migrate_audit`, which also creates `ix_audit_logs_country`, and it is **never back-filled**: rows written before the column existed stay `NULL` and are reported as `Unknown` rather than guessed at from an address. Country level only, no city and no coordinates derived from a visitor's own address.

`allow_ip / allow_time / rate_limit` on `rules` are **reserved** (stored, not enforced on hot path).

### The settings table

Settings are the third source of gateway behaviour, alongside the rule tables and the compose environment. The split is deliberate: anything an operator changes while the gateway is running is a `settings` row, and anything that describes how the process was started stays in the environment.

`shared/settings_spec.py` is the single description of every key: accepted values, default, and the direction to fall back in when a stored value is unusable. Four things read it and none of them repeats a rule from it:

1. `api/app.py` validates `PUT /api/settings/{key}` against it, so an invalid value is refused at the only write path and cannot reach the database through the API at all.
2. `shared/settings_spec.py` normalises a stored value on the reader side, and `auth-gateway` goes through `read_value()` (via `as_int` / `as_bool`) for every settings value it acts on. The database can still be edited by hand or restored from an older backup, and no reader may act on a value the writer would have rejected. A `NULL` row is one of those cases and takes the same fallback as any other unusable value, which matters because `NULL` stringified is `"none"`, a valid and permissive `unmatched_action`.
3. The `api` lifespan seeds a row for every key the panel edits, so the page shows the value the process is actually running with rather than a blank that means "default".
4. `management/app.py` builds the settings form from `MANAGE_FIELDS`, so a key cannot exist in the database and be unreachable in the UI.

Fallbacks are chosen to be the *safe* reading of each key rather than the convenient one: `unmatched_action` falls back to `access_code` (refuse what it cannot classify) and `maintenance_mode` falls back to `false`, because defaulting a gateway into an outage on a settings blip would take the site down rather than protect it. A key whose value cannot be read is never more permissive than the documented default.

Two keys have an environment variable that seeds them rather than a constant default: `log_retention_days` is seeded from `LOG_RETENTION_DAYS`, and both accept the environment value only when it is itself in range, so an out-of-range variable falls back to the built-in window rather than seeding a row the panel would refuse to edit.

### Where the settings act

The gate consults settings at three points, in this order, in both gate paths:

```
request
  ├─ 1. maintenance_mode        → 503 themed page (manage hosts exempt)
  ├─ 2. find_group_rule         → group + rule, or group + none, or none + none
  └─ 3. resolve_rule_action     → the rule's action, or a refusal, or unmatched_action
          ↑ session_lifetime_hours is read where a cookie is minted, not here
```

Serving order once the action is known:

```
maintenance → custom page (only when the action is `none`) → rule dispatch
            → cookie → ?access_code= → redirect
```

Steps 2 and 3 are `shared/gate.py` and are the fail-closed core: a group that matched the host with no matching rule is always refused, while a host in no group follows `unmatched_action`. Step 1 sits above both so the maintenance switch means the same thing on every host and cannot be reached around. Because step 1 runs first, a request that `access_code` would have gated receives the `503` instead of a login redirect while maintenance is on, and turning it off restores exactly the previous behaviour. See [Auth Flow](auth-flow.md) for the decision table and [Rules](rules.md) for the catch-all invariant.

### Configuration vs history

The six **configuration** tables above (`routes`, `rule_groups`, `rules`,
`codes`, `custom_pages`, `settings`) hold only in the `gatekeeper_data` volume,
are not seeded from git, and have no migration to undo. `audit_logs` is
**history** and is never touched by a configuration change.

`shared/backup.py` exports the configuration as signed plain JSON and restores it
in one transaction. `custom_pages` is exported as an **optional** section, so a
file written before it existed still validates and restores. The signature
(HMAC-SHA256 over the canonicalised `config`, keyed by `SECRET_KEY`) covers
integrity only: the file contains every access code in cleartext. Row ids are
preserved so `audit_logs.code_id` / `rule_id` / `rule_group_id` keep resolving; a
reference the restored configuration no longer satisfies is nulled, never
cascaded into a deleted log row. See Backup & Restore.

### Boot migrations kept on purpose

Three pieces of code read like leftovers and are not. Each one is the mechanism
by which a database or a backup file written by an older build survives a deploy:

| Code | What it rescues |
|------|-----------------|
| `api/app.py:_migrate_routes` | A `routes` table that predates `path`, `route_type`, `redirect_target` or `redirect_code`, or whose `upstream` / `port` columns were still `NOT NULL`, or that still carries the single-column `ix_routes_host` index. It adds the columns, and where the old shape cannot be altered in place it rebuilds the table through `routes_new` and copies the rows across. |
| `shared/rule_defaults.py:add_is_default_column` | A `rules` table created before `rules.is_default` existed. `PRAGMA table_info` first, then `ALTER TABLE`, so it runs once and is inert afterwards. |
| `shared/rule_defaults.py:add_rule_active_column` | A `rules` table created before `rules.active` existed. Same guard; the constant `DEFAULT 1` means existing rows come back active. |
| `shared/backup.py:derive_rule_defaults` / `RULES_HAVE_IS_DEFAULT` | A **backup file** written before `rules.is_default` was a column. The flag is derived at read time rather than required from the file, so an older export still restores. `RULES_HAVE_IS_DEFAULT` is a capability probe for a database whose `rules` table genuinely lacks the column, and it is why `VERSION` stays `1`, bumping it would refuse those files. |

There is no Alembic in this stack: these guarded `ALTER TABLE` blocks *are* the
migration path, and deleting one would strand every deployment that has not yet
booted the newer schema.

### DB Init

`api/app.py:lifespan` runs `create_all`, then `ALTER TABLE` migrations (try/except; `audit_logs` gains `method`, `status_code`, `attempted_code` and `country` plus their indexes, and a `country` index is created in the same pass as the column rather than the one after), seeds default `*.*/*` group (`/* → access_code`), public groups `gatekeeper.projectnova.download` + `projectnova.download` (`/* → none`), and `BACKUP_CODE` if set. Reseats `display_order` so `*.*/*` stays bottom. It then backfills the per-group catch-all invariant (`shared/rule_defaults.py`), seeds a `settings` row for every key the panel edits, and runs one audit-log retention sweep inside a guarded `try/except` so a boot never fails on housekeeping.

## Auth Flow (summary)

```
Browser → Caddy :7000 → Auth Gateway :8001 /api/authz/forward-auth
 ├─ Rule lookup: RuleGroups ASC display_order → host_matches → Rules ASC → path_matches → first wins
 ├─ 200 / 302 / 403 per rule action
 ├─ on a `none` action: serve the matching custom page, if one exists
 └─ on pass: longest-path Route match → proxy to upstream or redirect
```

Cache: in-memory `RuleGroup+Route+custom page` polled every `CACHE_TTL=5s` under `asyncio.Lock` via `GET http://api:8002/api/routes|groups|rules|pages` (`X-Internal-Api-Key` on `net-api` `internal:true`), only `api:8002` imports `shared/db.py`. Code verification is `POST /api/auth/verify-*` on `net-api`. Audit via `BackgroundTasks → POST http://api:8002/api/logs` (`X-Internal-Api-Key` `internal:true`) + rate-limit `POST /api/auth/check-rate-limit {ip}` for `?access_code=` tries/min; `POST /api/routes/{id}/test` and `POST /api/routes/test` both `socket.create_connection((upstream,port))` and need `api` on `gatekeeper` to reach `portfolio_main:8000` etc.

## Security headers

`shared/csp.py` is the only definition of `Content-Security-Policy`,
`X-Content-Type-Options` and `Referrer-Policy`. Two services serve HTML on this
stack, `auth-gateway:8001` and `management:8003`, and each has a `CSPMiddleware`
that calls `apply_security_headers(response)` on the way out. Neither holds a
header value of its own, and `tests/test_csp.py` asserts that both send the
shared constant byte for byte and that no literal reappears in either app.

The single definition is not tidiness, it is the fix for a defect. A response
from the management service reaches a browser through the gateway, which buffers
it and writes its own headers over the upstream's. Only one of the two
`Content-Security-Policy` values can survive that, and it is the gateway's, so a
second copy in the gateway is not a fallback for the management service's copy
but a replacement for it. The two had drifted: the management service allowed
the OpenStreetMap tile hosts the audit map loads in `img-src`, the gateway's copy
stopped at `'self' data:`, and every tile on `/manage/audit` was refused with
nothing on the page to say so. The order of edits is the trap, not the CSP
itself: whichever service was updated second was the only one that mattered, and
which one that was changed as the header was maintained.

The policy is the union of what both services load and nothing else, so widening
it shows up as a diff in one file. Directive by directive:

| Directive | Hosts | Why |
|-----------|-------|-----|
| `default-src` | `'self'` | the floor for anything not named below |
| `script-src` | `'self'`, `cdn.jsdelivr.net`, `stackpath.bootstrapcdn.com`, `cdnjs.cloudflare.com`, `static.cloudflareinsights.com` | Bootstrap and Font Awesome, Leaflet, the Cloudflare Web Analytics beacon. `'unsafe-inline'` is required by the inline bootstrap script and the inline styles in the base template |
| `style-src` | the same, plus `fonts.googleapis.com` | Bootstrap and Font Awesome stylesheets, the Google Fonts stylesheet |
| `font-src` | `'self'`, `fonts.gstatic.com`, `cdnjs.cloudflare.com` | Inter and JetBrains Mono, Font Awesome's webfonts |
| `img-src` | `'self'`, `data:`, `cdn.jsdelivr.net`, `tile.openstreetmap.org`, `*.tile.openstreetmap.org` | the audit map's raster tiles. jsdelivr is here because Leaflet resolves its own default marker images relative to the script URL, and `data:` because several templates embed small inline images |
| `connect-src` | `'self'` | the pages use no `fetch`/`XHR`; every dynamic element is server-rendered or a form post |
| `frame-src` | `'self'`, `*.projectnova.download`, `portfolio.projectnova.download` | the gateway serves gated project pages in an iframe on the landing page |
| `frame-ancestors` | `'self'`, `portfolio.projectnova.download`, `*.projectnova.download` | who may frame these pages, the inverse of `frame-src` |

The tile hosts are named in `img-src` and nowhere else, because tiles arrive as
`<img>` elements through the Leaflet layer and no other directive has any use for
them: `tests/test_csp.py` asserts the host has not leaked into `script-src`,
`style-src`, `connect-src`, `font-src` or `default-src`. A policy that appears to
allow more than the page needs is a policy nobody can reason about later.

## When an upstream fails

A routed host whose container is not answering used to return a bare JSON body whatever the caller asked for, and every failure reported the same status. Both are now decided in `auth-gateway/app.py` `_proxy_to_upstream`, and the two failure classes are kept apart:

| Failure | Status | What it means |
|---------|--------|---------------|
| `httpx.ConnectError` | `502 Upstream unavailable` | nothing is listening on that address |
| `httpx.TimeoutException` | `504 Upstream timed out` | the connection was accepted and then went quiet |
| any other transport error | `502 Upstream unavailable` | the gateway could not complete the request |

They are distinct because they have different causes and different fixes. "Nothing is listening" points at a stopped or misnamed container; "accepted and went quiet" points at a process that is running but stuck, under load, or holding a connection it will not answer. Collapsing the two, as one `except Exception` did, sends the operator to look in the wrong place. `httpx.ConnectTimeout` is a `TimeoutException` and not a `ConnectError`, so the branch order cannot misclassify it, and a connect that times out is reported as a timeout because that is what it was.

All three go through the shared `_error_response` helper, which is the same one the `404` route-not-found path already used. It branches on `wants_html(request)`:

- a browser (an `Accept` header containing `text/html`) gets `render_error_html` from `shared/error_pages.py`, the dark-theme document every other gateway error uses, so an outage is not the moment to learn a second layout;
- an API caller (`Accept: application/json`) gets `{"detail": …}` with the upstream and port named;
- anything else gets the detail as plain text.

The status is the same in every case, so the caller can branch on it without parsing the body. Themed or not, an upstream failure is never a `200`. A route whose upstream is alive is unaffected: this is the error path only.


## Networks

```
default, net-api (internal), net-data (internal),
gatekeeper (GateKeeper-owned routable network, `name: gatekeeper`), join = permission to receive traffic,
cloudflared-tunnel (external cloudflared-tunnel)
```

Caddy terminates TLS at Cloudflare Tunnel; after tunnel, traffic is plain HTTP on `cloudflared-tunnel`. Only Caddy joins the public networks; apps stay internal.

## Ports

| Port | Service |
|------|---------|
| 7000 | Caddy (only published, loopback) |
| 8001 | Auth Gateway |
| 8002 | API (REST) |
| 8003 | Management UI |
| 8005 | Docs |
| 3306 | MySQL (internal) |
