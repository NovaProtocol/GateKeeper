# Auth Flow

`GET /api/authz/forward-auth` is Caddy's `GateKeeper gate` check. Caddy sends `X-Forwarded-Uri`, `X-Forwarded-Host`, `X-Forwarded-Proto`; GateKeeper answers `200` or `302`. Apps never check tokens themselves.

```
Request → Caddy GateKeeper gate → Auth Gateway /api/authz/forward-auth
 ├─ Rule = none → 200
 ├─ Rule = deny → 403
 ├─ Rule = custom_password (cookie/header/qs)→ 200 or 302 to login
 ├─ Valid gatekeeper_token cookie → 200
 ├─ Valid ?access_code= (stripped) → 302 + Set-Cookie (rate-limited tries/min)
 └─ None → 302 → https://gatekeeper.<apex>/login?redirect=<original>
```

## Rule Dispatch

1. Load `RuleGroups` ordered by `display_order` (is_default `*.*/*` last).
2. `host_matches(group.domain, host)` — supports `*.` prefix and exact.
3. Within group, `Rules` ordered by `display_order`; first `path_matches(rule.path, uri.path)` wins (`/*` prefix).
4. No match → default group's first rule.

`CACHE_TTL=5s` in-memory under `asyncio.Lock` — auth-gateway loads `Route`+`RuleGroup` via `GET http://api:8002/api/routes|groups|rules` (`X-Internal-Api-Key` on `net-api` `internal:true`), `api:8002` is sole `shared/db.py` owner (`net-data`). All auth paths audit via `BackgroundTasks → POST http://api:8002/api/logs` (`X-Internal-Api-Key`, `internal:true`); on failure keep stale cache / drop audit — no direct DB fallback in `auth-gateway`.

## Cookie

`gatekeeper_token = PyJWT HS256` (`shared/jwt.py` `create_access_token(cid,name)` `iss=gatekeeper` `aud=projectnova.download` `exp 12h` `jti`). Verified as `verify_access_token(token)` checks `exp/aud/iss/signature` then `POST http://api:8002/api/auth/verify-code-id {cid}` checks `codes.active=1` + bumps `last_accessed` on `net-api` `internal:true`; `jwt.ExpiredSignatureError` / bad signature → no cookie.

## Magic Link

`?access_code=<code>` on any gated URL → `POST http://api:8002/api/auth/verify-code {code}` via `api:8002` → `Set-Cookie gatekeeper_token=PyJWT HS256` on `.<apex>` (`HttpOnly`, `Lax`, `Secure`, `Max-Age=43200` `exp 12h`) → `302` to same URL with param stripped (`urlsplit`/`parse_qsl`/`urlencode` keeps other params).

## Custom Password

Per-rule `custom_password_hash/salt` (`pbkdf2_hmac sha512 100k`). Checked as:
`gatekeeper_custom_{rule.id}` cookie (per-rule salt) → `X-Custom-Password` header → `?custom_password=` query. Sets per-rule cookie on success.

## Rate Limit (access_code tries/min)

`settings` `rate_limit_access_code_per_min` (default 5) enforced per-IP in `auth-gateway` via `POST /api/auth/check-rate-limit {ip}` on `api:8002` (`internal:true` `X-Internal-Api-Key`) — counts `audit_logs` last 60s. On deny → `429`.

## Login

`GET /` or `GET /login` → if valid cookie, redirect to `?redirect=` target (validated by `_safe_redirect_target` against apex). `POST /` / `POST /login` validates form `code`, sets `gatekeeper_token`, rate-limited `5/min` by `X-Forwarded-For[0]`.
