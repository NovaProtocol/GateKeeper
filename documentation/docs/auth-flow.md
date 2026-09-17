# Auth Flow

`GET /api/authz/forward-auth` is Caddy's `GateKeeper gate` check. Caddy sends `X-Forwarded-Uri`, `X-Forwarded-Host`, `X-Forwarded-Proto`; GateKeeper answers `200` or `302`. Apps never check tokens themselves.

```
Request → Caddy GateKeeper gate → Auth Gateway /api/authz/forward-auth
 ├─ Rule = none → 200
 ├─ Rule = deny → 403
 ├─ Rule = custom_password (cookie/header/qs)→ 200 or 302 to login
 ├─ Valid gatekeeper_token cookie → 200
 ├─ Valid ?access_code= (stripped) → 302 + Set-Cookie (rate-limited tries/min)
 ├─ No rule matched, host in a group → 302 → login (always; see Rule Dispatch)
 └─ No group matched the host → per `unmatched_action` (default 302 → login)
```

## Rule Dispatch

1. Load `RuleGroups` ordered by `display_order` (is_default `*.*/*` last).
2. `host_matches(group.domain, host)` — supports `*.` prefix and exact.
3. Within group, `Rules` ordered by `display_order`; first `path_matches(rule.path, uri.path)` wins (`/*` prefix).
4. No match → default group's first rule.

`shared/gate.py` holds the resolution (`find_group_rule`) and the decision (`resolve_rule_action`); both gate paths call it, so `forward_auth` and the wildcard proxy can no longer reach different verdicts about the same request. It distinguishes two states that used to look alike:

| State | Action |
|-------|--------|
| Rule matched | The rule's `action` |
| Group matched the host, no rule matched the path | **Always** redirect to login. Never governed by a setting. Every group is meant to end in a `/*` catch-all, so this state means that invariant is broken, and a setting must not be able to turn a config fault into an open proxy. |
| No group matched the host | `settings` `unmatched_action`, one of `access_code` (default) / `deny` / `none` |

The seeded default group's domain is `*.*/*`, which `host_matches` treats as "any host", so in a healthy database no request reaches the third row. Reaching it means the default group is missing or its `domain` no longer matches everything, which is why the setting exists as a backstop rather than as everyday policy.

`unmatched_action` reuses the rule vocabulary. `access_code` redirects to login (matching what `forward_auth` already did), `deny` returns the themed `403`, and `none` proxies without auth, which was the pre-existing behaviour, now explicit, named, and greppable rather than an `if rule is None: pass` branch nobody could see. On a fallback the audit row carries `matched_action` = the setting value with `rule_id`/`rule_group_id` null, so a fallback is distinguishable from a policy that allowed the request.

`auth-gateway` reads the setting through a 60s-cached `GET /api/settings/unmatched_action` (`X-Internal-Api-Key` on `net-api`); any error falls back to `access_code`, and that fallback is cached too, so a settings outage makes the gateway stricter rather than slower.

`CACHE_TTL=5s` in-memory under `asyncio.Lock` — auth-gateway loads `Route`+`RuleGroup` via `GET http://api:8002/api/routes|groups|rules` (`X-Internal-Api-Key` on `net-api` `internal:true`), `api:8002` is sole `shared/db.py` owner (`net-data`). All auth paths audit via `BackgroundTasks → POST http://api:8002/api/logs` (`X-Internal-Api-Key`, `internal:true`); on failure keep stale cache / drop audit — no direct DB fallback in `auth-gateway`.

## Cookie

`gatekeeper_token = PyJWT HS256` (`shared/jwt.py` `create_access_token(cid,name)` `iss=gatekeeper` `aud=projectnova.download` `exp 12h` `jti`). Verified as `verify_access_token(token)` checks `exp/aud/iss/signature` then `POST http://api:8002/api/auth/verify-code-id {cid}` checks `codes.active=1` + bumps `last_accessed` on `net-api` `internal:true`; `jwt.ExpiredSignatureError` / bad signature → no cookie.

## Magic Link

`?access_code=<code>` on any gated URL → `POST http://api:8002/api/auth/verify-code {code}` via `api:8002` → `Set-Cookie gatekeeper_token=PyJWT HS256` on `.<apex>` (`HttpOnly`, `Lax`, `Secure`, `Max-Age=43200` `exp 12h`) → `302` to same URL with param stripped (`urlsplit`/`parse_qsl`/`urlencode` keeps other params).

## Custom Password

Per-rule `custom_password_hash/salt` (`pbkdf2_hmac sha512 100k`). Checked as:
`gatekeeper_custom_{rule.id}` cookie (per-rule salt) → `X-Custom-Password` header → `?custom_password=` query. Sets per-rule cookie on success.

## Visitor IP

`audit_logs.ip`, the per-IP rate limiter, and the `X-Forwarded-For` header forwarded upstream all use `shared/client_ip.py:get_client_ip()`, which resolves in this order:

1. `CF-Connecting-IP` — set by Cloudflare at the edge, forwarded by cloudflared. The authoritative source.
2. `True-Client-IP`, then `X-Real-IP` — equivalent edge headers.
3. `X-Forwarded-For[0]` — kept as a fallback for non-Cloudflare callers.
4. The peer address.

`X-Forwarded-For` alone is **not** usable on this stack: cloudflared does not set it on the origin dial, so Caddy's `reverse_proxy` fills it with the immediate peer — the cloudflared container's own bridge address (`172.18.x.x`). Every visitor then collapsed into a single identity, and the per-IP rate limiter throttled all visitors as one. Result is truncated to 64 chars to match the `audit_logs.ip` column.

Trust model: only the tunnel may reach the origin (`gatekeeper_caddy` is the sole `cloudflared-tunnel` member and its port is loopback-bound to `127.0.0.1:7000`), so an inbound request cannot arrive from anywhere but Cloudflare. These headers are plain strings — if the origin ever becomes directly reachable they are forgeable.

## Rate Limit (access_code tries/min)

`settings` `rate_limit_access_code_per_min` (default 5) enforced per-IP in `auth-gateway` via `POST /api/auth/check-rate-limit {ip}` on `api:8002` (`internal:true` `X-Internal-Api-Key`) — counts `audit_logs` last 60s. On deny → `429`.

## Login

`GET /` or `GET /login` → if valid cookie, redirect to `?redirect=` target (validated by `_safe_redirect_target` against apex). `POST /` / `POST /login` validates form `code`, sets `gatekeeper_token`, rate-limited `5/min` per visitor IP (`shared/client_ip.py` — see Visitor IP above).
