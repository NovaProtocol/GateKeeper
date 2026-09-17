# Auth Flow

`GET /api/authz/forward-auth` is Caddy's `GateKeeper gate` check. Caddy sends `X-Forwarded-Uri`, `X-Forwarded-Host`, `X-Forwarded-Proto`; GateKeeper answers `200` or `302`. Apps never check tokens themselves.

```
Request → Caddy GateKeeper gate → Auth Gateway /api/authz/forward-auth
 ├─ maintenance_mode on (non-manage host) → 503 themed page
 ├─ Rule = none → 200
 ├─ Rule = deny → 403
 ├─ Rule = custom_password (cookie/header/qs)→ 200 or 302 to login
 ├─ Valid gatekeeper_token cookie → 200
 ├─ Valid ?access_code= (stripped) → 302 + Set-Cookie (rate-limited tries/min)
 ├─ No rule matched, host in a group → 302 → login (always; see Rule Dispatch)
 └─ No group matched the host → per `unmatched_action` (default 302 → login)
```

## Maintenance Mode

`maintenance_mode` (default `false`) is checked in **both** gate paths, from `auth-gateway/app.py:_maintenance_response`, **before rule dispatch**. The order is the point: the switch has to mean the same thing on every host, and if it were consulted per rule then whether a visitor saw the maintenance page would depend on which rule happened to match, which is not something an operator turning a switch on wants to reason about.

When it is on:

- A request from a browser gets a themed `503` with `Retry-After: 300`; the same request with an `Accept` that wants JSON gets `503 {"detail": "maintenance mode"}` instead. The page is `shared/error_pages.py:render_maintenance_html`, the same document as every other gateway error, because an outage is the worst moment to make a visitor learn a second layout.
- `maintenance_message` is rendered into it, escaped, and is the operator's own line. Blank means the page says nothing extra.
- An audit row is written per refused request with `action` and `matched_action` both `maintenance_mode` and `rule_id` / `rule_group_id` / `code_id` null, so the switch is visible in the log it is explained by rather than invisible.
- `/manage` and `/manage/login` on the gatekeeper host are **exempt**, and the rest of that host is not: `/documentation` on the same host still gets the `503`. Without the exemption a maintenance switch would also hide the page that turns it off, which is a foot-gun rather than a feature. The exemption is a host check and a path check together, matched on the hostname ignoring any port.
- The API is untouched, so `X-Internal-Api-Key` callers still work. That is the escape hatch if the panel is ever unreachable for another reason.

### How it interacts with fail-closed

Maintenance mode runs **above** rule dispatch, so a request that `access_code` would have gated never reaches the gate while the switch is on: it gets the `503`, not a redirect to login, and the upstream is not dialled. The fail-closed invariant underneath is unchanged and no setting can reach it: a group that matched the host with no matching rule is still refused, and with maintenance on that refusal is expressed as the `503` rather than the redirect. `unmatched_action=none` cannot turn either state into a proxy.

Turning the switch off restores the previous behaviour exactly, because nothing about rule resolution was modified by it.

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

`auth-gateway` reads the setting through a 60s-cached `GET /api/settings/unmatched_action` (`X-Internal-Api-Key` on `net-api`); any error falls back to `access_code`, and that fallback is cached too, so a settings outage makes the gateway stricter rather than slower. Every value it does read is passed through `shared/settings_spec.py:read_value()` first, so a row edited by hand or restored from an older file cannot be acted on unless the panel's own validation would accept it.

`CACHE_TTL=5s` in-memory under `asyncio.Lock` — auth-gateway loads `Route`+`RuleGroup` via `GET http://api:8002/api/routes|groups|rules` (`X-Internal-Api-Key` on `net-api` `internal:true`), `api:8002` is sole `shared/db.py` owner (`net-data`). All auth paths audit via `BackgroundTasks → POST http://api:8002/api/logs` (`X-Internal-Api-Key`, `internal:true`); on failure keep stale cache / drop audit — no direct DB fallback in `auth-gateway`.

## Cookie

`gatekeeper_token = PyJWT HS256` (`shared/jwt.py` `create_access_token(cid,name,expires_hours)` `iss=gatekeeper` `aud=projectnova.download` `exp 12h` `jti`). Verified as `verify_access_token(token)` checks `exp/aud/iss/signature` then `POST http://api:8002/api/auth/verify-code-id {cid}` checks `codes.active=1` + bumps `last_accessed` on `net-api` `internal:true`; `jwt.ExpiredSignatureError` / bad signature → no cookie.

### Session lifetime

The visitor cookie's lifetime is the `session_lifetime_hours` setting (default `12`, accepted `1..720`), not a constant. `_set_auth_cookie` and `_set_custom_cookie` pass it to `create_access_token` / `create_custom_token` as `expires_hours` **and** to `set_cookie(max_age=...)`, so the cookie's `Max-Age` and the JWT's `exp` are always the same number of seconds and are set from one read.

They are set together on purpose. A cookie that outlives its own token fails on its next request, and a token that outlives its cookie is a credential the browser has already thrown away; either mismatch is a bug that only shows up `N` hours after a settings change, which is the worst time to find it.

Changing the setting does not touch a cookie that is already issued. Existing visitors keep the lifetime they were given until they log in again, at which point the new value applies. Lowering it is therefore not an instant revocation: use `codes.active=0` for that.

**`manage_session` is a separate lifetime and deliberately does not follow this setting.** It stays at its own fixed 8 hours (`shared/jwt.py:create_manage_token`), and the admin login sets it independently. An admin session and a visitor session are different trust levels; one dial for both would mean that extending a visitor's access also extends the operator's, and that shortening a visitor's access could sign the operator out mid-work. The two numbers are visible side by side on the settings page so the asymmetry is not a surprise.

## Magic Link

`?access_code=<code>` on any gated URL → `POST http://api:8002/api/auth/verify-code {code}` via `api:8002` → `Set-Cookie gatekeeper_token=PyJWT HS256` on `.<apex>` (`HttpOnly`, `Lax`, `Secure`, `Max-Age` = `session_lifetime_hours` × 3600, `exp` the same) → `302` to same URL with param stripped (`urlsplit`/`parse_qsl`/`urlencode` keeps other params).

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

## Visitor country

`audit_logs.country` holds the visitor's country, resolved by `shared/geo.py:get_country()` from `CF-IPCountry`, the same edge header family as `CF-Connecting-IP`. Country level only: two uppercase letters, `XX` (Cloudflare's unknown) and `T1` (a Tor exit) treated as absent, everything else discarded rather than trimmed into shape. No city, no coordinates derived from the visitor address, no lookup service.

The gateway reads it once per request, gated by the `geo_lookup_enabled` setting (default `true`), and sends it with the audit payload; `api` stores it after the same validation. Both ends tolerate the key being absent, so a gateway container that predates the column cannot break logging, and a stale one cannot store a value the reader would refuse.

**Unverified:** that cloudflared forwards `CF-IPCountry` to the origin was not testable from the build environment. The design degrades to `NULL`, which the audit page reports as `Unknown`; see [Logs & Audit](logs.md) for the fallback and the post-deploy check.

## Rate Limit (access_code tries/min)

`settings` `rate_limit_access_code_per_min` (default 5) enforced per-IP in `auth-gateway` via `POST /api/auth/check-rate-limit {ip}` on `api:8002` (`internal:true` `X-Internal-Api-Key`) — counts `audit_logs` last 60s. On deny → `429`.

## Login

`GET /` or `GET /login` → if valid cookie, redirect to `?redirect=` target (validated by `_safe_redirect_target` against apex). `POST /` / `POST /login` validates form `code`, sets `gatekeeper_token`, rate-limited `5/min` per visitor IP (`shared/client_ip.py` — see Visitor IP above).
