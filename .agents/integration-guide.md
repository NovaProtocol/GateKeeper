# GateKeeper Integration Guide

Reference for AI agents integrating a new web app with GateKeeper (the auth
service in this repo). Read this before writing any GateKeeper-related code.

## What GateKeeper is

A minimal Flask auth service. One access code grants access to every subdomain
of the same apex domain (e.g. `*.projectnova.download`). Auth state is a single
signed, non-expiring cookie (`gatekeeper_token`) set on the apex domain.

There is exactly one integration mode: **reverse-proxy forward auth**. The
old app-level flow (`/api/verify`, short-lived tickets, `gatekeeper_check`
hooks) was **removed** — do not re-introduce it, and do not add any other auth
path. The forward-auth endpoint is the only way to authenticate.

## Mode A — Caddy forward auth (the only mode)

The gate lives in the reverse proxy. Every request on a protected site is
forwarded to GateKeeper's authz endpoint before it can reach the app.

### Contract

`GET /api/authz/forward-auth` (internal network, plain HTTP):

| Input | Behavior |
|-------|----------|
| Valid `gatekeeper_token` cookie | `200` empty body → Caddy proxies the request to the app |
| No cookie, valid `?access_code=` on the original URL | `302` + `Set-Cookie` (apex, HttpOnly, Lax, no expiry) + `Location` = same URL with the param stripped |
| Neither | `302` → `https://gatekeeper.<apex>/?redirect=<original URL>` |

Check order is fixed: cookie first, then param. Caddy relays every non-2xx
response to the client untouched, so the redirect and the `Set-Cookie` both
reach the browser. The endpoint is a pure check-and-respond: it never serves
content.

### Caddyfile

```caddy
# Caddy >= 2.5.1 — forward_auth is core, no plugins needed
:7020 {
    handle /webhook/* {
        reverse_proxy webhook-container:8009   # public callbacks bypass the gate
    }
    handle /customer/* {
        forward_auth gatekeeper:7000 {
            uri /api/authz/forward-auth
        }
        reverse_proxy customer-portal:8002
    }
    # ...every other handle gets the same forward_auth block
}
```

Notes:

- The auth upstream is `gatekeeper:7000` — reachable only over the
  `gatekeeper_default` external Docker network. Add that network to the proxy
  container's `networks:` list if it isn't there.
- Leave any path public by simply not putting `forward_auth` in its `handle`.
- Caddy adds `X-Forwarded-Uri` (original path+query), `X-Forwarded-Host`, and
  `X-Forwarded-Proto` to the auth request. GateKeeper uses all three — do not
  strip or override them.

### Shareable magic links

Any URL on a gated domain works as a login link when `?access_code=` is
appended. First visit: cookie is set, user lands on the page, code is stripped
from the URL. Afterwards the cookie covers everything, no param needed.

### Network topology

```
Cloudflare Tunnel → Caddy (gateway, joins gatekeeper_default) → GateKeeper :7000
                       └── forward_auth check → 200/302
                       └── then reverse_proxy → app container
```

- GateKeeper must NOT be reachable through the public tunnel — it answers
  internal calls and the LAN/host port only.
- The `gatekeeper_token` cookie is set on the apex domain, so one login covers
  every subdomain. No per-app secret sharing.
- Protected apps must NOT join the `gatekeeper_default` network or hold any
  GateKeeper env vars — the proxy is the only client.

### Machine clients (scraper, mobile apps, API calls)

The forward-auth endpoint accepts only the cookie or the `access_code` param.
Machine clients cannot do the redirect dance. They must call the app over an
internal/LAN route that bypasses the gate, or have their own token check
inside the app (the app's own API auth is separate from GateKeeper).

## Cookie details

- Name: `gatekeeper_token`
- Value: `URLSafeSerializer(SECRET_KEY, salt="cookie")` of the raw code
- Domain: apex (`.projectnova.download`), derived dynamically from
  `request.host` — never hardcode domains
- Attributes: `HttpOnly`, `SameSite=Lax`, `Path=/`, no expiry
- Tamper-evident: any modification breaks the signature; an invalid cookie is
  treated as "no cookie"

## Environment variables (GateKeeper)

| Variable | Required | Purpose |
|----------|----------|---------|
| `SECRET_KEY` | yes | Signs the auth cookie. |
| `MANAGE_PASSWORD` | yes | Basic auth for `/manage`. |
| `BACKUP_CODE` | no | Seeds a fallback code if the table is empty. |

## Testing the forward-auth endpoint

```bash
SECRET_KEY=dev MANAGE_PASSWORD=dev python app.py   # dev server on :7000

curl -si http://localhost:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /staff/"                     # → 302 to login
curl -si http://localhost:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /staff/?access_code=test123" # → 302 to /staff/ + Set-Cookie
curl -si -b "gatekeeper_token=<cookie>" \
  -H "X-Forwarded-Uri: /staff/"                     # → 200
```

## Pitfalls

- **Do not expose GateKeeper publicly.** It is an internal service; the
  forward-auth endpoint is called over Docker networks only.
- **Do not add auth to the apps.** No `gatekeeper_check`, no `/api/verify`
  calls, no shared secrets. The proxy gates everything; the app is naked
  behind it.
- **404s belong to the apps.** GateKeeper never serves content — it returns
  `200` (pass) or redirects. A nonexistent path on a gated domain 404s from
  the backend app after passing the gate.
- **`?redirect=` is user-controlled** (login page and forward-auth both).
  If you ever add validation, restrict it to the apex domain.
- **Code-in-URL exposure**: an `access_code` in a URL is visible in browser
  history until the 302 strips it. Codes are instantly revocable — treat them
  like passwords in logs and chat.
- **SameSite=Lax** cookies are sent on top-level navigation across subdomains
  of the same site — iframes and embedded apps on the same apex work; truly
  cross-site embeds will not get the cookie.
