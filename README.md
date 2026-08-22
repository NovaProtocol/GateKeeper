# GateKeeper

Lightweight Flask auth service that protects web apps through a reverse-proxy gate. A signed, non-expiring access-code cookie (`gatekeeper_token`) on the apex domain is the only credential; Caddy `forward_auth` checks it before any request reaches a protected app.

## How it works

```text
Request → Caddy forward_auth → GateKeeper /api/authz/forward-auth
                               ↓ valid gatekeeper_token cookie
                         200  → Caddy proxies to the app
                               ↓ no cookie, but valid ?access_code= param
                         302  → Caddy relays: Set-Cookie (apex, no expiry)
                                 + redirect to the same URL, param stripped
                               ↓ neither valid
                         302  → redirect to gatekeeper.<apex>/?redirect=<original URL>
```

Any URL on a gated domain can carry `?access_code=<code>` as a shareable magic link — no cookie needed, the code is stripped from the URL immediately after use.

The forward-auth endpoint is the **only** auth path. The old app-level flow (`/api/verify`, short-lived tickets) was removed — apps must not attempt their own GateKeeper checks.

Caddyfile example:

```caddy
example.com {
    forward_auth gatekeeper:7000 {
        uri /api/authz/forward-auth
    }
    reverse_proxy app:8080
}
```

The original request URL arrives in the `X-Forwarded-Uri` header (set by Caddy); `X-Forwarded-Proto` and `X-Forwarded-Host` are used to reconstruct absolute redirect targets.

## Quick Start

There is no `.env` file — values come from compose interpolation or exported
shell vars (compose interpolation; see `.env.example`).

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export MANAGE_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")

docker compose up -d
```

Visit `http://localhost:7000` to access the login page, or `http://localhost:7000/manage` to create access codes.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key for signing the auth cookie |
| `MANAGE_PASSWORD` | Yes | Password for the `/manage` admin panel |
| `BACKUP_CODE` | No | Seeds the "backup" access-code row whenever that row is missing from the codes table |
| `DB_DIR` | No | Where the SQLite DB lives; compose sets it to `/data` (default: app directory) |

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `GET /` | Public | Login page. Valid code sets cookie, redirects. |
| `POST /` | Public | Validate submitted code, set cookie, redirect. |
| `GET /api/authz/forward-auth` | Public | Caddy forward-auth endpoint. `200` = pass, `302` = set cookie from `?access_code=` or redirect to login. |
| `GET /manage` | Protected | Management UI — lists all codes. |
| `POST /manage/create` | Protected | Generate a new access code. |
| `POST /manage/invalidate` | Protected | Invalidate an existing code. |

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
SECRET_KEY=dev MANAGE_PASSWORD=dev python app.py
```

## Ports

| Port | Service |
|------|---------|
| 7000 | GateKeeper (gunicorn, loopback-bound — tunnel only) |

Ports are allotted in groups of 10 per project (GateKeeper owns the 7000 block).

## Domain Adaptation

No hardcoded domains. The cookie domain is dynamically extracted from `request.host`. If no `?redirect=` parameter is provided, the fallback redirect goes to `portfolio.<apex_domain>`.

404s on protected apps are handled by the apps themselves — GateKeeper never serves app content, only `200` pass responses or redirects.
