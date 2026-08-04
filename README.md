# GateKeeper

Lightweight Flask auth service that protects web apps through a reverse-proxy gate. A signed, non-expiring access-code cookie (`gatekeeper_token`) on the apex domain is the only credential; Caddy `forward_auth` checks it before any request reaches a protected app.

## How it works

```
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

```bash
cp .env.example .env
# edit .env with your SECRET_KEY and MANAGE_PASSWORD

docker compose up -d
```

Visit `http://localhost:7000` to access the login page, or `http://localhost:7000/manage` to create access codes.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key for signing the auth cookie |
| `MANAGE_PASSWORD` | Yes | Password for the `/manage` admin panel |
| `BACKUP_CODE` | No | Falls back to this code if no codes exist |

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

## Domain Adaptation

No hardcoded domains. The cookie domain is dynamically extracted from `request.host`. If no `?redirect=` parameter is provided, the fallback redirect goes to `portfolio.<apex_domain>`.

404s on protected apps are handled by the apps themselves — GateKeeper never serves app content, only `200` pass responses or redirects.
