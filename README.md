# GateKeeper

Lightweight Flask auth service that protects access to other web apps (e.g., a portfolio site) by requiring a valid access code. Issues short-lived tickets so protected apps can cache auth state without calling GateKeeper on every request.

## How it works

```
User → Protected App → [check cookie for ticket (in-memory cache, 5 min TTL)]
                          ↓ no valid ticket / expired
                    GateKeeper /api/verify?token=<signed_code>
                          ↓ valid
                    Returns signed ticket (5-min TTL)
                          ↓
                    Protected app caches ticket, serves page

User → Protected App → [no cookie at all]
                          ↓
                    Redirect → gatekeeper.<apex>/?redirect=<current_url>
                          ↓
                    GateKeeper shows login form
                    Valid code → cookie set
                    Redirect back
```

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
| `SECRET_KEY` | Yes | Flask secret key for signing cookies/tickets |
| `MANAGE_PASSWORD` | Yes | Password for the `/manage` admin panel |
| `BACKUP_CODE` | No | Falls back to this code if no codes exist |

## Routes

| Route | Method | Description |
|-------|--------|-------------|
| `GET /` | Public | Login page. Valid code sets cookie, redirects. |
| `POST /` | Public | Validate submitted code, set cookie, redirect. |
| `GET /api/verify?token=` | Public | Verify a signed code, return ticket. |
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
