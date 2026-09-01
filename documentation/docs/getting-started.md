# Getting Started

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Docker & Compose | latest |
| Python 3.14 | for local dev |

## 1. Configure

```bash
git clone https://github.com/NovaProtocol/GateKeeper.git
cd GateKeeper
```

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | yes | Signing key (32+ hex chars) |
| `MANAGE_PASSWORD` | yes | Password for `/manage/login` |
| `DEPLOYMENT_TYPE` | yes | `debug` or `production` |
| `INTERNAL_API_KEY` | no | Gate for `POST /api/*` from management |
| `DATABASE_URL` | no | `mysql+aiomysql://...` or `sqlite+aiosqlite:////data/gatekeeper.db` |
| `BACKUP_CODE` | no | Seeded as `backup` code if missing |
| `DB_DIR` | no | `/data` in container |

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export MANAGE_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export DEPLOYMENT_TYPE=production
```

No `.env` file is committed. Compose fails with `${VAR:?}` if required vars are missing.

## 2. Run

```bash
docker compose up -d --build
docker compose ps
```

| URL | Purpose |
|-----|---------|
| `https://gatekeeper.projectnova.download/` | Login (`GET /`, `POST /`, `GET /login`) |
| `https://gatekeeper.projectnova.download/manage/login` | Management login |
| `https://gatekeeper.projectnova.download/api/authz/forward-auth` | forward_auth (Caddy) |
| `https://gatekeeper.projectnova.download/health` | Health probe |
| `http://127.0.0.1:7000/health` | Local Caddy health |

Login sets `gatekeeper_token` (apex, HttpOnly, Lax, Secure, no expiry). Management login sets `manage_session` (`/manage`, 8h).

## 3. Create Codes

1. Open `/manage/login` → enter `MANAGE_PASSWORD`.
2. Go to **Codes** → Create with explicit `code` value.
3. Share `https://app.example.com/page?access_code=<code>` — first hit sets cookie and strips param.

## 4. Local Dev (without Docker)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
SECRET_KEY=dev MANAGE_PASSWORD=dev DEPLOYMENT_TYPE=debug \
  python -m granian --interface asgi --host 127.0.0.1 --port 8001 auth-gateway.app:app
```
