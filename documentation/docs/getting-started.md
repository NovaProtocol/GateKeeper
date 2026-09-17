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
| `LOG_RETENTION_DAYS` | no | Seeds the `log_retention_days` setting on a fresh volume (default `30`) |

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
| `https://gatekeeper.projectnova.download/api/authz/forward-auth` | GateKeeper gate (Caddy) |
| `https://gatekeeper.projectnova.download/health` | Health probe |
| `http://127.0.0.1:7000/health` | Local Caddy health |

Login sets `gatekeeper_token` (`PyJWT HS256` apex, `HttpOnly`, `Lax`, `Secure`) with a lifetime of `session_lifetime_hours` (default 12, so `Max-Age=43200`). Management login sets `manage_session` (`8h` `Path /manage`). Per-rule `gatekeeper_custom_{id}` follows the same visitor setting.

## 3. First Run: What the Panel Owns

A fresh volume seeds a row for every setting the panel edits, so `/manage/settings` shows the value the process is actually running with rather than a blank. Three things are therefore configured in the panel, not in the environment, and need no redeploy to change:

| Setting | Default | What to know before you touch it |
|---------|---------|----------------------------------|
| `log_retention_days` | `LOG_RETENTION_DAYS` (`30`) | The environment variable seeds it once; after that the setting wins, and only a restart or the **Prune now** button actually deletes rows, because there is no scheduler |
| `session_lifetime_hours` | `12` | Applies to visitor cookies only. `manage_session` keeps its own fixed `8h`, deliberately |
| `maintenance_mode` | `false` | Serves a `503` on every gated host. `/manage` and `/manage/login` stay reachable so you can turn it back off |

The environment variables that remain load-bearing are the ones that describe how the process starts: `SECRET_KEY`, `MANAGE_PASSWORD`, `DEPLOYMENT_TYPE`, `INTERNAL_API_KEY`, `DATABASE_URL`, `DB_DIR`. The settings page has a read-only environment panel that reports `DEPLOYMENT_TYPE`, the database backend, and whether the two secrets are configured, as presence only: it never reads or renders a secret value.

One habit worth forming on day one: take an export from `/manage/backup` before the first change you make. Rules, groups, routes, codes and settings live only in the database volume, with no git history and no migration to undo, so a wrong click has no other undo. See [Backup & Restore](backup.md).

## 4. Create Codes

1. Open `/manage/login` → enter `MANAGE_PASSWORD`.
2. Go to **Codes** → Create with explicit `code` value.
3. Share `https://app.example.com/page?access_code=<code>` — first hit sets cookie and strips param.

## 5. Local Dev (without Docker)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
SECRET_KEY=dev MANAGE_PASSWORD=dev DEPLOYMENT_TYPE=debug \
 python -m granian --interface asgi --host 127.0.0.1 --port 8001 auth-gateway.app:app
```
