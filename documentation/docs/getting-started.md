# Getting Started

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Docker & Docker Compose | Latest | Production stack (recommended) |
| Python | `3.14` (`.python-version`) | Local dev |
| `pip` / `venv` | stdlib | Dependency install |

---

## 1. Clone & Configure

```bash
git clone https://github.com/NovaProtocol/GateKeeper.git
cd GateKeeper
```text

Environment variables are injected by compose interpolation. Full list in `.env.example`:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | yes | Flask secret key for signing the auth cookie |
| `MANAGE_PASSWORD` | yes | HTTP Basic password for `/manage` |
| `BACKUP_CODE` | no | Fallback access code; seeded as `backup` row when missing |
| `DB_DIR` | no | Directory for `gatekeeper.db` (compose sets `/data`) |

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export MANAGE_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
# optional
export BACKUP_CODE=$(python3 -c "import secrets; print(secrets.token_hex(8))")
```

> No `.env` file is committed or loaded. Compose fails fast with `${VAR:?}` if `SECRET_KEY` or `MANAGE_PASSWORD` is unset. App reads strictly from `os.environ`.

---

## 2. Run Locally (dev)

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
SECRET_KEY=dev MANAGE_PASSWORD=dev .venv/bin/python app.py
# or: SECRET_KEY=dev MANAGE_PASSWORD=dev python app.py
```text

- Dev server: `http://127.0.0.1:7000/` (login) and `http://127.0.0.1:7000/health`
- `app.py` guards serving with `if __name__ == "__main__": app.run(host="0.0.0.0", port=7000)`.
- SQLite DB is created on first request via `before_request` (`_db_initialized` flag, WAL mode). A `BACKUP_CODE` row is seeded if absent.

---

## 3. Run in Docker (prod parity)

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export MANAGE_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
docker compose up -d --build
docker compose ps
docker compose logs -f gatekeeper
```

| URL | What |
|-----|------|
| `http://127.0.0.1:7000/` | Login page (public, via loopback) |
| `http://127.0.0.1:7000/manage` | Manage panel (Basic-auth) |
| `http://127.0.0.1:7000/api/authz/forward-auth` | forward_auth endpoint (Caddy calls it) |
| `http://127.0.0.1:7000/health` | Health probe (public) |
| `http://documentation:8005/health` (inside network) | Docs healthcheck |

First build installs `requirements.txt` (Flask, gunicorn, itsdangerous) and builds `documentation/` (MkDocs `site/` then `granian` on `8005`).

---

## 4. MkDocs Site Alone

```bash
pip install -r documentation/requirements.txt
mkdocs build --config-file documentation/mkdocs.yml
mkdocs serve --config-file documentation/mkdocs.yml  # http://127.0.0.1:8000
```text

Inside Docker, the docs container serves prebuilt `site/` via FastAPI + granian:

```bash
docker compose up -d --build documentation
# from sibling container
docker compose exec gatekeeper python -c "import urllib.request; print(urllib.request.urlopen('http://gatekeeper_documentation:8005/health').read())"
# local port-forward preview (if you publish)
docker run --rm --network gatekeeper_default curlimages/curl http://gatekeeper_documentation:8005/health
```

---

## 5. Create and Test Codes

1. Open `http://127.0.0.1:7000/manage` — Basic-auth user `admin`, password `$MANAGE_PASSWORD`.
2. Click **Create** (optional label) → 16-hex code in table.
3. Share magic link: `https://any-gated-app.example.com/some/page?access_code=<code>` — first visit sets cookie and strips the param.
4. Test forward_auth directly:

```bash
# no cookie → redirect to login
curl -si http://127.0.0.1:7000/api/authz/forward-auth -H "X-Forwarded-Uri: /private/" | head

# magic link → Set-Cookie + redirect to /private/
curl -si http://127.0.0.1:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /private/?access_code=<code>" | grep -i "set-cookie\|location"

# valid cookie → 200
curl -si http://127.0.0.1:7000/api/authz/forward-auth \
  -H "Cookie: gatekeeper_token=<serializer.dumps(code)>" \
  -H "X-Forwarded-Uri: /private/"
```text

---

## 6. Development Workflow

```bash
# Run tests
.venv/bin/pytest -q
# or: python -m pytest tests/ -v

# Format and lint (pre-commit)
pre-commit run --all-files

# Validate compose (fails on missing env)
docker compose config > /dev/null

# Rebuild one service
docker compose up -d --build gatekeeper
docker compose up -d --build documentation
```

> No migration CLI. Schema is self-healing: `CREATE TABLE IF NOT EXISTS codes`, plus `ALTER TABLE ADD COLUMN last_accessed` wrapped in try/except, committed via SQLite.
