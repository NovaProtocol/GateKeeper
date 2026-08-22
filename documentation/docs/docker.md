# Docker

## GateKeeper Image

**Dockerfile** — single-stage, cached, non-root (`reference/docker/dockerfile.md`):

```dockerfile
FROM python:3.14-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python3 -m compileall -q /app 2>/dev/null || true

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /app /data

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 7000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:7000", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-"]

USER appuser
```text

- Base `python:3.14-slim` — no custom `python3146t` free-threaded image.
- `COPY requirements.txt` before `COPY . .` caches the pip layer.
- `--no-cache-dir` on every `pip install`.
- `compileall` catches syntax errors at build time.
- `useradd --create-home --uid 10001 appuser` + `USER appuser` — verify with `docker run --rm <image> whoami` → `appuser`.
- `ENTRYPOINT ["/entrypoint.sh"]` fixes volume ownership (`chown -R appuser:appuser /data`) because named volumes retain root ownership from the pre-non-root era.
- `EXPOSE 7000` matches gunicorn bind and compose mapping.
- Gunicorn `gthread` with 1 worker / 4 threads; access + error logs to stdout (`-`).

## Documentation Image

**documentation/Dockerfile** — same base, `mkdocs build` in-image, granian on `8005`:

```dockerfile
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY documentation/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY documentation/ .

RUN mkdocs build

RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app

EXPOSE 8005

USER appuser

CMD ["granian", "--interface", "asgi", "--host", "0.0.0.0", "--port", "8005", "--workers", "1", "app:app"]
```

- Reuses the same slim base; no apt toolchains.
- `mkdocs` pinned: `mkdocs==1.6.1`, `mkdocs-material==9.7.6`, `mkdocs-glightbox==0.5.2`, `pymdown-extensions==11.0.1`.
- `CMD` is exec-form `granian --interface asgi` so signals reach PID 1.

## Compose

```yaml
name: gatekeeper

services:
  gatekeeper:
    container_name: gatekeeper_main
    build: .
    ports:
      - "127.0.0.1:7000:7000"
    environment:
      SECRET_KEY: ${SECRET_KEY:?SECRET_KEY is required}
      MANAGE_PASSWORD: ${MANAGE_PASSWORD:?MANAGE_PASSWORD is required}
      BACKUP_CODE: ${BACKUP_CODE:-}
      DB_DIR: /data
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7000/health', timeout=5)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    networks:
      - default
      - gatekeeper
      - cloudflared-tunnel
    volumes:
      - gatekeeper_data:/data
    restart: unless-stopped

  documentation:
    build:
      context: .
      dockerfile: documentation/Dockerfile
    container_name: gatekeeper_documentation
    restart: unless-stopped
    expose:
      - "8005"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8005/health', timeout=5)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    networks:
      - default

volumes:
  gatekeeper_data:

networks:
  default:
  gatekeeper:
    external: true
    name: gatekeeper_default
  cloudflared-tunnel:
    external: true
    name: cloudflared-tunnel_default
```text

- `container_name` is `<project>_<role>` (`gatekeeper_main`, `gatekeeper_documentation`) — what Caddy proxies to, never the service name.
- Secrets use `${VAR:?}` so compose fails fast with a clear message.
- `DB_DIR: /data` + named volume `gatekeeper_data:/data` persists SQLite.
- Documentation is **internal-only** (`expose`, no `ports:`) — `python -c urllib` healthcheck on `127.0.0.1:8005/health`, `networks: [default]`, `restart: unless-stopped`, no `depends_on`.
- Gatekeeper publishes loopback-only (`127.0.0.1:7000:7000`); public ingress is the Cloudflare Tunnel (external `cloudflared-tunnel_default`).

## .dockerignore

```
.venv/
venv/
.git/
__pycache__/
*.pyc
.env
.env.*
*.db
*.sqlite3
*.db-wal
*.db-shm
.mypy_cache/
.pytest_cache/
docs/
.agents/
.superpowers/
.opencode/
.claude/
.cursor/
.continue/
*.code-workspace
```text

`.env` and `*.db` never enter the build context; `docs/` keeps superpowers scratch out of the image.

## Running

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export MANAGE_PASSWORD=$(python3 -c "import secrets; print(secrets.token_hex(32))")
docker compose up -d --build
docker compose ps                    # 7000 must show 127.0.0.1:7000->7000
docker compose logs -f gatekeeper
docker compose exec gatekeeper python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:7000/health').read())"
# docs — from sibling container
docker compose exec gatekeeper python -c "import urllib.request; print(urllib.request.urlopen('http://gatekeeper_documentation:8005/health').read())"
docker compose down
```

`docker inspect gatekeeper_main --format '{{.HostConfig.Memory}}'` should be non-zero only if you add `mem_limit`; `deploy:` is not used (Swarm-only, ignored by compose).
