# Docker

## Images

All services use `python:3.14-slim`, `PYTHONDONTWRITEBYTECODE=1`, `pip --no-cache-dir`, `compileall`, `USER appuser (10001)`.

| Service | Dockerfile | CMD |
|---------|------------|-----|
| auth-gateway | `auth-gateway/Dockerfile` | `granian --interface asgi --host 0.0.0.0 --port 8001` |
| api | `api/Dockerfile` | `granian --interface asgi --host 0.0.0.0 --port 8002` |
| management | `management/Dockerfile` | `granian --interface asgi --host 0.0.0.0 --port 8003` (+ jinja2, python-multipart) |
| caddy | `caddy/Dockerfile` | `caddy:2-alpine` |
| documentation | `documentation/Dockerfile` | `mkdocs build` then `granian --port 8005` |
| mysql-db | `mysql:8.4` | n/a |

## Compose

```yaml
name: gatekeeper
services:
 caddy: { build: ./caddy, ports: ["127.0.0.1:7000:7000"] }
 auth-gateway: { build: auth-gateway/Dockerfile, expose: [8001] }
 api: { build: api/Dockerfile, expose: [8002] }
 management: { build: management/Dockerfile, expose: [8003] }
 mysql-db: { image: mysql:8.4, expose: [3306] }
 documentation: { build: documentation/Dockerfile, expose: [8005] }
volumes: [gatekeeper_data, mysql_data]
networks: [default, net-api(internal), net-data(internal), gatekeeper(GateKeeper-owned)(external, caddy only)]
```

All healthchecks: `python -c "urllib.request.urlopen('http://127.0.0.1:<port>/health')"`.
Caddy is the only published port (`127.0.0.1:7000:7000`); others are `expose` internal.

## Build

```bash
docker compose build
docker compose up -d
```
