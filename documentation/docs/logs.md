# Logs & Warnings

## Audit Logs

```bash
GET /api/logs?host=&ip=&action=&endpoint=&from=&to=&page=&per_page=&code= # ?endpoint=host/path glob, ?code= label/code masked
GET /api/logs/top?limit=&host=&path=
GET /api/logs/export?format=csv
GET /api/logs/by-ip?limit=50 # grouped by ip → {calls, recent[5], codes}
DELETE /api/logs/clear # X-Internal-Api-Key
POST /api/logs # internal ingest — auth-gateway BackgroundTasks X-Internal-Api-Key
POST /api/auth/check-rate-limit {ip} # X-Internal-Api-Key → {allowed,count,limit}
GET|PUT /api/settings[/{key}] # settings table — PUT needs X-Internal-Api-Key
```

- Host/path filters use `LIKE%` glob; `code` matches `code_label/code_value/attempted_code`.
- `X-Total-Count` header for pagination; `/manage/logs` does infinite scroll (`IntersectionObserver` → `GET /manage/logs?format=json&page=N` → `X-Total-Count`).
- `GET /manage/monitoring` shows `GET /api/logs/by-ip` grouped by the visitor IP — recent pages + access code per IP (`shared/client_ip.py` resolves it from `CF-Connecting-IP`, not `X-Forwarded-For` — see Auth Flow → Visitor IP).
- `GET /manage/settings` is DB-backed (`settings` table `rate_limit_access_code_per_min` tries/min); `POST /manage/settings` validates `1..1000` with `csrf_token` + `same_origin`.

`GET /api/warnings` — shadowed groups/rules.
`POST /api/dry-run {host,path}` — preview what rule would match.

## Observability

- `RequestIDMiddleware` → `X-Request-ID` (echoed).
- `structlog` JSON on gateway.
- `CSPMiddleware` (`default-src self`) + `ProxyFixMiddleware` + `X-Forwarded-*`.
- `audit_logs.ip` holds the **visitor** address (max 64 chars) — resolved by `shared/client_ip.py`, never the cloudflared container's bridge address.
