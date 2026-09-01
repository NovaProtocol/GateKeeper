# Logs & Warnings

## Audit Logs

```bash
GET /api/logs?host=&ip=&action=&endpoint=&from=&to=&page=&per_page=
GET /api/logs/top?limit=&host=&path=
GET /api/logs/export?format=csv
DELETE /api/logs/clear  # internal key
POST /api/logs          # ingested from gateway
```

- Host/path filters use `LIKE%` glob.
- `X-Total-Count` header for pagination.
- Gateway logs via `BackgroundTasks → POST /api/logs` with DB fallback.

`GET /api/warnings` — shadowed groups/rules.
`POST /api/dry-run {host,path}` — preview what rule would match.

## Observability

- `RequestIDMiddleware` → `X-Request-ID` (echoed).
- `structlog` JSON on gateway.
- `CSPMiddleware` (`default-src self`) + `ProxyFixMiddleware` + `X-Forwarded-*`.
