# Logs & Warnings

## Audit Logs

```bash
GET /api/logs?host=&ip=&action=&endpoint=&from=&to=&page=&per_page=   # ?endpoint=host/path glob
GET /api/logs/top?limit=&host=&path=
GET /api/logs/export?format=csv
DELETE /api/logs/clear   # X-Internal-Api-Key
# No POST /api/logs — auth-gateway audits via internal _queue_audit → POST /api/logs is not an API route
```

- Host/path filters use `LIKE%` glob.
- `X-Total-Count` header for pagination.
- Auth gateway + management audit is internal-only; `api` exposes read/delete.

`GET /api/warnings` — shadowed groups/rules.
`POST /api/dry-run {host,path}` — preview what rule would match.

## Observability

- `RequestIDMiddleware` → `X-Request-ID` (echoed).
- `structlog` JSON on gateway.
- `CSPMiddleware` (`default-src self`) + `ProxyFixMiddleware` + `X-Forwarded-*`.
