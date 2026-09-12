# Routes

DB table `routes` drives the wildcard proxy in `auth-gateway`.

| Column | Type | Notes |
|--------|------|-------|
| `host` | String(255) | exact host, e.g. `portfolio.projectnova.download` |
| `path` | String(1024) | prefix, default `/` |
| `route_type` | `proxy` or `redirect` | |
| `upstream` | String(255) | container:port for proxy |
| `port` | Integer | upstream port |
| `redirect_target` | String(1024) | URL for redirect |
| `redirect_code` | Integer | 301, 302, 307, 308 |

Longest `path` match wins for `host`. `projectnova.download /` → redirect to `https://portfolio.projectnova.download`.

## Test

```bash
curl -X POST http://api:8002/api/routes/1/test \
 -H "X-Internal-Api-Key: $INTERNAL_API_KEY"
# checks socket reachability
```
