# Management UI

`/manage` is the admin surface behind `manage_session` (not GateKeeper's gate). All pages proxy to `api:8002` with `X-Internal-Api-Key`.

## Auth

`GET/POST /manage/login` form: `manage_password` + `csrf_token` (double-submit cookie `csrf_token`), `same_origin` apex check, rate `10/min`. Success → signed `manage_session` (`Path=/manage`, `max_age 8h`). Every `/manage*` checks `manage_session` via `_require_manage_auth`; API callers get `401 JSON`, browsers get `302` to login. `POST` also requires `same_origin`.

`GET /manage/logout` clears the cookie.

## Pages

| Path | Purpose |
|------|---------|
| `GET /manage` | Dashboard — stats (routes/groups/codes) + warnings |
| `GET/POST /manage/routing` | Routes CRUD (`host`, `path`, `proxy` upstream:port or `redirect` target:code) + `POST /{id}/test` |
| `GET /manage/rules` | Rule groups list (▲/▼ reorder) |
| `POST /manage/groups` | Create group (`name`, `domain`) |
| `POST /manage/groups/{gid}/order` | Move group up/down (`direction`) |
| `GET /manage/rules/{gid}` | Rules in group (▲/▼ reorder, real positions) |
| `POST /manage/groups/{gid}/rules` | Create rule (`path`, `action`, `custom_password`) — see `PUT /api/rules/{rid}` for edit |
| `POST /manage/rules/{rid}/order` | Move rule up/down (`direction`) — the fix when a new rule is masked |
| `GET /manage/codes` | Codes list + create/revoke/edit |
| `GET /manage/logs` | Audit logs (filters host/ip/action/endpoint) |
| `GET /manage/top-pages` | Top paths by hits |
| `GET /manage/warnings` | Shadowed rules/groups |
| `GET /manage/settings` | Settings |
| `GET /manage/backup` | Backup |

All mutating `POST/PUT/DELETE` require `csrf_token` + `same_origin`.

## Codes

`label`/`display_name`/`active`/`last_accessed`. Creating requires explicit `code` value (`POST /api/codes {"code": "...", "label": "..."}` `X-Internal-Api-Key`).

## Logs — live scroll + monitoring

`GET /manage/logs` supports `?format=json&page&per_page&ip&host&endpoint&code&from&to` with `X-Total-Count`; template `logs.html` does `IntersectionObserver` infinite scroll loading next page as you scroll. `GET /manage/monitoring` (`GET /api/logs/by-ip?limit=50`) lists IPs → `{calls, recent: [{host,path,ts,action,code_label,attempted_code}], codes}`.

## Settings — real DB-backed

`GET /manage/settings` loads `GET /api/settings` and shows `rate_limit_access_code_per_min` (default 5). `POST /manage/settings` validates `1..1000` with `csrf_token` + `same_origin` and `PUT /api/settings/{key}`. Enforced per-IP in `auth-gateway` on `?access_code=` via `POST /api/auth/check-rate-limit {ip}` → `429` when `count >= limit`.
