# Management UI

`/manage` is the admin surface behind `manage_session` (not GateKeeper's gate). All pages proxy to `api:8002` with `X-Internal-Api-Key`.

## Auth

`GET/POST /manage/login` form: `manage_password` + `csrf_token` (double-submit cookie `csrf_token`), `same_origin` apex check, rate `10/min`. Success → signed `manage_session` (`Path=/manage`, `max_age 8h`). Every `/manage*` checks `manage_session` via `_require_manage_auth`; API callers get `401 JSON`, browsers get `302` to login. `POST` also requires `same_origin`.

`GET /manage/logout` clears the cookie.

## Pages

| Path | Purpose |
|------|---------|
| `GET /manage` | Dashboard — stats (routes/groups/codes/api_keys) + warnings |
| `GET/POST /manage/routing` | Routes CRUD (`host`, `path`, `proxy` upstream:port or `redirect` target:code) + `POST /{id}/test` |
| `GET /manage/rules` | Rule groups list |
| `POST /manage/groups` | Create group (`name`, `domain`) |
| `GET /manage/rules/{gid}` | Rules in group |
| `POST /manage/groups/{gid}/rules` | Create rule (`path`, `action`, `custom_password`) — see `PUT /api/rules/{rid}` for edit |
| `GET /manage/codes` | Codes list + create/revoke/edit |
| `GET /manage/logs` | Audit logs (filters host/ip/action/endpoint) |
| `GET /manage/top-pages` | Top paths by hits |
| `GET /manage/warnings` | Shadowed rules/groups |
| `GET /manage/settings` | Settings |
| `GET /manage/backup` | Backup |

All mutating `POST/PUT/DELETE` require `csrf_token` + `same_origin`.

## Codes

`label`/`display_name`/`active`/`last_accessed`. Creating requires explicit `code` value; API auto-generates if `key` omitted (`POST /api/keys` without `key` → `secrets.token_urlsafe(16)`).
