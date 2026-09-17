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
| `GET /manage/rules` | Rule groups list (▲/▼ reorder, ✎ edit) |
| `POST /manage/groups` | Create group (`name`, `domain`) |
| `POST /manage/groups/{gid}/edit` | Edit group (`name`, `domain`) — `domain` is disabled for the default group |
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

## Actions are icons, not words

Every action control in the manage UI is icon-only, with `title` **and** `aria-label` carrying the old visible label (`aria-hidden` on the glyph) — removing the word removes the accessible name, so it has to come from somewhere. The one deliberate exception is the card header on `/manage/routing`, where `Add Proxy Route` and `Add Redirect Route` sit adjacent and two bare `+` glyphs would be indistinguishable; `Add Group`, `Add Rule` and `Add Code` are icon-only because each page has exactly one. `Delete` and `Revoke` keep their `confirm()` step — icon-ifying a destructive action without it would be a safety regression.

This also pays off structurally: dropping the widest column's text is part of what removes the narrow-width clipping described below.

## Table layout

The action cell of every row is a real table cell — `<td class="actions-cell"><div class="actions">…</div></td>`. The flex layout must not go on the `<td>` itself: `display:flex` on a table cell takes it out of the table layout algorithm, so it stops stretching to its row height and its bottom border ends early, and the column borders no longer meet. The layout lives once in `manage.css` (`.actions-cell`, `.actions`, `.actions form`, `.icon-btn`) rather than as an inline style repeated per template.

`.card` keeps `overflow: hidden` for its rounded corners, so every table sits inside a `.table-scroll` wrapper that scrolls it: `tabindex="0"`, `role="region"` and an `aria-label`, because an unfocusable scroll box is itself an accessibility defect. Without it the clipped columns are not merely off-screen but unreachable — the document does not scroll at all.

`base.html` loads `manage.css` with `?v=2`; bump that when the stylesheet changes so a cached copy cannot make a correct deploy look broken.

## Codes

`label`/`display_name`/`active`/`last_accessed`. Creating requires explicit `code` value (`POST /api/codes {"code": "...", "label": "..."}` `X-Internal-Api-Key`).

## Logs — live scroll + monitoring

`GET /manage/logs` supports `?format=json&page&per_page&ip&host&endpoint&code&from&to` with `X-Total-Count`; template `logs.html` does `IntersectionObserver` infinite scroll loading next page as you scroll. `GET /manage/monitoring` (`GET /api/logs/by-ip?limit=50`) lists IPs → `{calls, recent: [{host,path,ts,action,code_label,attempted_code}], codes}`.

## Settings — real DB-backed

`GET /manage/settings` loads `GET /api/settings` and shows `rate_limit_access_code_per_min` (default 5). `POST /manage/settings` validates `1..1000` with `csrf_token` + `same_origin` and `PUT /api/settings/{key}`. Enforced per-IP in `auth-gateway` on `?access_code=` via `POST /api/auth/check-rate-limit {ip}` → `429` when `count >= limit`.
