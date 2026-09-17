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
| `POST /manage/rules/{rid}/order` | Move rule up/down (`direction`); disabled on the catch-all, see `documentation/docs/rules.md` |
| `GET /manage/codes` | Codes list + create/edit, activate/deactivate, permanent delete, `?include_inactive=1` |
| `GET /manage/logs` | Audit logs (filters host/ip/action/endpoint) |
| `GET /manage/top-pages` | Top paths by hits |
| `GET /manage/warnings` | Shadowed rules/groups |
| `GET /manage/settings` | Settings |
| `GET /manage/backup` | Backup — signed plain-JSON export, and a two-step restore |
| `GET /manage/backup/download` | Streams the configuration export as a download |
| `POST /manage/backup/restore` | Preview or apply a restore (`file` + `confirm=REPLACE` + `stage`) |

All mutating `POST/PUT/DELETE` require `csrf_token` + `same_origin`.

## Actions are icons, not words

Every action control in the manage UI is icon-only, with `title` **and** `aria-label` carrying the old visible label (`aria-hidden` on the glyph), because removing the word removes the accessible name, so it has to come from somewhere. The one deliberate exception is the card header on `/manage/routing`, where `Add Proxy Route` and `Add Redirect Route` sit adjacent and two bare `+` glyphs would be indistinguishable; `Add Group`, `Add Rule` and `Add Code` are icon-only because each page has exactly one. Destructive actions keep their confirmation step: a `confirm()` for the reversible ones and a typed confirmation checked server-side for the irreversible ones. Icon-ifying a destructive action without any confirmation would be a safety regression.

This also pays off structurally: dropping the widest column's text is part of what removes the narrow-width clipping described below.

## Table layout

The action cell of every row is a real table cell — `<td class="actions-cell"><div class="actions">…</div></td>`. The flex layout must not go on the `<td>` itself: `display:flex` on a table cell takes it out of the table layout algorithm, so it stops stretching to its row height and its bottom border ends early, and the column borders no longer meet. The layout lives once in `manage.css` (`.actions-cell`, `.actions`, `.actions form`, `.icon-btn`) rather than as an inline style repeated per template.

`.card` keeps `overflow: hidden` for its rounded corners, so every table sits inside a `.table-scroll` wrapper that scrolls it: `tabindex="0"`, `role="region"` and an `aria-label`, because an unfocusable scroll box is itself an accessibility defect. Without it the clipped columns are not merely off-screen but unreachable — the document does not scroll at all.

`base.html` loads `manage.css` with `?v=2`; bump that when the stylesheet changes so a cached copy cannot make a correct deploy look broken.

Controls that the server would refuse are rendered `disabled` with a `title` that says why (`aria-disabled="true"` alongside), rather than hidden. The default group's delete button and the group catch-all's delete button are the two cases: a control that is simply absent tells an operator nothing, while a greyed-out one that explains itself answers the question they were about to ask.

## Codes

`label`/`display_name`/`active`/`last_accessed`. Creating requires an explicit `code` value (`POST /api/codes {"code": "...", "label": "..."}` with `X-Internal-Api-Key`).

A code has two different endings and the difference is the point:

- **Deactivate** (`POST /manage/codes/{cid}/active` proxying `PUT /api/codes/{cid}` with `active`) flips the flag and keeps the row, so it can be turned back on. This is the reversible kill switch, and it is the same column the gate reads, so deactivation takes effect on the next request.
- **Permanent delete** (`POST /manage/codes/{cid}/delete`) removes the row. Audit rows are history and are never deleted: `audit_logs.code_id` is nulled instead, the same policy a restore applies, so the row survives with its host, path and action intact. The response reports how many rows were detached.

Inactive codes are hidden by default. The **Show inactive** toggle on the codes card re-requests the page with `?include_inactive=1`, which the API honours server-side (`GET /api/codes` filters inactive rows unless asked). Inactive rows render with the `tag-inactive` style and an **activate** control instead of a deactivate one.

The **Permanent delete** toggle turns each row's deactivate button into a delete button that opens a modal asking for the code to be typed out. The typed confirmation is re-checked on the **server**, against the code read back from the API with `secrets.compare_digest`, so a modal alone cannot be bypassed by a stale tab, a replayed form post or a script. A mismatch is `400`.

`POST /api/codes/{cid}/revoke` still exists and still works; it is the older, deactivate-only spelling of the same flag. `PUT /api/codes/{cid}` accepts `active` as a boolean, an integer or the strings `"true"`/`"false"`/`"1"`/`"0"`, because the panel posts form values while other callers send JSON. Anything else is refused with `400 active must be true or false` rather than guessed at.

## Logs — live scroll + monitoring

`GET /manage/logs` supports `?format=json&page&per_page&ip&host&endpoint&code&from&to` with `X-Total-Count`; template `logs.html` does `IntersectionObserver` infinite scroll loading next page as you scroll. `GET /manage/monitoring` (`GET /api/logs/by-ip?limit=50`) lists IPs → `{calls, recent: [{host,path,ts,action,code_label,attempted_code}], codes}`.

## Settings — real DB-backed

`GET /manage/settings` loads `GET /api/settings` and shows `rate_limit_access_code_per_min` (default 5). `POST /manage/settings` validates `1..1000` with `csrf_token` + `same_origin` and `PUT /api/settings/{key}`. Enforced per-IP in `auth-gateway` on `?access_code=` via `POST /api/auth/check-rate-limit {ip}` → `429` when `count >= limit`.

The same `PUT` also accepts `unmatched_action`, the action for a request whose host is in no rule group. It is validated per key against `access_code` (default) / `deny` / `none`; any other value is refused with `400 must be one of access_code, deny, none`. The setting page still shows only the rate limit, so changing it today means calling the API directly. See Rules → When nothing matches for what each value does.
