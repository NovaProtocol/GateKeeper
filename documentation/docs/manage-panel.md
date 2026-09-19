# Management UI

`/manage` is the admin surface behind `manage_session` (not GateKeeper's gate). All pages proxy to `api:8002` with `X-Internal-Api-Key`.

## Auth

`GET/POST /manage/login` form: `manage_password` + `csrf_token` (double-submit cookie `csrf_token`), `same_origin` apex check, rate `10/min`. Success → signed `manage_session` (`Path=/manage`, `max_age 8h`). Every `/manage*` checks `manage_session` via `_require_manage_auth`; API callers get `401 JSON`, browsers get `302` to login. `POST` also requires `same_origin`.

`GET /manage/logout` clears the cookie.

## Pages

The sidebar is the navigation and it has three categories, in this order:

| Category | Entries |
|---|---|
| Access | Rules, Codes |
| System | Routing, Pages, Settings, Backup |
| Audit | Audit, Traffic Logs, Top Pages |

Every entry resolves to a page below. There is no second navigation: the dashboard used to repeat the sidebar as a sentence and three buttons.

| Path | Purpose |
|------|---------|
| `GET /manage` | Dashboard — stat strip, warning banner, recent traffic, top pages, code health |
| `GET/POST /manage/routing` | Routes CRUD (`host`, `path`, `proxy` upstream:port or `redirect` target:code) + `POST /{id}/test` |
| `POST /manage/routing/test` | Probe the values currently in the route modal: upstream reachability, and the gate's verdict for the typed host and path |
| `GET/POST /manage/pages` | Custom pages list and create (`pattern`, `body`, `content_type`) |
| `POST /manage/pages/{pid}/edit` | Edit a page (`pattern`, `body`, `content_type`) |
| `POST /manage/pages/{pid}/active` | Deactivate or reactivate a page (`active`) |
| `POST /manage/pages/{pid}/order` | Move a page up/down (`direction`) |
| `POST /manage/pages/{pid}/delete` | Delete a page |
| `GET /manage/rules` | Rule groups list (▲/▼ reorder, ✎ edit) |
| `POST /manage/groups` | Create group (`name`, `domain`) |
| `POST /manage/groups/{gid}/edit` | Edit group (`name`, `domain`) — `domain` is disabled for the default group |
| `POST /manage/groups/{gid}/order` | Move group up/down (`direction`) |
| `GET /manage/rules/{gid}` | Rules in group (▲/▼ reorder, real positions, `active` switch) |
| `POST /manage/rules/test` | Ask the gate what it would do with the typed host and path, before the rule is saved |
| `POST /manage/groups/{gid}/rules` | Create rule (`path`, `action`, `custom_password`) — see `PUT /api/rules/{rid}` for edit |
| `POST /manage/rules/{rid}/order` | Move rule up/down (`direction`); disabled on the catch-all, see `documentation/docs/rules.md` |
| `POST /manage/rules/{rid}/edit` | Edit rule (`path`, `action`, `custom_password`) **and** the row's status switch (`active`), which posts to this same route |
| `GET /manage/codes` | Codes list + create/edit, activate/deactivate, permanent delete, `?include_inactive=1` |
| `GET /manage/logs` | Audit logs (filters host/ip/action/endpoint) |
| `GET /manage/audit` | Viewer map (country, four aggregation modes) plus the per-visitor table: IPs, their recent pages and the code they used |
| `GET /manage/monitoring` | `302` to `/manage/audit`, so an old bookmark still lands |
| `GET /manage/top-pages` | Top paths by hits |
| `GET/POST /manage/settings` | Seven editable settings in sections, plus a read-only environment panel |
| `POST /manage/logs/prune` | Delete audit rows past the retention window (`confirm=PRUNE`), rendering the count back onto the page that posted it |
| `POST /manage/logs/clear` | Delete every audit row (`confirm=DELETE`), checked on the server |
| `GET /manage/backup` | Backup — signed plain-JSON export, and a two-step restore |
| `GET /manage/backup/download` | Streams the configuration export as a download |
| `POST /manage/backup/restore` | Preview or apply a restore (`file` + `confirm=REPLACE` + `stage`) |

All mutating `POST/PUT/DELETE` require `csrf_token` + `same_origin`. Every relay to the API carries the internal key through one `_api_headers()` helper; it used to be defined twice in `management/app.py`, byte for byte, with the second silently shadowing the first, and the duplicate is gone so there is one place where that header is built.

## Testing before saving

Every add and edit modal in Routing, Rules and Pages has a **Test before saving** control, sitting immediately to the left of Save in the footer. It is icon-only like every other action, with `title` and `aria-label` carrying the words, and the verdict it produces renders in a `role="status" aria-live="polite"` slot at the leading edge of the same footer, so the answer appears next to the buttons that will act on it rather than somewhere else on the page.

The button asks the server, it does not guess. On Routing it does two things at once with the values **as currently typed**, without saving anything:

- **upstream**: relays to `POST /api/routes/test`, which connects to the named host and port and closes. Reported as `upstream: reachable` or `upstream: <reason>`.
- **gate**: relays the typed host and path to `/manage/rules/test`, which runs `POST /api/dry-run` against the stored rules. Reported as `gate: <action> via <group> · <rule>`, or `shadowed: …` when the response carries a warning.

On Rules the same button asks the gate about the typed path. A group has a domain but a rule does not, so the modal derives a probe host from the group: the group's hostname, or `probe.<suffix>` for a `*.<suffix>` group, or `probe.example.com` for the default `*.*/*` group. That is enough to answer "which rule wins for this path inside this group", which is the question the ordering arrows exist for. A shadowed path is thus visible **before** the rule is saved, instead of only on the dashboard banner afterwards.

The verdict is advisory. Neither button writes anything: the draft probe is DB-free and the rule probe is a dry run, so pressing Test and then Save is exactly the same as pressing Save. Both management routes carry the usual three gates (manage session, CSRF pair, `same_origin`) and the same key-gated API calls the rest of the panel makes, and a failure to reach the API is rendered as the reason rather than raised.

What reachability does **not** promise is documented in [Routes](routes.md): the probe proves something is listening, never that it is the right application. A form left untouched and saved unchecked behaves exactly as it did before this existed.

## Width and density

The content column is fluid. `/manage/*` pages used to cap themselves at `max-width:1100px` (`1200px` on Routing, `1400px` on Logs and Monitoring) with an inline `padding:2rem`, which left most of a 1440px window empty and repeated the same style eleven times. The cap is gone and the padding lives once in `manage.css` as `.container`. `.container-narrow` (`max-width:900px`) exists for `/manage/settings`, the one page where a long line of reading text hurts.

Three numbers do not need three cards. The old `.stats-row`/`.stat-card`/`.stat-number` block rendered each figure at `2rem` inside its own bordered, padded, hover-lifting box, so "6 Total Codes / 5 Active / 1 Inactive" occupied a card each. It is replaced by `.stat-strip`: one wrapping row of `label / value` pairs with `border-left` dividers, monospace values at `0.8rem` and no card chrome. Measured in Chromium at 1440px, the strip renders 19px tall against the 113px the card block took on the codes page and 243px on the dashboard (which carried four figures), a saving of 94px and 224px respectively. No template renders a `.stat-card` any more.

The dashboard then uses the width for something: a two-column grid (`minmax(0, 1fr)` so a long host/path cannot widen its track) with recent traffic on the left and top pages plus code health on the right, collapsing to one column below 1200px. The three quick-link buttons and the "Manage categories: Access, Monitoring, System" paragraph are gone; the sidebar already said all of it.

## Actions are icons, not words

Every action control in the manage UI is icon-only, with `title` **and** `aria-label` carrying the old visible label (`aria-hidden` on the glyph), because removing the word removes the accessible name, so it has to come from somewhere. The one deliberate exception is the card header on `/manage/routing`, where `Add Proxy Route` and `Add Redirect Route` sit adjacent and two bare `+` glyphs would be indistinguishable; `Add Group`, `Add Rule` and `Add Code` are icon-only because each page has exactly one. Destructive actions keep their confirmation step: a `confirm()` for the reversible ones and a typed confirmation checked server-side for the irreversible ones. Icon-ifying a destructive action without any confirmation would be a safety regression.

This also pays off structurally: dropping the widest column's text is part of what removes the narrow-width clipping described below.

## Table layout

The action cell of every row is a real table cell — `<td class="actions-cell"><div class="actions">…</div></td>`. The flex layout must not go on the `<td>` itself: `display:flex` on a table cell takes it out of the table layout algorithm, so it stops stretching to its row height and its bottom border ends early, and the column borders no longer meet. The layout lives once in `manage.css` (`.actions-cell`, `.actions`, `.actions form`, `.icon-btn`) rather than as an inline style repeated per template.

`.card` keeps `overflow: hidden` for its rounded corners, so every table sits inside a `.table-scroll` wrapper that scrolls it: `tabindex="0"`, `role="region"` and an `aria-label`, because an unfocusable scroll box is itself an accessibility defect. Without it the clipped columns are not merely off-screen but unreachable — the document does not scroll at all.

`base.html` loads `manage.css` with `?v=4`; bump that when the stylesheet changes so a cached copy cannot make a correct deploy look broken.

Form controls use one `.input` class. At `971500b`, `logs.html` carried 5 inputs with the control styles written inline and `routing.html` 20 more `<input>`/`<select>` elements the same way, every one of them spelling out the same `background`/`border`/`border-radius`/`padding`/`color` by hand, so a padding tweak meant 25 edits and a miss was invisible. `.input` holds the shared declarations and the modifiers are written compound (`.input.input-mono`, `.input.input-dense`, `.input.input-cap-left` / `-right` for the two halves of a `host:port` pair) so they outrank both `.input` and `.form-group input`, which is what makes a modifier take effect on a control inside a form group. Layout stays inline where it describes the row rather than the control. The font is deliberately not set on `.input`: the routing controls already inherit it from `.form-group` and its `<select>`s relied on that, so setting it would have silently resized them.

Two blocks left the shared sheet in the same pass, because neither described a panel component. `.create-form` was 25 lines of rules referenced by no template: it is deleted. The four `.status-*` classes (`.status-card`, `.status-card-header`, `.status-label`, `.status-dot`) were used only by `landing.html`, the authenticated landing page rather than a `/manage/*` page: they moved into a page-local `<style>` block in that template, which is the same treatment `routing.html` and `logs.html` already give their page-specific rules.

Controls that the server would refuse are rendered `disabled` with a `title` that says why (`aria-disabled="true"` alongside), rather than hidden. The default group's delete button, the group catch-all's delete button and the catch-all's **status switch** are the three cases: a control that is simply absent tells an operator nothing, while a greyed-out one that explains itself answers the question they were about to ask. The catch-all's switch reads `title="The catch-all cannot be deactivated — it is the group's fallback"`, and the API refuses the same attempt with `400 the catch-all cannot be deactivated`.

## Rules: the status switch

Each rule row on `/manage/rules/{gid}` carries a **Status** switch (the same `.toggle` component the codes page uses). It posts `csrf_token` + `active` to the existing `/manage/rules/{rid}/edit` — no new route — and an inactive row renders with the `inactive` style so "off" is visible at a glance rather than only in the switch's position. The catch-all's switch is `disabled` with its reason in a `title`, and a refusal is logged as `rule_active_refused` rather than swallowed, so a control that does not take is visible in the container log instead of looking broken.

The switch means `active`/inactive and nothing else. What skipping does — fall-through to the next matching rule, and the one case that is still refused — is documented in [Rules](rules.md).

## Codes

`label`/`display_name`/`active`/`last_accessed`. Creating requires an explicit `code` value (`POST /api/codes {"code": "...", "label": "..."}` with `X-Internal-Api-Key`).

A code has two different endings **and two separate controls**, and the difference is the point:

- **Deactivate** (`POST /manage/codes/{cid}/active` proxying `PUT /api/codes/{cid}` with `active`). This is the row's `.toggle` **switch**, and it is a state control: it posts `csrf_token` + `active` and nothing else, asks for no confirmation, and does not touch deletion. It is reversible from the same control, and it is the same column the gate reads, so deactivation takes effect on the next request.
- **Permanent delete** (`POST /manage/codes/{cid}/delete`) removes the row. This is a **separate trash control** beside the switch, rendered `disabled` in the sense that it is hidden until the page-level **Permanent delete** toggle is on. It does not post anything itself: it opens the typed-confirm modal. Audit rows are history and are never deleted: `audit_logs.code_id` is nulled instead, the same policy a restore applies, so the row survives with its host, path and action intact. The response reports how many rows were detached.

Inactive codes are hidden by default. The **Show inactive** toggle on the codes card re-requests the page with `?include_inactive=1`, which the API honours server-side (`GET /api/codes` filters inactive rows unless asked). Inactive rows render with the `tag-inactive` style, and the switch's `title`/`aria-label` change from *Deactivate code* to *Activate code*.

The **Permanent delete** toggle governs the **trash control's visibility** — it shows and hides it, and it does not re-point the switch at a different action. The trash control opens a modal asking for the code to be typed out, and that typed confirmation is re-checked on the **server**, against the code read back from the API with `secrets.compare_digest`, so a modal alone cannot be bypassed by a stale tab, a replayed form post or a script. A mismatch is `400`.

Both capabilities are kept, and the split is deliberate: a switch is a state indicator, and a switch that sometimes deletes misstates what it is. `DELETE`-style irreversibility never shares a control with a flag that is meant to be flipped back.

`POST /api/codes/{cid}/revoke` still exists and still works; it is the older, deactivate-only spelling of the same flag. `PUT /api/codes/{cid}` accepts `active` as a boolean, an integer or the strings `"true"`/`"false"`/`"1"`/`"0"`, because the panel posts form values while other callers send JSON. Anything else is refused with `400 active must be true or false` rather than guessed at.

## Logs, Audit, and the warnings banner

`GET /manage/logs` supports `?format=json&page&per_page&ip&host&endpoint&code&from&to` with `X-Total-Count`; template `logs.html` does `IntersectionObserver` infinite scroll loading next page as you scroll. `GET /manage/audit` pairs the viewer map with `GET /api/logs/by-ip?limit=50`, which lists IPs → `{calls, recent: [{host,path,ts,action,code_label,attempted_code}], codes}` for the per-visitor view.

Warnings are no longer a page. `GET /api/warnings` reports a shadowed group or rule only when one exists, and on a healthy gateway it answers `{groups: [], rules: []}`, so `/manage/warnings` rendered two empty tables under a red header and nothing else. The page is deleted, the endpoint is not: the dashboard reads it and renders a `.warn-banner` **only when the response is non-empty**, linking to `/manage/rules` where the order can be fixed. Nothing about shadowing detection changed, only where it is shown.

## Settings

The page is no longer one field. It is seven settings in four sections, each control carrying a one-line note naming the file and function that enforces it, plus a read-only environment panel.

| Section | Key | Default | Accepted | Enforced by |
|---------|-----|---------|----------|-------------|
| Gateway | `unmatched_action` | `access_code` | `access_code` / `deny` / `none` | `shared/gate.py:resolve_rule_action`, both gate paths |
| Gateway | `rate_limit_access_code_per_min` | `5` | `1..1000` | `api/app.py:check_rate_limit`, last 60s of `audit_logs` per IP |
| Sessions | `session_lifetime_hours` | `12` | `1..720` | `auth-gateway/app.py:_set_auth_cookie` and `_set_custom_cookie` |
| Maintenance | `maintenance_mode` | `false` | `true` / `false` | `auth-gateway/app.py:_maintenance_response`, before rule dispatch |
| Maintenance | `maintenance_message` | empty | at most 200 characters, escaped | `shared/error_pages.py:render_maintenance_html` |
| Audit | `log_retention_days` | `LOG_RETENTION_DAYS` (`30`) | `7..3650` | `api/app.py:prune_audit_logs`, at boot and on demand |
| Audit | `geo_lookup_enabled` | `true` | `true` / `false` | `auth-gateway/app.py:_visitor_country`, checked before the header is read |

Every key is described exactly once, in `shared/settings_spec.py`, and three callers read that table rather than re-implementing a rule from it: the API validates a `PUT /api/settings/{key}` against it, so an invalid value is refused at the only write path; `auth-gateway` normalises every stored value through `read_value()` before acting on it, so a row edited by hand or restored from an older file cannot change behaviour to something the panel would refuse; and this page builds its form from `MANAGE_FIELDS` and validates against the same specs, so a key cannot exist in the database and be unreachable in the UI.

The fallback direction is the safe reading of each key, not the convenient one. `unmatched_action` falls back to `access_code`, which refuses a request it cannot classify, and `maintenance_mode` falls back to `false`, because defaulting a gateway into an outage on a settings blip would take the site down rather than protect it. An empty or `NULL` stored value is treated as unusable and takes the same fallback, so an absent row can never become the permissive value.

What the settings do is documented where they act: [Auth Flow](auth-flow.md) for `unmatched_action`, the session lifetime and maintenance mode, [Logs & Audit](logs.md) for retention and country capture. This page owns the surface.

### Saving

`POST /manage/settings` iterates `MANAGE_FIELDS`, validates each submitted value against the same spec the API uses, and issues one `PUT /api/settings/{key}` per changed field. A field the browser did not send is left alone, so a partial form cannot blank a setting it never showed, and a key outside `MANAGE_FIELDS` is dropped, so a crafted post cannot reach a setting this page does not own. A checkbox is sent as a hidden `false` followed by the box's `true` when it is checked, and the last value wins, which is why an unchecked box saves `false` rather than nothing.

A rejected value is reported on the page with its reason and a `400`, and no write is issued for that key. Valid fields submitted alongside an invalid one are still saved, so one typo does not discard the rest of the form.

### Prune audit logs

The card below the form deletes every audit row older than `log_retention_days`. `POST /manage/logs/prune` requires `csrf_token`, `same_origin` and `confirm=PRUNE`, then proxies `POST /api/logs/prune` and re-renders the page with the returned count: how many rows were deleted and how many remain. There is no export behind it and no undo, which is why the word is checked on the server rather than only in the form. The same route serves the Audit page, which posts a closed-enum `back=audit` field and gets the count rendered there instead; a field naming its own destination is a value the caller picks from two options, not a URL the caller supplies. See [Logs & Audit](logs.md) for the retention model.

## The Audit page

`/manage/audit` answers "who is visiting, and from where" in two halves: a map card of countries at the top, and the per-IP table underneath.

The map card holds an aggregation dropdown, a `prune` button and a `clear` button. The dropdown is a **GET form** (`?mode=`), so the view is a URL that can be bookmarked or shared and there is no client-side arithmetic to get wrong: the server counts and the browser draws. It offers `views` (requests), `visitors` (distinct addresses), `gated` (a code was presented) and `blocked` (the gate refused); an unknown value in the URL falls back to `views` rather than erroring, while the API itself refuses it with a `400` naming the accepted four.

The map is Leaflet 1.9.4 from `cdn.jsdelivr.net`, which `script-src` and `style-src` already allow, and OpenStreetMap raster tiles, which arrive as `<img>` requests and therefore needed one CSP change: `img-src` gained `https://cdn.jsdelivr.net`, `https://tile.openstreetmap.org` and `https://*.tile.openstreetmap.org`. `cdn.jsdelivr.net` is in that list because Leaflet resolves its own default marker images relative to the script URL. No other directive changed.

A tile host missing from `img-src` is a silent break: the script loads, the container renders and every tile is refused with nothing on the page to say so. That is why the check in `tests/ui/check_audit_page.py` reads the served header and counts the tile responses in a real browser rather than trusting the page source.

The page degrades rather than failing. No rows, no centroids to plot, a blocked tile host or an offline browser all end at the same place: the card renders a sentence instead of a map, the country table carries the same numbers, and nothing raises. Leaflet keeps its own DOM and is driven imperatively rather than through a reactive binding, because a reactive layer cannot own that element.

Clearing is the destructive control on that page and the only one with nothing behind it, so `POST /manage/logs/clear` checks the session, the CSRF pair, the origin and a typed `DELETE` before issuing `DELETE /api/logs/clear`. The modal is the affordance; the gate is the route. The card also shows the current audit row count, because an empty table and a table whose rows were just deleted look identical without a number.

### Environment (read-only)

The last card answers "what is this thing running as" without exposing anything: `DEPLOYMENT_TYPE`, the database backend derived from the scheme of `db_url` only (`mysql` or `sqlite`, with a note when `DATABASE_URL` overrides the default), whether `INTERNAL_API_KEY` and `SECRET_KEY` are configured, and where the retention window actually comes from (the stored setting, the `LOG_RETENTION_DAYS` environment variable, or the built-in default).

The two secrets are reported as `configured` or `not set` and nothing else. The panel never reads a secret value, so there is nothing on the page to leak, and the value is one template mistake away from being rendered if it were read. Unlike the settings above, these follow the compose environment and changing one needs a redeploy.
