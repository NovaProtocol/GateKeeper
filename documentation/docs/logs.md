# Logs & Audit

## Audit Logs

```bash
GET /api/logs?host=&ip=&action=&endpoint=&from=&to=&page=&per_page=&code= # ?endpoint=host/path glob, ?code= label/code masked
GET /api/logs/top?limit=&host=&path=
GET /api/logs/geo?mode=views|visitors|gated|blocked&host=&from=&to= # per-country totals, ready to plot
GET /api/logs/export?format=csv
GET /api/logs/by-ip?limit=50 # grouped by ip → {calls, recent[5], codes}
DELETE /api/logs/clear # X-Internal-Api-Key
POST /api/logs/prune?days= # X-Internal-Api-Key, days 7..3650, defaults to the stored setting
POST /api/logs # internal ingest — auth-gateway BackgroundTasks X-Internal-Api-Key
POST /api/auth/check-rate-limit {ip} # X-Internal-Api-Key → {allowed,count,limit}
GET|PUT /api/settings[/{key}] # settings table — PUT needs X-Internal-Api-Key
```

- Host/path filters use `LIKE%` glob; `code` matches `code_label/code_value/attempted_code`.
- `X-Total-Count` header for pagination; `/manage/logs` does infinite scroll (`IntersectionObserver` → `GET /manage/logs?format=json&page=N` → `X-Total-Count`).
- `GET /manage/audit` is the viewer page: where visitors came from (map and country table), then `GET /api/logs/by-ip` grouped by the visitor IP with recent pages and access codes per IP. It was `/manage/monitoring` until the Audit category was named for what the page actually is; that address still answers with a `302` to the new one.
- `GET /manage/settings` is DB-backed and now carries five sections of settings plus a read-only environment panel; `POST /manage/settings` validates every field against `shared/settings_spec.py` with `csrf_token` + `same_origin` and issues one `PUT /api/settings/{key}` per changed field. See [Management UI](manage-panel.md) for the page and [Auth Flow](auth-flow.md) for what the gateway keys do.

## Visitor country

`audit_logs.country` holds a two-letter country code, and nothing finer. It is read from `CF-IPCountry`, the header Cloudflare stamps at the edge the same way it stamps `CF-Connecting-IP`, in `shared/geo.py:get_country`. It is **not** a lookup service and **not** a GeoIP database: no visitor address leaves this stack to be identified, there is no city, and no coordinate is ever derived from a visitor's own address. Storing a country is coarse enough to be defensible in an audit trail; storing where exactly someone was would not be.

The reader is deliberately strict about what it will accept, because a stored value is a claim about a real country:

| Header value | Stored | Why |
|---|---|---|
| `PH` | `PH` | two uppercase letters is the only shape Cloudflare sends |
| `ph` | `NULL` | lowercase did not come from Cloudflare |
| `XX` | `NULL` | Cloudflare's documented "could not tell" |
| `T1` | `NULL` | a Tor exit, not a country |
| `PHL`, `1.2.3.4`, `<script>`, empty | `NULL` | not a country code |

`geo_lookup_enabled` (default `true`) is the switch. It is checked **before** the header is read, so turning it off means no country is captured at all, while the address, host, path and action are still audited: the switch is a privacy choice, not a logging outage. An unreadable value for the switch leaves capture on, matching the seeded default.

**The header reaching the origin is unverified.** cloudflared is documented to forward `CF-IPCountry`; that it does so on this deployment was not testable from the build environment. The design's response is to degrade rather than guess: if the header never arrives, every request stores `NULL`, `GET /api/logs/geo` returns a single `Unknown` bucket, the map card renders a text sentence instead of a map, and nothing raises. The proof by effect after a deploy is one request followed by a read of the newest row: a non-NULL `country` means it arrived, a `NULL` across several requests means it did not, and the fix in that case is a Cloudflare setting rather than code.

There is **no backfill**. Rows written before the column existed stay `NULL` and are reported as `Unknown`, which is honest: deriving a country for an old row would need a lookup service, and it would be a guess written into a record.

## The viewer map

`GET /api/logs/geo` returns one entry per country, ordered by count, with the name, the centroid, the share of the total and a marker radius. Four modes answer four different questions about the same rows, and the page's dropdown is a GET form so the mode is in the URL and the view is linkable:

| `mode` | Counts |
|---|---|
| `views` (default) | requests |
| `visitors` | distinct visitor addresses |
| `gated` | requests a code was presented for (`code_id IS NOT NULL`) |
| `blocked` | requests the gate turned away (`action` in `deny`, `access_code_fail`, `access_code_rate_limited`) |

Only the grouping happens in SQL. Ordering, share, radius and the `Unknown` bucket are decided by `shared/geo.py:build_points`, which is pure and unit-tested without a browser.

The page draws **radius-scaled circle markers**, not a heat layer. With country-level data, one centroid per country, a heat map would render the shape of the centroid table weighted by traffic and imply a per-visitor density the data does not contain. The circle area scales with the count instead (radius proportional to the square root, so area tracks the number), which is the honest rendering of what was recorded. A real heat map would need a city-level GeoIP database, which is a separate decision with a licence and an update story attached.

A country the centroid table does not carry still counts, appears in the table, and is simply not plotted; the `Unknown` bucket behaves the same way. The card carries the top countries as text as well, so the numbers exist without the picture for a screen reader, a failed tile fetch or an export.

`mode` is validated at the API (an unknown value is a `400` naming the accepted four); the page normalizes what it is given and falls back to `views`, so a hand-edited URL renders a page rather than an error.

## Clearing and pruning

Two different removals, and the difference is the point:

- **Prune** (`POST /api/logs/prune`, `confirm=PRUNE`) deletes rows older than the retention window and keeps everything inside it. It reports `{deleted, remaining}` back onto the page that asked. See Retention below.
- **Clear** (`DELETE /api/logs/clear`, `confirm=DELETE`) deletes every audit row. It has no export behind it and no undo, so the management route checks the session, the CSRF pair, the origin and the typed word on the server before it issues the call; the modal is an affordance, not the gate.

The reason clear exists is legibility rather than tidiness. Before `shared/client_ip.py` resolved the visitor address correctly (`4c8617d`), every request was logged against the cloudflared container's own bridge address, so the table was thousands of identical `172.18.x.x` rows and a new visitor address could not be seen among them. Clearing is how fresh addresses become observable. Both pages that offer the controls render the current row count, so an empty table is distinguishable from a table whose rows were just removed.


### Retention

Audit rows are deleted by age, and the age is the `log_retention_days` setting (default `30`, accepted `7..3650`). The environment variable `LOG_RETENTION_DAYS` is what a fresh volume is seeded from; it is not consulted while a stored row exists, and the settings page states which of the two is currently in force.

Rows are removed in exactly two places, and there is deliberately **no scheduler**:

1. **The boot sweep.** `api/app.py:lifespan` calls `prune_audit_logs` once at startup, inside a guarded `try/except`: a failed sweep logs `audit_logs_prune_skipped` and never stops the API from starting. When it deletes anything it logs `audit_logs_pruned` with the count and `reason="boot"`, so a surprise drop in row count has an explanation in the log.
2. **`POST /api/logs/prune`**, on demand, with an optional `days` query (the same `7..3650` range). It returns `{deleted, remaining}`, and the **Prune now** button on `/manage/settings` proxies it after a typed `PRUNE` confirmation so the operator sees both numbers on the page.

Both paths share one function and one window, so the button and the sweep cannot disagree about what counts as expiring.

A row exactly on the cutoff is kept: the window is "older than N days", not "not newer than N days", so a prune at the boundary cannot delete a record that is still inside it. There is no backfill and no archive: a pruned row is gone, which is why the manual control asks for a typed confirmation and the danger styling it does.

**No scheduler, on purpose.** There is no Celery, APScheduler or systemd timer in this stack, and adding one to delete 30-day-old rows is not proportionate. The consequence is honest and worth stating: while the API runs continuously, nothing ages rows out. The table only shrinks on a restart or when someone presses the button. A gateway that has been up for a year with retention set to 30 days will hold much more than 30 days of rows until one of those two happens.

### Fallback rows

When no rule matched, the row carries `matched_action` = the governing fallback (`access_code`, `deny`, or `none`, i.e. the `unmatched_action` setting) with `rule_id` and `rule_group_id` both null, and `action` = what happened (`no_cookie_redirect`, `deny`, `none_gate`). So `action='no_cookie_redirect'` with `matched_action='access_code'` and no `rule_id` is a request that was refused because nothing matched, not because a rule asked for it. A group that matched the host without a matching rule reports the same `matched_action='access_code'` regardless of the setting, because that state is always refused (see Rules → When nothing matches).

`GET /api/warnings` — shadowed groups/rules. The dashboard banner is its only reader in the panel: the old `/manage/warnings` page is gone, because on a healthy gateway the endpoint answers `{groups: [], rules: []}` and the page rendered two empty tables.
`POST /api/dry-run {host,path}` — preview what rule would match.

The second action string a request can carry without a rule behind it is `maintenance_mode`, written by both gate paths while `maintenance_mode` is on. With it, `action` and `matched_action` are both `maintenance_mode` and `rule_id`, `rule_group_id` and `code_id` are all null, so a maintenance refusal is distinguishable from a rule that refused for its own reasons.

## Observability

- `RequestIDMiddleware` → `X-Request-ID` (echoed).
- `structlog` JSON on gateway.
- `CSPMiddleware` (`default-src self`) + `ProxyFixMiddleware` + `X-Forwarded-*`.
- `audit_logs.ip` holds the **visitor** address (max 64 chars) — resolved by `shared/client_ip.py`, never the cloudflared container's bridge address.
- `audit_logs.country` holds the **visitor's country** (2 chars), resolved by
  `shared/geo.py` from `CF-IPCountry`, or `NULL` when it is absent, a sentinel, or
  not a country code.
