# Logs & Warnings

## Audit Logs

```bash
GET /api/logs?host=&ip=&action=&endpoint=&from=&to=&page=&per_page=&code= # ?endpoint=host/path glob, ?code= label/code masked
GET /api/logs/top?limit=&host=&path=
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
- `GET /manage/audit` shows `GET /api/logs/by-ip` grouped by the visitor IP — recent pages + access code per IP (`shared/client_ip.py` resolves it from `CF-Connecting-IP`, not `X-Forwarded-For` — see Auth Flow → Visitor IP). It was `/manage/monitoring` until the Audit category was named for what the page actually is; that address still answers with a `302` to the new one.
- `GET /manage/settings` is DB-backed and now carries four sections of settings plus a read-only environment panel; `POST /manage/settings` validates every field against `shared/settings_spec.py` with `csrf_token` + `same_origin` and issues one `PUT /api/settings/{key}` per changed field. See [Management UI](manage-panel.md) for the page and [Auth Flow](auth-flow.md) for what the gateway keys do.

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
