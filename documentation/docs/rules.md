# Rules & Rule Groups

```sql
rule_groups(name unique, domain, display_order, is_default)
rules(group_id, path, action, custom_password_hash, custom_password_salt, display_order)
```

- `display_order` decides priority — lower first. `*.*/*` default group is pinned bottom.
- `domain` supports `*` prefix (`*.projectnova.download`).
- `path` uses `/*` prefix match.
- `action`: `access_code` (check cookie/magic link), `none` (allow), `custom_password` (per-rule password), `deny` (403).
- `allow_ip`, `allow_time`, `rate_limit` are **reserved** — stored, not enforced on hot path.

Reorder via `PUT /api/groups/{id}/order` and `PUT /api/rules/{id}/order` (`up`/`down`).

Shadowing: `GET /api/warnings` reports `/*` rules that hide later rules.
