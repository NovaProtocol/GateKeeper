# Rules & Rule Groups

```sql
rule_groups(name unique, domain, display_order, is_default)
rules(group_id, path, action, custom_password_hash, custom_password_salt, display_order)
```

- `display_order` decides priority — lower first. `*.*/*` default group is pinned bottom.
- `domain` supports `*` prefix (`*.projectnova.download`).
- `path` uses `/*` prefix match — and it is **exact** otherwise. `/documentation` matches only that one path; `/documentation/*` is what covers `/documentation/rules/`.
- `action`: `access_code` (check cookie/magic link), `none` (allow), `custom_password` (per-rule password), `deny` (403).
- `allow_ip`, `allow_time`, `rate_limit` are **reserved** — stored, not enforced on hot path.

## Reordering

Both lists are ordered in the UI with ▲/▼ buttons (no drag, no JS dependency) and the `Order` column shows the real position (1, 2, 3…) rather than the raw sparse `display_order`. The arrows are disabled where the API would refuse or no-op: on the first/last row, and on the default group.

Underlying endpoints, both `X-Internal-Api-Key`:

- `PUT /api/groups/{gid}/order {"direction": "up|down"}` — `400 cannot reorder default`, `400 cannot swap with default`.
- `PUT /api/rules/{rid}/order {"direction": "up|down"}` — `400 direction must be up|down`.

Each swap trades `display_order` with the adjacent row; at the ends the API returns `{"ok": true}` without changing anything.

## New rules land last — read this before wondering why a rule does nothing

`POST /api/groups/{gid}/rules` appends with `display_order = max + 1`. The gate then walks the group **ascending** and takes the **first** rule whose path matches, so a newly added rule sits *below* everything already there.

If a broader rule above it matches first, the new rule never fires and there is no error anywhere. The common case is a `/*` rule: add `/documentation/* → access_code` under an existing `/* → none` and the docs stay public, because `/*` matches `/documentation/rules/` first.

**If a rule has no effect, move it up with ▲ until it sits above the rule that is shadowing it.**

Shadowing: `GET /api/warnings` (and `/manage/warnings`) reports `/*` rules that hide later rules.
