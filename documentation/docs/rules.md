# Rules & Rule Groups

```sql
rule_groups(name unique, domain, display_order, is_default)
rules(group_id, path, action, custom_password_hash, custom_password_salt, display_order, is_default)
```

Resolution and the unmatched-request decision live in `shared/gate.py`; both the `forward_auth` check and the wildcard proxy call it, so they cannot drift apart.

- `display_order` decides priority — lower first. `*.*/*` default group is pinned bottom.
- `domain` supports `*` prefix (`*.projectnova.download`).
- `path` uses `/*` prefix match — and it is **exact** otherwise. `/documentation` matches only that one path; `/documentation/*` is what covers `/documentation/rules/`.
- `action`: `access_code` (check cookie/magic link), `none` (allow), `custom_password` (per-rule password), `deny` (403).
- `allow_ip`, `allow_time`, `rate_limit` are **reserved** — stored, not enforced on hot path.

## When nothing matches

Two different situations used to look identical to the gate, and one of them leaked. `shared/gate.py` now separates them, and both gate paths (`forward_auth` and the wildcard proxy) go through it:

| Situation | Result |
|-----------|--------|
| A rule matched the path | That rule's `action` |
| A group matched the host, no rule matched the path | **Always** redirect to login |
| No group matched the host at all | `settings` `unmatched_action` |

A group ends in a `/*` catch-all, so "group matched, no rule matched" means that catch-all is missing or has been reordered below a narrower rule. The gate refuses unconditionally in that state and the `unmatched_action` setting cannot change it. A setting that could would turn a data mistake into a silent bypass, which is exactly how the previous behaviour (`if rule is None: pass` in the proxy path, while `forward_auth` redirected) leaked: the two paths disagreed about the same request, and the only reason it never showed was that every group happened to carry a catch-all.

That catch-all is no longer a convention nobody enforces. See the next section.

`unmatched_action` applies only when the host is in no group. Values: `access_code` (default) redirects to login, `deny` returns `403`, `none` proxies without auth. Set it on [Management UI](manage-panel.md) → Settings, or with `PUT /api/settings/unmatched_action`; anything else is refused with `400 must be one of access_code, deny, none` in both places. It defaults to `access_code` when the row or the setting API is unavailable, so a missing value gates rather than opens.

Worth knowing before reaching for it: the seeded default group is `*.*/*`, which matches **every** host, so normally no request can reach the "no group matched" branch. It becomes reachable when the default group is missing or its `domain` has been changed away from `*.*/*`. The setting is therefore a backstop for a broken default group, not a per-host policy dial; the middle row of the table above is the state a normal misconfiguration actually produces, and that one is always refused.

## Reordering

Both lists are ordered in the UI with ▲/▼ buttons (no drag, no JS dependency) and the `Order` column shows the real position (1, 2, 3…) rather than the raw sparse `display_order`. The arrows are disabled where the API would refuse or no-op: on the first/last row, and on the default group.

Underlying endpoints, both `X-Internal-Api-Key`:

- `PUT /api/groups/{gid}/order {"direction": "up|down"}` — `400 cannot reorder default`, `400 cannot swap with default`.
- `PUT /api/rules/{rid}/order {"direction": "up|down"}` returns `400 direction must be up|down`, `400 cannot move default rule`, or `400 cannot swap with default rule`.

Each swap trades `display_order` with the adjacent row; at the ends the API returns `{"ok": true}` without changing anything.

## Editing a group

`POST /manage/groups/{gid}/edit` (manage session) proxies `PUT /api/groups/{gid}` with `name` and `domain`. Only the fields actually submitted are sent, so a rename never carries a `domain` the caller did not touch.

The default group is the catch-all the gate falls back to, so its **`domain` is fixed**: the modal disables the input, and the API refuses a change with `400 cannot change default domain`, matching the neighbouring `cannot reorder default` / `cannot delete default` guards. Its **`name` stays editable**.

Validation mirrors `PUT /api/rules/{rid}` — each field is checked only when present, so a pure rename cannot be refused for an unrelated reason:

| Response | When |
|----------|------|
| `400 name required` | `name` present but empty |
| `400 domain required` | `domain` present but empty |
| `400 invalid domain` | `domain` fails `is_valid_host` — `*/` / `*.example.com` / `*.*/*` all pass |
| `400 cannot change default domain` | `domain` present on the default group |
| `409 group exists` | `name` collides with another group (`name` is `unique`) |
| `404 not found` | no such group |

`GET /api/groups` reports `is_default`, which is also how the lifespan seed finds the default group — keyed on the flag rather than on the name `*.*/*`, so renaming it cannot cause a second default group to be seeded on restart.

## The mandatory catch-all

Every group has exactly one `/*` catch-all, it carries `rules.is_default = 1`, and it is always last. The gate's fail-closed rule above depends on it: without a catch-all a group refuses every path it does not name, which is safe but surprising, and a catch-all that is not last leaves a rule behind it that can never fire.

The flag is what makes that verifiable. `is_default` is set by the migration on an existing database, by `POST /api/groups` on a new one, and re-established on every boot by the backfill in `shared/rule_defaults.py`.

### The guards

| Attempt | Response |
|---------|----------|
| `POST /api/groups/{gid}/rules` with `path = "/*"` | `400 path /* is reserved` |
| `PUT /api/rules/{rid}` on a non-default rule with `path = "/*"` | `400 path /* is reserved` |
| `PUT /api/rules/{rid}` on the default rule with a different `path` | `400 cannot change default rule path` |
| `PUT /api/rules/{rid}/order` on the default rule | `400 cannot move default rule` |
| `PUT /api/rules/{rid}/order` where the neighbour is the default rule | `400 cannot swap with default rule` |
| `DELETE /api/rules/{rid}` on the default rule | `400 cannot delete default rule` |

`/*` is reserved rather than merely protected from delete, because a second whole-host rule would sit behind the first and never fire, silently. The one thing that stays editable on the catch-all is its `action`: flipping a group's default policy from `access_code` to `none` is a legitimate operation and is how the seeded project groups are set up.

**Deleting the group is the only way to remove its catch-all**, and a new group always arrives with one.

The manage UI shows these controls rather than hiding them: the default group's delete button and the catch-all's delete button are rendered `disabled` with a `title` explaining why, so the panel never leaves an operator guessing whether a control is missing or refused.

### New groups gate by default

`POST /api/groups` seeds `Rule(path="/*", action="access_code", display_order=0, is_default=True)` for the group it just created. Gating is the default because a public path has to be a deliberate `none` rule, not the absence of one. The two seeded project groups keep the `none` catch-all they have always had, and the default `*.*/*` group keeps `access_code`.

### Where a new rule lands

A rule added through the API takes effect on the first request: the catch-all is renumbered last, so a new rule lands above it. The old trap (a rule added under an existing `/*` that could never fire, with no error anywhere) is now prevented rather than merely diagnosable.

Order within a group is otherwise what it was. The migration renumbers each group's rules `0..n-1` in their existing ascending order with the catch-all moved to the end, and a catch-all that was already last produces no change at all.

Shadowing is still possible and still reported: `GET /api/warnings` reports `/*` rules that hide later rules, and the dashboard renders the result as a banner that appears only when there is something to report. The old `/manage/warnings` page rendered two empty tables on a healthy gateway and is gone; the endpoint it read is unchanged.
