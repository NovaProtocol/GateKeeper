# Backup & Restore

Rules, rule groups, routes, access codes and settings live in the database volume
and nowhere else. They are not seeded from git and there is no migration to roll
back, so a wrong click has no undo. `/manage/backup` is that undo: it exports the
whole configuration to a file, and restores the configuration from one.

## The file

```json
{
  "version": 1,
  "created_at": "2026-09-17T19:00:32Z",
  "config": {
    "routes": [ ... ],
    "groups": [ ... ],
    "rules": [ ... ],
    "codes": [ ... ],
    "settings": [ ... ],
    "pages": [ ... ]
  },
  "sig": "9f2c…"
}
```

Plain, indented JSON. Not a JWT, not a container format: you can read it, diff it
and edit it in any editor.

- `version` — the file format. Currently `1`. A file with any other version is
  refused as `bad-version` before anything else is checked, so a file from a
  future release fails with the reason rather than a signature complaint.
- `created_at` — when the export was taken. Informational; not signed.
- `config` — everything that is configuration, sorted by row id.
- `sig` — HMAC-SHA256, hex, over the canonicalised `config` **only**.

`pages` is **optional**, and that is deliberate. Every file written before
[custom pages](custom-pages.md) existed has no such key, and `validate()` refuses
a file with a missing required section — so promoting it to a required section
would make every earlier backup unrestorable, and bumping `version` would refuse
them too. Either would destroy the only rollback point that exists at exactly the
moment it is needed. A file with no `pages` key therefore validates, restores, and
leaves no custom pages, which is what it described. A `pages` key that is present
but is not a list is still refused as malformed.

### What `sig` covers, and what it does not

`sig` is computed over `config` alone, canonicalised as
`json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
Signing the configuration rather than the whole envelope means the envelope can
gain metadata in a later version without invalidating every existing file, while
every byte that is actually restored stays covered.

> **The file is plaintext and contains every access code.**
>
> `sig` proves the file came from this deployment and has not been altered. It
> says nothing about who can read it. Store it like a password: not in email, not
> in a shared folder, not in a chat. There is no encryption here and none is
> planned; that would need a key-management story this project does not have.

Canonicalisation is deterministic, so the same configuration always produces the
same signature. Two consequences worth knowing:

- An export taken twice with no change in between is byte-identical in `config`
  and `sig`.
- The panel's own `backup_exported_at` bookkeeping is **excluded** from the file.
  If it were included, every export would sign differently and a restore could
  rewrite configuration that had not changed.

### What is not in the file

`audit_logs`. Logs are history, not configuration: restoring a configuration must
never delete or rewrite the record of what happened under the old one. There is
also no row-level log export here; use `GET /api/logs/export` for that.

## Exporting

`GET /manage/backup` → **Download backup**, or `GET /manage/backup/download`
directly. Either way the manage panel relays `GET /api/backup` unchanged and
sends it as a download named `gatekeeper-config-<YYYYMMDD-HHMMSS>.json`.

The export also stamps `backup_exported_at`, which is what the page shows as
"last export taken". That setting is not part of the file.

## Restoring

Restoring **replaces** all six sections. Anything added since the export is
gone. The page makes this two steps on purpose:

1. **Choose the file** and **type `REPLACE`**. Both buttons stay disabled until
   both are done, and the confirmation is re-checked on the server, so a crafted
   form post or a stale tab cannot skip the step.
2. **Preview** posts the file to the API with `?dry_run=1`. This verifies the
   signature and validates the configuration, and writes nothing. You get the
   signature verdict, the row count per section and every validation problem.
3. **Restore** applies it. The page then reports what was written, and how many
   audit rows had to be detached.

A restore is one transaction. If anything fails part way through, the previous
configuration is still in place; there is no state in which half the sections
come from the new file and half from the old.

Signatures are checked **first**. A file whose signature does not match is
refused before the configuration is even parsed for validity, so an altered file
cannot reach the database at all.

## What a restore does to audit history

`audit_logs` carries three foreign keys into configuration: `code_id` →
`codes.id`, `rule_id` → `rules.id`, `rule_group_id` → `rule_groups.id`.

Row ids are **preserved** across a restore, so in the normal case the export was
taken from this deployment and every reference still resolves. When the restored
configuration no longer contains a referenced row, the reference is **nulled**:

```sql
UPDATE audit_logs SET code_id = NULL WHERE code_id IS NOT NULL
  AND code_id NOT IN (SELECT id FROM codes);
```

The audit row itself is never deleted. A log line survives with one fewer claim
about what it pointed at, which is the honest outcome: the code is gone, the
visit happened. The API returns the counts as `detached_logs` and the page lists
them, so you can see exactly how many rows this affected. The same policy applies
to `rule_id` and `rule_group_id`.

The permanent code delete added later uses the identical rule, so there is one
behaviour to remember rather than two.

## Validation

`validate()` reports **every** problem, not just the first. The field rules
mirror the create endpoints:

| Section | Checked |
|---|---|
| `routes` | `host` present, `path` starts `/`, `route_type` ∈ `proxy`/`redirect`, proxy needs `upstream` and `port` 1..65535, redirect needs `redirect_target` and `redirect_code` ∈ 301/302/307/308, no duplicate host+path |
| `groups` | `name` present and unique, `domain` present, `display_order` an integer, **exactly one** group `is_default` |
| `rules` | `group_id` must exist in the same file, `path` starts `/`, `action` ∈ `access_code`/`none`/`custom_password`/`deny`, a `custom_password` rule must carry both hash and salt, `display_order` an integer, **every group has a `/*` catch-all** |
| `codes` | `code` present and unique, `active` boolean |
| `settings` | `key` present and unique, `value` a string |

### Warnings, not refusals

Two shapes are reported without blocking the restore, because the API can still
produce them and refusing them would mean a file the panel cannot put back:

- a group whose `domain` matches no host shape, so its rules never run;
- a group with **more than one** `/*` catch-all, where only the first can ever
  match.

Both are fail-closed at the gate. They are named in the preview so the operator
sees them; they do not stop the restore. A restore also renumbers each group so
its catch-all sorts last, because `display_order` is what the gate walks and a
restored file whose catch-all sat in the middle would reinstate the exact shape
the invariant forbids.

### A group with no catch-all is a refusal

This one *does* block the restore, and it is the only rule that is checked at
that severity. Since `/*` became a reserved path, a group without a catch-all
cannot be repaired through the panel at all: the group has to be deleted and
recreated. A file carrying such a group is refused with the reason, while the
operator can still fix the file, rather than applied into a host that answers
nothing. The check reads the file, not the database, so it holds for any file.

## Rolling back a risky change

Between phases a restore is the only rollback for the `rules` table, so take an
export before anything that rewrites it:

1. `GET /manage/backup/download`, and put the file somewhere safe.
2. Make the change.
3. If it needs undoing, upload the same file with **Preview** first to confirm
   the signature, then **Restore**.

The first production restore is an operator action.

## Endpoints

| Method | Path | Auth | Behaviour |
|---|---|---|---|
| `GET` | `/api/backup` | `X-Internal-Api-Key` | The signed file, as an attachment |
| `POST` | `/api/backup/restore` | `X-Internal-Api-Key` | Body is the file. `?dry_run=1` verifies and validates only. `{ok, sig, reason, problems[], warnings[], counts{}, detached_logs{}}`. `409` on a signature mismatch, `400` on a bad version or a validation problem |
| `GET` | `/manage/backup` | manage session | The page: export card, restore card, current counts, last export time |
| `GET` | `/manage/backup/download` | manage session | Streams the API file through unchanged |
| `POST` | `/manage/backup/restore` | manage session + `csrf_token` + `same_origin` | `file` + `confirm=REPLACE` + `stage=preview\|apply` |

`reason` is one of `ok`, `bad-json`, `bad-version`, `missing-sig`, `bad-sig`,
`bad-config`, `invalid-config`, `apply-failed`.

## Older files

The `is_default` flag on rules arrives with the mandatory-catch-all work. A file
written before that column existed simply omits it, and the restore derives it:
the highest-`display_order` `/*` rule in each group becomes the default. A file
from either side of that change restores under the newer code.

## Limitations

- **No field-level diff in the preview.** The preview reports counts and
  validation problems, not a before/after of each changed row. It catches the
  common failures (wrong file, truncated file, altered file) and not "this file
  is right but older than you think".
- **The file is only as good as its last export.** If no export has been taken,
  there is nothing to restore from.
- **A restore is not a merge.** It replaces all six sections together; there is
  no way to restore only the codes, or to skip a section. `pages` is the one
  section a file may omit entirely, and omitting it restores an empty set.
