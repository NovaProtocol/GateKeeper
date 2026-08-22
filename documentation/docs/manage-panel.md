# Manage Panel

`/manage` is the only authenticated admin surface — HTTP Basic-auth, no cookie, no GateKeeper gate. It lists, creates, and kills access codes.

## Auth

```python
def require_manage_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        manage_pw = os.environ.get("MANAGE_PASSWORD")
        if not manage_pw:
            return "MANAGE_PASSWORD not configured", 500
        if not auth or not secrets.compare_digest(auth.password, manage_pw):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="GateKeeper Manage"'})
        if request.method == "POST" and not same_origin():
            return ("Cross-site request rejected", 403)
        return f(*args, **kwargs)
    return decorated
```text

- **Username:** any value is accepted; only the **password** is checked against `MANAGE_PASSWORD` (`secrets.compare_digest`).
- Missing `MANAGE_PASSWORD` → `500`.
- Wrong password → `401` with `WWW-Authenticate: Basic realm="GateKeeper Manage"`.
- `POST` requests require same-origin `Origin`/`Referer` (`same_origin()` checks `apex_domain()`) — CSRF guard.

```python
def same_origin():
    origin = request.headers.get("Origin")
    if origin is None:
        origin = request.headers.get("Referer")
    if not origin:
        return False
    origin_host = urlsplit(origin).hostname or ""
    return origin_host == request.host.split(":")[0] or origin_host.endswith("." + apex_domain()) or origin_host == apex_domain()
```

> Manage is intentionally **not** behind `forward_auth` — it is inside the gate (only GateKeeper's own `/manage` checks Basic-auth). Browser login to GateKeeper does not grant `/manage`; the panel is a separate credential.

## Routes

| Route | Method | Auth | Behavior |
|-------|--------|------|----------|
| `/manage` | `GET` | Basic-auth | Renders `manage.html` with all codes ordered by `created_at DESC` |
| `/manage/create` | `POST` | Basic-auth + same_origin | Generates `secrets.token_hex(8)` + optional `label`; inserts into `codes` |
| `/manage/invalidate` | `POST` | Basic-auth + same_origin | Sets `active=0` for `id` form field |

All three use `@require_manage_auth`.

## List — `GET /manage`

```python
@app.route("/manage")
@require_manage_auth
def manage():
    db = get_db()
    codes = db.execute("SELECT id, code, label, active, created_at, last_accessed FROM codes ORDER BY created_at DESC").fetchall()
    return render_template("manage.html", codes=codes)
```text

`manage.html` shows:

- Stats row: **Total / Active / Inactive** counts.
- **Create Code** card: `POST` to `manage_create` with optional `label` input.
- **Existing Codes** table: `Code | Label | Status | Created | Last Accessed | Invalidate` with a toggle to hide inactive rows.

Columns map directly to `codes` schema (`label` may be `NULL` → rendered as *no label*).

## Create — `POST /manage/create`

```python
@app.route("/manage/create", methods=["POST"])
@require_manage_auth
def manage_create():
    new_code = secrets.token_hex(8)
    label = request.form.get("label", "").strip() or None
    db = get_db()
    try:
        db.execute("INSERT INTO codes (code, label) VALUES (?, ?)", (new_code, label))
        db.commit()
    except sqlite3.IntegrityError:
        return "Code generation collision, try again", 500
    return redirect("/manage")
```

- Code is 16 lower-hex chars, globally unique (`UNIQUE` constraint). Collision → `500` retry.
- Label is optional, stored as `TEXT`, displayed as badge; empty string → `NULL`.
- No rate limit — panel is admin-only; brute-force of the GET form is not applicable.

## Invalidate — `POST /manage/invalidate`

```python
@app.route("/manage/invalidate", methods=["POST"])
@require_manage_auth
def manage_invalidate():
    code_id = request.form.get("id", type=int)
    if not code_id:
        return "Missing code id", 400
    db = get_db()
    db.execute("UPDATE codes SET active = 0 WHERE id = ?", (code_id,))
    db.commit()
    return redirect("/manage")
```text

- Soft delete: `active` flips to `0`; row stays for audit (`created_at`, `last_accessed` retained).
- Idempotent — invalidating an already-inactive id is a no-op.
- Instant effect: next `forward_auth` with that code's cookie fails and redirects to login.

## Styling

- `templates/manage.html` extends `templates/base.html`, loads `static/css/manage.css` (dark portfolio theme: `--bg-primary #0a0a0f`, `--accent #64ffda`).
- Inline toggle JS hides `tr.inactive` rows when checked — no framework needed.

## Backup Code Seeding

On first request (or `init_db()`), if `BACKUP_CODE` env is set and no row with that `code` exists:

```python
backup = os.environ.get("BACKUP_CODE")
if backup:
    existing = db.execute("SELECT 1 FROM codes WHERE code = ?", (backup,)).fetchone()
    if not existing:
        db.execute("INSERT INTO codes (code, label) VALUES (?, ?)", (backup, "backup"))
```

This seeds a code labeled `backup` that appears in `/manage` and can be invalidated like any other.

## Security Notes

- Do not log `code` values at `INFO` — they are secrets. `last_accessed` is the only usage signal.
- `/manage` forms use `url_for('manage_create')` / `url_for('manage_invalidate')` — no hardcoded paths.
- Never expose `codes` via an API — only the server-rendered `/manage` HTML lists them, gated by Basic-auth.
