# Auth Flow

GateKeeper's only auth endpoint is `GET /api/authz/forward-auth`. It is called by **Caddy `forward_auth`**, not by browsers directly, and returns either `200` (let the request through) or `302` (set a cookie or go to login). No tokens are checked inside the apps.

## Diagram

```text
Request → Caddy forward_auth → GateKeeper /api/authz/forward-auth
                                ├─ valid gatekeeper_token cookie   → 200 → Caddy proxies to app
                                ├─ valid ?access_code= on URL     → 302 + Set-Cookie (apex, no expiry)
                                │                                     + redirect to same URL, param stripped
                                └─ neither                         → 302 → https://gatekeeper.<apex>/?redirect=<original>
```

Check order is fixed: **cookie first**, then `?access_code=` query param on the original URL (from `X-Forwarded-Uri`), then redirect to login.

## 1. Cookie Check

```python
# app.py — fragment
token = request.cookies.get("gatekeeper_token")
if token:
    try:
        code = serializer.loads(token)
    except Exception:
        code = None
    if code:
        row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
        if row:
            db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
            db.commit()
            return "", 200
```text

- `gatekeeper_token` is `URLSafeSerializer(SECRET_KEY, salt="cookie").dumps(raw_code)`.
- Invalid signature → treated as "no cookie".
- Inactive code (`active=0`) → 200 is not returned; falls through to magic-link then redirect.
- `last_accessed` is bumped on **every** successful auth.

## 2. Magic Link (`?access_code=`)

Any gated URL can carry `?access_code=<code>`:

```
https://staff.example.com/dashboard?access_code=3f9a12...&foo=bar
```text

GateKeeper strips **only** the `access_code` param and preserves the rest:

```python
original_uri = request.headers.get("X-Forwarded-Uri", "")
parts = urlsplit(original_uri)
query = parse_qsl(parts.query)
code_param = next((v for k, v in query if k == "access_code"), "")
if code_param:
    row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code_param,)).fetchone()
    if row:
        db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        db.commit()
        clean_query = urlencode([(k, v) for k, v in query if k != "access_code"])
        resp = redirect(urlunsplit(("", "", parts.path, clean_query, parts.fragment)))
        set_auth_cookie(resp, code_param)
        return resp
```

- Caddy relays the `Set-Cookie` (`Domain=.apex, HttpOnly, SameSite=Lax, Secure`) and the `302` to the cleaned URL.
- The browser follows the redirect to the same page without the param — the secret leaves the address bar and history after one hop.
- Only **one** `access_code` occurrence is consumed; duplicates after the first are stripped together via `urlencode` of the filtered list.

## 3. Redirect to Login

If neither cookie nor magic link is valid, GateKeeper reconstructs the original request and redirects to the apex login:

```python
proto = request.headers.get("X-Forwarded-Proto", request.scheme)
host = request.headers.get("X-Forwarded-Host", request.host)
host = host.split(":")[0].lower()
apex = apex_domain()
if host != apex and not host.endswith("." + apex):
    host = apex
target = quote(f"{proto}://{host}{original_uri}", safe="")
return redirect(f"https://gatekeeper.{apex_domain()}/?redirect={target}")
```text

- `apex_domain()` = last two labels of `request.host` (e.g., `sub.example.com` → `example.com`). One GateKeeper serves any apex it is fronted on.
- `?redirect=` is user-controlled. Its host is validated via `_safe_redirect_target()` before use at login.

## 4. Login Page (`GET /` / `POST /`)

```
GET /?redirect=https://staff.example.com/dashboard
POST /  (form: code=<candidate>)
```text

```python
@app.route("/", methods=["GET"])
def login():
    token = request.cookies.get("gatekeeper_token")
    if token:
        try:
            serializer.loads(token)
            return redirect(get_redirect_target())
        except Exception:
            pass

    code = request.args.get("access_code", "").strip()  # GET magic link on login host too
    if code:
        row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
        if row:
            db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
            db.commit()
            resp = redirect(get_redirect_target())
            set_auth_cookie(resp, code)
            return resp

    return render_template("login.html")
```

```python
@app.route("/", methods=["POST"])
def login_post():
    code = request.form.get("code", "").strip()
    row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
    if row:
        db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        db.commit()
        resp = redirect(get_redirect_target())
        set_auth_cookie(resp, code)
        return resp
    return render_template("login.html", error="Invalid code")
```text

### Redirect Safety — Open-Redirect Guard

```python
def _safe_redirect_target(target: str) -> bool:
    apex = apex_domain()
    parts = urlsplit(target)
    if not parts.scheme and not parts.netloc:
        return target.startswith("/")
    if parts.scheme in ("http", "https") and parts.netloc:
        host = parts.netloc.split(":")[0].lower()
        return host == apex or host.endswith("." + apex)
    return False

def get_redirect_target():
    target = request.args.get("redirect", "").strip()
    if target and _safe_redirect_target(target):
        return target
    apex = apex_domain()
    return f"https://portfolio.{apex}"
```

- Without `?redirect=`, fallback is `https://portfolio.<apex>` (portfolio-specific default retained from history).
- Absolute redirects are only allowed when the host is the apex or a subdomain of it — kills open-redirect to attacker domains.
- Paths like `/staff/` are always allowed.

## 5. Caddy Plumbing

```caddy
example.com {
    forward_auth gatekeeper:7000 {
        uri /api/authz/forward-auth
    }
    reverse_proxy app:8080
}
```text

Caddy sets `X-Forwarded-Uri`, `X-Forwarded-Host`, `X-Forwarded-Proto` for GateKeeper to read. Do not strip or override them.

Manual tests:

```bash
curl -si http://127.0.0.1:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /staff/"                     # → 302 to login
curl -si http://127.0.0.1:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /staff/?access_code=test123" # → 302 to /staff/ + Set-Cookie
curl -si -b "gatekeeper_token=<cookie>" \
  http://127.0.0.1:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /staff/"                     # → 200
```

## Removed: `/api/verify` + Tickets

The old app-level flow (`/api/verify`, `URLSafeTimedSerializer` 5-min tickets, `GATEKEEPER_INTERNAL`) is deleted. Apps must not embed any GateKeeper logic — they trust Caddy only proxies authenticated traffic.
