# Cookie Contract

One cookie is the entire credential. No session table, no JWT, no expiry.

## Spec

| Field | Value |
|-------|-------|
| Name | `gatekeeper_token` |
| Value | `URLSafeSerializer(SECRET_KEY, salt="cookie").dumps(raw_code)` |
| Domain | `.<apex>` — last two labels of `request.host` (e.g., `https://staff.example.com` → `.example.com`) |
| Path | `/` |
| HttpOnly | `true` |
| SameSite | `Lax` |
| Secure | `true` |
| Max-Age / Expires | *none* — session cookie, non-expiring |
| Signing | `itsdangerous.URLSafeSerializer` with salt `"cookie"` |

Implementation:

```python
def apex_domain():
    host = request.host.split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:])

def set_auth_cookie(response, code):
    apex = apex_domain()
    response.set_cookie(
        "gatekeeper_token",
        serializer.dumps(code),
        domain=f".{apex}",
        path="/",
        httponly=True,
        samesite="Lax",
        secure=True,
    )
```text

## Why This Shape

- **Apex domain** means one login covers all subdomains: `gatekeeper.example.com`, `portfolio.example.com`, `staff.example.com`, etc. The cookie is set on `.example.com` so every subdomain sends it.
- **No expiry** keeps the UX trivial: one valid code logs the visitor in forever across all gated apps. Revocation is via `active=0` in the DB, not TTL.
- **HttpOnly + Secure** keeps the token out of JS and forces HTTPS (tunnel/Caddy terminates TLS upstream).
- **SameSite=Lax** allows top-level navigation across subdomains (`<a href="https://staff.example.com">`) to carry the cookie while still blocking most cross-site POST leaks. Iframe embeds on the same apex work; truly cross-site embeds do not — by design.

## Signing

```python
from itsdangerous import URLSafeSerializer

serializer = URLSafeSerializer(app.secret_key, salt="cookie")
raw = "3f9a12bc4d5e6f78"
token = serializer.dumps(raw)   # tamper-evident base64
code = serializer.loads(token)  # raises on bad signature
```

- `SECRET_KEY` is the single Flask secret (`os.environ["SECRET_KEY"]`), required (`app.secret_key = os.environ["SECRET_KEY"]` fails fast). Rotate it and every existing cookie becomes invalid.
- Salt is fixed `"cookie"` — isolates this serializer from any other use of the same secret.
- The **raw code** (hex string) is what is signed, not a user id. Server checks the code against the `codes` table; the cookie is just a signed bearer for that code.

## Validation

On every auth check (`/` and `/api/authz/forward-auth`):

```python
token = request.cookies.get("gatekeeper_token")
if token:
    try:
        code = serializer.loads(token)
    except Exception:
        code = None
    if code:
        row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
        ...
```text

- Bad signature or tampering → `loads` raises, treated as "no cookie" → redirect to login.
- Valid signature but `active=0` or missing row → not authenticated.
- Valid + active → `200` (forward_auth) or immediate redirect to `?redirect=` target (login page).

## Domain Adaptation

- `apex_domain()` is recomputed per request from `request.host`, never hardcoded.
- If no `?redirect=` is supplied or it fails the open-redirect guard, fallback is `https://portfolio.<apex>` (portfolio-specific default retained for history).
- Deploys on any apex work without config change — the cookie domain tracks whatever `Host` GateKeeper sees.

## Rotation & Revocation

- **Per-code kill:** `POST /manage/invalidate` with `id` → `UPDATE codes SET active=0`. Instant, global, checked on the next request.
- **Global kill:** rotate `SECRET_KEY` and restart GateKeeper — every existing signature fails validation. Use for compromise.
- **Backup code:** `BACKUP_CODE` env seeds a row `label="backup"` when absent; revoking it requires `active=0` via `/manage`.

## Testing the Cookie

```python
# In pytest, using the app serializer
from app import serializer

code = "test-backup-code"
token = serializer.dumps(code)
client.set_cookie("gatekeeper_token", token, domain="localhost")
resp = client.get("/api/authz/forward-auth")
assert resp.status_code == 200
```

```bash
# Manual with curl
TOKEN=$(python3 -c "from itsdangerous import URLSafeSerializer; print(URLSafeSerializer('secret', salt='cookie').dumps('mycode'))")
curl -si http://127.0.0.1:7000/api/authz/forward-auth -H "Cookie: gatekeeper_token=$TOKEN" -H "X-Forwarded-Uri: /"
```text

## Relationship to `?access_code=`

The cookie and the magic link carry the **same** raw code. Visiting any gated URL with `?access_code=<code>` sets the apex cookie via `Set-Cookie` in the `302` response and then strips the param. Subsequent requests ride the cookie — the param is never stored.

Treat `?access_code=` URLs as secrets in logs, chat, and browser history — they are the code in clear text for one hop.
