# Cookie Contract

Three cookies share the apex domain (last two labels of host → `.example.com`).

| Name | Value | Domain | Path | HttpOnly | SameSite | Secure | Max-Age |
|------|-------|--------|------|----------|----------|--------|---------|
| `gatekeeper_token` | `URLSafeSerializer(SECRET_KEY, salt="cookie").dumps(code)` | `.<apex>` | `/` | yes | Lax | yes | none (session) |
| `manage_session` | `URLSafeSerializer(SECRET_KEY, salt="cookie").dumps("manage-ok")` | host | `/manage` | yes | Lax | yes | 8h |
| `gatekeeper_custom_{id}` | `URLSafeSerializer(SECRET_KEY, salt="custom-{id}").dumps("ok")` | `.<apex>` | `/` | yes | Lax | yes | session |

```python
from itsdangerous import URLSafeSerializer
ser = URLSafeSerializer(SECRET_KEY, salt="cookie")
token = ser.dumps(raw_code)  # gatekeeper_token
code = ser.loads(token)      # raises BadSignature on tamper
```

- **Apex** `.example.com` covers `gatekeeper.example.com`, `portfolio.example.com`, etc. One login works everywhere.
- **No expiry** on `gatekeeper_token` — revocation is `codes.active=0`; `manage_session` expires in 8h.
- **SameSite=Lax** allows top-level navigation across subdomains to carry cookies; iframe on same apex works, cross-site does not.
- Rotate `SECRET_KEY` → all cookies invalid.

## Validation

```python
token = request.cookies.get("gatekeeper_token")
code = URLSafeSerializer(SECRET_KEY, salt="cookie").loads(token)
row = await session.execute(select(Code).where(Code.code==code, Code.active==True))
```

Bad signature, missing or inactive code → unauthenticated → `302` to login.
