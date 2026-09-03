# Cookie Contract

Three cookies share the apex domain (last two labels of host → `.example.com`).

| Name | Value | Domain | Path | HttpOnly | SameSite | Secure | Max-Age |
|------|-------|--------|------|----------|----------|--------|---------|
| `gatekeeper_token` | `PyJWT HS256` (`SECRET_KEY`, `cid`/`name`, `iss=gatekeeper`, `aud=projectnova.download`, `exp 12h`) | `.<apex>` | `/` | yes | Lax | yes | 12h |
| `manage_session` | `URLSafeSerializer(SECRET_KEY, salt="cookie").dumps("manage-ok")` | host | `/manage` | yes | Lax | yes | 8h |
| `gatekeeper_custom_{id}` | `URLSafeSerializer(SECRET_KEY, salt="custom-{id}").dumps("ok")` | `.<apex>` | `/` | yes | Lax | yes | session |

```python
import jwt
from shared.jwt import create_access_token, verify_access_token
token = create_access_token(cid, name)  # HS256, exp 12h
token = ser.dumps(raw_code)  # gatekeeper_token
data = verify_access_token(token)  # checks exp/aud/iss/signature
```

- **Apex** `.example.com` covers `gatekeeper.example.com`, `portfolio.example.com`, etc. One login works everywhere.
- **No expiry** on `gatekeeper_token` — revocation is `codes.active=0`; `manage_session` expires in 8h.
- **SameSite=Lax** allows top-level navigation across subdomains to carry cookies; iframe on same apex works, cross-site does not.
- Rotate `SECRET_KEY` → all cookies invalid.

## Validation

```python
token = request.cookies.get("gatekeeper_token")
data = verify_access_token(token); code = data["cid"] if data else None
row = await session.execute(select(Code).where(Code.code==code, Code.active==True))
```

Bad signature, missing or inactive code → unauthenticated → `302` to login.
