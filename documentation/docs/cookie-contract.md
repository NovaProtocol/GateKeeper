# Cookie Contract

Three cookies share the apex domain (last two labels of host → `.example.com`).

| Name | Value | Domain | Path | HttpOnly | SameSite | Secure | Max-Age |
|------|-------|--------|------|----------|----------|--------|---------|
| `gatekeeper_token` | `PyJWT HS256` (`SECRET_KEY`, `cid`/`name`, `iss=gatekeeper`, `aud=projectnova.download`, `exp 12h`) | `.<apex>` | `/` | yes | Lax | yes | 12h |
| `manage_session` | `PyJWT HS256` (`SECRET_KEY`, `sub=manage` `role=manage`, `iss=gatekeeper`, `aud=projectnova.download`, `exp 8h`) | host | `/manage` | yes | Lax | yes | 8h |
| `gatekeeper_custom_{id}` | `PyJWT HS256` (`SECRET_KEY`, `rid`, `iss=gatekeeper`, `aud=projectnova.download`, `exp 12h`) | `.<apex>` | `/` | yes | Lax | yes | 12h |

```python
import jwt
from shared.jwt import create_access_token, verify_access_token, create_manage_token, create_custom_token
token = create_access_token(cid, name) # HS256, exp 12h, aud projectnova.download
manage = create_manage_token() # 8h, Path /manage
custom = create_custom_token(rid) # 12h, rid
data = verify_access_token(token) # checks exp/aud/iss/signature + cid active via api
```

- **Apex** `.example.com` covers `gatekeeper.example.com`, `portfolio.example.com`, etc. One login works everywhere (`SameSite=Lax`).
- **Expiry** — `gatekeeper_token` `12h` (`Max-Age=43200`), `manage_session` `8h`, `gatekeeper_custom_{id}` `12h` — revocation is `codes.active=0` via `api:8002`; expired `jwt.ExpiredSignatureError` → `302 /login`.
- **SameSite=Lax** allows top-level navigation across subdomains to carry cookies; iframe on same apex works, cross-site does not.
- Rotate `SECRET_KEY` → all cookies invalid.

## Validation

```python
token = request.cookies.get("gatekeeper_token")
data = verify_access_token(token); code = data["cid"] if data else None
data = verify_access_token(token)
if not data: raise
row = await session.execute(select(Code).where(Code.id==data["cid"], Code.active==True)) # cid from JWT, active kill via api
```

Bad signature, missing or inactive code → unauthenticated → `302` to login.
