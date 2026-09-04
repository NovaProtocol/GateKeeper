# API Keys

Generate with `GET /api/keys/dice?len=8` (`len 4–64`, alias `?len=` not `?dice=`) or provide 8–64 chars via `POST /api/keys {"key": "...", "label": "...", "mode": "none|whitelist|blacklist"}` (`X-Internal-Api-Key`).

Stored as `pbkdf2_hmac sha512 100k` hash + `salt` + `key_prefix` (masked). One-time `key` returned on create.

| Column | Notes |
|--------|-------|
| `mode` | `none` (any host), `whitelist` (only listed), `blacklist` (all except) |
| `whitelist`/`blacklist` | JSON list of `host/path` globs |
| `expires_at` | optional expiry |
| `last_used` | bumped on success |

## Transports

`Authorization: Bearer <key>` → `X-Api-Key` → `?api_key=` (also via `X-Forwarded-Uri`).

```bash
curl -H "Authorization: Bearer <key>" https://app.example.com/api/data
curl -H "X-Api-Key: <key>" https://app.example.com/api/data
curl "https://app.example.com/api/data?api_key=<key>"
```
