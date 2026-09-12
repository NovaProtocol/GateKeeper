# Caddy Integration

## Wildcard Gateway (primary)

`caddy:7000` is the wildcard ingress for `*.projectnova.download`. It does:

```caddy
:7000 {
 handle /health { respond `{"status":"ok"}` 200 }
 handle_path /documentation/* {
 forward_auth gatekeeper_auth:8001 {
            uri /api/authz/forward-auth
        }
 reverse_proxy gatekeeper_documentation:8005
 }
 handle { reverse_proxy gatekeeper_auth:8001 }
}
```

Live `GateKeeper/caddy/Caddyfile` is exactly that — 3 handles only (no `phpmyadmin`). `gatekeeper_auth:8001` looks up `Route` (longest `path` for `host`), then `RuleGroup`/`Rule` dispatch (cache `CACHE_TTL=5s` via `api:8002` on `net-api`), then proxies or redirects. Gated apps join the GateKeeper-owned `gatekeeper` network (join = permission to receive traffic) and need no `cloudflared-tunnel` of their own. All DB work (`shared/db.py`) is `api:8002` only (`net-data`).

## Per-App Caddy (legacy)

Apps with their own Caddy historically joined `gatekeeper` and gated per-handle:

```caddy
example.com {
 reverse_proxy app:8080
}
```

Live GateKeeper no longer exposes `gatekeeper:7000` per-app — the wildcard `:7000 → gatekeeper_auth:8001` is the sole gate. Legacy `gatekeeper` / `gatekeeper:7000` examples remain only for historical per-app Caddy setups that still run that pattern; new apps join `gatekeeper` behind the wildcard and need no per-project gate of their own or `cloudflared-tunnel`. Only `caddy` joins those networks; `app` stays on `default`. Proxy to `container_name:port`, not `app:port` (shared DNS collision → 502s). Published ports are `127.0.0.1:<port>:<port>`; public ingress is Cloudflare Tunnel.

## Public vs Gated

Leave a `handle` without a GateKeeper `none`-rule for health or webhooks on per-app Caddy (legacy pattern):

```caddy
:7050 {
 handle /health { reverse_proxy app:8080 }
 handle /webhook/* { reverse_proxy app:8080 }
 handle { reverse_proxy app:8080 }
}
```

GateKeeper itself is not gated (self-loop would block `/`). Docs may be gated via the GateKeeper gate or left public.

## Magic Links

`https://app.example.com/page?access_code=<code>` → sets `gatekeeper_token` on `.<apex>` and `302`s stripped. No app code needed.
