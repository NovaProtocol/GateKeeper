# Caddy Integration

## Wildcard Gateway (primary)

`caddy:7000` is the wildcard ingress for `*.projectnova.download`. It does:

```caddy
:7000 {
  handle /health { respond `{"status":"ok"}` 200 }
  handle_path /phpmyadmin/* {
    forward_auth gatekeeper_auth:8001 { uri /api/authz/forward-auth }
    reverse_proxy gatekeeper_phpmyadmin:80
  }
  handle_path /documentation/* {
    forward_auth gatekeeper_auth:8001 { uri /api/authz/forward-auth }
    reverse_proxy gatekeeper_documentation:8005
  }
  handle { reverse_proxy gatekeeper_auth:8001 }
}
```

`gatekeeper_auth:8001` looks up `Route` (longest `path` for `host`), then `RuleGroup`/`Rule` dispatch, then proxies or redirects. Gated apps join `gatekeeper_dynamic` and need no Caddy/ `cloudflared-tunnel` of their own.

## Per-App Caddy (legacy)

Apps with their own Caddy join `gatekeeper_default` and gate per-handle:

```caddy
example.com {
  forward_auth gatekeeper:7000 { uri /api/authz/forward-auth }
  reverse_proxy app:8080
}
```

```yaml
networks:
  gatekeeper: { external: true, name: gatekeeper_default }
  cloudflared-tunnel: { external: true, name: cloudflared-tunnel_default }
```

Only `caddy` joins those networks; `app` stays on `default`. Proxy to `container_name:port`, not `app:port` (shared DNS collision → 502s). Published ports are `127.0.0.1:<port>:<port>`; public ingress is Cloudflare Tunnel.

## Public vs Gated

Leave a `handle` without `forward_auth` for health or webhooks:

```caddy
:7050 {
  handle /health { reverse_proxy app:8080 }
  handle /webhook/* { reverse_proxy app:8080 }
  handle { forward_auth gatekeeper:7000 { uri /api/authz/forward-auth } reverse_proxy app:8080 }
}
```

GateKeeper itself is not gated (self-loop would block `/`). Docs may be gated via `forward_auth` or left public.

## Magic Links

`https://app.example.com/page?access_code=<code>` → sets `gatekeeper_token` on `.<apex>` and `302`s stripped. No app code needed.
