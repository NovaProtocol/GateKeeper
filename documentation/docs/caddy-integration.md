# Caddy Integration

GateKeeper is only useful when Caddy calls it before proxying. Any project that wants to be gated adds one `forward_auth` stanza and joins the `gatekeeper_default` Docker network.

## The Gate — One Stanza

```caddy
example.com {
    forward_auth gatekeeper:7000 {
        uri /api/authz/forward-auth
    }
    reverse_proxy app:8080
}
```text

- `gatekeeper:7000` resolves via Docker DNS on `gatekeeper_default` (external).
- `uri /api/authz/forward-auth` is the only auth endpoint — do not point it at `/` or `/api/verify` (removed).
- Caddy forwards `X-Forwarded-Uri` (original path+query), `X-Forwarded-Host`, `X-Forwarded-Proto`; GateKeeper needs all three to reconstruct redirects and validate `?redirect=`.

## Compose — Join the Gate Network

```yaml
services:
  caddy:
    build: ./caddy
    container_name: myproject_caddy
    restart: unless-stopped
    ports:
      - "127.0.0.1:7050:7050"  # loopback-only; public ingress is the tunnel
    networks:
      - default
      - gatekeeper          # so caddy can dial gatekeeper:7000
      - cloudflared-tunnel  # so the tunnel can reach caddy
  app:
    build: .
    container_name: myproject_main
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=5)"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    networks:
      - default             # NOT gatekeeper, NOT tunnel — only caddy is on those

networks:
  gatekeeper:
    external: true
    name: gatekeeper_default
  cloudflared-tunnel:
    external: true
    name: cloudflared-tunnel_default
```

Rules:

- Only `caddy` joins `gatekeeper_default`; `app` never does and never holds GateKeeper env vars.
- Create the network once on the host: `docker network create gatekeeper_default` (GateKeeper's compose declares it external).
- Proxy to the app via its **container_name** (`myproject_main:8080`), never generic `app:8080` — shared-network DNS collision returns every project's `app` alias on `cloudflared-tunnel_default` and causes intermittent 502s.

## Public vs Gated Routes

Not everything behind Caddy must be gated. Leave a `handle` without `forward_auth` to keep it public:

```caddy
:7050 {
    handle /health {
        reverse_proxy myproject_main:8080
    }

    handle /webhook/* {
        reverse_proxy myproject_main:8080
    }

    handle {
        forward_auth gatekeeper:7000 {
            uri /api/authz/forward-auth
        }
        reverse_proxy myproject_main:8080
    }
}
```text

- `/health` must bypass auth for tunnel/uptime probes and compose healthchecks.
- `/webhook/*` may be public when it validates its own token (e.g., Xendit).
- Docs handled similarly: `handle_path /documentation/* { reverse_proxy myproject_documentation:8005 }` is typically gated, but for GateKeeper itself docs are **public** (see below).

## Magic Links

Any gated URL can be shared as:

```
https://myapp.example.com/some/page?access_code=<16-hex>
```text

- The first hit sets `gatekeeper_token` on `.<apex>` and `302`s to `https://myapp.example.com/some/page` (param stripped, cookie persists).
- No code lives in app code — the strip happens in GateKeeper; Caddy relays the `Set-Cookie`.

## GateKeeper Is Not Gated — Exception for Docs

GateKeeper's own login (`https://gatekeeper.<apex>/`) must be reachable **without** a loop through itself — gating GateKeeper with `forward_auth gatekeeper:7000` is a self-loop. Therefore:

- **No Caddy in this repo** — GateKeeper runs on `:7000` directly; other projects' Caddy instances call it.
- **Docs are public** — the `documentation` service would, if exposed via a Caddy, use an ungated route:

```caddy
handle_path /documentation/* {
    reverse_proxy gatekeeper_documentation:8005
}
# no forward_auth — docs are public, GateKeeper is the gate
```

In this repo docs are **internal-only** (`expose: ["8005"]`, no `ports:`, `networks: [default]`). Reach them via container DNS (`http://gatekeeper_documentation:8005`) or local `docker compose` port-forward. If a Caddy is added to this repo later, document the above ungated docs handler and keep GateKeeper itself ungated.

## Verification

```bash
# From a gated project's Caddy container — must resolve to GateKeeper's IP, not 127.0.0.1
docker exec myproject_caddy getent hosts gatekeeper

# forward_auth 200 with a valid cookie
curl -si -b "gatekeeper_token=<signed>" http://gatekeeper:7000/api/authz/forward-auth \
  -H "X-Forwarded-Uri: /" | head -n 5

# Compose validates missing env
docker compose config > /dev/null
```text

### Network DNS Gotcha

`cloudflared-tunnel_default` and `gatekeeper_default` are **shared across every project** on the host. Service name `app` on any of them collides. Always proxy to `container_name` (`myproject_main:8080`), never `app:8080` — see `reference/docker/compose.md`.
