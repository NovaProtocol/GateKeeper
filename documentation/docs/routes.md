# Routes

DB table `routes` drives the wildcard proxy in `auth-gateway`.

| Column | Type | Notes |
|--------|------|-------|
| `host` | String(255) | exact host, e.g. `portfolio.projectnova.download` |
| `path` | String(1024) | prefix, default `/` |
| `route_type` | `proxy` or `redirect` | |
| `upstream` | String(255) | container:port for proxy |
| `port` | Integer | upstream port |
| `redirect_target` | String(1024) | URL for redirect |
| `redirect_code` | Integer | 301, 302, 307, 308 |

Longest `path` match wins for `host`. `projectnova.download /` → redirect to `https://portfolio.projectnova.download`.

## Testing a saved route

```bash
curl -X POST http://api:8002/api/routes/1/test \
 -H "X-Internal-Api-Key: $INTERNAL_API_KEY"
# checks socket reachability
```

## Testing a route before it is saved

`POST /api/routes/test` takes the four fields the form holds rather than a route id, so a mistake can be found while it is still a draft:

```bash
curl -X POST http://api:8002/api/routes/test \
 -H "X-Internal-Api-Key: $INTERNAL_API_KEY" \
 -H "Content-Type: application/json" \
 -d '{"route_type":"proxy","upstream":"portfolio_main","port":8000}'
# {"ok": true, "latency": "reachable"}
```

| Body | Probe |
|------|-------|
| `{"route_type":"proxy","upstream":…,"port":…}` | `socket.create_connection((upstream, port))` with a two second timeout |
| `{"route_type":"redirect","redirect_target":"https://…"}` | the host in the URL is resolved |
| `{"route_type":"redirect","redirect_target":"/path"}` | nothing to resolve, reported as `redirect path ok` |

Validation mirrors `POST /api/routes`: `route_type` must be `proxy` or `redirect`, `port` must be `1..65535`, `upstream` is required for a proxy and `redirect_target` for a redirect. A bad shape is `400`, because that is a question the caller asked wrongly.

### What it promises, and what it does not

An unreachable upstream is **`200` with `ok: false`**, not a `4xx`: the probe worked and the answer was no. A `4xx` would make the modal show a validation error for a well-formed route and would leave a caller unable to tell a typo from a stopped container.

The probe opens a TCP connection and closes it. It sends no request and reads no response, so it can answer **"something is listening on that address"** and never **"that is the right application"**. A port held open by the wrong container, a service that has not finished starting, or a healthy process that will still reject the route's paths all report as reachable. Reachability is a necessary condition for a proxy route, not a sufficient one, and the button is a pre-flight check rather than a validation.

Neither endpoint touches the database. `POST /api/routes/{rid}/test` and `POST /api/routes/test` share the same probe functions, so the two cannot drift into disagreeing about the same upstream and port.

### Keys and sessions

Both endpoints sit behind the same gate as the rest of the internal API: `X-Internal-Api-Key`, reachable only from `net-api`. The modal reaches them through the panel, which holds the key:

- `POST /manage/routing/test` (manage session, CSRF pair, `same_origin`) relays the typed fields and returns the verdict as JSON.
- `POST /manage/routing/{rid}/test` is the saved-route variant, unchanged.

The draft probe is key-gated exactly as the saved-route probe is, so it widens no surface: an authenticated manage session could already ask about any stored upstream, and this variant asks about an unsaved one. The upstream name and port are caller-supplied and reach the docker networks the `api` container joins, which makes this a bounded server-side request forgery surface. A host allowlist would close it properly, and nothing yet requires one: both endpoints need the internal API key or a manage session, and the panel is the only caller.


## Reaching an upstream on another machine

A route whose `upstream` is a **container on this compose file** resolves through
Docker's internal DNS and costs nothing. A route whose upstream is the *hostname of
another machine* — a name Tailscale publishes, like `main-server` — costs a DNS
lookup, and on this host that lookup used to take **four seconds**.

### What was wrong

Docker copies the host's search domains into every container's `resolv.conf`, and
this host runs `systemd-resolved` with Tailscale MagicDNS in front of it. What it
also copied was `options ndots:0`, and `ndots:0` tells glibc that **any** name is
absolute and should be tried as written *first*.

`main-server` is not a public name. So the resolver asked for `main-server.`, waited
for the timeout, got `NXDOMAIN`, and only then tried the search domain —
`main-server.ghoul-aldebaran.ts.net` — which answered immediately. The delay was a
name that does not exist being asked for and waited on, every single request.

Measured on the live stack, both forms, same container:

| Query | Time |
|---|---|
| `main-server.ghoul-aldebaran.ts.net` | 0.001s |
| `main-server` (with `ndots:0`) | 3.94s |
| `main-server` (with `ndots:1`) | 0.000s |

The fix is one line in `compose.yaml`:

```yaml
  auth-gateway:
    dns_opt:
      - ndots:1
```

`ndots:1` means "try the search domain first for a name with no dots", which is
what the operator wrote the name to mean. Docker-internal names are unaffected:
they are answered by Docker's resolver before the search list is consulted
(verified — `gatekeeper_api` still resolves in 0.000s).

### Why it looks intermittent

The gateway pools its outbound sockets, so the lookup happens only when it has to
open a **new** connection. httpx's `keepalive_expiry` defaults to five seconds, so
a visitor who pauses to read a page has an empty pool and pays the lookup again on
their next click, while rapid clicks reuse the socket and feel instant. The audit
log shows both halves as plain latency — mostly 3ms, with the occasional 3.8s:

```
id=12846       3 ms  /
id=12844    3811 ms  /        <- new connection, DNS timeout
id=12842    3658 ms  /
id=12836    4002 ms  /
```

Three separate causes had to line up to produce it, and each is worth knowing on
its own:

1. **`ndots:0` inherited into the container** — the four seconds.
2. **A five-second keepalive** — why only *some* requests pay it.
3. **A route to another machine** — Docker-internal routes never resolve through
   the host's search list at all, so this only affects cross-host upstreams.

The gateway also raises `keepalive_expiry` to five minutes, so a normal reading
pause no longer empties the pool. That is a mitigation, not the fix: with `ndots:1`
a cold lookup costs a fraction of a millisecond anyway.
