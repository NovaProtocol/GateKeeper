# Caching

GateKeeper sits in front of every project, so it is the layer that decides what
a shared cache is allowed to keep. Get this wrong in the permissive direction and
a gated page is stored against its URL and served to the next visitor, who has
proved nothing. Get it wrong in the other direction and every static asset,
badge and stylesheet is pinned to `no-store` on a deployment that could have
served them from cache.

The policy is decided in code, not in Cloudflare and not in a `Caddyfile`. This
page states the rule, the reasons behind the values, and the cases that look like
special pleading but are not.

## The invariant

> A response may be `public`-cacheable only when the path is ungated (the gate
> resolved `action == "none"`) **and** the upstream chose that header itself.

Both halves are load-bearing. A path the owner configured to gate nothing is a
path whose bytes are meant to be published; that is what lets an embedded badge
work. A path the gate actually decided belongs to one visitor, whatever header
the upstream stamped on it.

## Where the policy lives

| Layer | File | Role |
|-------|------|------|
| Gateway | `shared/middleware.py` | the precedence rule, the control-plane rule, and `enforce_private_cache_control` |
| Gateway | `auth-gateway/app.py` | applies the helper to every response the gate produced, and to proxied responses it decided |
| Docs service | `documentation/cache.py` | the same policy for the pages on this site, minus the gate rules, because this site is never the gate |
| Management UI | `management/app.py` | uses `shared/middleware.py` like every other service |

`CacheControlMiddleware` runs on every service on this stack and fills a
`Cache-Control` only when the response does not already carry one. The
`is_debug` flag from `DEPLOYMENT_TYPE` chooses the value it fills with, not
whether it overwrites.

## Precedence, in order

`CacheControlMiddleware.dispatch` decides in this order, and the order is the
whole mechanism:

1. **Control-plane paths are forced.** `/api/`, `/manage`, `/login`, `/logout`
   and `/api/authz/` get `private, no-store` in both modes, whatever the
   upstream sent. A cached verdict is the one mistake that would break the gate
   itself, so this branch is checked first and it does not consult the flag.
2. **An existing header is kept.** If the response already carries
   `Cache-Control`, it is left exactly as it is. The upstream knows its own
   content and its own decision to publish; a deployment-type default is not a
   reason to overrule it.
3. **A gap is filled.** Only when nothing is present does the middleware write a
   value: `no-store` in debug, the path class's lifespan otherwise.

Step 2 is safe only because of the safety net below. On its own, "keep whatever
the upstream sent" would let a gated upstream publish a `public` page.

## Path classes

Filled values, per class. The constants are at the top of
`shared/middleware.py` and are deliberately not environment variables: four
integers do not justify new required config, and a redeploy is the honest way to
change them.

| Class | Paths | Debug | Production |
|-------|-------|-------|------------|
| Control plane | `/api/`, `/manage`, `/login`, `/logout`, `/api/authz/` | `private, no-store` | `private, no-store` |
| Static | `/static/` | `no-store` | `public, max-age=86400` |
| Health | `/health` | `no-store` | `public, max-age=3600` |
| Everything else | any other path | `no-store` | `private, max-age=60` |

The control-plane prefix wins over the health list, so `/api/health` on this
stack is `private, no-store` and the `"/api/health"` entry in the docs service's
`_MISC_PATHS` never reaches its own branch. The gateway's own `_MISC_PATHS` holds
`/health` alone, which is the probe to point a monitor at.

`_HTML_MAX_AGE` is `60` here and `300` in `documentation/cache.py`. That
difference is intentional and stays. The gateway's HTML is a verdict about one
visitor, produced per request, and a minute is already generous for it. The docs
site's HTML is built once and changes only on deploy, so it can be held five
minutes. Unifying the two numbers would either pin the docs site to an
unnecessarily short life or let a per-visitor page sit in a cache for five
minutes.

## The safety net

`enforce_private_cache_control(response)` in `shared/middleware.py` keeps the
step 2 promise above from being a hole. It is called on:

- every response the gate produced itself: the `302` login redirects, the
  `action == "none"` custom-page bytes, the rate-limit `429`, and every body from
  `_error_response` (`403`, `404`, `502`, `503`, `504`);
- the maintenance `503`, on both its HTML and JSON shapes;
- a proxied response, when the gate decided the request, meaning any resolved
  action other than `none`.

It replaces `Cache-Control` with `private, no-store` unless the value already
says `private` or `no-store`. A bare `max-age=300` is replaced too: without
`private` or `no-store` it is shared-cacheable, which is what HTTP says a bare
`max-age` means. That is the point of the check being on the value rather than on
the word `public`.

### The `none` exception, and why it must not be tightened

A response is left alone when the gate resolved `action == "none"` and the
upstream set the header. NovaProtocol's SVG badges are exactly this case: the
rule group for `github.projectnova.download` holds `/public/*` as `none`, the app
stamps `public, max-age=300` plus a strong `ETag`, and Cloudflare and GitHub's
image proxy are what make an embedded badge render at all. A `private` response
is skipped by every shared cache, so demoting it would break every badge on the
owner's profile.

If you are here to "tighten" the demotion so that everything the gate touches is
private, note what it costs: `action == "none"` is the owner stating that a path
is public. The gate is not making a decision there, it is passing one along.

## `/documentation/*` and who is authoritative

The gateway's `Caddyfile` handles `/documentation/*` for **its own hosts only**
(`gatekeeper.<apex>`, the apex, and the in-network aliases) by calling `forward_auth`
and then proxying straight to `gatekeeper_documentation:8005` inside a `route` block.
The proxied response therefore never passes through `auth-gateway`'s
`_proxy_to_upstream`, and `auth-gateway`'s middleware never sees it.

On every other host the prefix belongs to that project. The gateway's matcher does
not apply, so the request falls through to the catch-all and is proxied through the
gate to the project caddy, which serves its own docs. See
[Caddy Integration](caddy-integration.md) for why a bare `handle` was wrong here.

The docs service is the authority for the prefix wherever it owns it. Its
`documentation/cache.py` carries the same precedence rule and the same static and
health lifespans, so the two agree on what a page may carry, and only the docs
service applies them.

## Origin policy and edge lifetime

Everything above is decided at the origin. A shared cache stands between this
stack and a browser, and it is free to substitute its own lifetime for any
response it is allowed to store. The two layers therefore own different things:

- the **origin owns the validator and the policy**, meaning the middleware's
  choice of value and the `ETag` that says whether a stored copy is still good;
- the **edge owns the client-facing lifetime**, meaning the `max-age` a browser
  is actually given, which is the edge's number and not necessarily the one this
  stack emitted.

Measured on the running stack, from inside `gatekeeper_caddy` on `:7000`:

| Request | Origin `Cache-Control` | Origin `ETag` | At the edge |
|---------|------------------------|---------------|-------------|
| `github.projectnova.download/public/name.svg` (gate resolved `none`) | `public, max-age=300` | the app's strong validator, passed through unchanged | re-emitted as `public, max-age=14400`, `cf-cache-status: HIT` with `age` counting up from zero |
| `gatekeeper.projectnova.download/documentation/caching/` | `private, max-age=300` | the docs service's own | unchanged, `cf-cache-status: DYNAMIC` |
| `gatekeeper.projectnova.download/` | `no-store` | none | unchanged, `cf-cache-status: DYNAMIC` |

The rows say the same thing twice. A response this stack marks `private` or
`no-store` is never stored, so the edge has nothing to re-emit and the value a
client sees is exactly the one the middleware chose. A response this stack marks
`public` **is** stored, and from then on the edge answers for it: it hands the
client its own `max-age`, and it does so without consulting this stack at all
while its copy is fresh. The origin's validator survives that hop untouched,
which is what lets the edge revalidate instead of serving a stale copy forever.

Two consequences worth stating plainly, because both mislead a reader who
assumes a header travels unchanged:

- **Editing a constant here does not retune an asset clients already have.** For
  anything shared-cacheable, the client-visible lifetime is set at the edge. The
  constants on this page govern what this stack is *willing* to have stored, and
  what a client is told when nothing stores the response.
- **The `ETag` is what bounds staleness in practice.** When the edge's copy
  expires it forwards `If-None-Match`; a `304` means the stored copy is reused,
  a `200` with a new `ETag` means it is replaced. The edge's window bounds how
  long a stale copy may be *reused*, not how long a change takes to appear once
  something asks.

`max-age` is a permission, not a promise. The client-facing number is whichever
cache stored the response, so a value on this page is the origin half of the
answer and never the whole of it.

## Verifying a change

Read the header on the running stack rather than trusting the middleware:

```bash
docker compose exec caddy wget -qS -O /dev/null \
  --header="Host: github.projectnova.download" \
  http://127.0.0.1:7000/public/name.svg
```

A badge path should show `public, max-age=300` and the upstream `ETag`. A gated
path, an error page or anything under `/manage` should show a value that contains
neither `public` nor a bare `max-age`.

Cloudflare is a shared cache that keys on the URL alone, so what it stores is a
property of the URL, not of the visitor. When a behaviour looks wrong, check
`cf-cache-status` on the response: `BYPASS` and `DYNAMIC` mean Cloudflare stored
nothing, and `HIT` on a gated path would be the failure this whole page exists to
prevent.
