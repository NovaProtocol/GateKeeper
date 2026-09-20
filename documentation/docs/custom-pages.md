# Custom Pages

GateKeeper usually does one of three things with a request: passes it through,
redirects it to login, or refuses it. A **custom page** is the fourth: a body the
gateway serves itself, so the request is answered before any project route is
consulted. The first use is `/robots.txt`, which lets a project retire its own
route for a path that is not really the project's business.

A page is not a fixed path list. A row holds a **pattern** describing a URL
shape, the first match wins by priority, and the panel shows the priority number
with ▲/▼ raise/lower and a deactivate switch, the same controls, in the same
order, as Rules.

```sql
custom_pages(id, pattern unique, body, content_type, active, display_order, created_at, updated_at)
```

## Where a page sits in the order

Four tiers, and each one can only be reached if the one above it did not answer:

```
1. GateKeeper's own control plane   /health, /documentation/*, login, /manage, /logout, /static
2. Custom page                      only when the governing rule's action is `none`
3. Rule dispatch                    access_code / custom_password / deny / none
4. Project route                    the upstream app
```

Tier 1 is not a denylist you configure; it is what the stack already does.
`/health` is answered by Caddy's own site-level `handle` and never reaches the
gateway at all. `/documentation/*` is GateKeeper's own Caddy handle, and because
that handler carries no host matcher it claims that prefix on **every** host.
`/api/authz/forward-auth` and `/logout` are literal gateway routes registered
ahead of the wildcard. `/login` is different and worth knowing about: it is
served by the wildcard proxy into the management service, so the gateway carries
an explicit guard for it, a page can never answer `/login`, `/`, `/logout`,
`/manage/*` or `/static/*` on the gatekeeper host or the apex, whatever its
pattern says. `/static/*` is on that list because the panel's own stylesheet is
served the same way the login page is: reserving `/login` but not the CSS it
loads would leave the operator with a panel that answers and renders unstyled,
which is a lockout by another route. The reserve is **host-scoped**: a project
host's own `/static/*` is untouched, because the predicate is false for every
non-manage host.
`/robots.txt` on the gatekeeper host is **not** part of that guard and stays
yours to intercept.

Tiers 2 and 3 are the same decision, made in one place. A page is only considered
inside the branch where the gate has already decided the request may pass, so a
page cannot open a gate that was closed: if the governing rule says
`access_code`, the visitor is redirected to login and the page is never read.
Tier 4 is unchanged, and untouched by any of this.

**Maintenance mode is above all four tiers**, so it is the one case where a page
does not appear even though its pattern matched and its rule allows `none`. While
`maintenance_mode` is on, every request gets the maintenance `503`, including
`/robots.txt`, and turning the switch off restores the page exactly. That
ordering is deliberate rather than an oversight: an operator who turns maintenance
on expects the whole site to say so, and a robots file during an outage is not
worth a special case.

## The pattern

One column, `host-glob/path-glob`, because a pattern is a URL shape rather than
a host pattern and a path pattern that can be recombined:

```
*.projectnova.download/robots.txt
gatekeeper.projectnova.download/*
*.example.com/legal/*
```

| Token | Matches |
|-------|---------|
| `*` | any sequence of characters, **including `/`** |
| `?` | exactly one character |
| anything else | itself, literally, `*.` is a dot, not a regex |

Anchored at both ends: `/robots.txt` does not match `/robots.txt.bak`, and
`/a/*` does not match `/ab`. Hosts compare case-insensitively and paths
case-sensitively, which is the split the rule vocabulary already makes.
`*.example.com` matches the bare `example.com` as well as any subdomain of it,
mirroring `host_matches`, so a page and a rule that both name `*.example.com`
cover the same set of hosts. `*` alone matches any host.

The glob vocabulary is deliberately **not** the rules' vocabulary. A rule path is
exact unless it ends in `/*`, because a rule is a policy boundary and a
near-miss should not be caught by accident. A page names a URL to swallow, so the
operator wants `*` to do the obvious thing and needs no reserved characters.

A malformed pattern matches **nothing**. A row whose pattern cannot be read is
never the reason a body is served.

### Precedence

`display_order` ascending, then `id`; the first match is the only match. Nothing
merges and nothing cascades, a response is one row's body, or it is not a page
response at all. Both priority tables in the panel mean the same thing, which is
why the column is called `Priority` on both.

The gate holds the page list for `CACHE_TTL = 5s`, so a new or edited page takes
up to five seconds to appear. If the list cannot be read at all the gateway keeps
its stale copy, and if it has none it treats that as "no page matched", never as
"some page matched".

## The body and the content type

The stored bytes are served exactly as stored. No sanitising, no escaping, no
rewriting, no content-type restriction and no sniffing. An HTML body carrying an
inline redirect is a legitimate use and stays one.

- `content_type` is sent as the response's type. `X-Content-Type-Options:
  nosniff` is applied to every response on this stack, so the declared value is
  the only thing a browser has to go on. **Do not label an HTML body
  `text/plain`**, with `nosniff` it will be shown as text, not rendered.
- A bare `text/*` type gains `; charset=utf-8`; a stored value that already
  names a charset keeps it.
- `body` is capped at **256 KiB** (262,144 characters). The cap exists because
  every page is held whole in the gateway's in-memory cache and re-fetched on
  each five-second refresh, with no streaming path: the bound on that is
  `256 KiB × pages`.
- A zero-byte body is allowed. It is a legitimate way to swallow a path.

**A page cannot set a response header.** There is no header field on the row, so
it cannot emit `X-Robots-Tag`. What it *can* do is put `<meta name="robots"
content="…">` inside an HTML body, which is a per-page signal for a crawler that
renders the document.

### What that means for robots files

A `robots.txt` body is plain text and is not a place to put policy about crawling
*this* site, beyond the file's own vocabulary. A `none` rule makes exactly the
matched path public on every host that pattern governs, which is the intent for
a robots file, since a crawler arrives without a cookie and must be able to read
it, but it is a gate decision, not a side effect. It grants nothing beyond the
pattern's paths.

## The governing rule, and why a page may never be served

A page is served only when the rule that governs its host and path has the action
`none`. Every other action runs the ordinary gate flow instead:

| Governing action | What a request to the page's path gets |
|------------------|---------------------------------------|
| `none` | the page body |
| `access_code` | `302` to login, exactly as before |
| `custom_password` | `302` to login, exactly as before |
| `deny` | the themed `403` |
| no group for the host | `settings.unmatched_action`, and the page is not served |

The panel states this per row rather than leaving it to be discovered: every page
carries a banner naming the group and rule that govern a representative URL, and
a page whose action is not `none` says so on the same line. The representative is
a **sample**, not a promise, a wildcard can span hosts governed by different
groups, and the banner can only report one of them.

Both modals also carry a **Test before saving** control, which asks the gate the
same question about the pattern as typed, so an unreachable page is visible before
it is saved rather than after a crawler fails to see it.

Two other ways a page can be reachable-looking and dead, both of which the panel
warns about in the row rather than refusing at the API:

- the pattern targets `/health`, `/api/authz/forward-auth`, `/logout` or
  `/documentation/*`, so something above the page answers first;
- the pattern is malformed, or another page matches first at a lower priority.

A third case is warned about only when the pattern's host half can name the panel
or the apex, a pattern over `/`, `/login`, `/logout`, `/manage/*` or
`/static/*` there is reserved by the control plane. The same path on a project
host is not, so `portfolio.projectnova.download/static/*` is a legitimate page
and does not warn.

## Managing pages

`/manage/pages` lists every row with its priority, pattern, governing rule,
content type and status. The controls are the ones the rest of the panel uses:
▲/▼ reorder, an edit button in each row, a `Test before saving` button in each
modal, an open-in-new-tab anchor to the sample URL, and a toggle that deactivates
the page without deleting it. Deactivating is immediate and reversible; the gate skips a page whose
`active` is `false` before it even reads the pattern.

The endpoints, with `X-Internal-Api-Key` on every write:

| Method | Path | Notes |
|--------|------|-------|
| `GET` | `/api/pages` | keyless, like `GET /api/routes` |
| `POST` | `/api/pages` | `{pattern, body, content_type?}` |
| `PUT` | `/api/pages/{pid}` | partial: only the keys present are validated and applied |
| `DELETE` | `/api/pages/{pid}` | |
| `PUT` | `/api/pages/{pid}/order` | `{"direction": "up"\|"down"}`; the ends are no-ops, as on rules |

Refusals, each naming its reason:

| Condition | Response |
|-----------|----------|
| no `/`, an empty host half, an empty path half, whitespace, or `..` in the pattern | `400` |
| pattern longer than 1024 characters | `400` |
| `content_type` with a CR or LF | `400`, it becomes a response header, so a line break there is response splitting |
| `content_type` that is not `type/subtype` | `400` |
| body over 256 KiB | `400` |
| a pattern that already exists | `409` |

There is **no reserved-path denylist**. Reachability is surfaced in the panel
instead of refused at the API, because a denylist of "paths GateKeeper answers
first" can only ever be incomplete and a refusal it got wrong would be a page the
operator could not create. A dead row is visible on the page that lists it.

## Audit

Every request answered by a page writes one row with `action = "custom_page"` and
`matched_action = "custom_page"`, the greppable marker that a page, rather than
a rule, produced the body. `rule_group_id` and `rule_id` carry the rule that
allowed it, because that is the interesting fact, and the status is `200` for a
page served. A request the gate refused writes no page row; the refusal is
recorded under its own action as it always was.

Only `GET` and `HEAD` are served. A `POST` to a page's path is not a page request
and follows the ordinary gate flow.

## Backup

`pages` is a section in the signed export, and it is **optional**: a file written
before this feature existed has no `pages` key, restores as an empty set of pages,
and is otherwise untouched. Files remain `version: 1`. The validation rules are
the API's own field rules, so a file the API could not have produced is refused
with a line naming the row and the fault, rather than restored into a row the
panel would reject. See [Backup & Restore](backup.md).

## `/robots.txt`

A single page with the pattern `*.projectnova.download/robots.txt` replaces the
route Portfolio used to own. Because a page is served only on a `none` action,
which hosts actually serve it is decided by their rule groups, not by the
pattern:

| Host | Group's `/robots.txt` rule | Result |
|------|---------------------------|--------|
| `portfolio.projectnova.download` | `/robots.txt` → `none` | body |
| `projectnova.download` (apex) | `/robots.txt` → `none` | body |
| `gatekeeper.projectnova.download` | `/*` → `none` | body |
| `github`, `water-billing-system`, `solver`, `melereview` | `/*` → `access_code` | `302` to login |

The broad pattern is deliberate and needs no new rule: a host whose group does not
allow `none` still redirects, so adding the page cannot widen anything. Extending
the file to another host is a rule decision taken on that host's group, not a
change to the pattern.

The body is the same file the retired route served:

```
User-agent: *
Disallow: /
```

This page and Portfolio's own route no longer coexist for that path, the route
is gone, and GateKeeper answers instead.

### The `noindex` signals are unchanged

Retiring the route removed a `/robots.txt` handler. It did **not** touch
Portfolio's `noindex` signals, which remain exactly as they were:

- the `X-Robots-Tag: noindex, nofollow` response header in Portfolio's Caddyfile;
- the `<meta name="robots" content="noindex, nofollow">` in its base template.

That is deliberate. The header is the primary mechanism precisely because
middleware in the app cannot cover the separately-containerised documentation
service, so removing it would quietly undo an earlier decision rather than tidy
anything. A custom page cannot set `X-Robots-Tag` at all, see above, and is not
a substitute for either signal.
