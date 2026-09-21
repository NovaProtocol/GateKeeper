# GateKeeper

<div align="center">

![GateKeeper](https://github.projectnova.download/public/project/gatekeeper.svg)

</div>

One login for a family of self-hosted web apps.

GateKeeper sits in front of every app I run and answers a single question before a request is
allowed through: has this visitor already proven who they are?

A signed cookie on the shared domain is the credential. Anyone without one is sent to a login page
instead of the app they asked for. Entering a correct access code once is enough to get into every
app behind the gate, and closing the browser or letting the cookie expire closes that session again.

## What it does

**One gate, many apps.** Every app keeps its own domain and its own code, and none of them implement
login themselves. They also do not have to trust the gate blindly: the gate tells them who the
visitor is, and they act on that. This means adding a new app behind the gate is a routing change,
not an authentication project.

**Access codes with a real lifecycle.** Codes are created from an admin panel, can be labelled with
who they were given to, and are revoked with one click. Revoking a code signs that visitor out of
everything on their next request, which matters when a code was handed out and should not have been.

**A way back in.** A backup code exists so that losing the admin password cannot lock the owner out
of their own panel. This is the failure mode that makes home-grown authentication frightening to
operate, and it is worth designing around up front.

**Per-path rules.** A single app can be public on one path and private on another. It is common to
want `/robots.txt` readable while the rest of a site is not, or to keep a status endpoint open for a
monitoring service.

**Maintenance mode.** Every gated site can be switched to a themed notice while the admin panel stays
reachable. Flipping that switch cannot strand the operator, because the panel is deliberately exempt.

**Custom pages.** Small static responses, such as a `robots.txt` or a domain verification file, are
served from the panel instead of being deployed into an application. They are also the one thing
allowed to be served without authentication, and only where the governing rule permits it.

**A visitor map.** Recent traffic grouped by country and by address, so an unexpected spike has an
explanation rather than being a mystery.

## Running it

```bash
cp .env.example .env
# then fill in the values it documents, and start the stack
docker compose up -d
```

The login page is at `/`, and the admin panel lives at `/manage/login`.

## Documentation

Full documentation is served by the stack at `/documentation/`, and the sources are in
[`documentation/docs`](documentation/docs).

It covers the rule model and how a request is resolved, the session and cookie contract, the audit
and retention behaviour, and the management panel page by page.


## License

BSD 3-Clause. See [LICENSE](LICENSE).
