# GateKeeper

<div align="center">

![GateKeeper](https://github.projectnova.download/public/projects/gatekeeper.svg)

</div>

One login for a family of self-hosted web apps.

GateKeeper sits in front of every app I run and answers a single question before a request is
allowed through: has this visitor already proven who they are? A signed cookie on the shared domain
is the credential. Unauthenticated visitors get a login page instead of the app, and one correct
access code lets them in everywhere at once.

## What it does

- **One gate, many apps.** Each app keeps its own domain and its own code. None of them implement
  login, and none of them trust a request that has not been through the gate first.
- **Access codes with a real lifecycle.** Codes are created from an admin panel, can be handed to a
  specific person with a label, and revoked instantly. Revoking one signs that visitor out of
  everything on their next request.
- **A way back in.** A backup code exists so the owner cannot lock themselves out of their own
  panel, which is the failure mode that makes home-grown auth terrifying to operate.
- **Per-path rules.** A single app can be public on one path and private on another. `/robots.txt`
  can be readable while the rest of the site is not.
- **Maintenance mode.** Every gated site can show a themed notice while the admin panel stays
  reachable, so flipping the switch cannot strand the operator.
- **Custom pages.** Small static responses, like a `robots.txt` or a verification file, are served
  from the panel instead of being deployed into an app.
- **A visitor map.** Recent traffic grouped by country and by address, so a sudden spike has an
  explanation.

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
