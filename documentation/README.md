# Documentation

Full project documentation for GateKeeper, built with [MkDocs](https://www.mkdocs.org/) and the Material theme.

## Contents

| Section | Description |
|---------|-------------|
| [Home](./docs/index.md) | Overview, services, and quick links |
| [Getting Started](./docs/getting-started.md) | Prerequisites, env vars, and startup |
| [Architecture](./docs/architecture.md) | Request flow, DB schema, and layout |
| [Auth Flow](./docs/auth-flow.md) | forward_auth, magic links, redirects |
| [Cookie Contract](./docs/cookie-contract.md) | gatekeeper_token signing and domain |
| [Manage Panel](./docs/manage-panel.md) | /manage Basic-auth, create/invalidate |
| [Caddy Integration](./docs/caddy-integration.md) | How apps gate behind forward_auth |
| [Docker](./docs/docker.md) | Dockerfile, compose, healthchecks |

## Building Locally

```bash
pip install -r requirements.txt
mkdocs build
mkdocs serve    # preview at http://localhost:8000
```

Inside Docker the prebuilt `site/` is served by FastAPI + granian on `:8005`:

```bash
docker compose up -d --build documentation
curl -s http://127.0.0.1:8005/health
```
