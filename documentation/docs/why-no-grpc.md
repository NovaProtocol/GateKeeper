# Why No gRPC

GateKeeper has **no gRPC server, no `.proto` files, and no `api:50051`** — by design.

## House Rule (`reference/fastapi/grpc.md`)

> Use gRPC for container-to-container server-side traffic only. The API runs `grpc.aio.server` on `api:50051`; other containers call it with `grpc.aio.insecure_channel("api:50051")`. If you have no server-side container-to-container calls, skip gRPC entirely.

| Traffic | Protocol | Endpoint |
|---------|----------|----------|
| `api:50051` internal (worker→api, portal→api) | gRPC | `grpc.aio.server` |
| Browser / webhook / public via Caddy → api | HTTP | `handle /api/*` + `reverse_proxy api:8008` |

`50051` is `expose:` only, never `ports:`-published, on an `internal: true` network.

## Why GateKeeper Needs None of It

GateKeeper is a **single service** with **no container-to-container calls**:

- One Flask monolith (`app.py`) on `:7000` serves every route: `/` login, `/api/authz/forward-auth`, `/manage`, `/health`.
- The `documentation` service (`:8005`) is read-only MkDocs — stateless, builds at image-build time, serves prebuilt `site/`, never calls GateKeeper and is never called by it.
- There is no `api` → `worker` fanout, no `portal` → `api` internal RPC, no shared DB sharding that would benefit from typed protos or streaming.
- The only integration is **Caddy `forward_auth`** — an HTTP GET to `/api/authz/forward-auth` over the `gatekeeper_default` Docker network with `X-Forwarded-*` headers. That traffic is HTTP by contract; gRPC over HTTP/2 would require a dedicated gRPC gateway that the house Caddy does not do.

Adding a `grpc.aio.server` on `:50051` would:

- Require `grpcio`, `grpcio-tools`, `protobuf` in `requirements.txt` (`grpcio>=1.60,<2`, `protobuf>=4,<7`) with no caller.
- Introduce `.proto` compilation (`shared/proto/`, `proto_gen/`) and a stub that nothing imports.
- Publish `expose: ["50051"]` that is never probed — noise in compose and docs.
- Duplicate logic: the single `codes` table lookup would be exposed over two transports for zero benefit.

## What We Document Instead

- **HTTP is the only contract:** `GET /api/authz/forward-auth` → `200` or `302` + `Set-Cookie`; login and manage are plain HTTP forms.
- **Magic links** (`?access_code=`) are the shareable credential — no internal RPC, no service token, no `X-Internal-API-Key`.
- If GateKeeper ever grew a second container that needed server-side calls (e.g., a sidecar stats aggregator or a separate audit writer), the addition would be: `shared/proto/api.proto`, `shared/proto_gen/`, `grpc.aio.server` on `api:50051`, `grpc.aio.insecure_channel("api:50051")` on `internal: true` `net-api`, `expose: ["50051"]` only, business logic in `*_service.py` called by both HTTP and gRPC — per `reference/fastapi/grpc.md` lifespan pattern.

Until then, this page is the evidence that **no gRPC** is the correct, documented decision — not an omission.
