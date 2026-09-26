# API Versioning & Deprecation Policy

Status: active · Owner: Platform · Last reviewed: 2026-09-26

This document defines how the Weissman HTTP API is versioned, how the OpenAPI
specification is kept complete and honest, and the contract we make to callers
about stability and deprecation.

## 1. Surfaces and how they are versioned

| Surface | Prefix | Stability |
|---|---|---|
| Canonical API | `/api/...` | Current. This is the live surface; new endpoints land here first. |
| Stable alias | `/api/v1/...` | A **prefix alias** for the canonical surface. `/api/v1/<x>` is served by the exact same handler as `/api/<x>`. |
| WebSocket | `/ws/...` | Streaming upgrade endpoints; not covered by the request/response REST contract. |
| Webhooks / installers | `/hooks/...`, `/install/...`, `/status` | Integration + agent bootstrap endpoints. |

### The `/api/v1` alias

`/api/v1` is implemented as a single outermost middleware
(`api_v1_alias_rewrite` in `fingerprint_engine/src/http/serve.rs`) that rewrites
the request URI `/api/v1/<x>` → `/api/<x>` **before** routing, tenant/client
scope enforcement, and RBAC run. Consequences:

- Every canonical endpoint is automatically reachable under `/api/v1`.
- There is **no** duplicated route table and **no** duplicated auth/scope logic.
  Client-scope isolation (which keys on the `/api/clients/` and
  `/api/financial-risk/` prefixes) and the `PUBLIC_ROUTES` allow-list see the
  canonical path, so the alias cannot be used to bypass a security layer.
- Routes that are *natively* versioned (registered directly under `/api/v1/...`
  in `serve_route_groups.rs`, e.g. `/api/v1/alerts/aws-canary`) are listed in
  `V1_NATIVE_ROUTES` and are **not** rewritten — they route as-is.

New callers and integrations SHOULD pin to `/api/v1`. The alias is the version
we promise not to break within the guarantees in §3.

## 2. The OpenAPI specification

- Served at `GET /api/openapi.json` (OpenAPI 3.1). Swagger UI at `/api/docs`.
  Both are public only outside production (`RouteGate::NonProdOnly`).
- The spec is assembled at first request and cached
  (`build_openapi_spec` in `fingerprint_engine/src/server_handlers_rest2.inc`):
  1. A **generated** path inventory covering *every* registered route
     (`src/openapi_paths.generated.json`).
  2. **Curated** hand-authored operations (rich request/response schemas) that
     are overlaid on top — the curated operation wins per `(path, method)`.
- Operations are grouped into ~24 domain **tags** (Findings, Auth & Identity,
  Risk & Exposure, SOAR & Playbooks, …) so the spec is navigable.

### Generator + drift gate (no hand-maintained path list)

The path inventory is derived from the axum route table, never hand-written:

```
node scripts/generate_openapi.mjs          # regenerate the committed artifacts
node scripts/generate_openapi.mjs --check   # CI gate: fail if artifacts are stale
```

Inputs: `serve_route_groups.rs` (the `.route(...)` registrations) and the
`PUBLIC_ROUTES` allow-list in `serve.rs` (so unauthenticated operations are
marked `security: []`). Outputs (committed):

- `fingerprint_engine/src/openapi_paths.generated.json` — embedded into the
  served spec via `include_str!`.
- `docs/openapi/ROUTE_INVENTORY.md` — a human-readable route table.

Two gates keep the spec honest:

- **CI**: `node scripts/generate_openapi.mjs --check` fails the build when a
  route was added or changed without regenerating.
- **Rust**: `fingerprint_engine/tests/openapi_route_coverage.rs` asserts the
  committed artifact documents every registered route and that its recorded
  route count matches the live table.

> **When you add or change a route**, run `node scripts/generate_openapi.mjs`
> and commit the updated `openapi_paths.generated.json` and
> `docs/openapi/ROUTE_INVENTORY.md`.

### Coverage status (honest)

- **Path/operation coverage: 100%** — every registered route appears in the
  spec with tags, path parameters, an operation id, an `x-handler` back-pointer,
  and a public/authenticated security marker.
- **Rich request/response schemas: partial** — a curated subset (auth, findings,
  clients, reporting, …) carries full request/response schemas. The remainder
  ship as accurate stubs. Enriching per-endpoint schemas is an ongoing,
  incremental follow-up; accuracy of the route list is never traded for it.

## 3. Stability & deprecation guarantees

For the `/api/v1` surface:

1. **No breaking changes within a version.** We will not remove a `v1` endpoint,
   remove a response field, add a required request field, or change the type of
   an existing field without a new major version (`/api/v2`).
2. **Additive changes are allowed** at any time: new endpoints, new optional
   request fields, new response fields.
3. **Deprecation** of a `v1` endpoint is announced by:
   - setting `deprecated: true` on the operation in the OpenAPI spec, and
   - returning a `Deprecation` response header (and a `Sunset` header once a
     removal date is set, per RFC 8594).
4. **Minimum deprecation window: 180 days** between announcement and removal for
   any endpoint that has been generally available.
5. A new major version (`/api/v2`) is introduced as a second prefix alias, run
   in parallel with `v1` for at least one deprecation window before `v1` sunset.

## 4. Introducing `/api/v2` (future)

When a breaking change is unavoidable:

1. Register the new/changed handlers canonically under `/api/...`.
2. Add a `v2` rewrite (or a `v2`-specific handler set for the changed endpoints).
3. Keep `v1` serving the previous behavior until its sunset date.
4. Regenerate the spec; document the delta in this file.

## 5. Files

| Path | Role |
|---|---|
| `scripts/generate_openapi.mjs` | Generator + `--check` drift gate. |
| `fingerprint_engine/src/openapi_paths.generated.json` | Generated path inventory (committed). |
| `fingerprint_engine/src/server_handlers_rest2.inc` | `build_openapi_spec` — merges generated + curated, serves `/api/openapi.json`. |
| `fingerprint_engine/src/http/serve.rs` | `api_v1_alias_rewrite`, `v1_canonical_path`, `V1_NATIVE_ROUTES`. |
| `fingerprint_engine/tests/openapi_route_coverage.rs` | Route-coverage drift test. |
| `docs/openapi/ROUTE_INVENTORY.md` | Generated human-readable route table. |
