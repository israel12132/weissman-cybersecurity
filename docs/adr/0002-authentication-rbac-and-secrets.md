# ADR 0002 — Authentication, RBAC, and secrets-at-rest

- Status: Accepted
- Date: 2026-09-20
- Deciders: platform maintainer

## Context

The platform authenticates human operators (with roles) and endpoint agents, must
stop a read-only user from mutating, and stores secrets (MFA seeds, SOAR provider
credentials, CEO vault) that must not be decryptable by whoever can read the
token-signing key.

## Decision

### Tokens (`fingerprint_engine/src/auth_jwt.rs`)

- Short-lived **HS256 JWT** access tokens (default 15 min, clamped 5–240), minted with
  a required `WEISSMAN_JWT_SECRET` (no default; ≥48 chars in production). Verification
  uses a keyring (current + `WEISSMAN_JWT_SECRET_PREVIOUS`) for zero-downtime rotation;
  a token signed with a key outside the ring never verifies (unit-tested).
- Tokens are `typ`-discriminated (`access` / `agent` / `mfa_pending` / `refresh` /
  `sse_ticket`); each verify path rejects the wrong `typ`. `role` and `is_superadmin`
  are embedded at mint time and trusted only because the token is signed.
- Transport is `Authorization: Bearer` or an HttpOnly `weissman_token` cookie
  (`SameSite=Lax`; `Secure` in production). Never in URLs. SSE streams are bound to the
  mint-time client IP / TLS fingerprint.
- Refresh is opaque DB-backed (`auth_refresh`), not a long-lived JWT.

### RBAC (`fingerprint_engine/src/rbac.rs`)

Defense in depth:
1. Central `mutation_rbac_middleware` enforces a minimum role for every mutating
   (non-GET) request via `required_min_role(path)` — baseline ≥`analyst` (viewers
   cannot write), with `/api/admin`→admin, `/api/ceo` & `/api/sovereign/operator`→ceo
   (owner plane returns 404 to non-owners), client create/delete→ceo. It emits
   fail-closed telemetry (`weissman_rbac_missing_authcontext_total`) if a mutating
   request reaches it without an `AuthContext` (an `auth_guard` ordering regression).
2. Per-handler `require_analyst/operator/admin/…` gates are the primary check; the
   `AuthContext` extractor fails closed (401) when auth did not run.

### Production startup guards (`fingerprint_engine/src/security_startup.rs`)

Refuse to boot in production on: a weak/blocklisted JWT secret or one <48 chars; a
default-dev DB password in any DSN; admin password <12 chars; `WEISSMAN_COOKIE_SECURE`
off; missing `WEISSMAN_MIGRATE_URL`; metrics/destructive-confirm/job-orchestrator
secrets <32 chars; `REDIS_URL` unset (distributed lockout/rate-limit) unless single
node is acknowledged; self-serve signup unless explicitly acknowledged; and — key —
**no dedicated secrets-at-rest vault key** (deriving from the JWT secret would let the
token-signing key also decrypt every stored MFA/SOAR/CEO secret). The RAG-provenance
HMAC is fail-closed in **release** builds via `cfg(not(debug_assertions))`, not an env
flag, so unsetting `WEISSMAN_ENV` cannot disable it. Vault keys are scrubbed from the
process environment after boot.

### Finding-scoring integrity

The finding scoring/persist path (`findings_persist.rs`, `findings_gate.rs`,
`intel_epss.rs`) is deterministic and randomness-free — enforced by
`scripts/verify_no_rand_in_scoring.mjs` so a fabricated/randomised score can never
reach the `vulnerabilities` table. See ADR-adjacent note in `findings_gate.rs` for
what the evidence gate does (non-empty proof + determinism) and does NOT (verify
probe-provenance — an engine-level convention).

## Consequences

- Role changes require re-login (JWT-embedded claims).
- The RBAC middleware fails OPEN (pass-through + telemetry) when `AuthContext` is
  absent; the per-handler extractor is the fail-closed gate. A fail-closed variant for
  known-protected prefixes is a possible future hardening.
- Rotating `WEISSMAN_JWT_SECRET` requires setting `WEISSMAN_JWT_SECRET_PREVIOUS` (and,
  for vault rows, keeping the legacy key) so existing tokens/secrets keep verifying.
