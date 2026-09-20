# ADR 0001 — Multi-tenant and customer (MSSP) data isolation

- Status: Accepted
- Date: 2026-09-20
- Deciders: platform maintainer

## Context

Weissman is a multi-tenant SaaS used by MSSPs. Two isolation boundaries must hold,
both fail-closed:

1. **Tenant** — organization A must never read organization B's rows.
2. **Customer (client)** — inside one tenant, a portal-scoped customer C1 must never
   read a sibling customer C2's rows. Tenant RLS alone does NOT cover this, because
   both customers live in the same tenant.

Application-layer `WHERE` filters are not sufficient: a single forgotten filter leaks
data. The boundary must be enforced by the database.

## Decision

**PostgreSQL Row-Level Security, FORCE'd, on every tenant-scoped table**, driven by a
per-request GUC — not by application query discipline.

- Tenant scope: `public.app_current_tenant_id()` reads the `app.current_tenant_id`
  GUC (NULL when unset → tables fail closed). Every tenant table has a policy
  `USING (tenant_id = app_current_tenant_id())`.
- The GUC is set transaction-locally by `weissman_db::begin_tenant_tx(pool, tenant_id)`
  — the transaction opens first, then the GUC is set, so the scope lives exactly as
  long as the queries that rely on it. A bare-connection transaction-local `set_config`
  does NOT survive to the next statement (regression-locked in
  `crates/weissman-db/tests/rls_tenant_guc_regression.rs`).
- Customer scope: `public.weissman_client_row_visible(client_id)` (NULL client GUC ⇒
  owner/staff sees all; set ⇒ only that customer's rows) is AND'd onto the tenant
  policy of every table with a `client_id` column.
- The database-level default for `app.current_tenant_id` must be UNSET (NULL), never
  `'0'` — a role/db default makes tables fail OPEN into that tenant. Migration
  `20260811000100_reset_role_tenant_guc_defaults` reset it.

### Database roles

| Role | DSN | Privileges |
|------|-----|------------|
| `weissman_app` | `DATABASE_URL` | DML subject to FORCE RLS — **NOSUPERUSER / NOBYPASSRLS** |
| `weissman_auth` | `WEISSMAN_AUTH_DATABASE_URL` | Login/billing plane — BYPASSRLS (acts before a tenant is known) |
| `weissman_ro` | `WEISSMAN_READ_ONLY_DATABASE_URL` | Ask Weissman NL→SQL, SELECT-only, 15s statement timeout |
| `weissman_worker` | `WEISSMAN_WORKER_DATABASE_URL` | Job-bus claim across tenants — BYPASSRLS, job-bus tables only |
| `weissman_analytics` | `WEISSMAN_ANALYTICS_DATABASE_URL` | Global metrics SELECT — BYPASSRLS |

A superuser / table-owner DSN belongs **only** in `WEISSMAN_MIGRATE_URL`. A runtime
pool connecting as a superuser silently bypasses every policy.

## Enforcement (CI-gated)

- `crates/weissman-db/tests/rls_live_schema_contract.rs` — introspects the LIVE,
  migrated schema and fails CI if any `tenant_id` table is not ENABLE+FORCE RLS with a
  tenant-GUC policy (or uses `USING(true)`), if any `client_id` table lacks the
  customer-visibility predicate, or — behaviourally — if a `weissman_app` session
  scoped to customer A can see customer B's rows.
- `crates/weissman-db/tests/bypassrls_write_grants_contract.rs` — fails CI if a
  BYPASSRLS role gains write on a FORCE-RLS table outside a documented allowlist.
- `crates/weissman-db/tests/role_guard_guc_drift.rs` + `role_guard::assert_pool_role`
  — production boot fails closed if a DB-/role-level `app.current_tenant_id` default
  reappears.
- `fingerprint_engine/tests/rls_policy_contract.rs` — static migration-text guard
  (fast missing-policy net) that complements the live contract above.
- `weissman_db::role_guard` — refuses production boot on a wrong-role / superuser
  runtime DSN; `WEISSMAN_ALLOW_SUPERUSER_DSN` is inert in production.

## Consequences

- Every new tenant/customer table MUST carry the RLS + client-visibility predicates;
  the live contract turns a miss into a red build rather than a silent leak.
- A user's role change requires re-login (role is embedded in the JWT — see ADR 0002).
- `weissman_app` still holds direct INSERT on `vulnerabilities`; moving finding writes
  behind a dedicated writer role/connection is deferred (needs a runtime pool +
  credential change validated in staging).
