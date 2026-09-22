# ADR 0003 — Dedicated (single-tenant) deployment tier vs logical (shared-RLS) tier

- Status: Accepted
- Date: 2026-09-22
- Deciders: platform maintainer

## Context

The MSA Order Form (`docs/legal/MSA-ORDER-FORM-OUTLINE-en.md`) lets a customer pick a
`Deployment` of **Cloud SaaS / Dedicated / Self-hosted** and a `Data residency` of
**EU-West / US / IL / customer VPC**. Until now only one of those is real: a single
shared cluster (`deploy/k8s/`, fixed namespace `weissman`) whose customer boundary is
PostgreSQL Row-Level Security (ADR 0001). "Dedicated" and "customer VPC" had nothing
behind them; selling them against a shared database would be a compliance misstatement,
not just a missing feature.

Two isolation models are legitimately different products:

- **Logical (shared) tier** — many tenants/customers in one cluster and one database,
  separated by FORCE'd RLS + a per-request GUC (ADR 0001). One JWT-signing key, one
  at-rest vault key (ADR 0002), one Redis, one blast radius. This is GA and the default.
- **Dedicated (single-tenant) tier** — one customer gets its own namespace, its own
  Postgres, its own Redis, and — critically — its own JWT-signing key and its own
  secrets-at-rest vault keys, so a key compromise or a noisy-neighbour incident cannot
  cross a customer boundary. "Customer VPC" / "Self-hosted" is the same artifact run in
  the customer's own cluster.

## Decision

Deliver the dedicated tier as a **Helm chart, `deploy/helm/weissman/`**, installed once
per customer into a parameterized namespace (default `weissman-<customer.name>`). The
chart templates the existing, proven `deploy/k8s/` manifests — same `securityContext`,
probes, anti-affinity, HPA behaviour — so the dedicated tier does not fork the runtime.

Per-customer isolation the chart provisions:

- **Namespace** — `templates/namespace.yaml` (chart-owned option) or the `-n` install
  target; every resource pins `metadata.namespace`.
- **Database** — either a dedicated CloudNativePG `Cluster`
  (`postgres.provision=true`, templated from `deploy/k8s/postgres-ha.yaml`) or an
  external managed Postgres; per-customer DSNs live in the Secret. RLS (ADR 0001) still
  applies on the dedicated DB (defence in depth even for one tenant).
- **Redis** — a dedicated in-namespace `weissman-redis` (`redis.provision=true`).
- **Dedicated keys** — the Secret carries this customer's own `jwt_secret` (>=48),
  `integrations_vault_key` (>=32) and `vault_key` (64 hex). The chart wires
  `WEISSMAN_JWT_SECRET`, `WEISSMAN_INTEGRATIONS_VAULT_KEY` and `WEISSMAN_VAULT_KEY`
  into **both** backend and worker — closing a gap in
  `deploy/k8s/backend-deployment.yaml`, which never wired the vault keys the production
  boot guard in `fingerprint_engine/src/security_startup.rs` requires
  (`dedicated_key_configured()` for both the integrations vault and the CEO genesis
  vault).

The template fails closed: `templates/secret.yaml` uses Helm `required` on every DSN and
every mandated key (jwt / vault / integrations / rag / metrics / destructive /
job-orchestrator), so a render with a missing key errors instead of shipping a fail-open
instance.

**Plainly which is delivered:** Logical (shared-RLS) is what has shipped to date and
remains the default. Dedicated (single-tenant) is delivered by this chart; an Order Form
that says "Dedicated" or "customer VPC" MUST be fulfilled by an actual dedicated install
of `deploy/helm/weissman/` (its own namespace, DB, Redis and keys), never by adding the
customer to the shared cluster. Self-hosted is the same chart run in the customer's
cluster.

## Enforcement / prerequisites

- `templates/secret.yaml` `required` guards — a missing DSN/key fails
  `helm template` / `helm install`.
- A dedicated Postgres still MUST pass the RLS contract: bootstrap the
  `weissman_app` / `weissman_auth` / `weissman_worker` / `weissman_analytics` roles and
  run migrations, then run `crates/weissman-db/tests/rls_live_schema_contract.rs`
  against the dedicated DSN (ADR 0001).
- CNPG provisioning requires the CNPG operator and a pgvector-bearing image
  (`postgres.imageName`); documented in `deploy/k8s/postgres-ha.yaml`.
- `docs/legal/MSA-ORDER-FORM-OUTLINE-*.md` and sales must map the `Deployment` field to
  the tier actually installed.

## Consequences

- Per-customer operational cost rises (its own DB / Redis / keys), traded for a hard
  isolation boundary and residency control the shared tier cannot offer.
- Key rotation is per customer: rotating one customer's `jwt_secret` needs that
  customer's `jwt_secret_previous` (ADR 0002), independent of the fleet.
- The shared cluster (`deploy/k8s/`) stays the source of truth for manifests; the chart
  templates them, so a runtime-hardening change must be applied in both until the k8s
  manifests are themselves generated from the chart (future work).
- The chart wires the vault keys into the backend, which the raw k8s manifest omits;
  reconciling `deploy/k8s/backend-deployment.yaml` to do the same is a follow-up.
- NetworkPolicies are not yet shipped by the chart; apply the namespaced
  `deploy/k8s/network-policies.yaml` as defence in depth until they are templated.
