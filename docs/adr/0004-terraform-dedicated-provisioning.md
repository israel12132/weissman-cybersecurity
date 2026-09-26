# ADR 0004 — Terraform provisioning for the dedicated (single-tenant) tier

- Status: Accepted
- Date: 2026-09-26
- Deciders: platform maintainer
- Relates to: ADR 0003 (dedicated tier), ADR 0001 (RLS isolation), ADR 0002 (secrets)

## Context

ADR 0003 delivered the dedicated (single-tenant) tier as the Helm chart
`deploy/helm/weissman/` — one isolated namespace, its own Postgres, Redis,
JWT-signing key and secrets-at-rest vault keys per customer. That closes the
"how is one customer isolated" question but not "how is a dedicated instance
*provisioned* in a customer's own VPC". A `helm install` still assumes someone
has already stood up a cluster, a database, a Redis and generated the keys. For
the Order Form's **Dedicated** / **customer VPC** line, provisioning has to be
repeatable IaC, not a runbook.

Two shapes were considered:

- **(a) Helm-provider only** — a Terraform module that just `helm_release`s the
  chart into an existing namespace/cluster. Honest and tiny, but it punts the
  entire data tier (DB, Redis, key material, secret storage) back to a manual
  step, which is exactly the gap.
- **(b) Full greenfield AWS** — VPC + subnets + EKS/ECS + RDS + ElastiCache +
  Secrets Manager, all from scratch. Most complete, but it duplicates the runtime
  the chart already encodes, is a large surface we cannot meaningfully validate
  without a cloud account, and a customer-VPC engagement usually means the
  customer already owns the network and the cluster.

## Decision

Deliver `deploy/terraform/` as a **thin composition**: reuse the chart for the
runtime, add only the managed data tier and secret material around it.

- `modules/data-tier` (AWS) — managed **RDS Postgres 16** (gp3, encrypted,
  `rds.force_ssl=1`, Multi-AZ, deletion protection), managed **ElastiCache
  Redis 7** (at-rest + optional in-transit TLS with an AUTH token), and this
  customer's **own** minted key material: `jwt_secret`, `vault_key` (64 hex) and
  `integrations_vault_key`, plus the RAG/metrics/destructive/job-orchestrator
  secrets and every DB/Redis credential. The full bundle is recorded in **AWS
  Secrets Manager** (`weissman/<customer>/app`) as the source of record.
- `modules/app` (Helm provider) — installs the **existing** chart with
  `postgres.provision=false` / `redis.provision=false`, injecting the data
  tier's DSNs and keys as `set_sensitive` values. The runtime is not forked; the
  chart remains the single source of truth for probes, securityContext, HPA,
  anti-affinity, etc. (ADR 0003).

The stack is **bring-your-own customer VPC + EKS cluster** (both pre-exist). It
provisions the tier *inside* them and does not create the VPC or the cluster.

## Enforcement / prerequisites

- The chart's `required` guards on every DSN and mandated key (ADR 0003) still
  apply: the injected `set_sensitive` values satisfy them, and a missing input
  fails the render rather than shipping a fail-open instance.
- Both the integrations vault key and the CEO `vault_key` are wired, satisfying
  the production boot guard in `fingerprint_engine/src/security_startup.rs`
  (`dedicated_key_configured()` for both vaults).
- A dedicated Postgres still MUST pass the RLS contract: the four NOBYPASSRLS
  roles and `vector` extension are bootstrapped with the master credentials, then
  `crates/weissman-db/tests/rls_live_schema_contract.rs` is run against the DSN
  before serving (ADR 0001). Because those roles live inside Postgres, the apply
  is two-stage: `-target=module.data_tier`, bootstrap, then the full apply. The
  `deploy/terraform/README.md` ships the exact SQL.
- Secret material lives in Terraform state and Secrets Manager; a remote,
  encrypted, locked backend is required, and `*.tfvars`/state are git-ignored.

## Consequences

- One `terraform apply` (after the documented DB bootstrap) stands up a fully
  isolated customer instance, making "Dedicated / customer VPC" a real,
  repeatable product rather than a runbook.
- Terraform now also holds secret material; this is traded for a single audited
  source of record (Secrets Manager) and is mitigated by the optional External
  Secrets Operator path (chart `secrets.create=false`) described in the README.
- The chart stays the runtime source of truth; a hardening change still lands in
  the chart (and `deploy/k8s`, per ADR 0003) and flows through unchanged.
- Greenfield VPC/EKS creation is intentionally out of scope; a `vpc` + `eks`
  module can be added later without changing this composition.
- `terraform validate`/`plan` require a cloud account and the target VPC/EKS ids,
  so they run in the operator's environment, not in CI without creds.
