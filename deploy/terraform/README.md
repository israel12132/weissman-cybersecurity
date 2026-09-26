# Weissman — Terraform for the dedicated (single-tenant) tier

Terraform IaC that provisions **one dedicated Weissman instance in a customer
VPC** and installs the existing Helm chart (`deploy/helm/weissman`) into it.
This is the machine-provisioned counterpart of that chart for the "Dedicated" /
"customer VPC" line on the MSA Order Form. See
[`docs/adr/0003-dedicated-single-tenant-tier.md`](../../docs/adr/0003-dedicated-single-tenant-tier.md)
and [`docs/adr/0004-terraform-dedicated-provisioning.md`](../../docs/adr/0004-terraform-dedicated-provisioning.md).

## What it is (and is not)

This root module is deliberately **thin and honest**:

- `module.data_tier` (AWS) provisions the managed **RDS Postgres 16**, managed
  **ElastiCache Redis 7**, this customer's **own JWT-signing key and its own
  secrets-at-rest vault keys** (ADR 0002), and records the full bundle (DSNs +
  keys) in **AWS Secrets Manager**.
- `module.app` (Helm provider) installs the **existing chart** into a dedicated
  namespace with `postgres.provision=false` and `redis.provision=false`, wiring
  the data tier's DSNs/keys in as sensitive Helm `--set` values. The runtime is
  the chart, not a fork of it.

It is **bring-your-own customer VPC + EKS cluster**: both must already exist. The
module does **not** create the VPC, subnets, NAT, or the EKS cluster itself. That
keeps the surface small and matches how a customer-VPC engagement actually works
(the customer owns the network and cluster; we provision our tier inside it). A
greenfield `vpc` + `eks` module is a reasonable future addition; see the ADR.

## Files

| File | Purpose |
|------|---------|
| `versions.tf` | Terraform + provider version pins (aws, helm, kubernetes, random) |
| `variables.tf` | Root inputs: customer, domain, region, sizing, VPC/cluster ids, DB/Redis knobs |
| `main.tf` | Providers, sizing profiles, and the two module calls |
| `outputs.tf` | Namespace, endpoints, Secrets Manager ARN, release status |
| `terraform.tfvars.example` | A ready-to-copy customer stanza (no secrets) |
| `modules/data-tier/` | RDS + ElastiCache + Secrets Manager + generated keys |
| `modules/app/` | The `helm_release` of `deploy/helm/weissman` |

## Prerequisites

- Terraform `>= 1.6`, AWS credentials for the target account/region.
- An existing customer **VPC** with **>=2 private subnets** across AZs, and the
  **security group(s)** of the EKS node group(s) that will run the pods
  (`app_security_group_ids`) so the data tier can allow 5432/6379 from them.
- An existing **EKS cluster** (`eks_cluster_name`) whose API you can reach; the
  `kubernetes`/`helm` providers authenticate to it via `aws_eks_cluster_auth`.
- In-cluster: an ingress controller matching `ingress_class_name` and, if you use
  `ingress_cluster_issuer`, cert-manager with that ClusterIssuer.

## Sizing

`sizing = small | medium | large` selects a default profile (backend/worker
replica counts, RDS instance class + storage, ElastiCache node type) in
`main.tf`. Any field can be overridden explicitly (`db_instance_class`,
`db_allocated_storage`, `redis_node_type`, `backend_replica_count`, …).

## Usage — two-stage apply (required)

The application roles the app connects as (`weissman_app`, `weissman_auth`,
`weissman_worker`, `weissman_analytics`) are **NOBYPASSRLS** roles that live
*inside* Postgres (ADR 0001); RDS only gives you the master/owner user. So the
data tier must exist and be bootstrapped **before** the pods start, or they will
crash-loop on connect. Apply in two stages:

```sh
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # then edit

terraform init

# 1) Stand up RDS + ElastiCache + Secrets Manager only.
terraform apply -target=module.data_tier

# 2) Bootstrap the DB (roles + pgvector + migrations + RLS). See below.

# 3) Install the app once the DB is ready.
terraform apply
```

### DB bootstrap (stage 2)

Pull the generated credentials from Secrets Manager (never printed to a
terminal by Terraform):

```sh
aws secretsmanager get-secret-value \
  --secret-id "weissman/<customer_name>/app" \
  --query SecretString --output text | jq .
```

Connect as the master user (`migrate_url` / `db_master_*` in the bundle) and
create the four roles with the generated per-role passwords
(`role_passwords.*`), then enable pgvector:

```sql
-- run as the RDS master/owner user, against database "weissman"
CREATE EXTENSION IF NOT EXISTS vector;

CREATE ROLE weissman_app       LOGIN PASSWORD '<role_passwords.weissman_app>'       NOSUPERUSER NOBYPASSRLS;
CREATE ROLE weissman_auth      LOGIN PASSWORD '<role_passwords.weissman_auth>'      NOSUPERUSER NOBYPASSRLS;
CREATE ROLE weissman_worker    LOGIN PASSWORD '<role_passwords.weissman_worker>'    NOSUPERUSER NOBYPASSRLS;
CREATE ROLE weissman_analytics LOGIN PASSWORD '<role_passwords.weissman_analytics>' NOSUPERUSER NOBYPASSRLS;
```

Grant the schema/table privileges exactly as the shared tier does (see
`crates/weissman-db` bootstrap and ADR 0001), run migrations, then run the RLS
live contract against this DSN before serving traffic:

```sh
DATABASE_URL="<migrate_url from the bundle>" \
  cargo test -p weissman-db --test rls_live_schema_contract
```

The application itself runs SQLx migrations on boot (`WEISSMAN_MIGRATE_URL`), so
stage 3's pods will migrate once the roles exist; keep the app's `migrate_url`
pointed at the master/owner DSN the bundle provides.

## Secrets

- Terraform **mints** this customer's `jwt_secret` (64-char), `vault_key`
  (64 hex), `integrations_vault_key` (>=32), plus the RAG/metrics/destructive/
  job-orchestrator secrets and all DB/Redis passwords, and records them in one
  Secrets Manager entry (`weissman/<customer>/app`) as the source of record.
- The same values are injected into the Helm release via `set_sensitive`, so the
  chart's in-cluster `Secret` (consumed by the pods) matches the bundle. Both the
  integrations vault key and the CEO `vault_key` are set, satisfying the
  production boot guard in `fingerprint_engine/src/security_startup.rs`
  (`dedicated_key_configured()` for both vaults).
- These live in Terraform state and in Secrets Manager. Use a remote backend with
  encryption + locking (e.g. S3 + DynamoDB, or Terraform Cloud) and restrict
  access. `*.tfvars` and state files are git-ignored here.
- For a stricter posture, wire the External Secrets Operator to sync
  `weissman/<customer>/app` into the namespace and set the chart's
  `secrets.create=false` instead of injecting via Helm; that removes the secret
  material from Terraform's Helm state. This module ships the direct-injection
  path for a self-contained first install.

## Redis TLS

`redis_transit_encryption_enabled=true` (default) provisions an AUTH token and
sets `redis_url` to `rediss://…`. Set it to `false` (plain `redis://`, no auth
token) only if the deployed Redis client cannot speak TLS.

## Provider pins

- `hashicorp/aws ~> 5.60`
- `hashicorp/helm ~> 2.17` (v2 block syntax: `set_sensitive { … }`, `kubernetes { … }`)
- `hashicorp/kubernetes ~> 2.31`
- `hashicorp/random ~> 3.6` (`random_bytes`)

## Validation status

`terraform validate` / `plan` were **not** run in the authoring environment: it
has no cloud credentials and no Terraform binary, and the `aws_eks_cluster` data
sources plus the local Helm chart require a reachable account and cluster. The
HCL is authored to be syntactically valid and internally self-consistent; run
`terraform fmt -recursive` and `terraform init && terraform validate` in your own
environment (validate needs provider plugins from `init`; a full `plan` needs AWS
creds and the target VPC/EKS ids).
