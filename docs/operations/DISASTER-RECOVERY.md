# Disaster Recovery — Weissman Platform

## Objectives

> **Committed RPO is ≤ 1 hour.** That is the figure in `SECURITY_AND_COMPLIANCE.md`,
> `SIG_CAIQ_PREP_QA.md` and the Bank of Israel Directive 361 mapping, and it is what
> customers are entitled to. The 15 minutes below is the *measured capability* of the
> Tier 2 PITR configuration — headroom against the commitment, not a second promise.
> Quote ≤ 1 hour externally; use 15 minutes for capacity planning.

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** — committed | **≤ 1 hour** | Contractual objective; the figure quoted to customers and auditors |
| **RPO** — measured capability | **15 minutes** | With WAL/PITR enabled (`scripts/backup_pitr_setup.sh`); **24 hours** with logical `pg_dump` only |
| **RTO** (Recovery Time Objective) | **4 hours** | Full stack restore on fresh VPS/K8s including Postgres PITR replay + Redis cold start |
| **RTO (degraded read-only)** | **1 hour** | Restore latest base backup + replay WAL to last consistent point |

## Backup tiers

### Tier 1 — Logical (always available)

- In-app scheduler: `WEISSMAN_PG_BACKUP_DIR` → nightly `pg_dump` + gzip (`fingerprint_engine/src/db_backup.rs`)
- Manual: `POST /api/system/backup` (admin)
- Retention: `WEISSMAN_BACKUP_RETENTION_DAYS` (default 14)

**RPO:** up to 24h (backup interval). **Not** point-in-time.

### Tier 2 — PITR (production required)

1. Enable WAL archiving (superuser):

   ```bash
   export DATABASE_URL=postgresql://postgres:...@host/weissman
   export WEISSMAN_PITR_ARCHIVE_DIR=/var/backups/weissman/wal
   export WEISSMAN_PITR_BASE_DIR=/var/backups/weissman/base
   ./scripts/backup_pitr_setup.sh init
   ./scripts/backup_pitr_setup.sh base
   ```

2. Schedule base backups daily + WAL archive to **offsite encrypted storage** (S3/GCS with versioning).

3. Verify quarterly:

   ```bash
   ./scripts/backup_pitr_setup.sh verify
   ```

**RPO:** 15 minutes (WAL segment flush + archive lag monitoring).

### Tier 3 — Managed database (recommended)

- AWS RDS / GCP Cloud SQL / Azure Flexible Server with **automated backups + PITR** enabled.
- Document provider retention (typically 7–35 days) in your runbook.
- Disable Tier 2 self-managed WAL when using provider PITR.

## Restore procedure (PITR)

1. Provision fresh Postgres 16 instance.
2. Restore latest base backup from `WEISSMAN_PITR_BASE_DIR/latest`.
3. Create `recovery.signal` and set `restore_command` to copy WAL from archive dir.
4. Start Postgres; replay to target timestamp (`recovery_target_time`).
5. Promote: remove recovery config, restart.
6. Point `DATABASE_URL` / `WEISSMAN_MIGRATE_URL` at new instance.
7. Redeploy backend + worker; verify `./scripts/go_live_check.sh --live https://...`.

## Redis / job bus

- Redis is **ephemeral** for job queues and SOAR idempotency caches.
- After DR: workers re-consume from Postgres event sourcing (`weissman_async_jobs`, job-bus tables).
- Expect **transient duplicate guard** until Redis repopulates (idempotency fail-open documented in SOAR ops guide).

## Secrets

- Store `weissman-secrets` (K8s) or `.env` (VPS) in **separate vault** (1Password, AWS Secrets Manager).
- Never rely on backup artifacts for secret recovery — rotate if backup media may be compromised.

## Testing schedule

| Test | Frequency | Owner |
|------|-----------|-------|
| `backup_pitr_setup.sh verify` | Weekly | Platform ops |
| Full restore to staging | Quarterly | Platform ops |
| `go_live_check.sh --live` post-restore | Each restore drill | Release engineer |
| Outage smoke (`deploy/verify-outage-recovery.sh`) | After any production incident | On-call |

## Related documents

- [Operations monitoring (EN)](../manuals/en/16-operations-monitoring.md)
- [Production security (EN)](../manuals/en/05-production-security.md)
- [SOAR verification worker](./SOAR-VERIFICATION-WORKER.md)
- [Kubernetes install (EN)](../manuals/en/04-installation-kubernetes.md)
