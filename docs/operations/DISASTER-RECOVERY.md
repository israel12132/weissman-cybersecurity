# Disaster Recovery — Weissman Platform

## Objectives

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** (Recovery Point Objective) | **15 minutes** | With WAL/PITR enabled (`scripts/backup_pitr_setup.sh`); **24 hours** with logical `pg_dump` only |
| **RTO** (Recovery Time Objective) | **4 hours** | Full stack restore on fresh VPS/K8s including Postgres PITR replay + Redis cold start |
| **RTO (degraded read-only)** | **1 hour** | Restore latest base backup + replay WAL to last consistent point |

## Backup tiers

### Tier 1 — Logical (always available)

- In-app scheduler: `WEISSMAN_PG_BACKUP_DIR` → nightly `pg_dump` + gzip (`fingerprint_engine/src/db_backup.rs`)
- Manual: `POST /api/system/backup` (admin)
- Retention: `WEISSMAN_BACKUP_RETENTION_DAYS` (default 14)

**RPO:** up to 24h (backup interval). **Not** point-in-time.

### Tier 2 — Encrypted PITR (production required)

All backups are **encrypted with `age` in asymmetric recipient mode**: the host holds only a
public key and cannot decrypt its own backups. Full architecture, threat model, key ceremony and
restore runbook: **[ENCRYPTED-DR-PITR.md](./ENCRYPTED-DR-PITR.md)**.

1. Do the one-time key ceremony (offline) and set recipients in `.env`:

   ```bash
   age-keygen -o dr-identity.txt            # keep the identity OFF this host
   WEISSMAN_ENV=production
   WEISSMAN_BACKUP_AGE_RECIPIENTS="age1...ops age1...breakglass"
   WEISSMAN_DR_OFFSITE_URL=s3://weissman-dr-independent/pitr
   ```

2. Enable ENCRYPTED WAL archiving (superuser) and take the first encrypted backup:

   ```bash
   export DATABASE_URL=postgresql://postgres:...@host/weissman
   ./scripts/backup_pitr_setup.sh init      # encrypted archive_command + recipients file
   ./scripts/dr_orchestrator.sh cycle       # encrypted base + off-site replication
   ./scripts/dr_orchestrator.sh drill       # PROVE it decrypts + restores
   ```

3. Schedule nightly (`scripts/backup_nightly.sh` = cycle + drill) and check posture any time:

   ```bash
   ./scripts/dr_orchestrator.sh status
   ```

**RPO:** 15 minutes (encrypted WAL segment flush + archive lag monitoring). Backups are refused
(fail-closed) rather than written in cleartext if encryption is unavailable.

### Tier 3 — Managed database (recommended)

- AWS RDS / GCP Cloud SQL / Azure Flexible Server with **automated backups + PITR** enabled.
- Document provider retention (typically 7–35 days) in your runbook.
- Disable Tier 2 self-managed WAL when using provider PITR.

## Restore procedure (encrypted PITR)

On the **restore trust zone** (the only place the age identity/private key lives):

```bash
export WEISSMAN_BACKUP_AGE_IDENTITY_FILE=/secure/dr-identity.txt
export WEISSMAN_DR_OFFSITE_URL=s3://weissman-dr-independent/pitr

# Pull latest encrypted base + WAL, verify integrity, decrypt, prepare replay to a point in time:
./scripts/dr_orchestrator.sh restore /recovery --target-time '2026-01-01 12:00:00+00'
# Start Postgres 16 on /recovery/pgdata — it replays WAL (decrypting each segment) and promotes:
pg_ctl -D /recovery/pgdata -o '-p 5432' -w start
```

Then point `DATABASE_URL` / `WEISSMAN_MIGRATE_URL` at the new instance, redeploy backend + worker,
and verify `./scripts/go_live_check.sh --live https://...`. Full detail (including the on-demand
WAL decryption during replay): [ENCRYPTED-DR-PITR.md](./ENCRYPTED-DR-PITR.md).

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
| `dr_orchestrator.sh drill` (decrypt + restore) | Nightly (`backup_nightly.sh`) | Platform ops |
| `dr_crypto_selftest.sh` (crypto/integrity/off-site) | Every CI run | CI |
| `dr_orchestrator.sh status` (RPO/RTO posture) | Weekly review | Platform ops |
| Full off-site `restore` to staging | Quarterly | Platform ops |
| `go_live_check.sh --live` post-restore | Each restore drill | Release engineer |
| Outage smoke (`deploy/verify-outage-recovery.sh`) | After any production incident | On-call |

## Related documents

- [Encrypted DR & PITR — architecture, threat model, key ceremony, restore runbook](./ENCRYPTED-DR-PITR.md)
- [Operations monitoring (EN)](../manuals/en/16-operations-monitoring.md)
- [Production security (EN)](../manuals/en/05-production-security.md)
- [SOAR verification worker](./SOAR-VERIFICATION-WORKER.md)
- [Kubernetes install (EN)](../manuals/en/04-installation-kubernetes.md)
