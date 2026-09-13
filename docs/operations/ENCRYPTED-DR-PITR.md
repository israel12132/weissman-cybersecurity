# Encrypted Disaster Recovery & Point-in-Time Recovery

> Authoritative design + runbook for confidential, recoverable backups of the Weissman
> platform database. This document is the "how it actually works and how to operate it"
> companion to the higher-level [DISASTER-RECOVERY.md](./DISASTER-RECOVERY.md).

## 1. Why this exists — the threat that plaintext backups ignore

A PostgreSQL base backup or WAL segment is a **verbatim copy of the entire database**: every
credential in the integrations vault, every finding, every customer record. Before this system,
those artifacts were written to `/var/backups` and shipped to object storage **in cleartext**.
The consequence is subtle and severe: the security boundary of the whole platform silently
collapsed onto the *file permissions of a backup directory* and the *access policy of a bucket*.

Volume-level "encryption at rest" does **not** close this. It protects a physically stolen disk.
It does nothing against the realistic threats:

| Threat | Cleartext backup outcome | With this design |
|---|---|---|
| Bucket misconfig / leaked object | Full DB disclosed | Ciphertext only; useless without the offline private key |
| Compromised backup/DB host | Attacker reads all history | Host holds only the **public** key — cannot decrypt any backup |
| Malicious insider with backup access | Exfiltrates everything | Sees ciphertext; decryption key is elsewhere |
| Ransomware reaching the backup mount | Encrypts/deletes backups | Off-site + Object-Lock copy survives; tamper is detected |
| Stolen off-site credentials | Full DB disclosed | Ciphertext only |

## 2. Design in one sentence

**Every backup artifact is encrypted with `age` in recipient (asymmetric X25519) mode, so the
production host holds only a public key and provably cannot decrypt its own backups; the private
key lives in a separate trust zone used only for restores; and encrypted copies are replicated to
an independent, ideally immutable, off-site store.**

```
                 PUBLIC key (recipient)                     PRIVATE key (identity)
                 ─ can only ENCRYPT ─                        ─ can DECRYPT ─
   ┌──────────────────────────────┐                    ┌────────────────────────────┐
   │  PRODUCTION / BACKUP HOST     │   encrypted age    │  RESTORE / DR TRUST ZONE    │
   │                              │   artifacts        │  (offline vault, HSM,       │
   │  pg_basebackup ─► base.tar.gz │ ─────────────────► │   break-glass host)         │
   │      │  age -r <pub>          │   off-site (S3/…)  │   age -d -i <identity>       │
   │      ▼                        │                    │      │                       │
   │  base.tar.gz.age              │                    │      ▼                       │
   │  WAL/%f ─► %f.age (archive)   │                    │  restore + PITR replay       │
   └──────────────────────────────┘                    └────────────────────────────┘
```

### Why `age` (and not GPG or hand-rolled OpenSSL)

- **Authenticated streaming AEAD** (ChaCha20-Poly1305 under an X25519-wrapped file key). Tamper
  is detected on decrypt — a corrupted or substituted DR copy fails loudly instead of silently
  restoring garbage.
- **Asymmetric recipients**: the host that makes backups never holds a key that can read them.
  This is the single most valuable property and GPG-for-files ergonomics can't beat age's.
- **Non-interactive, small, audited, ubiquitous.** `rage` (Rust) is a drop-in via
  `WEISSMAN_BACKUP_AGE_BIN`.
- Hand-rolling encrypt-then-MAC over a pipe in bash, or misusing `openssl enc -aes-256-gcm`
  (not stream-safe from the CLI), is exactly the bespoke crypto a security product must not ship.

This mirrors the platform's existing at-rest convention (AES-256-GCM envelopes in
`fingerprint_engine/src/soar/integrations_vault.rs`): authenticated encryption, versioned
envelopes, key material never logged, **fail-closed in production**.

## 3. Components

| Path | Role |
|---|---|
| `scripts/lib/backup_crypto.sh` | The engine. Encrypt/decrypt streams, recipient/identity resolution, `SHA256SUMS`+`MANIFEST.json` integrity, fail-closed policy, self-test. |
| `scripts/pitr_archive_wal.sh` | Postgres `archive_command` wrapper — atomic, idempotent, encrypted WAL archiving; fails closed rather than shipping cleartext WAL. |
| `scripts/pitr_restore_wal.sh` | Postgres `restore_command` wrapper — decrypts each WAL segment on demand during replay. |
| `scripts/backup_pitr_setup.sh` | `init` (encrypted archive_command) / `base` (encrypted base backup + manifest) / `verify` / `prune`. |
| `scripts/backup_restore_verify.sh` | Restore drill — **decrypts** and restores the latest backup into a throwaway cluster; proves recoverability, emits freshness metrics. |
| `scripts/dr_offsite_sync.sh` | Replicate encrypted artifacts to S3/GCS/MinIO/rclone/local; refuses to upload cleartext; pull + integrity-check for restores. |
| `scripts/dr_orchestrator.sh` | One entry point: `cycle` / `drill` / `restore` / `status` / `selftest`, with alerting. |
| `scripts/backup_nightly.sh` | Cron entry: one `cycle` + one `drill`. |
| `scripts/tests/dr_crypto_selftest.sh` | End-to-end proof (no database) run in CI. |
| `deploy/k8s/backup-cronjob.yaml` | K8s CronJobs + key-separated secrets. |
| `deploy/backup.Dockerfile` | Backup toolbox image (pg client + age + scripts). |

## 4. Key ceremony (do this once, offline)

The whole security model rests on **key separation**: the backup host must never hold the private
key. Perform this on an offline/trusted machine.

```bash
# 1. Generate the operations keypair
age-keygen -o dr-ops-identity.txt
#    → prints: Public key: age1qz...            (the RECIPIENT — safe to distribute)
#    → file contains: AGE-SECRET-KEY-1...        (the IDENTITY — GUARD IT)

# 2. Generate a SECOND break-glass keypair held by a different custodian, so no single lost
#    key destroys recoverability. Both public keys become recipients.
age-keygen -o dr-breakglass-identity.txt

# 3. Distribute ONLY the public keys to the production host:
#      WEISSMAN_BACKUP_AGE_RECIPIENTS="age1qz...ops age1qz...breakglass"
#    (or a recipients file). NEVER put an AGE-SECRET-KEY on the backup host.

# 4. Store each identity in a separate vault (1Password/AWS Secrets Manager/HSM). Optionally
#    wrap the identity file itself with a passphrase for at-rest protection in the vault:
age -p -o dr-ops-identity.txt.age dr-ops-identity.txt   # unwrap only during a restore
```

**Rotation.** Add the new public key to `WEISSMAN_BACKUP_AGE_RECIPIENTS` (keep the old one so
existing backups stay recoverable), run one `cycle`, then retire the old key after its backups age
out of retention. Because recipients are additive, rotation never orphans a backup.

## 5. RPO / RTO objectives

| Metric | Target | How it's met |
|---|---|---|
| **RPO** | ≤ 15 min | Encrypted WAL archiving (`archive_command`) + archive-lag monitoring |
| **RTO (read-only)** | ≤ 1 h | Restore latest encrypted base + replay bundled WAL |
| **RTO (full)** | ≤ 4 h | Off-site pull + decrypt + PITR replay to target + repoint app |

`scripts/dr_orchestrator.sh status` reports live posture against these targets.

## 6. Setup (self-managed Postgres)

```bash
# .env (see PRODUCTION.env.template for the full list)
WEISSMAN_ENV=production                       # → encryption REQUIRED (fail closed)
WEISSMAN_BACKUP_AGE_RECIPIENTS="age1ops age1breakglass"
WEISSMAN_PITR_ARCHIVE_DIR=/var/backups/weissman/wal
WEISSMAN_PITR_BASE_DIR=/var/backups/weissman/base
WEISSMAN_DR_OFFSITE_URL=s3://weissman-dr-independent/pitr
WEISSMAN_DR_ALERT_WEBHOOK=https://hooks.slack.com/services/...

export DATABASE_URL=postgresql://postgres:...@host/weissman

# 1. Enable ENCRYPTED WAL archiving (superuser; writes the recipients file, sets archive_command)
./scripts/backup_pitr_setup.sh init
#    In a containerised Postgres, mount scripts/, the archive dir, and the recipients file into
#    the DB container and ensure `age` is on its PATH.

# 2. First encrypted backup + off-site replication + prove it recovers
./scripts/dr_orchestrator.sh cycle
./scripts/dr_orchestrator.sh drill

# 3. Schedule nightly (cron)
15 3 * * *  /opt/weissman/scripts/backup_nightly.sh >> ~/weissman-backups/nightly.log 2>&1
```

On Kubernetes, apply `deploy/k8s/backup-cronjob.yaml` (after the key ceremony populates its
secrets) — the base-backup job gets only the recipients, the restore-drill job gets the identity.

## 7. Restore runbook (production is gone)

```bash
# On the RESTORE trust zone (the host/pod that holds the identity):
export WEISSMAN_BACKUP_AGE_IDENTITY_FILE=/secure/dr-ops-identity.txt
export WEISSMAN_DR_OFFSITE_URL=s3://weissman-dr-independent/pitr

# A. Prepare a replay-ready, decrypted data dir (optionally to a point in time)
./scripts/dr_orchestrator.sh restore /recovery --target-time '2026-01-01 12:00:00+00'
#    → pulls the latest encrypted base + WAL, verifies integrity, decrypts, and writes an
#      ENCRYPTED restore_command + recovery.signal into /recovery/pgdata.

# B. Start Postgres 16 on the prepared data dir; it replays WAL (decrypting each segment on
#    demand) and promotes at the target:
pg_ctl -D /recovery/pgdata -o '-p 5432' -w start        # or: dr_orchestrator.sh restore ... --start

# C. Repoint the app and verify
export DATABASE_URL=postgresql://.../weissman   # new instance
./scripts/go_live_check.sh --live https://...
```

During replay only the **single WAL segment currently being applied** is ever in cleartext, and
only on the trusted DR host that legitimately holds the identity.

## 8. What proves it works (not just claims)

- **`scripts/tests/dr_crypto_selftest.sh`** — real age keypair, real ciphertext, real tar
  round-trips, real integrity + tamper detection, real off-site round-trip, real recovery-dir
  preparation. Runs in CI (`nightly-e2e.yml`); no database needed.
- **`scripts/backup_restore_verify.sh`** — nightly, restores a real cluster from the encrypted
  backup and asserts applied migrations exist. Gated by `go_live_check.sh` (must be < 48 h old).
- **`go_live_check.sh`** — refuses go-live unless encryption is active, recipients are set, the
  latest base is encrypted, and an encrypted restore drill is fresh.
- **Metrics** — `weissman_pitr_base_backup_*`, `weissman_backup_restore_verify_encrypted`,
  `weissman_dr_offsite_push_*` feed Grafana/Alertmanager.

## 9. Fail-closed guarantees (the "nevers")

- Never writes a cleartext base backup or WAL segment when encryption is required — it aborts.
- Never marks a backup `latest` before its payload is verified present (and round-tripped when an
  identity is available).
- Never uploads a cleartext artifact off-site under a required-encryption policy.
- Never reports a restore drill as passing if the backup could not be decrypted, or if
  `SHA256SUMS` integrity fails.
- Never overwrites an already-archived WAL segment with different bytes.

## 10. Relationship to CNPG (Kubernetes)

`deploy/k8s/postgres-ha.yaml` (CloudNativePG) ships WAL/base to S3 with **server-side** encryption
(`barman … encryption: AES256`, or `aws:kms`). That protects objects at rest in the CNPG bucket.
The age envelope in these scripts is **stronger and complementary**: client-side, asymmetric, and
independent of the bucket/KMS — a compromise of the S3 bucket *and* its KMS key still yields only
ciphertext, and the copy lands in a *separate* bucket/region. Run both; they cover different
threats. Do not disable one assuming the other.

## 11. Managed Postgres (RDS / Cloud SQL / Azure)

Use the provider's PITR + storage encryption (KMS/CMK) and document retention. For confidential,
provider-independent copies, run `dr_orchestrator.sh cycle` against a logical/base export on a
worker that holds only the recipients, shipping age-encrypted artifacts to your own bucket.
