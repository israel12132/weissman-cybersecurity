# Operations runbook

> Current as of 2026-06-09. Covers env vars, migrations, intel workers,
> read-only role, day-to-day operational tasks.

## 1. Environment variables

### Required

| Var | Purpose |
|-----|---------|
| `DATABASE_URL` | App pool (role `weissman_app`, RLS). `postgres://…` |
| `WEISSMAN_JWT_SECRET` | Min 32-byte secret for JWT signing (`openssl rand -hex 32`) |
| `WEISSMAN_MIGRATE_URL` | Owner/superuser URL used by `run_migrations` (may equal `DATABASE_URL` in dev) |

### Recommended

| Var | Default | Effect |
|-----|---------|--------|
| `WEISSMAN_AUTH_DATABASE_URL` | = `DATABASE_URL` | Separate `weissman_auth` role with BYPASSRLS for login plane |
| `WEISSMAN_READ_ONLY_DATABASE_URL` | unset → `/api/ask` returns 503 | Connection string for the `weissman_ro` SELECT-only role |
| `WEISSMAN_REGION` | `EU-West` | Tenant-region matching for data residency |
| `WEISSMAN_PUBLIC_URL` | `http://localhost` | Used by signup verification email links |
| `WEISSMAN_LOG_FORMAT` | text | `json` for structured JSON logs (recommended in production) |

### Optional capability toggles

| Var | Default | Effect |
|-----|---------|--------|
| `WEISSMAN_SELF_SERVE_SIGNUP` | unset → 503 | `true` opens `/api/auth/signup` to the public |
| `WEISSMAN_ALLOW_SELF_SERVE_IN_PRODUCTION` | unset | Required with `WEISSMAN_SELF_SERVE_SIGNUP=true` in production (explicit operator acknowledgement) |
| `WEISSMAN_SIGNUP_RETURN_LINK` | unset | `1` returns the verification link in the response (DEV ONLY) |
| `WEISSMAN_BILLING_STRICT` | derived | When `true`, client-create + scan-run require an active Paddle subscription |
| `WEISSMAN_INTEL_KEV_ENABLED` | `true` | Disable to skip CISA KEV mirror refresh |
| `WEISSMAN_INTEL_EPSS_ENABLED` | `true` | Disable to skip FIRST EPSS back-fill |
| `WEISSMAN_SOVEREIGN_SELF_SCAN_INTERVAL_SECS` | `0` (off) | LLM review of `audit_logs` every N s (min 300 once on) |

### LLM / embeddings (used by Council RAG, NL-Query, Predictive)

| Var | Default | Effect |
|-----|---------|--------|
| `OPENAI_BASE_URL` / `WEISSMAN_LLM_BASE_URL` | `https://api.openai.com` | Any OpenAI-compatible server (vLLM, Ollama-mapped, Together) |
| `OPENAI_API_KEY` / `WEISSMAN_LLM_API_KEY` | unset | Bearer token if the server requires auth |
| `WEISSMAN_EMBEDDINGS_MODEL` | `text-embedding-3-small` | 1536-d. Mapped & padded if shorter |
| `WEISSMAN_NL_QUERY_MODEL` | `gpt-4o-mini` | Model used for Ask-Weissman planner |
| `WEISSMAN_COUNCIL_MODEL_*` | … | Override per-role models for the Supreme Council |

### Alerts

| Var | Effect |
|-----|--------|
| `WEISSMAN_ALERT_WEBHOOK_URL` | Generic webhook for critical-PoE alerts and SOAR fallback |
| `WEISSMAN_PAGER_WEBHOOK_URL` | PagerDuty / OpsGenie endpoint for `page_oncall` action |
| `WEISSMAN_SMTP_ENABLED` + `WEISSMAN_SMTP_*` | SMTP for verification + critical alert emails |
| `WEISSMAN_METRICS_TOKEN` | Required in production; protects `GET /api/metrics` via Bearer token |

### Pool tuning

| Var | Default |
|-----|---------|
| `WEISSMAN_APP_POOL_MAX` | 48 |
| `WEISSMAN_APP_POOL_MIN` | 2 |
| `WEISSMAN_SOVEREIGN_MPSC_CAPACITY` | unset → unbounded |

### TLS policy

| Var | Effect |
|-----|--------|
| `WEISSMAN_ALLOW_INSECURE_TLS` | `1` only outside production; backend refuses to start in production when set |

### Proxy trust / real client IP

| Var | Effect |
|-----|--------|
| `WEISSMAN_TRUST_PROXY_HEADERS` | Enables use of `X-Forwarded-For` / `X-Real-IP` for audit + rate limit client identity |
| `WEISSMAN_TRUST_PROXY_CIDRS` | Optional comma-separated trusted proxy CIDRs; when set, only peers in this list are allowed to supply forwarded client IP |

---

## 2. Migrations

### Standard (transactional) migrations

Place a SQL file in `crates/weissman-db/migrations/` named
`<yyyymmddHHMMSS>_<description>.sql`. SQLx wraps it in `BEGIN/COMMIT` and runs
it at boot via `weissman_db::run_migrations`. Idempotent SQL recommended
(`CREATE … IF NOT EXISTS`, `ALTER … ADD COLUMN IF NOT EXISTS`).

### No-transaction migrations

For statements Postgres rejects inside a transaction (CREATE/DROP/REINDEX
INDEX CONCURRENTLY, VACUUM FULL, ALTER SYSTEM), put **exactly** this on line 1
of the file (BOM tolerated, case-insensitive):

```sql
-- weissman:no-transaction
```

The pre-runner in `crates/weissman-db/src/no_tx_migrations.rs`:

1. Detects the header.
2. Computes the file's SHA-384 (SQLx-compatible).
3. Looks up `_sqlx_migrations` by version.
4. If absent: executes every statement on a fresh connection **outside** any
   transaction, then INSERTs a row in `_sqlx_migrations` with the SHA-384.
5. If present with matching checksum: skip.
6. If present with mismatching checksum: **refuse to boot** with
   `NoTxMigrateError::ChecksumMismatch` — operator must restore the file or
   supersede with a new migration. No silent drift.

The SQLx-native `sqlx::migrate!()` runner then sees the row as already-applied
and skips it. **CI/CD pipelines run the boot path; no separate `psql` step.**

Idempotency is the file author's responsibility. The canonical example:

```sql
-- weissman:no-transaction
DROP   INDEX CONCURRENTLY IF EXISTS ix_async_jobs_pending;
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_async_jobs_pending
    ON weissman_async_jobs (created_at, kind) WHERE status = 'pending';
DROP   INDEX CONCURRENTLY IF EXISTS ix_weissman_async_jobs_pending;
```

The first DROP cleans up any INVALID index from a previously interrupted run;
both CONCURRENTLY forms hold only ACCESS SHARE locks, so the live worker keeps
reading throughout.

### Adding the read-only role

The migration `20260608140300_nl_query_readonly_role.sql` creates the
`weissman_ro` role with a dev password, applies SELECT grants on 13 tables,
and sets per-session timeouts. For production, **change the password and grant
URL via `WEISSMAN_READ_ONLY_DATABASE_URL`**:

```bash
export WEISSMAN_READ_ONLY_DATABASE_URL=\
  'postgres://weissman_ro:STRONG_RANDOM_HERE@db.internal:5432/weissman'
```

---

## 3. Background workers (in-process)

All started from `serve::spawn_http_background_tasks`. Logs emit on `target =
…`:

| Worker | Interval | Target | Stops when |
|--------|----------|--------|------------|
| `intel_kev` | 6 h | `intel_kev` | env `WEISSMAN_INTEL_KEV_ENABLED=false` |
| `intel_epss` | 12 h | `intel_epss` | env `WEISSMAN_INTEL_EPSS_ENABLED=false` |
| `ueba_detector::retention` | 1 h | n/a (`DELETE` only) | never |
| `data_retention` | hourly | `data_retention` | never |
| `db_backup_scheduler` | nightly | `db_backup` | unset env |
| `sovereign_self_scan` | env (min 300 s) | `sovereign_self_scan` | env unset |
| `threat_intel_ingestor` | NVD/OSV/GHAdvisories | `threat_intel_ingestor` | NVD failure → retries |
| `payload_sync_worker` | minute-ish | `payload_sync` | never |

Each is `tokio::spawn`-ed once via `OnceLock` so duplicate spawns are no-ops.

---

## 4. SOAR playbook actions

The `soar_playbook` engine dispatches matching actions on every persisted
finding (best-effort, fire-and-forget after the DB commit).

| Action kind | Required env | Effect |
|-------------|-------------|--------|
| `set_status` | — | UPDATE vulnerabilities.status (also cascades to cluster) |
| `slack_notify` / `webhook` | params.url **or** `WEISSMAN_ALERT_WEBHOOK_URL` | POST JSON to URL |
| `http_post` | params.url | Generic JSON POST |
| `open_pr` | params or auto_heal config | INSERTs `auto_heal_job_specs` row for the worker |
| `isolate_host` | — | Records intent in `audit_logs.containment_requested` (wire up to your EDR) |
| `page_oncall` | `WEISSMAN_PAGER_WEBHOOK_URL` | POST summary + severity |

Cooldown: `trigger.cooldown_seconds` deduplicates by
`sha256(playbook_id | signature_hash | target)` over the window — same finding
in cooldown is a no-op for that playbook.

---

## 5. Common ops tasks

### Reset a tenant's $-at-risk snapshot

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
  http://api/financial-risk/$CLIENT_ID?recompute=1
```

### Rebuild attack-path graph for a client

```bash
curl -X GET -H "Authorization: Bearer $JWT" \
  'http://api/attack-paths/'"$CLIENT_ID"'?recompute=1&top_k=50'
```

### Undo an auto-suppression rule (3-FP rule was wrong)

```bash
# 1) list
curl -H "Authorization: Bearer $JWT" http://api/intel/suppressions | jq
# 2) delete by id
curl -X DELETE -H "Authorization: Bearer $JWT" \
  http://api/intel/suppressions/$ID
```

### Manually re-apply an asset's tag→USD rules

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
  http://api/financial-risk/$CLIENT_ID/apply-tags
```

### Dry-run a SOAR playbook against a synthetic event

```bash
curl -X POST -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{ "dry_run": true,
        "event": {
          "kind":"finding_persisted","tenant_id":0,"client_id":1,
          "finding_id":1,"title":"test","severity":"critical","source":"asm",
          "target":"https://example.com","status":"OPEN",
          "cvss":9.8,"epss":0.9,"kev":true,"kev_known_ransomware":true,
          "cve":"CVE-2021-44228","internet_exposed":true
        } }' \
  http://api/playbooks/fire | jq
```

### Verify the no-tx runner state

```bash
docker compose exec postgres psql -U postgres -d weissman -c "
  SELECT version, description, length(checksum) AS sha384_bytes, success
    FROM _sqlx_migrations
   WHERE description = 'async_jobs_pending_partial_index';
"
```

### Confirm pgvector is live + supreme_council retrieval works

```bash
docker compose exec postgres psql -U postgres -d weissman -c "
  SELECT extname, extversion FROM pg_extension WHERE extname='vector';
  SELECT count(*) FILTER (WHERE embedding_vec IS NOT NULL) AS embedded,
         count(*) AS total
    FROM supreme_council_memory;
"
```

### Inspect the Ask-Weissman audit trail

```bash
docker compose exec postgres psql -U postgres -d weissman -c "
  SELECT asked_at, rows_returned, elapsed_ms, error,
         left(question, 80) AS q
    FROM nl_query_audit ORDER BY asked_at DESC LIMIT 20;
"
```

---

## 6. CI/CD checklist before deploy

1. `cargo check --workspace` — green
2. `cargo test  --workspace` — green (current baseline: 14 weissman-db + 58
   fingerprint_engine + agent build)
3. `docker compose build backend gateway` — green
4. Migration smoke: `docker compose up postgres -d`, then point a clean DB
   at `WEISSMAN_MIGRATE_URL` and run the backend — should boot and report
   `applied N no-transaction migrations` and then sqlx applies the rest.
5. Probe new endpoints (see `qa-shots/probe-phase3-endpoints.sh`).
6. Watch logs for `target = intel_kev` / `intel_epss` confirming first refresh.

---

## 7. Failure-mode quick reference

| Symptom | Cause | Fix |
|---------|-------|-----|
| Boot fails: `migration #N was previously applied with a different checksum` | The migration SQL file was edited after deploy | Restore the original file, OR supersede with a new migration that achieves the same effect |
| `/api/ask` returns `503 self_serve_disabled` | `WEISSMAN_READ_ONLY_DATABASE_URL` unset | Provision `weissman_ro`, set the env var, restart backend |
| `/api/auth/signup` returns `503` | `WEISSMAN_SELF_SERVE_SIGNUP` not `true` | Set the env var (and configure SMTP for production) |
| Council retrieval falls back to "in-app cosine" path | LLM embeddings unreachable | Verify `OPENAI_BASE_URL` + key; check `target = council_rag` warnings |
| UEBA never fires anomalies | Less than 24 samples in the relevant `hour_of_week` bucket | Wait (one sample/hour by default = ≥1 week per bucket) — by design |
| `intel_kev` worker logs "HTTP 0" | Outbound block on cisa.gov | Provide an HTTPS proxy (`HTTPS_PROXY`) or mirror the feed |
| PoE registry growing without bound | Pre-2026.06.0 build | Already fixed: empty Vec is removed from the DashMap |
