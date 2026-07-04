# Weissman Cybersecurity — Security & Compliance Overview

Last updated: 2026-07-03 (synced with Phase 7 audit gate — 558 engines, 112 routes, JWT ≥48)

## 1. Scope

This document summarises the platform's current security architecture and
controls, suitable for customer security reviews and procurement questionnaires.
Detailed Q&A is in [`SIG_CAIQ_PREP_QA.md`](SIG_CAIQ_PREP_QA.md); SLA in
[`SLA_AND_STATUS.md`](SLA_AND_STATUS.md).

### Platform scale (code-verified)

| Metric | Value | Audit script |
|--------|-------|--------------|
| Production engines | **558** | `scripts/verify_engine_wiring.mjs` |
| Command Center routes | **112** | `scripts/weissman-ui-audit.mjs` |
| UI pages audited | **95/95** | same |
| Engine kinds | 300 real_probe, 213 alias, 45 agent_required | `scripts/engine_reality_audit.mjs` |

Global release gate: **`bash scripts/full_audit_gate.sh`** (G1–G7, exit 0).
Inspection-day script: **`docs/operations/INSPECTION-DAY-RUNBOOK.md`**.

## 2. Data handling

- **Multi-tenant by construction.** Every multi-tenant table carries
  `tenant_id BIGINT NOT NULL REFERENCES tenants(id)` and has **forced
  PostgreSQL Row-Level Security** (`USING (tenant_id = current_setting(...)::bigint)`).
  80+ tables, no exceptions.
- **Audit trail.** Every authenticated write goes through
  `audit_log::insert_audit`; rows land in `public.audit_logs` with
  `(tenant_id, user_id, user_label, action_type, details, ip_address,
  created_at)`. Append-only by application convention; revisions never
  modify history.
- **Finding lifecycle.** Status workflow `OPEN → ACKNOWLEDGED → IN_PROGRESS →
  FIXED | FALSE_POSITIVE` with timestamps in `vulnerabilities.status_changed_at`.
  Analyst-set status is preserved across re-scans (the dedup upsert never
  resets it).
- **NL-query audit.** Every `/api/ask` call is recorded in `nl_query_audit`:
  the question, the LLM-generated plan, the compiled SQL, row count, ms,
  error message (if any).

## 3. Data residency

- `WEISSMAN_REGION` env var drives the deployment region (default `EU-West`).
- `region_manager.should_process_tenant` enforces the per-tenant region match
  before any cross-region work.
- Cloud SaaS data is stored in EU-West (Ireland) by default; Enterprise
  customers may select US-East or AU-East. Self-hosted: data never leaves
  customer infrastructure.

## 4. Identity, authentication, authorization

- **Roles (5 levels + a flag).**
  `viewer < analyst < operator < admin < ceo`, plus the boolean
  `is_superadmin` for cross-tenant CEO operations. Enforced via the
  `rbac` module + `ceo_rbac_middleware`.
- **Local password auth.** bcrypt cost-12 hashes (`bcrypt::hash`). Minimum
  12 chars + character-class diversity at signup.
- **TOTP MFA.** `auth_mfa.rs` with `totp-rs`. Per-tenant `mfa_required` config
  rejects logins without enrolled MFA (`403 mfa_enrollment_required`).
- **SSO (OIDC + SAML).** `oidc_auth.rs` (PKCE, id-token verify) and
  `saml_auth.rs` (signed assertions, JIT user provisioning). Pluggable per
  tenant.
- **Session security.** Two-pool architecture: `weissman_app` (subject to
  RLS) for app queries, `weissman_auth` (BYPASSRLS) only for the login plane
  (`auth.v_user_lookup`) — minimises blast radius. A third **read-only role**
  `weissman_ro` exists for the NL→SQL feature: SELECT-only on 13 whitelisted
  tables, `statement_timeout=15s`, `idle_in_transaction_session_timeout=30s`.

## 5. Cryptography

- **Webhook signing.** Outbound integration webhooks signed
  `X-Weissman-Signature: sha256=…` (HMAC-SHA256); Paddle inbound webhooks
  verified via `subtle::ct_eq` to prevent timing attacks
  (`billing/webhook.rs`).
- **Bearer token comparison.** All bearer-token equality checks use
  constant-time helpers (`subtle::ConstantTimeEq` with length padding) —
  see `cicd_interceptor.rs::constant_time_str_eq`.
- **TLS.** TLS 1.2+ enforced on outbound HTTP via `weissman_core::tls_policy`.
  `WEISSMAN_ALLOW_INSECURE_TLS=1` refuses to start in production
  (`WEISSMAN_REGION` non-empty).
- **At-rest encryption.** Postgres data volume is operator-managed (LUKS / KMS
  on the deployment platform); MFA secrets are stored encrypted at the
  application layer (Vault Transit primary, Fernet fallback in
  `database_encryption.py`).

## 6. Threat intelligence integrity

- **CISA KEV mirror.** `intel_kev.rs` downloads the official
  `known_exploited_vulnerabilities.json` from `cisa.gov` every 6 hours,
  upserts into `kev_intel`, back-fills `vulnerabilities.kev_*` columns.
- **FIRST.org EPSS.** `intel_epss.rs` batches CVE lookups against
  `api.first.org/data/v1/epss`, caches in `epss_intel` (24 h TTL), embeds the
  score on every CVE-tagged finding at persist time.
- **No silent failure.** When either feed is unreachable, the finding lands
  without the enrichment (UI shows "—") and the background worker re-tries on
  the next cycle. **We never fabricate a score.**

## 7. Retention & lifecycle controls (env-driven)

| Var | Default |
|-----|---------|
| `WEISSMAN_INTEL_EPHEMERAL_RETENTION_DAYS` | 7 |
| `WEISSMAN_INTEL_DYNAMIC_RETENTION_DAYS` | 30 |
| `WEISSMAN_ASYNC_JOB_RETENTION_DAYS` | 14 |
| `WEISSMAN_BACKUP_RETENTION_DAYS` | 30 |

UEBA-specific:
- `agent_metric_samples` purged hourly when older than 14 days
  (`ueba_detector::spawn_retention_loop`).

## 8. API & abuse protection

- **Per-tenant scan rate-limit.** `http::tenant_scan_limit` middleware blocks
  excessive POST `/api/command-center/scan` per tenant.
- **AI quota.** `scan_routing::DEFAULT_AI_DAILY_SCAN_QUOTA` (50/day per
  tenant) — exceeded returns `429 quota_exceeded` with `Retry-After`.
- **API keys.** Stored hashed (`api_keys.key_hash`) with prefix-based lookup
  for operational use; no plaintext at rest.
- **Scope validation.** Every scan target is matched against
  `clients.domains / ip_ranges` *before* the engine runs. Out-of-scope →
  `403 target outside approved tenant scope`. Private IP ranges
  (`10/8`, `172.16/12`, `192.168/16`, link-local) are rejected at the
  default policy.
- **Auto-suppression.** Three FALSE_POSITIVE marks on the same
  `(engine, signature_hash)` add a row in `finding_suppressions`; subsequent
  detections are silently demoted to FALSE_POSITIVE — audit trail preserved.

## 9. Operational logging

- Audit helper logs to `audit_logs`; tracing emits structured JSON
  (`WEISSMAN_LOG_FORMAT=json`) for SIEM ingestion.
- Prometheus scrape endpoint at `/api/metrics`.
- Public status page at `/status` (no auth) for uptime monitors.

## 10. Migration safety

- `crates/weissman-db/migrations/` is the source of truth.
- Standard files run inside transactions (`sqlx::migrate!()`).
- `-- weissman:no-transaction` files (e.g. `CREATE INDEX CONCURRENTLY`) are
  applied by a pre-runner with **SQLx-compatible SHA-384 checksums** stored in
  `_sqlx_migrations`. Re-runs are checksum-verified — any post-deploy edit to a
  migration file is detected at boot and refuses to start
  (`NoTxMigrateError::ChecksumMismatch`).

## 11. Compliance posture (declaration)

This document is a technical-controls overview, **not** a third-party
certification report. SOC 2 Type II / ISO 27001 status is declared by the
operating entity and its auditor. The Standard Contractual Clauses (Module 2,
Controller-to-Processor) for EEA / UK / Switzerland data flows are
incorporated by reference in [`/dpa.html`](deploy/public/dpa.html).

## 12. Evidence references (in this repository)

| Concern | Implementation |
|---------|----------------|
| Full audit gate G1–G7 | `scripts/full_audit_gate.sh` |
| Auditor evidence pack (JSON + PDF) | `scripts/generate_audit_evidence_pack.sh` |
| Live Playwright E2E | `frontend/tests-e2e/live-journey.spec.ts` |
| Tenant isolation + RLS | `crates/weissman-db/src/lib.rs` (`begin_tenant_tx`, GUC `app.current_tenant_id`) |
| Audit trail | `fingerprint_engine/src/audit_log.rs` |
| RBAC | `fingerprint_engine/src/rbac.rs` + `http/ceo_rbac.rs` |
| MFA | `fingerprint_engine/src/auth_mfa.rs` |
| OIDC / SAML | `fingerprint_engine/src/oidc_auth.rs`, `saml_auth.rs` |
| Scope validation | `fingerprint_engine/src/security_hardening.rs`, `scan_routing.rs` |
| KEV mirror | `fingerprint_engine/src/intel_kev.rs` |
| EPSS client | `fingerprint_engine/src/intel_epss.rs` |
| FP/TP feedback + suppressions | `fingerprint_engine/src/fp_feedback.rs` |
| Finding cluster dedup | `fingerprint_engine/src/findings_correlator.rs` |
| FAIR-aligned $-at-risk | `fingerprint_engine/src/financial_risk.rs` |
| NL → safe SQL | `fingerprint_engine/src/nl_query.rs` (+ migration `20260608140300`) |
| UEBA detector | `fingerprint_engine/src/ueba_detector.rs` + agent `detections/baseline.rs` |
| SOAR playbooks | `fingerprint_engine/src/soar_playbook.rs` |
| Attack-path BFS | `fingerprint_engine/src/attack_path.rs` |
| Constant-time bearer | `fingerprint_engine/src/cicd_interceptor.rs::constant_time_str_eq` |
| Rate limiting | `fingerprint_engine/src/http/tenant_scan_limit.rs` |
| Data retention | `fingerprint_engine/src/data_retention.rs` |
| Webhook HMAC verify | `fingerprint_engine/src/billing/webhook.rs` |
| No-transaction migration runner | `crates/weissman-db/src/no_tx_migrations.rs` |
