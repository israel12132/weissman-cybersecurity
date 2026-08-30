# Weissman Cybersecurity — Security & Compliance Overview

Last updated: 2026-08-18 (added Directive 361 mapping, IL region, PDPA 2023, SLA 99.95%)

## 1. Scope

This document summarises the platform's current security architecture and
controls, suitable for customer security reviews and procurement questionnaires.
Detailed Q&A is in [`SIG_CAIQ_PREP_QA.md`](SIG_CAIQ_PREP_QA.md); SLA in
[`SLA_AND_STATUS.md`](SLA_AND_STATUS.md).

### Platform scale (code-verified)

| Metric | Value | Audit script |
|--------|-------|--------------|
| Production engine IDs | **565** | `scripts/verify_engine_wiring.mjs` |
| Command Center routes | **134** | `scripts/weissman-ui-audit.mjs` |
| UI pages audited | **115/115** | same |
| Engine kinds | 305 real_probe (297 distinct impls), 212 alias, 48 agent_required, 0 no_path | `scripts/engine_reality_audit.mjs` |

Global release gate: **`bash scripts/full_audit_gate.sh`** (G1–G7, exit 0).
Inspection-day script: **`docs/operations/INSPECTION-DAY-RUNBOOK.md`**.

## 2. Data handling

- **Multi-tenant by construction.** Every multi-tenant table carries
  `tenant_id BIGINT NOT NULL REFERENCES tenants(id)` and has **forced
  PostgreSQL Row-Level Security** (`USING (tenant_id = current_setting(...)::bigint)`).
  `FORCE ROW LEVEL SECURITY` is applied to every RLS-enabled table (catch-all
  migration `20260828180000_force_rls_all_tenant_tables.sql`) so table owners
  and the planner cannot skip `USING` quals. 80+ tables, no exceptions.
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

- `WEISSMAN_REGION` env var drives the deployment region.
- `region_manager.should_process_tenant` enforces the per-tenant region match
  before any cross-region work.
- Supported regions and their regulatory scope:

| Region code | Location | Regulatory framework |
|---|---|---|
| `IL` | Israel | Bank of Israel Directive 361; Israeli Privacy Protection Law 5741-1981 (as amended 2023) |
| `EU-West` | Ireland (AWS eu-west-1) | GDPR, EBA Cloud Outsourcing Guidelines |
| `US-East` | Virginia (AWS us-east-1) | SOC 2 Type II, NIST SP 800-53 |
| `AU-East` | Sydney (AWS ap-southeast-2) | Australian Privacy Act 1988 |

- **Default for Israeli financial-sector customers: `IL`.**
- Self-hosted: data never leaves customer infrastructure regardless of region setting.

## 3a. Israeli regulatory compliance

### Bank of Israel Directive 361 (ניהול תקין 361)
Full control mapping: [`docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md`](docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md).

Summary of key controls:
- **Cyber risk management:** 565 production engines mapped to MITRE ATT&CK (14/14 tactics)
- **Tenant isolation:** PostgreSQL RLS on 80+ tables, enforced at DB level
- **Incident response:** SEV-1 ≤ 15 minutes, 24/7 on-call (see `SLA_AND_STATUS.md`)
- **DR / BCP:** RTO ≤ 4h, RPO ≤ 1h, PITR backups, restore-verify every 48h
- **Audit trail:** every write → `audit_logs`; every AI query → `nl_query_audit`
- **RBAC + MFA:** 5-level RBAC, TOTP MFA enforceable per-tenant
- **Supplier contract:** DPA + MSA with audit-rights clause

### Israeli Privacy Protection Law 5741-1981 (as amended 2023)
- Per-tenant data minimization and retention policies enforced at application layer.
- DPA (`deploy/public/dpa.html`) incorporates obligations under the amended law.
- Data processed exclusively in Israel (`region = IL`) for Israeli customers.
- Separate Hebrew DPA (`deploy/public/dpa.html`) covers local requirements.
- **Sensitive data handling:** financial-sector customer data is classified as sensitive; access is logged and restricted to `operator` role and above.

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
  Production DSNs must use `weissman_app` / `weissman_auth` / `weissman_ro`
  (never the superuser) for runtime SQLx.
  Pre-auth Axum rate limiting (`login_rate_limit_middleware`) sits **outside**
  `auth_guard` and checks the in-process governor before any Redis or Postgres
  I/O, so a password-spray cannot exhaust the dedicated `weissman_auth` pool
  (`/api/login`, `/api/auth/mfa/verify`, `/api/auth/refresh`).

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
  on the deployment platform); MFA TOTP seeds and SOAR integration credentials
  are additionally encrypted at the application layer with an AES-256-GCM
  envelope (`fingerprint_engine/src/soar/integrations_vault.rs`, applied to MFA
  via `auth_mfa::encrypt_secret_at_rest` / `decrypt_secret_at_rest`), keyed by a
  dedicated vault key (`WEISSMAN_INTEGRATIONS_VAULT_KEY` / `WEISSMAN_VAULT_KEY`).
  Production **fails closed** at startup when no key material is present (never
  silently stores plaintext), and a previous-key ring (`WEISSMAN_VAULT_KEY_PREVIOUS`
  plus the existing `WEISSMAN_JWT_SECRET_PREVIOUS` rotation keyring) keeps
  already-encrypted secrets readable across key rotation.
  After boot the process loads vault keys into `zeroize::Zeroizing` heap
  containers (env `String` copies and hex-decode buffers are overwritten on
  `Drop`), then wipes `WEISSMAN_VAULT_KEY` and
  `WEISSMAN_INTEGRATIONS_VAULT_KEY` from the environment so a
  `/proc/self/environ` or leftover-heap leak cannot recover the raw key material.

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

### Israeli regulated entities
- **Bank of Israel Directive 361:** full control mapping in
  [`docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md`](docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md).
- **Israeli Privacy Protection Law 5741-1981 (as amended 2023):** data
  processed in `IL` region; DPA covers local obligations.
- **SLA for financial sector:** 99.95% availability, SEV-1 ≤ 15 min,
  24/7 on-call. See [`SLA_AND_STATUS.md`](SLA_AND_STATUS.md).

## 12. Evidence references (in this repository)

| Concern | Implementation |
|---------|----------------|
| Full audit gate G1–G7 | `scripts/full_audit_gate.sh` |
| Auditor evidence pack (JSON + PDF) | `scripts/generate_audit_evidence_pack.sh` |
| Bank of Israel Directive 361 mapping | `docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md` |
| Enterprise onboarding guide | `docs/ENTERPRISE-ONBOARDING.md` |
| SLA (99.95%, SEV-1 ≤ 15 min, 24/7) | `SLA_AND_STATUS.md` |
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
