# Weissman Cybersecurity — SIG / CAIQ Preparation Q&A

Last updated: 2026-07-05 (559 engines, JWT ≥48 chars production minimum)

This is a practical response bank for SIG / CAIQ-style customer security
questionnaires. Answers reflect repository-implemented controls; finalise with
your legal / compliance owners before external submission.

## Governance

### Q1. Do you maintain security policies and control ownership?
**Answer:** The platform maintains security controls at code, database, and
infrastructure layers (auth, RBAC, RLS, audit, encryption, rate-limiting,
regional processing, no-transaction migration safety). Customer-facing
policies (incident response SLA, BCP/DR) are operator-owned and map onto
these technical controls.

### Q2. Do you provide third-party certifications (SOC 2, ISO 27001)?
**Answer:** This repository documents the technical control implementation. It
does not constitute a certification report; certification status is declared
by the operating entity. Automated evidence for auditors is produced by
`scripts/generate_audit_evidence_pack.sh` (wiring audits, SBOM hash, NIST/SOC2
framework mapping) and validated by `bash scripts/full_audit_gate.sh`.

### Q2b. How many security engines are production-wired?
**Answer:** **559** engines in `PRODUCTION_ENGINE_IDS`, mirrored in the frontend
catalog (`enginesRegistry.js`). CI gate `verify_engine_wiring.mjs` enforces
zero gaps; `engine_reality_audit.mjs` reports **0 no_path**. Breakdown: 301
real_probe, 212 alias, 46 agent_required. Command Center exposes **112 routes**
with live API evidence banners (`weissman-ui-audit.mjs`).

## Data security & privacy

### Q3. How is tenant data isolated?
**Answer:** Every multi-tenant table carries `tenant_id NOT NULL` and **forced
PostgreSQL Row-Level Security** with the policy `tenant_id =
current_setting('app.current_tenant_id', true)::bigint`. The application sets
the GUC at the start of every tenant-scoped transaction via
`weissman_db::begin_tenant_tx`. Cross-tenant queries are physically blocked
by Postgres regardless of application bugs.

### Q4. Is data residency supported?
**Answer:** Yes. `WEISSMAN_REGION` env var drives the deployment region and
`region_manager.should_process_tenant` enforces per-tenant region matching.
Cloud SaaS default: EU-West (Ireland). Self-hosted: data never leaves
customer infrastructure.

### Q5. How are retention periods handled?
**Answer:** Configurable per data class:
`WEISSMAN_INTEL_EPHEMERAL_RETENTION_DAYS` (7), `…DYNAMIC…` (30),
`WEISSMAN_ASYNC_JOB_RETENTION_DAYS` (14), `WEISSMAN_BACKUP_RETENTION_DAYS`
(30). UEBA agent samples are purged hourly when older than 14 days.

### Q6. Can customer data actions be audited?
**Answer:** Yes. `audit_logs` records `(tenant_id, user_id, user_label,
action_type, details, ip_address, created_at)` for every authenticated write.
`/api/ask` queries land in `nl_query_audit` (question + compiled SQL + rows +
ms). Both are append-only by application convention.

## Identity and access management

### Q7. What RBAC roles are supported?
**Answer:** Five ordered roles plus a flag:
`viewer < analyst < operator < admin < ceo` + `is_superadmin` (boolean for
cross-tenant CEO operations). Enforced by the `rbac` module and middleware
`ceo_rbac_middleware`.

### Q8. Is MFA supported?
**Answer:** Yes. TOTP-based MFA implemented in `auth_mfa.rs` (`totp-rs`).
Per-tenant policy `system_configs.mfa_required` forces enrollment;
non-enrolled logins return `403 mfa_enrollment_required`.

### Q9. Is SSO supported?
**Answer:** Yes. OIDC (PKCE + id-token verification, `oidc_auth.rs`) and
SAML (signed assertions, JIT provisioning, `saml_auth.rs`). Configured
per tenant.

### Q10. How are passwords handled?
**Answer:** Stored as bcrypt (cost-12) hashes. Self-serve signup enforces a
12-char minimum with character-class diversity. No plaintext at rest. No
password retrieval — only reset via verified email. Production JWT signing
requires `WEISSMAN_JWT_SECRET` of **at least 48 characters**; weak known values
are refused at boot (`security_startup.rs`).

### Q11. How is read-only access enforced for NL queries?
**Answer:** A dedicated Postgres role `weissman_ro` has SELECT-only grants on
13 whitelisted tables, `statement_timeout=15s`,
`idle_in_transaction_session_timeout=30s`, `work_mem=32MB`. The `/api/ask`
endpoint executes the LLM-derived plan on this role. **Defense in depth:** the
NL→SQL planner validates the plan against a strict allow-list before
compilation, AND Postgres refuses non-SELECT regardless.

## Cryptography & key handling

### Q12. Are sensitive fields encrypted?
**Answer:** MFA secrets and integration credentials are encrypted via
`database_encryption.py` (Vault Transit primary, Fernet fallback). DB volume
encryption is operator-managed (LUKS / KMS at the platform layer).

### Q13. Are webhook payloads protected?
**Answer:** Outbound webhooks signed `X-Weissman-Signature: sha256=…`
(HMAC-SHA256). Inbound Paddle webhooks verified with `subtle::ct_eq`
(constant-time, timing-attack-safe).

### Q14. Are bearer token comparisons constant-time?
**Answer:** Yes. `cicd_interceptor::constant_time_str_eq` pads both inputs to
equal length and uses `subtle::ConstantTimeEq`. Length is checked
separately to avoid revealing it via response time.

## Logging, monitoring, detection

### Q15. Is security-relevant activity logged?
**Answer:** Yes. `audit_logs` for authenticated actions; `tracing` JSON output
(`WEISSMAN_LOG_FORMAT=json`) for SIEM ingestion; Prometheus metrics at
`/api/metrics`.

### Q16. Do you provide UEBA / anomaly detection?
**Answer:** Yes. Endpoint agent ships per-host metric samples
(`ueba_baseline` capability). Server runs a 7-day rolling baseline per
`(agent, metric, hour_of_week)`. `|z| > 3` fires `medium`-severity finding;
`|z| > 6` fires `high`. New-port / new-process categorical detection
included. **Strict learning window:** never fires before 24 samples in the
bucket.

### Q17. Do you provide automated response (SOAR)?
**Answer:** Yes. JSON DSL playbooks (`when {trigger} do [actions]`) with
seven actions (`set_status`, `slack_notify`, `webhook`, `http_post`,
`open_pr`, `isolate_host`, `page_oncall`). Dispatched off-transaction on
every persisted finding; full audit in `weissman_playbook_runs`.

## Application and API security

### Q18. How are API credentials stored?
**Answer:** Hashed (`api_keys.key_hash`) with prefix-based lookup
(`key_prefix`); plaintext shown to the user once at creation, never again.

### Q19. Do you implement rate limiting?
**Answer:** Yes. Per-tenant scan rate-limit middleware
(`http/tenant_scan_limit.rs`); per-tenant AI-heavy daily quota (default 50;
exceeded returns `429 + Retry-After`); webhook delivery with bounded
exponential-backoff retries.

### Q20. Is scope validation enforced for scans?
**Answer:** Yes. Every scan target is matched against the client's
`domains` / `ip_ranges` *before* the engine runs. Private IP ranges
(`10/8`, `172.16/12`, `192.168/16`, link-local) are rejected by the default
policy. Out-of-scope → `403 target outside approved tenant scope`.

## Threat intel integrity

### Q21. Where do CVE prioritisation signals come from?
**Answer:** Live mirrors of:
- **CISA Known Exploited Vulnerabilities** (`known_exploited_vulnerabilities.json`)
  refreshed every 6 hours into `kev_intel`.
- **FIRST.org EPSS** (`api.first.org/data/v1/epss`) refreshed every 12 hours
  + on-demand on each CVE-tagged finding persist.
- Every finding row carries `epss_score`, `epss_percentile`, `kev_listed`,
  `kev_known_ransomware`, `kev_due_date`.
- If either feed is unreachable, the finding lands without enrichment; we
  **never** fabricate a score.

### Q22. How is false-positive learning implemented?
**Answer:** A Bayesian-shrinkage `confidence_multiplier =
(tp+1)/(tp+fp+1)` clamped to `[0.1, 1.0]` per
`(tenant, engine, signature_hash)`. Three FALSE_POSITIVE marks on the same
signature add a row in `finding_suppressions`; subsequent detections are
silently demoted to FALSE_POSITIVE — audit trail preserved.

## Supply chain and cloud security capabilities

### Q23. Do you provide cloud compliance checks?
**Answer:** Yes. Cloud engines (AWS / Azure / GCP / serverless / K8s) cover
IAM enumeration, IAM shadow-admin paths, serverless cold-path attacks, K8s
admission-control bypass, container-registry signing.

### Q24. Do you provide software supply-chain visibility?
**Answer:** Yes. Engines cover SBOM diffing, leaked secrets across GitHub /
GitLab / PyPI / npm, typosquatting monitor, CI/CD pipeline poisoning,
signed-PR verification via the auto-heal pipeline.

## Migration safety

### Q25. How are zero-downtime DDL changes handled?
**Answer:** Migrations whose first line is `-- weissman:no-transaction` are
applied outside any transaction by the pre-runner in
`crates/weissman-db/src/no_tx_migrations.rs`. Their rows are recorded in
`_sqlx_migrations` with **SQLx-compatible SHA-384 checksums**. The standard
`sqlx::migrate!()` runner then sees them as already-applied and skips. On
re-boot, checksum drift is detected and the process **refuses to start**
rather than silently re-applying a modified file
(`NoTxMigrateError::ChecksumMismatch`). The reference example is the
`CREATE INDEX CONCURRENTLY` for `ix_async_jobs_pending` shipped in
`20260608150000_async_jobs_pending_partial_index.sql`.

## Response-use guidance

- Treat this document as a technical baseline.
- For external questionnaire submission, layer in your organisation-specific
  controls (incident-response SLA, BCP/DR governance, third-party assurance
  reports + certificate IDs, signed DPA / MSA).

## Evidence references (in this repository)

| Concern | Implementation |
|---------|----------------|
| Tenant isolation + RLS | `crates/weissman-db/src/lib.rs` |
| Audit trail | `fingerprint_engine/src/audit_log.rs` |
| RBAC | `fingerprint_engine/src/rbac.rs` + `http/ceo_rbac.rs` |
| MFA | `fingerprint_engine/src/auth_mfa.rs` |
| OIDC / SAML | `fingerprint_engine/src/oidc_auth.rs`, `saml_auth.rs` |
| Scope validation | `fingerprint_engine/src/security_hardening.rs`, `scan_routing.rs` |
| KEV mirror | `fingerprint_engine/src/intel_kev.rs` |
| EPSS client | `fingerprint_engine/src/intel_epss.rs` |
| FP/TP feedback + suppressions | `fingerprint_engine/src/fp_feedback.rs` |
| Finding cluster dedup | `fingerprint_engine/src/findings_correlator.rs` |
| FAIR-aligned financial risk | `fingerprint_engine/src/financial_risk.rs` |
| NL → safe SQL | `fingerprint_engine/src/nl_query.rs` |
| UEBA detector + agent baseline | `fingerprint_engine/src/ueba_detector.rs` + `crates/weissman-agent/src/detections/baseline.rs` |
| SOAR playbooks | `fingerprint_engine/src/soar_playbook.rs` |
| Attack-path BFS | `fingerprint_engine/src/attack_path.rs` |
| Constant-time bearer comparison | `fingerprint_engine/src/cicd_interceptor.rs` |
| Rate limiting | `fingerprint_engine/src/http/tenant_scan_limit.rs` |
| Data retention | `fingerprint_engine/src/data_retention.rs` |
| Webhook HMAC verify | `fingerprint_engine/src/billing/webhook.rs` |
| No-transaction migration runner | `crates/weissman-db/src/no_tx_migrations.rs` |
| Full audit gate | `scripts/full_audit_gate.sh` |
| Evidence pack generator | `scripts/generate_audit_evidence_pack.sh` |
| Production .env template | `PRODUCTION.env.template` |
