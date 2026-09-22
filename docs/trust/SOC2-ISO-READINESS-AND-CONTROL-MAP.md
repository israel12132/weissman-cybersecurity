# SOC 2 / ISO 27001 Readiness & Control Mapping

> **This is a readiness and control-mapping document — NOT an audit report or certification.**
> Weissman does not currently hold a SOC 2 Type II report or ISO 27001 certificate. This maps
> the platform's implemented controls to the SOC 2 Trust Services Criteria (TSC) and ISO 27001:2022
> Annex A themes, states the honest status of each, and defines the path to a Type I bridge and a
> Type II report. Provide this to a buyer's TPRM team **in place of** an attestation, with a dated
> remediation roadmap — never imply certification you do not hold (`docs/operations/INSPECTION-DAY-RUNBOOK.md`
> already sets that rule internally).

Last updated: 2026-09-22 · Scope: production SaaS (Enterprise HA reference architecture)

Status legend: **✅ In place** (implemented + evidence) · **◑ Partial** (implemented, needs formalization/evidence) · **○ Gap** (planned).

---

## A. SOC 2 — Common Criteria (Security) mapping

| TSC | Control | Status | Evidence in repo |
|---|---|---|---|
| CC6.1 | Logical access — RBAC, least privilege | ✅ | `fingerprint_engine/src/rbac.rs`, `ceo_rbac.rs`; DB role split `crates/weissman-db/src/role_guard.rs` |
| CC6.1 | Tenant data isolation | ✅ | Forced RLS, `NOBYPASSRLS`; live contract tests `crates/weissman-db/tests/rls_*`; `isolation_attestation.rs` |
| CC6.1 | Encryption at rest / key custody | ◑ | App-layer AES-256-GCM (`ceo/vault.rs`); **BYOK/KMS** now added (`docs/trust/` + KMS provider) — needs KMS in prod |
| CC6.1 | Encryption in transit | ✅ | TLS 1.2+ enforced `weissman-core/src/tls_policy.rs`; edge Caddy/nginx |
| CC6.1 | MFA | ◑ | TOTP `auth_mfa.rs`; **WebAuthn/FIDO2 + step-up** on roadmap (identity-access finding) |
| CC6.1 | SSO (OIDC/SAML) | ◑ | `oidc_auth.rs`; `saml_auth.rs` **hardened** (XSW/replay closed) — needs real-IdP integration test |
| CC6.6 | Boundary protection / secrets hygiene | ✅ | Fail-closed startup guards `security_startup.rs`; gitleaks + semgrep CI; env-scrub of vault keys |
| CC6.7 | Data-in-transit to sub-processors (AI egress) | ✅ | **Fail-closed LLM egress guard** (sovereign default) — `security_startup.rs` + LLM path |
| CC7.2 | Security monitoring / logging | ◑ | Structured JSON logs, Prometheus/Grafana/Tempo (`monitoring/`); **customer SIEM streaming** on roadmap |
| CC7.3 | Incident response | ◑ | Runbooks `docs/operations/INCIDENT-ONCALL-RUNBOOK.md`; needs breach-notification SLA + PIR evidence trail |
| CC7.1 | Vulnerability management | ✅ | cargo-audit, `deny.toml`, renovate, Trivy, DAST in CI |
| CC8.1 | Change management | ◑ | PR review + CI gates; **four-eyes branch protection** required (see viability doc) |
| CC1.x | Governance / org | ○ | Single maintainer — see `docs/trust/VENDOR-VIABILITY-AND-GOVERNANCE.md`; needs policies + org |
| CC9.x | Vendor/sub-processor risk | ◑ | `deploy/public/subprocessors.html`; resolve either/or vendors + list LLM providers |

## B. SOC 2 — additional categories

| Category | Status | Notes / evidence |
|---|---|---|
| **Availability** | ◑ | SLA tiered to HA reference architecture (`SLA_AND_STATUS.md`); PgBouncer wired; DR/PITR `docs/operations/ENCRYPTED-DR-PITR.md`. Gap: published uptime history, tested failover evidence |
| **Confidentiality** | ✅ | RLS + at-rest encryption + BYOK; retention env-driven (`data_retention.rs`) — enforce & evidence retention |
| **Processing Integrity** | ✅ | Deterministic scoring (randomness lock-out), migration checksums, honesty ratchets, no-fabricated-score policy |
| **Privacy** | ◑ | DPA + privacy pages (softened to match reality); **GDPR DSR (erasure/portability)** implementation tracked in `docs/trust/DATA-LIFECYCLE-AND-DSR.md` |

## C. ISO 27001:2022 Annex A themes (summary)

- **Organizational (A.5):** policies partial; supplier/sub-processor management partial; needs ISMS scope + risk treatment plan. ○/◑
- **People (A.6):** NDAs + training claimed — formalize evidence; onboarding/offboarding for the second engineer. ◑
- **Physical (A.7):** cloud-provider inherited (AWS) — document shared-responsibility. ◑
- **Technological (A.8):** strong — access control, crypto, logging, secure development, vulnerability mgmt, network security all have implementations above. ✅/◑

---

## D. Path to attestation (dated roadmap)

1. **Now → 30 days:** stand up the Trust Center (`docs/trust/TRUST-CENTER.md`), close the honesty gaps
   (done: SLA tiering, FIPS wording, DPA/pen-test language, LLM egress guard), define ISMS scope,
   pick an auditor (licensed CPA firm for SOC 2; accredited body for ISO 27001).
2. **30 → 90 days:** SOC 2 **Type I** (design of controls at a point in time) as a bridge; write the
   missing policies (access control, IR, change mgmt, vendor mgmt, BCP); enable four-eyes branch protection;
   bind insurance; execute escrow.
3. **90 days → ~12 months:** SOC 2 **Type II** observation window (operating effectiveness over 3–12 months);
   in parallel, ISO 27001:2022 certification if buyers require it.
4. **Continuous:** feed evidence into a trust portal (SafeBase/Vanta/Drata/Whistic) so buyers self-serve
   the report + sub-processor list + status under NDA.

**Interim buyer artifact:** this document + a Type I / readiness-assessment letter + the security-controls
overview (`SECURITY_AND_COMPLIANCE.md`). Do not present a self-generated evidence pack as third-party assurance.
