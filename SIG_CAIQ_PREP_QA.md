# Weissman-cybersecurity — SIG/CAIQ Preparation Q&A

Last updated: 2026-06-01

This is a practical response bank for customer security questionnaires (SIG/CAIQ-style). Answers reflect repository-implemented controls and should be finalized with legal/compliance owners before external submission.

## Governance & program

### Q1. Do you maintain security policies and control ownership?
**Answer:** The platform maintains security control implementation at code and infrastructure levels (authentication, authorization, auditability, encryption hooks, rate limiting, and regional processing controls). Formal policy artifacts should be maintained by the operating organization and mapped to these technical controls.

### Q2. Do you provide third-party certifications (SOC 2, ISO 27001)?
**Answer:** This repository currently documents technical controls and security architecture. It does not itself constitute a certification report. Any certification status should be declared by the operating entity and its external auditor.

## Data security & privacy

### Q3. How is tenant data isolated?
**Answer:** Tenant-aware schema design is used across core entities through `tenant_id` fields, and role/tenant access patterns are implemented in the platform data model.

### Q4. Is data residency supported?
**Answer:** Yes. Regional processing constraints are supported via `WEISSMAN_REGION` and region matching logic (`should_process_tenant` / `region_matches`) to enforce deployment-region handling.

### Q5. How are retention periods handled?
**Answer:** Retention is configurable through environment variables for multiple data classes (ephemeral intel, dynamic intel, async jobs, and backups). Retention display wiring is also available for trust/compliance presentation.

### Q6. Can customer data changes and actions be audited?
**Answer:** Yes. Immutable audit logging is implemented through `system_audit_logs`, including timestamp, user, IP, action, and JSON details.

## Identity and access management

### Q7. What RBAC roles are supported?
**Answer:** `super_admin`, `security_analyst`, and `viewer`, with explicit role hierarchy logic.

### Q8. Is MFA supported?
**Answer:** Yes. TOTP-based MFA support is implemented (`pyotp` model with user MFA fields).

### Q9. Is SSO supported?
**Answer:** The data model includes SSO mapping fields (`sso_provider`, `sso_id`) and supports enterprise integration paths for IdP-linked users.

### Q10. How are passwords handled?
**Answer:** Password complexity validation is enforced and passwords are stored as hashes (bcrypt context in enterprise auth utilities).

## Cryptography & key handling

### Q11. Are sensitive fields encrypted?
**Answer:** Sensitive-field encryption abstraction is implemented with Vault Transit primary backend and Fernet fallback for protected fields such as MFA secrets and integration/webhook secret material.

### Q12. Are webhook payloads protected against tampering?
**Answer:** Yes. Outbound webhook payloads are signed with HMAC-SHA256 in `X-Weissman-Signature`.

## Logging, monitoring, and detection

### Q13. Is security-relevant activity logged?
**Answer:** Yes. Audit helper functions persist structured activity logs and can publish events for operational monitoring pipelines.

### Q14. Do you support security telemetry and findings workflows?
**Answer:** Findings are persisted with lifecycle status and evidence fields; this supports triage, remediation tracking, and reporting workflows.

## Application and API security

### Q15. How are API credentials stored?
**Answer:** API keys are stored as cryptographic hashes with prefix-based lookup for operational use.

### Q16. Do you implement rate limiting?
**Answer:** Yes. Rust HTTP layer includes tenant scan POST rate limiting, and Python services include reusable Redis-backed (with in-memory fallback) sliding-window rate limiting.

### Q17. Is webhook delivery resilient?
**Answer:** Yes. Webhook delivery includes bounded retries and exponential backoff behavior.

## Supply chain and cloud security capabilities

### Q18. Do you provide cloud compliance checks?
**Answer:** Cloud security/compliance engines are implemented (e.g., CSPM checks and cloud asset discovery) with compliance issue detection and reporting logic.

### Q19. Do you provide software supply-chain visibility?
**Answer:** Yes. Supply-chain analysis capabilities include dependency and license-compliance checks with related reporting.

## Response-use guidance

- Treat this document as a technical baseline response set.
- For external questionnaire submission, add organization-specific controls:
  - Incident response SLAs
  - Business continuity / disaster recovery governance
  - Third-party assurance reports and certificate IDs
  - Legal commitments (DPA/MSA/privacy notice)

## Evidence references

- `/tmp/workspace/israel12132/weissman-cybersecurity/src/database.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/src/audit.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/src/region_manager.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/src/auth_enterprise.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/src/database_encryption.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/src/webhooks.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/src/rate_limiter.py`
- `/tmp/workspace/israel12132/weissman-cybersecurity/fingerprint_engine/src/http/tenant_scan_limit.rs`
- `/tmp/workspace/israel12132/weissman-cybersecurity/fingerprint_engine/src/data_retention.rs`
- `/tmp/workspace/israel12132/weissman-cybersecurity/PRODUCTION.env.template`
