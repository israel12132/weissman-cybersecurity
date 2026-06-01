# Weissman-cybersecurity — Security & Compliance Overview

Last updated: 2026-06-01

## 1) Scope

This document summarizes the platform's current security controls and compliance-relevant architecture for customer security reviews and procurement questionnaires.

## 2) Data handling model

- The platform is multi-tenant, with tenant-level isolation fields in core entities (`tenant_id` on users, API keys, vulnerabilities, report runs, and related tables).
- Audit events are captured in an immutable audit table (`system_audit_logs`) with timestamp, user, action, IP, and JSON details.
- Finding lifecycle state is persisted (`OPEN`, `IN_PROGRESS`, `FIXED`, `FALSE_POSITIVE`) to support remediation workflows and traceability.

## 3) Data residency and regional processing

- Regional control is environment-driven via `WEISSMAN_REGION`.
- Tenant-region matching logic enforces that processing can be restricted to the deployment region (`should_process_tenant`).
- Region-aware visibility helpers are implemented for stored report/run access checks.

## 4) Identity, authentication, and authorization

- Role-based access control (RBAC) model uses three roles:
  - `super_admin`
  - `security_analyst`
  - `viewer`
- Role hierarchy logic is implemented in enterprise auth utilities.
- MFA model is based on TOTP (`pyotp`, Google Authenticator compatible) with per-user MFA fields (`mfa_secret`, `mfa_enabled`).
- Password policy enforcement includes minimum length and complexity checks.
- User model supports SSO identity mapping fields (`sso_provider`, `sso_id`) for enterprise IdP integration paths.

## 5) Cryptography and secrets

- Outbound webhooks are signed with `X-Weissman-Signature` using HMAC-SHA256.
- Sensitive database fields have an encryption abstraction (`database_encryption.py`) with Vault Transit primary path and Fernet fallback.
- The encryption module explicitly targets sensitive fields such as MFA secrets, webhook secrets, and API/integration credential material.

## 6) Retention and lifecycle controls

- Security/intel lifecycle controls are environment-configurable:
  - `WEISSMAN_INTEL_EPHEMERAL_RETENTION_DAYS`
  - `WEISSMAN_INTEL_DYNAMIC_RETENTION_DAYS`
  - `WEISSMAN_ASYNC_JOB_RETENTION_DAYS`
  - `WEISSMAN_BACKUP_RETENTION_DAYS`
- Retention presentation for trust/compliance pages is supported via `RETENTION_DAYS` template wiring.

## 7) API and abuse protection

- Public API keys are stored hashed (`api_keys.key_hash`) with prefix-based lookup (`key_prefix`).
- Per-tenant scan enqueue rate limiting exists in Rust HTTP layer (`tenant_scan_limit`).
- Python services include a reusable Redis-backed/in-memory fallback sliding-window rate limiter (`RateLimiter`) for expensive endpoints.
- Webhook delivery includes retry with exponential backoff.

## 8) Operational security logging

- Audit helper logs security-relevant actions (including login and scan/report actions) and persists to `system_audit_logs`.
- Audit events can also be published to command-center event streams for operational monitoring.

## 9) Current compliance posture (declaration)

- This document is a controls overview, not a third-party certification report.
- No claim is made here that SOC 2 Type II or ISO 27001 is already certified.
- This package is intended to accelerate customer due-diligence and security questionnaire completion.

## 10) Availability and status policy

- SLA and uptime policy are documented in:
  - `/tmp/workspace/israel12132/weissman-cybersecurity/SLA_AND_STATUS.md`
- Public runtime status endpoint:
  - `/status`

## 11) Evidence references in repository

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
