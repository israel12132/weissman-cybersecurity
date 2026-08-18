# Weissman-cybersecurity — SLA & Service Status Policy

Last updated: 2026-08-18

## 1) Availability objective

- Target monthly uptime for production service: **99.95%**.
- Maximum permitted downtime per calendar month: **21.9 minutes**.
- Availability is measured monthly as:
  - `((total minutes - unavailable minutes) / total minutes) * 100`

## 2) What is considered unavailable

- Unavailable means core customer-facing capability cannot be used in production (for example: API, job orchestration, or dashboard access failures).
- Planned maintenance windows that were announced **≥72 hours in advance** are excluded.
- Outages caused by customer-side infrastructure, customer misconfiguration, or third-party force majeure are excluded.

## 3) Service credits (if objective is missed)

| Monthly availability | Credit |
|---|---|
| ≥ 99.9% and < 99.95% | **10%** of affected monthly fee |
| ≥ 99.0% and < 99.9% | **25%** of affected monthly fee |
| < 99.0% | **50%** of affected monthly fee |

- Credits are applied to future invoices and are not cash refunds.
- Credits must be claimed in writing within 30 days of the incident.

## 4) Incident severity & response targets (24/7)

| Severity | Definition | Initial response | Status update cadence |
|---|---|---|---|
| **SEV-1** | Platform unreachable, tenant data breach, RCE | **≤ 15 minutes** | Every 30 minutes |
| **SEV-2** | Scans not processing, auth degraded, billing broken | **≤ 1 hour** | Every 2 hours |
| **SEV-3** | Single engine failure, UI degradation, non-critical bug | **≤ 4 business hours** | Daily |
| **SEV-4** | Question, docs, feature request | **≤ 1 business day** | Weekly |

- **On-call coverage: 24 hours / 7 days / 365 days per year** (including Israeli holidays).
- Post-incident review (PIR) delivered within **5 business days** for SEV-1/SEV-2.

## 5) Incident communication and status transparency

- Public service status endpoint: **`/status`**.
- Current status page includes:
  - Redis health check result
  - Last completed run timestamp (from `ReportRunModel`)
  - Harvester freshness signals (mtime/count)
- **SEV-1:** Customer notification within **30 minutes** of detection.
- **SEV-2:** Customer notification within **2 hours** of detection.
- Incident updates and maintenance notices are communicated via email, the `/status` endpoint, and the customer portal.

## 6) Data residency & regions

Weissman supports the following deployment regions:

| Region code | Location | Regulatory relevance |
|---|---|---|
| `IL` | Israel | Bank of Israel Directive 361, Israeli Privacy Protection Law 5741-1981 (as amended 2023) |
| `EU-West` | Ireland (AWS eu-west-1) | GDPR, EBA Cloud Guidelines |
| `US-East` | Virginia (AWS us-east-1) | SOC 2, NIST SP 800-53 |
| `AU-East` | Sydney (AWS ap-southeast-2) | Australian Privacy Act |

- Cloud SaaS default: **`IL`** for Israeli customers; `EU-West` for EU customers.
- Self-hosted deployments: data never leaves customer infrastructure.
- Region is enforced at the application layer via `WEISSMAN_REGION` and `region_manager.should_process_tenant`.

## 7) Support and escalation

- **Primary channel:** `support@weissman.io` (ticketed; SLA clock starts on first business confirmation).
- **Emergency (SEV-1/SEV-2):** dedicated on-call phone / PagerDuty — provided in the Order Form.
- Security incidents: `security@weissman.io` (encrypted PGP key available on request).
- Dedicated Customer Success Manager (CSM) assigned for Enterprise accounts (≥ 12-month term).

## 8) Maintenance windows

- Standard maintenance window: **Sundays 02:00–04:00 Israel time (UTC+2/UTC+3)**.
- Emergency patches may be applied with **4-hour notice** for critical CVEs (CVSS ≥ 9.0).
- Zero-downtime rolling deployments are the default; blue/green switchover is used for DB migrations.

## 9) Scope and legal note

- This document defines a baseline service policy for enterprise procurement and onboarding.
- Final contractual SLA terms are governed by the signed customer agreement (MSA/SOW/DPA where applicable).
- For regulated entities (banks, insurance, financial services) in Israel, SLA terms align with Bank of Israel Directive 361 requirements for critical outsourced services. See `docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md`.
