# Weissman-cybersecurity — SLA & Service Status Policy

Last updated: 2026-06-01

## 1) Availability objective

- Target monthly uptime for production service: **99.9%**.
- Availability is measured monthly as:
  - `((total minutes - unavailable minutes) / total minutes) * 100`

## 2) What is considered unavailable

- Unavailable means core customer-facing capability cannot be used in production (for example: API, job orchestration, or dashboard access failures).
- Planned maintenance windows that were announced in advance are excluded.
- Outages caused by customer-side infrastructure, customer misconfiguration, or third-party force majeure are excluded.

## 3) Service credits (if objective is missed)

- If monthly availability is below **99.9%** and above or equal to **99.0%**: eligible credit is **10%** of the affected monthly subscription fee.
- If monthly availability is below **99.0%**: eligible credit is **25%** of the affected monthly subscription fee.
- Credits are applied to future invoices and are not cash refunds.

## 4) Incident communication and status transparency

- Public service status endpoint: **`/status`**.
- Current status page includes:
  - Redis health check result
  - Last completed run timestamp (from `ReportRunModel`)
  - Harvester freshness signals (mtime/count)
- Incident updates and maintenance notices are communicated via operational channels and reflected in status reporting.

## 5) Support and response baseline

- Security-impacting incidents are triaged with highest priority.
- Initial response target for critical production incidents: within **4 business hours**.
- Post-incident review includes root-cause summary and corrective actions.

## 6) Scope and legal note

- This document defines a baseline service policy for enterprise procurement and onboarding.
- Final contractual SLA terms are governed by the signed customer agreement (MSA/SOW/DPA where applicable).
