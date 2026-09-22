# Weissman-cybersecurity — SLA & Service Status Policy

Last updated: 2026-08-18

## 1) Availability objective

The availability target is **tied to the deployed reference architecture** — the two are contracted together, because a single-node deployment cannot arithmetically meet a 99.95% budget.

| Deployment tier | Reference architecture | Monthly uptime target | Max downtime/month |
|---|---|---|---|
| **Enterprise HA** (required for the 99.95% SLA) | Kubernetes app tier with ≥2 backend/worker replicas + anti-affinity + HPA + PDB; **replicated** managed PostgreSQL (CloudNativePG or managed service) with a hot standby and automated failover; Redis with failover; continuous PITR backups (see `docs/operations/ENCRYPTED-DR-PITR.md`) | **99.95%** | **21.9 minutes** |
| **Standard** (single-node Docker Compose quickstart) | One Postgres, one Redis, one backend/worker on a single host; logical (pg_dump) backups | **99.5% best-effort** (not the 99.95% SLA) | ~3.6 hours |

- The **99.95%** figure applies **only** to the Enterprise HA reference architecture above. The single-host `docker-compose.prod.yml` quickstart is explicitly **not** covered by the 99.95% target; use the Kubernetes/CNPG stack for any account under an availability SLA.
- Availability is measured monthly as `((total minutes - unavailable minutes) / total minutes) * 100`.
- The exact reference architecture the SLA is measured against is named in the signed Order Form.

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

- **On-call coverage** and the contracted response window for your plan are specified in the Order Form. 24×7×365 coverage is offered on Enterprise plans and is backed by a staffed on-call rotation (minimum two qualified responders) and escalation contacts named in the Order Form; do not rely on 24×7 response for a plan whose Order Form does not state it.
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
- While the production origin cannot answer (restart, rebuild, migration, host outage), every layer in front of it — the nginx gateway, VPS nginx/Caddy, the Kubernetes ingress default backend, the Cloudflare edge Worker and the Command Center itself — serves the branded Weissman continuity page as **HTTP 503 with `Retry-After: 30`** (never a browser, nginx or Cloudflare error), in English and Hebrew, with a JSON body for API clients. The page re-checks `/api/health` and returns visitors to their original URL automatically; it shows the `/status` link, the standard maintenance window and the contact address weissmancybersecurity@gmail.com. Runbook: `docs/operations/MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD.md`.

## 6) Data residency & regions

Data residency is achieved by **where the instance is deployed**, not by an application-layer routing flag. Each customer instance runs in one region and its data stays there; residency across regions means a separate, independently-deployed instance — Weissman does not run a single cross-region cluster that silently moves data between the locations below.

| Region code | Location | Regulatory relevance |
|---|---|---|
| `IL` | Israel | Bank of Israel Directive 361, Israeli Privacy Protection Law 5741-1981 (as amended 2023) |
| `EU-West` | Ireland (AWS eu-west-1) | GDPR, EBA Cloud Guidelines |
| `US-East` | Virginia (AWS us-east-1) | SOC 2, NIST SP 800-53 |
| `AU-East` | Sydney (AWS ap-southeast-2) | Australian Privacy Act |

- Cloud SaaS default: **`IL`** for Israeli customers; `EU-West` for EU customers. The region for your account is fixed at provisioning and stated in the Order Form.
- Self-hosted / dedicated deployments: data never leaves customer infrastructure, regardless of the `WEISSMAN_REGION` label.
- `WEISSMAN_REGION` records the deployment's region for labeling and for the LLM/AI egress guard (which fails closed on an out-of-region inference endpoint — see §on AI). It is **not** a substitute for deploying the instance in the correct region; regional separation is a deployment/infrastructure property, not an app flag.

## 7) Support and escalation

- **Primary channel:** `support@weissman.io` (ticketed; SLA clock starts on first business confirmation).
- **Emergency (SEV-1/SEV-2):** dedicated on-call phone / PagerDuty — provided in the Order Form.
- Security incidents: `security@weissman.io` (encrypted PGP key available on request).
- Dedicated Customer Success Manager (CSM) assigned for Enterprise accounts (≥ 12-month term).

## 8) Maintenance windows

- Standard maintenance window: **Sundays 02:00–04:00 Israel time (UTC+2/UTC+3)**.
- Emergency patches may be applied with **4-hour notice** for critical CVEs (CVSS ≥ 9.0).
- Zero-downtime rolling deployments are the default; blue/green switchover is used for DB migrations.
- Rebuilds and rollouts use `deploy/rebuild.sh` (build first, recreate/restart, wait for `/api/health` → 200, report how long the origin was unreachable); the continuity page in §5 covers that window automatically, with no flag and no operator step.
- Announced windows (≥ 72 h notice per §2) may additionally be flagged on the day with `deploy/maintenance/maintenance-mode.sh on --reason "…" --until <ISO-8601>`, which makes the page read "Planned maintenance" with the reason and the expected return time; `… off` ends the announcement. The flag is optional and off by default.

## 9) Scope and legal note

- This document defines a baseline service policy for enterprise procurement and onboarding.
- Final contractual SLA terms are governed by the signed customer agreement (MSA/SOW/DPA where applicable).
- For regulated entities (banks, insurance, financial services) in Israel, SLA terms align with Bank of Israel Directive 361 requirements for critical outsourced services. See `docs/compliance/BANK-OF-ISRAEL-DIRECTIVE-361.md`.
