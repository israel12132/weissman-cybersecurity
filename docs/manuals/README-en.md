# Weissman Cybersecurity — Instruction Manuals (English)

**Version:** 2026-06-20  
**Audience:** Sales engineers, SOC operators, platform administrators, customer success, procurement reviewers

This directory is the **official delivery documentation pack** for Weissman Cybersecurity. Each topic is a standalone file. Read the index below and open only what you need.

---

## How to use this pack

| Role | Start here | Then |
|------|------------|------|
| **Sales / pre-sales** | [00-sales-delivery-readiness](en/00-sales-delivery-readiness.md) | [01-platform-overview](en/01-platform-overview.md), [08-billing-multitenancy](en/08-billing-multitenancy.md) |
| **DevOps / SRE** | [02-installation-docker](en/02-installation-docker.md) | [05-production-security](en/05-production-security.md), [16-operations-monitoring](en/16-operations-monitoring.md) |
| **SOC analyst** | [09-client-onboarding](en/09-client-onboarding.md) | [10-scans-engines-jobs](en/10-scans-engines-jobs.md), [11-findings-reports](en/11-findings-reports.md) |
| **Endpoint team** | [12-endpoint-agent](en/12-endpoint-agent.md) | [10-scans-engines-jobs](en/10-scans-engines-jobs.md) |
| **Security reviewer** | [05-production-security](en/05-production-security.md) | Root: `SECURITY_AND_COMPLIANCE.md`, `SIG_CAIQ_PREP_QA.md` |
| **QA / acceptance** | [18-qa-verification](en/18-qa-verification.md) | [17-troubleshooting](en/17-troubleshooting.md) |

---

## Manual index (English)

| # | File | What it covers |
|---|------|----------------|
| 00 | [00-sales-delivery-readiness.md](en/00-sales-delivery-readiness.md) | Sales completeness audit, gaps, customer deliverables checklist |
| 01 | [01-platform-overview.md](en/01-platform-overview.md) | Product layers, architecture, engine reality, data flow |
| 02 | [02-installation-docker.md](en/02-installation-docker.md) | Docker Compose full stack (recommended path) |
| 03 | [03-installation-vps-systemd.md](en/03-installation-vps-systemd.md) | Bare-metal / VPS with systemd units |
| 04 | [04-installation-kubernetes.md](en/04-installation-kubernetes.md) | K8s manifests, secrets, ingress |
| 05 | [05-production-security.md](en/05-production-security.md) | Hardening, secrets, cookies, destructive actions, startup guards |
| 06 | [06-environment-configuration.md](en/06-environment-configuration.md) | `.env`, `PRODUCTION.env.template`, key variables |
| 07 | [07-authentication-rbac-mfa.md](en/07-authentication-rbac-mfa.md) | Login, roles, MFA, sessions, audit |
| 08 | [08-billing-multitenancy.md](en/08-billing-multitenancy.md) | Tenants, Paddle, quotas, plans |
| 09 | [09-client-onboarding.md](en/09-client-onboarding.md) | Authorized scope, ROE, first scan, emergency procedures |
| 10 | [10-scans-engines-jobs.md](en/10-scans-engines-jobs.md) | Engines, Command Center hubs, jobs, schedules, agent gates |
| 11 | [11-findings-reports.md](en/11-findings-reports.md) | Triage, status workflow, PDF/CSV, crypto proof |
| 12 | [12-endpoint-agent.md](en/12-endpoint-agent.md) | Agent install, token, detections, fleet status |
| 13 | [13-integrations-cicd.md](en/13-integrations-cicd.md) | Webhooks, CI/CD, intel feeds, OAST |
| 14 | [14-sso-identity.md](en/14-sso-identity.md) | OIDC, SAML, SSO dashboard |
| 15 | [15-alerting-soar-ai.md](en/15-alerting-soar-ai.md) | Alert rules, playbooks, Council, General Mission |
| 16 | [16-operations-monitoring.md](en/16-operations-monitoring.md) | Metrics, Prometheus, backups, retention |
| 17 | [17-troubleshooting.md](en/17-troubleshooting.md) | Common failures and fixes |
| 18 | [18-qa-verification.md](en/18-qa-verification.md) | Pre-delivery test checklist, scripts |

### Command Center system book (boards + all engines)

| Book | Description |
|------|-------------|
| [WEISSMAN-COMMAND-CENTER-BOOK-en.md](en/WEISSMAN-COMMAND-CENTER-BOOK-en.md) | **Full operations book** — TOC, every board, workflows, 533 engines |
| [WEISSMAN-COMMAND-CENTER-BOOK.md](../he/WEISSMAN-COMMAND-CENTER-BOOK.md) | Same book in Hebrew |

---

## Related repository documents

| Document | Location |
|----------|----------|
| Quick start (legacy) | `/GETTING_STARTED.md` |
| Client onboarding runbook | `/ONBOARDING_RUNBOOK.md` |
| Security & compliance | `/SECURITY_AND_COMPLIANCE.md` |
| SLA policy | `/SLA_AND_STATUS.md` |
| Architecture deep dive | `/docs/architecture.md` |
| Operations reference | `/docs/operations.md` |
| Production env template | `/PRODUCTION.env.template` |
| Legal (web) | `/deploy/public/terms.html`, `privacy.html`, `dpa.html` |
| Executive briefing (EN) | `/Weissman_Cybersecurity_Executive_Technical_Briefing.md` |

---

## Hebrew manuals

See [README-he.md](README-he.md) — same structure, full Hebrew explanations.
