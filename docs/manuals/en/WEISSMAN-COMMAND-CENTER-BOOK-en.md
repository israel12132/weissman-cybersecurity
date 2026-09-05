<div dir="ltr">

# Weissman Command Center — System Operations Book
### Complete guide: every board, workflow, and 573 security engine IDs

**Version:** 2026-06-20  
**Base path:** `https://<host>/command-center/`

---

## Table of Contents

### Part A — Foundations
1. [How to use this book](#1-how-to-use-this-book)
2. [System map](#2-system-map)
3. [Board complexity ladder (small → large)](#3-complexity-ladder)
4. [One-day workflow](#4-one-day-workflow)

### Part B — Boards by navigation group
5. [Primary (Clients, Engines, Billing…)](#5-primary)
6. [Command (Cockpit, Findings, Jobs)](#6-command)
7. [Intelligence](#7-intelligence)
8. [Operations](#8-operations)
9. [Engine hubs](#9-engine-hubs)
10. [Governance](#10-governance)
11. [Administration](#11-administration)
12. [Dynamic / per-client boards](#12-dynamic-boards)

### Part C — Engines
13. [How to run any engine](#13-running-engines)
14. [Engine types (remote / agent / alias)](#14-engine-types)
15. [573 engine IDs by group — encyclopedia](#15-engine-encyclopedia)

### Appendices
- [Appendix A — RBAC](#appendix-a)
- [Appendix B — Legend](#appendix-b)

---

## 1. How to use this book

Each **board** includes: **What** | **When** | **Why** | **Prerequisites** | **Workflow steps**.

Each **engine** in Part C: ID, MITRE, remote vs agent, target required, description.

> **Weissman rule:** No fake findings. Agent-required engines show empty state until an agent is online.

---

## 2. System map

```
Login → Cockpit (/) → Select client → Run engine / scan
              ↓
       Jobs → Findings → Report (PDF/CSV)
              ↓
   Engine hubs (JWT, IAC, Cloud…) or /engines matrix
```

---

## 3. Complexity ladder

| Level | Examples | Purpose |
|-------|----------|---------|
| 0 | Login, Status | Access, health |
| 1 | Rate Limits, Metrics | KPIs |
| 2 | Clients, Jobs, Findings | Lists + triage |
| 3 | JWT Lab, Email Posture | Single-engine hub |
| 4 | Supply Chain, OT-ICS, Cloud | Multi-engine hub |
| 5 | Cockpit, CEO | Strategic overview |

---

## 4. One-day workflow

1. Login → `/command-center/login`
2. Clients → create with **authorized domains**
3. Client Detail → **Launch Scan**
4. Jobs → wait for `completed`
5. Findings → triage by severity
6. Report → PDF for customer

---

## 5. Primary

### `/clients` — Client list
**What:** Organizations and authorized scope. **When:** Before every scan. **Needs:** `operator+`, active billing (production).

**Workflow:** Clients → Add → domains (one per line) → Create.

### `/clients/:id` — Client detail
Launch Scan, Configure engines/ROE, View Findings, Generate Report. Sub-routes: Engagements, Evidence Vault, SaaS-IDP Discovery.

### `/engines` — Engine matrix (573 engine IDs)
Filter by group → open engine → Run from Engine Detail.

### `/engines/:engineId` — Single engine profile
History, Run, Export. Agent gate if `agent_required`.

### `/billing` — Paddle subscription & quota  
### `/playbooks` — SOAR when/do rules  
### `/ask` — NL→SQL (read-only, audited)  
### `/vuln-intel` — CVE / KEV / EPSS context  

---

## 6. Command

### `/` — Cockpit
Home KPIs, SSE telemetry, client selector.

### `/findings` — All findings
Filter → status workflow: OPEN → ACKNOWLEDGED → IN_PROGRESS → FIXED / FALSE_POSITIVE.

### `/jobs` — Async job queue
Monitor queued → running → completed/failed.

---

## 7. Intelligence

| Path | Purpose |
|------|---------|
| `/threat-intel` | Feeds, ingest jobs |
| `/threat-hunting` | Hypothesis-driven search |
| `/threat-analysis` | Correlation |
| `/dark-web` | Leak monitoring |
| `/intel-map` | Geo/network intel map |
| `/incident-response` | SOC incidents |
| `/zero-day-radar` | Threat intel run job |

---

## 8. Operations

| Path | Engine / API | Notes |
|------|--------------|-------|
| `/threat-emulation` | `threat_emulation` | APT scenarios |
| `/kill-chain` | kill chain orchestrator | |
| `/council-queue` | HITL → `council_debate` | Needs LLM |
| `/roe-approvals` | ROE overrides | |
| `/remediation` | auto-heal | Destructive confirm header |
| `/agents` | endpoint fleet | Required for agent engines |
| `/nexus-swarm` | `nexus_sovereign_swarm` | |
| `/timing-profiler` | `POST /api/timing-scan/run` | |
| `/ai-arena` | `POST /api/ai-redteam/run` | |

---

## 9. Engine hubs

Each hub: select **client** → **Run Scan** → `POST /api/command-center/scan` → monitor **Jobs**.

| Path | Primary engine |
|------|----------------|
| `/attack-surface` | `asm` |
| `/cloud-posture` | `cloud_posture` |
| `/iac-security` | `iac_misconfig` |
| `/graphql-security` | `graphql_attack` |
| `/jwt-lab` | `jwt_attack` |
| `/identity-security` | `oauth_oidc` |
| `/supply-chain` | 5 engines (cards) |
| `/ot-ics` | OT cards (Modbus, BACnet…) |
| `/social-engineering` | `spear_phishing` |
| … | See Hebrew book for full table |

---

## 10. Governance

`/compliance`, `/sbom`, `/risk-graph`, `/baseline-drift`, `/rate-limits`, `/alert-rules`, `/containment-rules`, `/scan-scheduler` (cron + bulk billing).

---

## 11. Administration

`/integrations`, `/sso-config`, `/engine-management`, `/system-config`, `/metrics`, `/admin`, `/ceo`, `/ceo-vault`, `/audit-log`.

---

## 12. Dynamic boards

`/report/:clientId`, `/attack-surface-graph/:clientId`, `/attack-chain/:clientId`, `/cicd-matrix/:clientId`, etc.

---

## 13. Running engines

| Method | Where | API |
|--------|-------|-----|
| A | Engine Detail / Hub | `POST /api/command-center/scan` |
| B | Client Launch Scan | all enabled engines |
| C | Schedules | cron worker |

**Before run:** client scope, billing quota, agent if required, valid target, ROE mode.

---

## 14. Engine types

| Kind | Remote? | Action |
|------|---------|--------|
| `real_probe` | Yes | Run immediately |
| `agent_required` | No | Enroll agent first |
| `alias` | Depends | Same as canonical |
| `special` | Job path | Async job |

`GET /api/engines/capabilities`

---

## 15. Engine encyclopedia

See generated appendix below (562 engines, 14 groups).

---

## Appendix A — RBAC

viewer < analyst < operator < admin < ceo (+ superadmin). Login: `POST /api/login`.

---

## Appendix B — Legend

| Symbol | Meaning |
|--------|---------|
| ✓ Remote | Probe from server |
| **Agent** | Endpoint agent required |
| Target yes | Domain/URL required |

---

*The live engine catalog is [`_engines-appendix-generated-en.md`](./_engines-appendix-generated-en.md), generated by `node scripts/generate_system_book_engines.mjs`.*

</div>
