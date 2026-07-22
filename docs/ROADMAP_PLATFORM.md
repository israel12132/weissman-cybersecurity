# Weissman Command Center — Platform Roadmap (B · C · D · F · G)

> Living roadmap for the remaining product surface after **A (Design System)** and
> **E (Performance/PWA)** were delivered. Each deliverable is scoped to be
> independently shippable, tested, and committed. Items are tagged by where they
> live so scope is honest:
>
> - 🟢 **FE** — frontend, deliverable on this UI branch.
> - 🟡 **FE-surface** — UI shell here; needs a backend endpoint to be fully live.
> - 🔴 **BE/Infra** — backend/engines/infra; needs its own branch + service work.

Status legend: ⬜ todo · 🚧 in progress · ✅ done.

---

## B — Command Center & Dashboard

| # | Deliverable | Scope | Status |
|---|---|---|---|
| B1 | `Sparkline` primitive (dependency-free SVG, area/line, tooltip) | 🟢 FE | ⬜ |
| B2 | `KpiTile` + `KpiStrip` — value, delta, trend sparkline, drill-down | 🟢 FE | ⬜ |
| B3 | AI **Command Bar** (⌘K) — command registry, fuzzy + NL-style parsing, actions | 🟢 FE | ⬜ |
| B4 | `SmartFilterBar` + Saved Views UI (on `useSavedViews`) | 🟢 FE | ⬜ |
| B5 | Finding Detail Drawer v2 — timeline, attack-path, remediation, evidence gallery | 🟢 FE | ⬜ |
| B6 | AI Risk Explanation panel (business-risk narrative) | 🟡 FE-surface | ⬜ |
| B7 | Collaborative cursors / comments on findings | 🔴 BE/Infra (realtime) | ⬜ |

## C — Visualizations & WarRoom

| # | Deliverable | Scope | Status |
|---|---|---|---|
| C1 | `BlastRadius` — SLE/ALE financial exposure viz + crown jewels | 🟢 FE | ⬜ |
| C2 | `AttackPath` — interactive path finder / kill-chain (SVG/@xyflow) | 🟢 FE | ⬜ |
| C3 | `MiniHeatmap` primitive (e.g. MITRE coverage, time-of-day) | 🟢 FE | ⬜ |
| C4 | Global swarm map heatmap + live connections layer | 🟡 FE-surface | ⬜ |
| C5 | WarRoom timeline replay control | 🟡 FE-surface | ⬜ |
| C6 | 3D attack surface (Three.js) upgrade of Battlespace | 🟢 FE (heavy) | ⬜ |

## D — Playbooks & SOAR UI

| # | Deliverable | Scope | Status |
|---|---|---|---|
| D1 | PlaybookBuilder node palette + condition/branch nodes (@xyflow) | 🟢 FE | ⬜ |
| D2 | Playbook **dry-run simulator** panel (sample-event trace) | 🟢 FE | ⬜ |
| D3 | AI-assisted playbook generation entrypoint | 🟡 FE-surface | ⬜ |
| D4 | Version history + approval workflow UI | 🟡 FE-surface | ⬜ |

## F — Compliance & Enterprise (UI surfaces)

| # | Deliverable | Scope | Status |
|---|---|---|---|
| F1 | Compliance report builder UI (ISO/SOC2/NIST/CIS mapping view) | 🟡 FE-surface | ⬜ |
| F2 | Evidence Vault browser + tamper-proof badge UI | 🟡 FE-surface | ⬜ |
| F3 | Audit-trail export UI | 🟢 FE | ⬜ |
| F4 | RBAC/ABAC policy editor UI | 🟡 FE-surface | ⬜ |
| F5 | Automated compliance reporting engine | 🔴 BE | ⬜ |

## G — Business & Go-to-Market (UI surfaces)

| # | Deliverable | Scope | Status |
|---|---|---|---|
| G1 | White-label admin panel (drives the `setBrand` engine from A) | 🟢 FE | ⬜ |
| G2 | Billing / usage dashboard UI | 🟡 FE-surface | ⬜ |
| G3 | Partner Portal (MSSP) shell | 🟡 FE-surface | ⬜ |
| G4 | Engine Marketplace browse/install UI | 🟡 FE-surface | ⬜ |
| G5 | Usage-based + seat billing backend | 🔴 BE | ⬜ |

---

## Out of scope for this UI branch (need dedicated branches)

These are 🔴 BE/Infra epics — each a multi-week service effort, not appropriate
to land on a design-system/UI branch:

- Autonomous agent swarm (Threat Hunter / Remediation / Compliance / Red-Team / Self-Healing agents), long-term memory + cross-client learning, multi-LLM.
- Engine work: marketplace backend, versioning + A/B testing, OT/ICS + Cloud + AI-LLM engine expansion, zero-day/novel-attack ML, deep dark-web/infostealer ingestion.
- Endpoint agent: EDR detections, real-time response (isolate/kill), UEBA baselining.
- Native integrations: Splunk, Sentinel, Elastic, Cortex XSOAR, ServiceNow, Jira, Slack, Teams; unified SIEM/SOAR/XDR ingestion; GraphQL layer; event-driven webhooks.
- Ops: Kubernetes auto-scaling, multi-tenant isolation + cost tracking, OpenTelemetry tracing, DR/backup, blue-green/canary.

## Working method

1. Build one deliverable at a time; ship reusable, token-based, RTL-safe, a11y-correct components matching the design system.
2. Unit-test each (vitest + testing-library); 0 ESLint errors.
3. Commit + push immediately once green (resilient to environment resets).
4. Register new showcase entries in `/design-system` where useful.
5. Keep this file updated as the source of truth for progress.
