# Weissman Command Center — Platform Roadmap (B · C · D · F · G)

> Living roadmap for the product surface after **A (Design System)** and
> **E (Performance/PWA)**. Scope tags: 🟢 **FE** (frontend, done on this branch) ·
> 🟡 **FE-surface** (UI here; needs a backend endpoint to be fully live) ·
> 🔴 **BE/Infra** (backend/infra; separate branch). Status: ⬜ todo · 🚧 partial · ✅ done.

The **UI branch (design-system-ui)** completion pass is effectively done: **70
primitives**, full gallery, and 579 passing tests. Remaining ⬜/🚧 items are
FE-surface (need backend) or the explicit finish items listed at the bottom.

---

## B — Command Center & Dashboard

| # | Deliverable | Scope | Status |
|---|---|---|---|
| B1 | `Sparkline` (SVG area/line) | 🟢 | ✅ |
| B2 | `KpiStrip`/`KpiTile` (value, delta, trend, drill-down) | 🟢 | ✅ |
| B3 | AI Command Bar — `CommandBar` (⌘K) + `AiCommandConsole` (multi-turn, context, suggestions, one-click, **voice**) | 🟢 | ✅ |
| B4 | `SmartFilterBar` + `DashboardGrid` (personalized) | 🟢 | ✅ |
| B5 | `FindingDrawerV2` (timeline, attack-path, evidence, discussion) | 🟢 | ✅ |
| B6 | `RiskExplanation` (AI business-risk) | 🟡 | ✅ |
| B7 | Collaborative real-time — `CommentThread` + `PresenceStack` | 🟡 (realtime BE) | ✅ UI |

## C — Visualizations & WarRoom

| # | Deliverable | Scope | Status |
|---|---|---|---|
| C1 | `BlastRadius` + `BlastRadiusSimulator` (what-if) | 🟢 | ✅ |
| C2 | `KillChainPath` | 🟢 | ✅ |
| C3 | `MiniHeatmap` | 🟢 | ✅ |
| C4 | `SwarmMap` (live global heatmap + arcs) | 🟡 (live feed BE) | ✅ UI |
| C5 | `ReplayControls` (replay scrubber) | 🟢 | ✅ |
| C6 | `Topology3D` (Three.js 3D topology) | 🟢 | ✅ |
| — | `Timeline` | 🟢 | ✅ |

## D — Playbooks & SOAR

| # | Deliverable | Scope | Status |
|---|---|---|---|
| D1 | `NodePalette` + `PlaybookNode` (drag/click nodes) | 🟢 | ✅ |
| D2 | `DryRunSimulator` (sample-event trace) | 🟢 | ✅ |
| D3 | AI-assisted generation (via `AiCommandConsole` surface) | 🟡 (LLM BE) | 🚧 |
| D4 | `ApprovalWorkflow` + `Stepper` (versioning/approval) | 🟡 | ✅ UI |
| — | Full @xyflow drag-drop **canvas** (wire nodes) | 🟢 | ⬜ finish item |

## F — Compliance & Enterprise

| # | Deliverable | Scope | Status |
|---|---|---|---|
| F1 | `ComplianceMatrix` (ISO/SOC2/NIST/CIS) | 🟡 | ✅ UI |
| F2 | `EvidenceVault` (tamper-evident) | 🟡 | ✅ UI |
| F3 | Audit-trail export | 🟢 | ⬜ |
| F4 | `AccessPolicyEditor` (RBAC/ABAC) | 🟡 | ✅ UI |
| F5 | Compliance reporting engine | 🔴 | ⬜ |

## G — Business & Go-to-Market

| # | Deliverable | Scope | Status |
|---|---|---|---|
| G1 | `WhiteLabelStudio` (drives the brand engine) | 🟢 | ✅ |
| G2 | `UsageMeter` (billing/usage) | 🟡 | ✅ UI |
| G3 | `PartnerPortal` (MSSP shell) | 🟡 | ✅ UI |
| G4 | `MarketplaceCard` (engine marketplace) | 🟡 | ✅ UI |
| G5 | Billing backend | 🔴 | ⬜ |

## E — Performance/PWA (delivered earlier)

`useApiMutation` (optimistic) · PWA offline app-shell · DataTable virtualization ·
**Web Workers** (`useComputeWorker` + `computeStats.worker`) — all ✅.

---

## Explicit UI finish items before merge

- **Storybook** — the `/design-system` gallery is the live catalog today; Storybook
  is a heavier dev-dependency install to add on top.
- **Full @xyflow playbook canvas** — `NodePalette` + `PlaybookNode` exist; the
  drag-drop wiring canvas is the remaining piece.
- **Gallery integration of the newest ~20 primitives** (they exist + are tested;
  showcasing them all in `/design-system` is incremental).
- **Audit-trail export (F3)**.

## Out of scope for this UI branch (Phase 2 — needs own branch + approval)

Observability (OpenTelemetry/tracing/Grafana), real-time stack (WebSocket/CRDT),
AI backend (multi-LLM/RAG/agentic/self-healing), zero-day ML, engine marketplace
backend, integration hub (Splunk/Sentinel/XSOAR/Jira), endpoint agent (EDR/UEBA),
multi-region + auto-scaling K8s, DR/backup, robust billing backend, supply-chain
security + secret management.

## Working method

Build one deliverable at a time; token-based, RTL-safe, WCAG-conscious, tested
(vitest), 0 ESLint errors; commit + push immediately once green.
