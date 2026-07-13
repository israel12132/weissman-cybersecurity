# CISO Intelligence API

A single, evidence-backed decision layer that turns raw findings into a board-ready
program: **what to fix first, by when, at what business cost, against which frameworks,
and how exposed we are.** Every score below is **deterministic** — computed from live
rows with no model calls — so the number a CISO reads always matches the queue behind it.

All endpoints are:

- **Read-only** and **tenant-isolated** — each runs inside a tenant transaction, so
  Postgres RLS scopes every row to the caller's tenant.
- **Client-scoped** — `:client_id` in the path; `?limit=N` (default 2000, clamped 1–5000)
  bounds how many findings are considered.
- Backed by the same open-finding set: `status NOT IN ('FIXED','FALSE_POSITIVE','VERIFIED_FIXED')`.

Shared foundation: `remediation_priority::load_findings` loads findings once, joined to
`risk_graph_nodes` for choke-point / crown-jewel / asset-value / business-value flags. The
posture, projection, SLA-forecast and executive-summary engines all consume that one loader,
so they can never disagree.

---

## GET /api/remediation/priority/:client_id

The **fix-first program**: findings collapsed to root-cause *actions* and ranked.

Grouping key: correlation `cluster_id` → else `CWE + asset` → else the finding itself.
So findings sharing one fix become one action, and the program ranks actions, not symptoms.

Per-action priority (0–100), deterministic:

- base = `max(effective_risk) × 10` (effective_risk already folds in EPSS + CISA KEV)
- `× 1.25` if any finding sits on an attack-path **choke point**
- `× 1.30` if the asset is a **crown jewel**; `×` clamped **asset_value** (0.25–3.0)
- `+ 1.5` per extra finding the one fix closes (capped `+15`)
- floors: **KEV ≥ 85**, **ransomware-KEV ≥ 95** (a known-exploited medium outranks a theoretical critical)

Each action also carries its **SLA** (below), the **compliance controls** its fix satisfies,
`business_value_usd` (max blast radius in the group), and a plain-language `rationale`.

Summary fields: `remediation_actions`, `kev_actions`, `choke_point_actions`,
`crown_jewel_actions`, `overdue_actions`, `due_soon_actions`, `actions_mapped_to_controls`,
`compliance_frameworks`.

### Remediation SLA (per action)

Windows follow **CISA BOD 22-01** for known-exploited vulns and NIST-aligned practice otherwise:

| Tier | Window |
|------|--------|
| Ransomware-associated KEV | 7 days |
| KEV (known exploited) | 14 days |
| Critical risk (≥ 9.0) | 15 days |
| High risk (≥ 7.0) | 30 days |
| Medium risk (≥ 4.0) | 90 days |
| Low / info | 180 days |

The **oldest** finding in a group drives the clock (most conservative). State is
`overdue` / `due_soon` (within the final 20% of the window) / `on_track` / `unknown`
(age unknown → never counted as breached — we do not invent a deadline).

---

## GET /api/attack-exposure/:client_id

Live **MITRE ATT&CK exposure** — the operational counterpart to the static coverage matrix
(`/api/attack-coverage`). Answers "which techniques is this client exposed to right now?"

- Technique ids are normalised across five keys (`mitre`, `mitre_attack`, `mitre_techniques`,
  `technique`, `techniques`) and two shapes (string or array), validated to `T####[.###]`,
  and deduped per finding.
- `techniques[]`: ranked by finding count with a severity breakdown, enriched with the curated
  **name + tactic** from `attack_coverage` (exact id, then base-id fallback). Unknown-but-valid
  ids bucket as `Unmapped` — coverage is never invented.
- `tactics[]`: rollup by ATT&CK tactic (technique + finding counts).

---

## GET /api/compliance/posture/:client_id

The **auditor's inverse** of the remediation crosswalk: per framework, which controls a client's
open findings touch. Reuses the same CWE→control map (`remediation_priority::controls_for_cwe`),
so compliance and remediation never disagree.

- `frameworks[]`: **OWASP Top 10 2021** (MITRE/OWASP's own CWE→category mapping), **NIST 800-53r5**,
  **PCI DSS 4.0**, **OWASP ASVS 4.0** — each with the touched controls, per-control finding counts,
  and severity breakdown. Ordered by finding count. Unmapped CWEs contribute nothing.

---

## GET /api/posture/score/:client_id

The **board number**: a 0–100 posture score (higher = healthier) + an **A–F** grade, distilled
from the fix-first program.

Four sub-scores, each starting at 100 and losing named-constant points, blended by fixed weights:

| Sub-score | Weight | Penalises |
|-----------|--------|-----------|
| Exploitability control | 0.35 | KEV / ransomware / high effective_risk |
| Remediation timeliness | 0.30 | SLA overdue / due-soon |
| Business exposure | 0.20 | crown-jewel / choke-point actions |
| Severity load | 0.15 | critical / high-risk action volume |

**Hard caps** encode a security truth per-action penalties would dilute: any ransomware-KEV open
caps exploitability at 35; any KEV past SLA caps timeliness at 35 — so *one truly bad thing* is a
failing posture, however few. `drivers[]` explains the grade in plain language.

`projection[]` — a what-if: fixing the top-ranked actions in rank order, the score/grade you would
reach at each step (`after_fixing_rank`, `actions_fixed`, `findings_closed`, `projected_score`,
`projected_grade`, `delta`). Reuses the same `score()` on subsets, so it is exactly consistent.

---

## GET /api/remediation/sla-forecast/:client_id

**Proactive** breach forecast — get ahead of SLAs instead of only reacting.

- `overdue_now`: actions already past SLA.
- `forecast[]`: for each horizon in `[7, 14, 30, 60, 90]` days, the **cumulative** count of actions
  in breach by then (already-overdue counts in every bucket → the curve is monotonic), with
  `kev_breached`, `ransomware_breached`, `crown_jewel_breached` subsets. Unknown-age actions are
  never forecast as a breach.

---

## GET /api/executive-summary/:client_id

**Backend-for-frontend**: loads findings **once**, ranks **once**, and composes `posture`,
`projection`, `sla` (forecast + overdue), and `remediation` (counts + top-10 actions) in a single
response — so an exec dashboard costs one query instead of three-plus. Pure composition of the
engines above; no scoring lives here.

---

## Design invariants

- **One source of truth.** Every view derives from the same loaded findings + ranked program.
- **Deterministic & evidence-backed.** No model calls; identical inputs always yield identical output.
- **Never invent coverage.** Unmapped CWEs / unknown technique ids / unknown finding ages are
  reported as such, not guessed.
- **Tenant isolation.** RLS scopes every query to the caller's tenant.
