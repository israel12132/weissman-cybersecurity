# CISO competitor fusion — what they show, what we must uniquely beat

**Audience:** CISO, board risk committee, Weissman product.  
**Scope:** *Public* marketed capabilities only (vendor docs, product pages, admin guides). Not live scans of those products.  
**Legal:** authorized assessment only. Safe proofs / OAST / ROE. No exploit payloads, no weaponized PoCs.

Weissman already has the *pieces* in code: OAST/`safe_proofs`, SOAR + crown-jewel HITL, FAIR SLE/ALE, Hebrew i18n, `leak_hunter` + `darkweb_intel`, Dijkstra internet→crown-jewel paths. **No peer ships the combination as one CISO GUI + board PDF/Excel.** The live board PDF today still renders Helvetica counts + SOC2/ISO/GDPR % (`fingerprint_engine/src/pdf_report.rs`) — it does not yet *be* the fusion.

---

## How to read this matrix

A CISO capability counts only if it is **visible in the product GUI or a board PDF/Excel/CSV**, not a blog slogan. Each vendor gets **three** such capabilities.

| Symbol | Meaning |
|--------|---------|
| Path | Attack path / toxic combination toward a critical asset |
| $ | Dollar or FAIR-style quantified loss |
| Proof | Live *authorized* reachability/exploit-validation evidence (not CVSS/EPSS inference) |
| Fix | Auto-remediation executed in-product (not “open a ticket”) |
| Leak | Adversary/dark-web/stealer/credential leak intel on *your* identifiers |
| HE | Native Hebrew / RTL board artifact |

---

## Public CISO surfaces (3 each)

### Wiz (CNAPP)

1. **Executive Overview Lens** — trending cloud risks, Wiz threat-research feed, compliance posture, team/business-unit performance (role-based CISO workspace).
2. **Security Graph Issues** — toxic combinations (exposure × identity × data) as ranked attack paths to critical cloud assets; “Zero Criticals” as a board KPI.
3. **Compliance heatmaps + board pack** — 100+ frameworks (NIST, CIS, PCI, HIPAA, ISO 27001, SOC 2, GDPR, DORA, …) with drill-down failed controls; CISO board-report template (risk reduction, automation, incidents).

*Does not combine:* native FAIR ALE in the GUI, Hebrew/RTL board PDF, adversary leak intel as a first-class CISO tile, or authorized OAST-style proof packets on every hop.

### CrowdStrike Falcon

1. **Charlotte AI executive reports** — Falcon Next-Gen SIEM + Exposure Management + Cloud Security fused into a scheduled/on-demand CISO report: urgent risks on critical assets, KEV coverage, exploitability-ranked actions (PDF via Fusion SOAR).
2. **Exposure Management / ExPRT.AI console** — exploitable vulns, misconfigs, and attack paths across endpoint, cloud, identity, OT/IoT; persona workspace for the CISO.
3. **Identity Protection dashboards** — AD/Entra/Okta risk, identity attack paths, dark-web *compromised credential* monitoring, NHI risk dashboards.

*Does not combine:* FAIR SLE/ALE as the board number, Hebrew/RTL native reporting, or stored safe-proof/OAST artifacts a lawyer can attach to an assessment.

### Palo Alto Cortex / XSIAM

1. **XSIAM Command Center** — ingested data, open vs resolved cases, *automated-playbook* vs manual cases, attacks prevented, KPI trends — the SOC-exec home screen.
2. **Compliance Overview dashboard + scheduled reports** — aggregated compliance score, assets assessed, most-failed controls; any dashboard saved as a report template (PDF distribution).
3. **Causality + playbook automation** — MITRE-mapped process causality (attacker path *after* detection) and XSOAR/XSIAM playbooks for contain/eradicate; Cloud Security Operations MTTR widgets.

*Does not combine:* pre-breach internet→crown-jewel *assessment* paths with FAIR $, Hebrew board PDF, or leak-intel fusion. Causality is incident forensics, not authorized exploit-validation proof.

### Mandiant Advantage (Google)

1. **Threat Intelligence home dashboard** — trending actors, malware, vulnerabilities, finished-intel reports; filter by industry/region; MITRE heat map. PDF/portal briefings.
2. **ASM Insights** — entities, issues, technologies; top critical/high issue types; issues-by-status; **Generate PDF** of the Insights view.
3. **Digital Threat Monitoring alerts** — open/deep/dark web + credential-leak monitors; alert dashboard (status, source, severity) for brand/VIP/org targeting.

*Does not combine:* in-product auto-remediation loop, FAIR blast radius, Hebrew/RTL, or a live attack-path-to-crown-jewel graph priced in dollars.

### Rapid7 InsightVM / InsightIDR

1. **InsightVM Executive Risk View** — unified 0–1000 risk score across cloud + on-prem, remediation progress, accepted risk, asset criticality/ownership tags; **PDF/HTML** Executive Risk View report (schedulable).
2. **Monthly Executive Summary Report** — assets, new vulns, remediation efficiency, Remediation Projects, agent coverage — curated for executives.
3. **InsightIDR dashboards & reports** — investigation/ATT&CK/MTTR/compliance (e.g. ISO 27001) widgets; scheduled **PDF/HTML/CSV**.

*Does not combine:* FAIR $, Hebrew/RTL, adversary leak intel as a first-class CISO pack, or live OAST proof on crown-jewel paths. Remediation Hub is *guidance + tickets*, not closed-loop verify-fixed.

### Tenable One

1. **Cyber Exposure Score (CES) + Exposure Cards** — the board number: “how exposed are we / vs peers / over time / by VM·OT·Cloud”; exportable dashboards (40+ widgets).
2. **Attack Path Analysis** — 150+ techniques, MITRE-mapped paths to sensitive systems; generative-AI **executive summary of a path** (plain language for the CISO).
3. **Hexa AI actioning** — agentic triage/remediation orchestration with HITL; marketed “verify exploitability” on the Exposure Data Fabric (inference + sensors, not a lawyer-grade proof pack).

*Does not combine:* FAIR dollars, Hebrew/RTL board artifacts, or stealer/dark-web leak intel fused onto the same path.

### Recorded Future (Intelligence Cloud)

1. **Impact & Metrics Dashboard** — detections enriched, prioritized actions, weeks-of-work saved, **estimated dollar business value**; **PDF download** for business-review decks.
2. **Org-specific Threat Maps** — actors/malware ranked High/Moderate/Basic with AI summary; vulnerability patch priority from *in-the-wild exploit + ransomware-group* activity.
3. **Digital Risk Protection + credential monitoring** — brand/fraud/impersonation plus compromised-credential identification speed (CISO-visible DRP tiles).

*Does not combine:* live authorized exploit-validation, auto-remediation of *your* infra, internet→crown-jewel graph, or Hebrew/RTL.

### Flare

1. **Operations dashboard** — unresolved events, severity mix, event-growth vs remediation, identifier-growth (MSSP-friendly); **MTTR** from first-seen to marked-remediated.
2. **Stakeholder PDF/DOCX reports** — scoped by identifier/category/severity/date; dashboard charts + highlighted events; CSV of the full event set.
3. **Threat Flow intel reports** — scoped actor/campaign/industry narrative for CISO/board: IOCs, MITRE TTPs, recommended actions (PDF/DOCX).

*Does not combine:* FAIR $, attack-path-to-crown-jewel, in-product auto-remediation of assets, or live exploit-validation proofs.

### Microsoft Defender EASM

1. **Attack Surface Summary** — inventory composition, H/M/L observations, cloud hosting, sensitive services, SSL/domain expiry, IP reputation; drill to asset lists; chart **CSV**.
2. **Security Posture + CISA KEV dashboards** — CVE exposure, domain/hosting/open-port/SSL hygiene, plus a dedicated **CISA Known Exploits** view a CISO can screenshot.
3. **GDPR / OWASP Top 10 dashboards** — compliance-shaped external-surface views; asset export + Log Analytics/ADX → Power BI for board Excel.

*Does not combine:* FAIR $, auto-remediation, Hebrew/RTL product, leak intel, or live proof. Paths are not crown-jewel graphs.

### Censys ASM

1. **Attack Surface Overview report** — top risk types/categories, asset counts, internet-facing inventory (console + export).
2. **Trends & Benchmarks** — attack-surface *size*, active-risk count, **average length of exposure (days)** vs 90-day benchmark — designed for board ROI conversations; CSV of contributing rows.
3. **Attribution + 400+ risk fingerprints** — daily scored exposures (impact × exploitability × likelihood) on a global all-ports Internet Map; ARC rapid-response notifications.

*Does not combine:* FAIR $, Hebrew/RTL, leak intel, auto-remediation execution, or live exploit-validation proof on a path to a named crown jewel.

---

## Combination matrix (honest)

| Vendor | Path | $ | Proof | Fix | Leak | HE |
|--------|------|---|-------|-----|------|-----|
| Wiz | Cloud graph | no native FAIR | Red Agent / runtime *inference* | Workflows / PR / IAM revoke | no | no |
| Falcon | Exposure + identity paths | no FAIR | ExPRT.AI *scoring* | Falcon response | creds (IDP) | no |
| Cortex/XSIAM | Post-*incident* causality | no FAIR | forensic evidence | XSOAR playbooks | TIM add-on | no |
| Mandiant | ASM issues, not $ paths | no | some ASM active checks | no loop | DTM | no |
| Rapid7 | limited | risk *score* not FAIR | scanner/exploitability flags | tickets | no | no |
| Tenable One | APA to sensitive systems | CES, not FAIR $ | marketed verify | Hexa HITL | no | no |
| Recorded Future | threat maps, not asset graph | estimated program $ | no | enrich others | yes | no |
| Flare | no | no | no | mark-remediated | **core** | no |
| Defender EASM | no crown-jewel graph | no | no | export to Sentinel | no | no |
| Censys | no crown-jewel graph | no | fingerprint, not proof | tickets | no | no |
| **Weissman (must)** | **internet→crown jewel** | **FAIR SLE/ALE** | **OAST/safe_proofs** | **SOAR + HITL** | **leak + darkweb** | **he + RTL** |

**The unique beat — none of them combine this in one CISO GUI or board PDF/Excel:**

> **Live exploit-validation proof (authorized, evidence-backed) + auto-remediation with verify-fixed + FAIR $ + Hebrew/RTL + adversary leak intel + attack path to a named crown jewel.**

That sentence *is* the product. If a demo still requires six screens and an English-only Helvetica PDF, we have not beaten them yet.

---

## What already exists vs the gap

| Pillar | Live today | Gap the CISO still feels |
|--------|-----------|--------------------------|
| Proof | `roe_mode=safe_proofs`, OAST hits, engine evidence JSON | Not printed as hop-level “proven reachable” on the path |
| Fix | SOAR playbooks, HITL isolate, HMAC remediation receipts (EN+HE HTML) | Not a FAIR **Δ$** on the same board number after verify-fixed |
| FAIR $ | `financial_risk.rs` SLE/ALE, `/api/financial-risk/:id`, Overview tiles | Not in `build_executive_board_pdf` |
| Hebrew/RTL | Command Center `he.json`, bilingual remediation HTML | Board PDF is Helvetica / English-only |
| Leak | `leak_hunter`, `darkweb_intel` / `dark_web_monitor` | Not fused onto path nodes / crown jewels |
| Path | `/attack-paths`, Dijkstra + choke points + per-path ALE | Leaks + proofs + remediations are other pages |

---

## Prioritized ship list (8) — ranked by uniqueness

Legal envelope for every increment: customer ROE, `safe_proofs` default, crown-jewel isolate **always HITL**, only the verify engine may set `VERIFIED_FIXED` (not the analyst, not SOAR). No exploit payloads. Evidence is HTTP/OAST/config/identity *observations* under authorization.

### 1. Crown-Jewel Proof Path — **highest uniqueness**

**Why first:** Wiz/Tenable/Falcon all *draw* paths. Nobody attaches **lawyer-grade authorized proof IDs** to each hop a CISO can click.

| Layer | Ship |
|-------|------|
| **Engine** | `crown_jewel_proof_path` — for each Dijkstra hop, join live findings whose evidence is `oast_interaction_hits` or `safe_proofs` (HTTP  status, header, identity signal). Mark hop `proven` / `inferred` / `unproven`. Never store payloads. |
| **API** | `GET /api/attack-paths/:client_id?proofs=1` — each step includes `proof_ids[]`, `evidence_sha256`, `roe_mode`, `proven_at`. |
| **UI** | `/attack-paths` hop chips: Proven (pulse) vs Inferred. Drawer: timestamp, engine id, evidence hash, ROE. |
| **Report** | Board PDF/Excel column **Proven hops / total hops** per path to the named crown jewel. |

**CISO sentence:** “This internet node is *proven* reachable under our ROE; it sits on the cheapest path to Payroll.”

### 2. CISO Fusion Pack (the artifact they take to the board)

**Why:** The combination is invisible until it is **one** PDF + Excel. This is the moat object.

| Layer | Ship |
|-------|------|
| **Engine** | Composer over existing loaders: `executive_summary` + `financial_risk` + attack-path snapshot + leak findings + SOAR run status. One deterministic JSON (no LLM). |
| **API** | `GET /api/ciso/fusion-pack/:client_id?lang=he\|en&currency=ILS\|USD` |
| **UI** | New route `/ciso-fusion` (Command Center): one screen — grade, ALE, top path, leak count, proofs, pending HITL. Hebrew `dir=rtl`. |
| **Report** | **PDF (Heebo RTL + Latin)** and **XLSX** (sheets: Paths, Proofs, Leaks, FAIR, SLA, ΔFix). Replace Helvetica `build_executive_board_pdf` for this pack. |

**CISO sentence:** “One file: ₪ at risk, path to the jewel, proof, leaks, what we auto-fixed.”

### 3. Adversary Leak → Path Ignition

**Why:** Flare/Mandiant/RF *show leaks*. Falcon shows leaked *creds*. None **ignite** a priced path to a crown jewel.

| Layer | Ship |
|-------|------|
| **Engine** | `adversary_leak_path_fusion` — inputs: `leak_hunter` + `darkweb_intel` + `dark_web_monitor` (IntelX when keyed). Match emails/domains/hosts to `risk_graph_nodes`. Raise edge weight; tag `leak_ignited`. |
| **API** | `GET /api/ciso/leaks/:client_id` — `{identifier, source, first_seen, node_id, paths_touched[], ale_usd}`. |
| **UI** | `/dark-web` and `/ciso-fusion`: “This stealer/paste hit **lights** path #3 ($ALE).” |
| **Report** | Fusion Pack sheet **Leaks** with path id + ALE. |

**CISO sentence:** “A marketplace listing of our helpdesk mailbox is now a dollar path to the crown jewel, not a CTI ticket.”

### 4. FAIR-delta auto-remediation (authorized, HITL-gated)

**Why:** XSIAM/Wiz/Hexa/Falcon *fix*. Rapid7 *tickets*. None **reprice ALE on the same board number** after a verified close, in Hebrew.

| Layer | Ship |
|-------|------|
| **Engine** | Extend SOAR: on `VERIFIED_FIXED` (engine-only), recompute client FAIR; persist `ale_before`, `ale_after`, `delta_usd` on `weissman_playbook_runs`. Allow-listed actions only (header/CSP, revoke key *the customer owns*, close SG the ROE names, rotate *their* secret). **No** exploit, **no** destructive OT. Crown jewel isolate stays HITL (`soar/blast_radius.rs`). |
| **API** | `POST /api/soar/runs/:id/verify-fair` ; `GET /api/ciso/fusion-pack` includes `remediation_delta_usd`. |
| **UI** | `/soar-hitl` + `/ciso-fusion`: “Approve → verify probe → ₪ ALE ↓”. |
| **Report** | HMAC bilingual **receipt** already in `remediation_report.rs` + new **ΔALE** line in Fusion Pack. |

**CISO sentence:** “We spent ₪X to cut ₪Y annualized loss; here is the signed receipt.”

### 5. Hebrew/RTL board typography (the geographic lock)

**Why:** Unique vs every vendor above. Israel/Hebrew-speaking boards cannot be an afterthought.

| Layer | Ship |
|-------|------|
| **Engine** | PDF writer embeds Heebo/Assistant (already in `scripts/pdf/fonts/`) instead of Helvetica; `dir=rtl` pages when `lang=he`; ILS from `financial_risk.currency`. |
| **API** | `GET /api/reports/board/:client_id.pdf?lang=he` ; `.xlsx` with `he` sheet names. |
| **UI** | Locale toggle on `/ciso-fusion` flips the *same* numbers (no second dataset). |
| **Report** | Print-quality Hebrew board PDF; LTR Latin for engine IDs/URLs (`<bdi>`). |

**CISO sentence:** “The board reads Hebrew; the evidence hashes stay Latin.”

### 6. Fusion Command Center page (adrenaline, professional)

**Why:** A PDF without a live cockpit is a consultant report. The GUI must be the adrenaline surface.

| Layer | Ship |
|-------|------|
| **Engine** | None new — consume fusion-pack JSON + WS job pulses. |
| **API** | Same `/api/ciso/fusion-pack/:client_id` + existing `/api/executive-summary/:client_id`. |
| **UI** | `/ciso-fusion`: kill-chain of the **top** path; proof pulse; leak ticker; FAIR waterfall; HITL CTA. Mobile + RTL. Reality badges. i18n keys in `en.json`/`he.json` (no defaultValue). Nav in `appNav.js`. |
| **Report** | “Export this view” → Pack #2. |

**CISO sentence:** “I open one URL before the board meeting.”

### 7. Board Excel workbook (audit-committee native)

**Why:** Rapid7/Censys/EASM export CSV *lists*. The unique workbook is **six sheets that cannot disagree** (one loader, like `CISO_INTELLIGENCE_API.md`).

| Layer | Ship |
|-------|------|
| **Engine** | XLSX serializer of fusion-pack JSON (deterministic column order). |
| **API** | `GET /api/ciso/fusion-pack/:client_id.xlsx` |
| **UI** | Export button on `/ciso-fusion` and `/attack-paths`. |
| **Report** | Sheets: `Summary`, `Paths`, `Proofs`, `Leaks`, `FAIR`, `Remediation`. |

**CISO sentence:** “Finance gets Excel; security gets the PDF; the numbers match.”

### 8. Closed-loop VERIFIED_FIXED on the pack (trust invariant)

**Why:** Every vendor lets a human click “fixed.” Weissman already forbids analyst/SOAR from setting `VERIFIED_FIXED`. Surface that invariant or the moat is invisible.

| Layer | Ship |
|-------|------|
| **Engine** | Re-probe job post-remediation; watermark rules in `finding_identity.rs` / `hack_fix_verify.rs` unchanged. |
| **API** | Fusion pack field `close_integrity: { analyst_cannot_set_verified_fixed, soar_cannot_set_verified_fixed, engine_verified_count }`. |
| **UI** | Badge on `/ciso-fusion` and finding drawer: **Engine-verified** vs **Claimed**. |
| **Report** | Pack footer: “Closed means re-probed. Analysts cannot attest.” |

**CISO sentence:** “The ₪ drop is not a ticket status.”

---

## Explicitly rejected (do not build)

- Exploit PoCs, weaponized payloads, or “copy Wiz Red Agent offensive packs.”
- Fake/demo fusion numbers when DB is empty — fail visible.
- English-only PDF “for now.”
- LLM-authored board $ that can disagree with `financial_risk.rs`.
- Marking leaks as proven paths without a graph node match.

---

## Team ideation (exit-grade)

**Module no competitor has:** **CISO Fusion Pack** — live proof × leak ignition × FAIR Δ$ × Hebrew RTL × crown-jewel path × engine-only verify-fixed, in one GUI and one PDF/Excel.

**Engine fusion:** `crown_jewel_proof_path` × `adversary_leak_path_fusion` × existing `fair_exposure_fusion` / Dijkstra / SOAR HITL.

**Demo (inspection):** Hebrew `/ciso-fusion` → top path with proven hop → leak chip → HITL approve non-destructive fix → ALE ↓ → download `he` PDF + xlsx.

**This sprint order:** 1 → 2 → 5 (so the pack is Hebrew on day one) → 3 → 4 → 6 → 7 → 8.

---

## Sources (public)

- Wiz: product/academy CNAPP, Lens, Exposure Management Dashboard, CISO Board Report template, Security Graph / toxic combinations, closed-loop remediation playbook.
- CrowdStrike: Falcon Exposure Management, ExPRT.AI, Charlotte executive reports, Identity Protection / dark-web creds, Kestrel persona UX.
- Palo Alto: Cortex XSIAM Command Center, Compliance Overview, Dashboards & Reports, Causality/Evidence, XSOAR playbooks.
- Mandiant: Advantage TI datasheets, ASM Insights PDF, Digital Threat Monitoring (Google Cloud).
- Rapid7: InsightVM Executive Risk View / Executive Summary Report / Remediation Hub; InsightIDR Dashboards and reports.
- Tenable: Tenable One product page (CES, APA, Hexa, Exposure Cards, dashboards).
- Recorded Future: Impact & Metrics Dashboard, Intelligence Cloud / Cyber Operations, DRP/credential monitoring.
- Flare: Dashboard, Reports, Event Explorer MTTR, Threat Flow.
- Microsoft: Defender EASM dashboards (Attack Surface Summary, Security Posture, CISA KEV, GDPR, OWASP), asset CSV / reports API.
- Censys: ASM product, Reports (Attack Surface / Exposure / Trends & Benchmarks), 400+ fingerprints, Attribution.

Weissman code anchors: `docs/CISO_INTELLIGENCE_API.md`, `fingerprint_engine/src/financial_risk.rs`, `soar/blast_radius.rs`, `pdf_report.rs` (`build_executive_board_pdf`), `frontend/src/pages/{ExecutiveOverview,AttackPaths,DarkWebMonitor,SoarHitlQueue}.jsx`.
