# Weissman Supreme Standard — Reference

## E2E Trace Template

Use for every feature/fix:

```
Feature: _______________
Entry point: (UI route / API / agent / worker job)
↓
Handler: (file:function)
↓
Engine / logic: (fingerprint_engine module or agent detection)
↓
Persistence: (table + migration)
↓
UI feedback: (page + WebSocket + i18n keys)
↓
CI: verify_engine_wiring + build + test
Status: PASS / GAP FOUND → ___
```

---

## Live-Only Audit Checklist

- [ ] No `const DEMO_*` or `mock*` used in prod code paths
- [ ] Scan results include `evidence` / `proof` / timestamps from real execution
- [ ] Dashboard metrics from DB queries, not hardcoded arrays
- [ ] WebSocket events reflect actual job state transitions
- [ ] Agent detections from real host telemetry, not seeded fixtures
- [ ] OAST callbacks verified before marking blind vulns confirmed
- [ ] `useEngineCapabilities` / reality API matches dispatch table

---

## Engine Wiring Files (canonical order)

1. `fingerprint_engine/src/<engine>_engine.rs` — implementation
2. `fingerprint_engine/src/engine_dispatch.rs` — runner registration
3. `fingerprint_engine/src/lib.rs` — module export if new file
4. `backend/weissman-core/src/models/engine.rs` — `PRODUCTION_ENGINE_IDS`
5. `frontend/src/lib/enginesRegistry.js` — UI catalog
6. `frontend/src/i18n/locales/en.json` + `he.json` — labels
7. Optional: `frontend/src/pages/<Engine>CommandCenter.jsx`
8. Optional: `frontend/src/lib/appNav.js` — navigation entry
9. `scripts/verify_engine_wiring.mjs` — must pass
10. `scripts/engine_reality_audit.mjs` — reality audit

---

## Engine Synthesis Pattern Library

### Pattern A: Telemetry Fusion
Combine two live data sources into one correlated finding.
- Example: NDR flow anomalies + ITDR identity events → lateral movement chain

### Pattern B: Posture + Exploit Proof
Static misconfig scan + active safe validation.
- Example: IaC public S3 + attempted anonymous list (blocked/safe) → confirmed exposure

### Pattern C: Cross-Cloud Correlation
Same misconfiguration class across AWS/Azure/GCP with unified scoring.

### Pattern D: Agent + Remote Surface
Endpoint behavior + external ASM asset linked by identity/device ID.

### Pattern E: Compliance Engine
Map findings to control frameworks with auto-generated evidence packs (NIST, ISO, PCI, HIPAA, SOC2).

Each synthesis must define: **inputs, probes, evidence artifact, severity model, remediation, MITRE IDs**.

---

## UI Professional Adrenaline Guidelines

### Professional baseline
- Typography scale consistent with Command Center
- Skeleton loaders during fetch
- Empty states with actionable next step
- Error boundaries with retry
- Keyboard navigation on tables and modals

### Adrenaline (tasteful)
- Subtle pulse on critical severity badges
- Animated risk graph edges on new correlations
- Live job progress via WebSocket
- Kill-chain stage transitions with micro-motion
- Dark theme contrast for SOC operators

### Avoid
- Stock hacker green-on-black clichés
- Fake particle effects
- Unlabeled icons
- English-only strings in Hebrew locale

---

## Competitor Gap Matrix (periodic review)

| Domain | Leaders to beat | Weissman must exceed |
|--------|-----------------|----------------------|
| EASM | ASM, Censys, Shodan | Live exploit validation + auto-remediation |
| CNAPP | Wiz, Orca, Prisma | IaC→runtime chain + agent correlation |
| XDR | CrowdStrike, SentinelOne | Autonomous red-team loop closing findings |
| ITDR | Microsoft, Silverfort | Kerberos/SAML/OAuth supreme engines |
| ASM supply chain | Snyk, Chainguard | SBOM + registry + CI/CD unified |
| OT/ICS | Claroty, Dragos | Digital twin + safe passive + active tiers |

For each row: list 1–3 gaps, assign engine IDs, ship within sprint.

---

## Team Ideation — Exit-Grade Module Criteria

A module qualifies as **exit-grade unique** when ALL true:

1. **No direct competitor product** combines the same capabilities
2. **Live evidence loop** — not rules-only or static posture
3. **Autonomous action** — detect → price risk → contain/remediate (with safety gates)
4. **Enterprise governable** — RLS, audit log, approval workflows
5. **Defensible IP** — novel correlation, probe technique, or closed-loop architecture

Document in ideation output with: market gap, technical moat, demo path, engine list.

---

## System Completeness Sweep

Run monthly or before major releases:

```bash
# Build & test
cargo clippy --workspace
cargo test --workspace
cd frontend && npm run build

# Engine integrity
node scripts/verify_engine_wiring.mjs
node scripts/engine_reality_audit.mjs

# Find orphan UI routes
rg "path:" frontend/src/main.jsx frontend/src/lib/appNav.js

# Find engines in UI not in PRODUCTION_ENGINE_IDS
# (verify_engine_wiring catches most)
```

Manual checks:
- Every Command Center page has working API
- Every API route in OpenAPI has handler
- Migrations applied on fresh DB boot
- Agent binary registers and sends heartbeats
- i18n: no missing keys in he.json vs en.json for new strings

---

## Response Standard

When reporting to the user:
- State what was verified end-to-end
- List gaps found and what was added
- Confirm live-only (no fakes introduced)
- Note engine synthesis opportunities
- No excuses — if blocked, state exact blocker and fix path
