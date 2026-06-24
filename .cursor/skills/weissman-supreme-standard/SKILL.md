---
name: weissman-supreme-standard
description: Weissman Cybersecurity supreme operating doctrine — end-to-end verification, live-only truth (no fakes/stubs), gap filling, real engine synthesis, world-class UI with adrenaline, system completeness audits, and team ideation for unmatched modules. Use for any Weissman platform work, engines, frontend, backend, agents, or when the user mentions חבת וייסמן, מנועים, אמת לייב, or world #1 cybersecurity vision.
---

# Weissman Supreme Standard

חזון: **חבת וייסמן אבטחת מידע — מקום ראשון בעולם.** אין תירוצים.

## חוקי ברזל (verbatim)

### חוק 1 — מקצה לקצה, ברמה הגבוהה בעולם
לוודא כל דבר בחברה מקצה לקצה שהוא תקין מהתחלה עד הסוף כולל הקבצים הקטנים שהכל יהיה ברמה הכי גבוהה בעולם

### חוק 2 — אמת לייב בלבד
כל דבר יהיה אמת לאמיתה בלי זיופים ובלי משהו קבוע בשום דבר אלא הכל בא בלייב בחי

### חוק 3 — תמיד למלא פערים
תמיד לבדוק מה אפשר עוד להוסיף למערכת ולהוסיף לה כל דבר שאפשר בתחום שלנו כמובן ברמה הכי גבוהה בעולם שיש ושניקח פער אבל

### חוק 4 — סינתזת מנועים (הכי משמעותי)
לחפש ולנתח כמה דברים יחד וליצור מאות של מנועים כמובן שכולם אמיתיים בלי פייק בכלל אבל שהם יקחו את החברה שלנו לחזון שלנו שזה שחבת וייסמן אבטחת מידע תהיה במקום הראשון בעולם

### חוק 5 — UI מקצועי עם אדרנלין
לשפר את התצוגה לרמה הכי נוחה ומקצועית שיש ועדיין שזה יראה עם אנדרנלין אבל הכי מקצועי שיש בעולם

### חוק 6 — ביקורת מערכת מלאה
לבדוק את כל המערכת ולראות מה חסר לה ולהוסיף לה כמובן ברמה הכי גבוהה בעולם ומעבר

### חוק 7 — יתרון בלתי-ניתן לחקות
שלא יהיה שום חברה בעולם שקרובה ליכולות שלנו ושאתה וכל הסוכנים תעשו ישיבת צוות ותבינו איזה עוד מודול או מנוע אין לאף אחד בכלל בכלל בעולם והוא כלכך חזק שנעשה מזה אקזיט ואני לא מקבל תירוצים על זה בכלל

---

## Quick Start — סדר עבודה חובה

לפני כל שינוי, ואחריו:

```
Progress:
- [ ] 1. End-to-end trace (API → worker → engine → DB → UI)
- [ ] 2. Live-only audit (no mocks/stubs/hardcoded demo data in prod paths)
- [ ] 3. Gap scan (what's missing vs vision + competitors)
- [ ] 4. Engine synthesis (combine domains → new real engines)
- [ ] 5. UI polish (professional + adrenaline)
- [ ] 6. Team ideation (modules nobody else has)
- [ ] 7. Verify: build, tests, engine wiring CI
```

---

## 1. End-to-End Verification

**Never ship a partial wire.** Trace the full path:

| Layer | Key paths |
|-------|-----------|
| Engine registry | `backend/weissman-core/src/models/engine.rs` (`PRODUCTION_ENGINE_IDS`) |
| Dispatch | `fingerprint_engine/src/engine_dispatch.rs` |
| Frontend catalog | `frontend/src/lib/enginesRegistry.js` |
| UI pages | `frontend/src/pages/`, `frontend/src/components/cockpit/` |
| API | `backend/weissman-server/`, OpenAPI spec |
| Worker | `crates/weissman-worker/` |
| Agent | `crates/weissman-agent/` |
| DB | `crates/weissman-db/migrations/`, `fingerprint_engine/migrations/` |

**Small files matter:** i18n (`frontend/src/i18n/locales/`), nav (`appNav.js`), engine profiles, badges (`EngineRealityBadge.jsx`), migrations, `.env.example` docs.

**Verification commands:**
```bash
cargo build --workspace && cargo test --workspace
cd frontend && npm run build
node scripts/verify_engine_wiring.mjs
node scripts/engine_reality_audit.mjs
```

---

## 2. Live-Only Truth (No Fakes)

**Forbidden in production paths:**
- Hardcoded findings, scores, or "demo" JSON returned as real scan results
- Static placeholder data presented as live telemetry
- Engine IDs in UI with no real `engine_dispatch` runner
- `TODO` stubs that return success without doing work

**Required:**
- Real probes, real DB reads/writes, real WebSocket/agent sessions
- Evidence-backed findings (OAST, HTTP proof, agent telemetry)
- `EngineRealityBadge` / capabilities API reflecting actual wiring

If env is missing (no DB/Redis), **fail visibly** — never silently fake success.

---

## 3. Gap Filling & System Completeness

After every task, ask:
1. What module/page/API/engine is referenced but missing?
2. What competitor capability (CrowdStrike, Wiz, Palo Alto, Mandiant, etc.) do we lack?
3. What compliance/control (NIST, ISO, PCI, HIPAA) has no engine or report?

Add the gap at world-class level — backend + frontend + i18n + migration if needed.

---

## 4. Engine Synthesis (Core Mission)

**Method:** Cross-analyze multiple domains and fuse into new **real** engines.

Examples of synthesis patterns:
- ASM + email DNS posture + cloud IAM → unified external exposure engine
- Kerberos + password spray + ITDR ingest → identity attack chain engine
- IaC misconfig + supply chain + CI/CD → pipeline-to-runtime risk engine

**Adding an engine (minimum checklist):**
1. Implement real logic in `fingerprint_engine/src/` (or agent in `crates/weissman-agent/`)
2. Register in `engine_dispatch.rs`
3. Add to `PRODUCTION_ENGINE_IDS` in `engine.rs`
4. Add to `enginesRegistry.js` + i18n labels
5. Add Command Center page or cockpit card if warranted
6. Run `verify_engine_wiring.mjs` — CI must pass

**Scale target:** hundreds of engines, all wired, all real. Aliases OK only when they map to real implementations.

---

## 5. UI — Professional Adrenaline

Balance:
- **Professional:** clear hierarchy, consistent spacing, accessible contrast, i18n (en/he), loading/error states, evidence drawers
- **Adrenaline:** motion on critical alerts, live pulse indicators, risk heat, kill-chain visuals — never cheesy

Reference patterns: `EngineCard.jsx`, `GodModeEngineMatrix.jsx`, Command Center pages under `frontend/src/pages/`.

Every new surface: mobile-safe layout, RTL support for Hebrew, reality badges on engines.

---

## 6. Team Ideation Session (Agent Protocol)

When scoping features or periodic audits, run an internal **team meeting** (multi-perspective analysis):

**Roles to simulate:**
- Red Team Lead — attack surface gaps
- Blue/SOC Lead — detection & response gaps
- Cloud Architect — multi-cloud blind spots
- Product/Exit Strategist — unique moats worth acquiring

**Output template:**
```markdown
## Weissman Team Ideation — [date/topic]

### Modules no competitor has
1. [Name] — why unique, why exit-grade

### Engine fusion proposals (real implementations)
1. [engine_id] — inputs, probes, evidence, MITRE mapping

### Gaps to close this sprint
- [ ] ...

### Rejected (fake/stub) — do not build
- ...
```

Prioritize ideas that combine **live evidence + autonomous loop + business risk pricing** — Weissman's differentiators.

---

## Anti-Patterns (Instant Reject)

| ❌ | ✅ |
|----|-----|
| UI engine with no backend runner | Full stack wiring + CI green |
| Mock scan results | Live probes + stored evidence |
| "Coming soon" without issue tracked | Ship or hide from prod catalog |
| Copy-paste engine with renamed label | Distinct logic or explicit alias to real impl |
| Excuses for missing tests/build | Fix until `cargo test` + `npm run build` pass |

---

## Additional Resources

- Detailed checklists, competitor matrix, and engine synthesis patterns: [reference.md](reference.md)
- Architecture & services: [AGENTS.md](../../../AGENTS.md)
- Executive vision doc: `Weissman_Cybersecurity_מסמך_טכני_מנהלי_עברית.md`
