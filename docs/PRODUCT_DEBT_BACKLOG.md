# Product Debt Backlog

Persistent record of **product / i18n** debt that is intentionally decoupled from the
security and build hard-gates. The CI step below (in the `Engine wiring audit & API
smoke` job of `.github/workflows/ci.yml`) is marked `continue-on-error: true` so it
surfaces as a **warning**, not a pipeline blocker:

- `i18n defaultValue gate` — `scripts/verify_i18n_no_default_values.mjs`

All other gates — security audits (`cargo deny`, `cargo audit`, Semgrep SAST,
gitleaks, Trivy), build/test, **and the `Weissman UI compliance audit`** — remain
strict hard-gates. (The UI-capability audit was brought to green by the PR #181
affordance campaign: evidence + refresh + CSV/PDF export + search across the Command
Center pages.)

This file is the intake list for a future dedicated **Product PR** that clears the i18n
debt and restores the step to blocking.

> Reproduce locally: `node scripts/verify_i18n_no_default_values.mjs`

---

## P1 — Rust test-coverage floor (`llvm-cov`) not met

The `Rust — coverage (llvm-cov)` job enforces
`cargo llvm-cov --workspace --lib --fail-under-lines 40` and currently **fails** — the
workspace library line-coverage is below the 40% floor. This is a **standalone check,
not part of the merge-gate `needs:` list**, so it does not block merges; it is tracked
here as **P1 product debt** for a dedicated coverage campaign.

**Decision (explicit): the 40% floor is NOT lowered.** Standards are not reduced to
turn a check green. The floor stays at 40 and coverage is raised to meet it in a
dedicated effort (prioritise security-critical modules: auth/JWT, RLS, SOAR, crypto,
compliance).

**Exit criteria:** `cargo llvm-cov --workspace --lib --fail-under-lines 40` exits 0
with the floor unchanged (then ratchet the floor upward).

---

## i18n `defaultValue` fallbacks — needs real en.json + he.json keys

`verify_i18n_no_default_values.mjs` fails on inline `t('key', { defaultValue: '...' })`
fallbacks; every such string must become a real key present in **both**
`frontend/src/i18n/locales/en.json` and `he.json`. Current state: **442/461 files
clean; 19 files dirty; ~223 `defaultValue` occurrences total.**

| File | `defaultValue` count |
|---|---|
| `components/remediation/RemediationDetail.jsx` | 42 |
| `pages/FixFirstProgram.jsx` | 27 |
| `pages/ArsenalInventory.jsx` | 19 |
| `pages/ArsenalConsole.jsx` | 14 |
| `pages/PostureScoreCard.jsx` | 14 |
| `pages/RemediationAnalytics.jsx` | 14 |
| `pages/PortfolioPosturePanel.jsx` | 12 |
| `pages/AttackExposurePanel.jsx` | 11 |
| `pages/CompliancePosturePanel.jsx` | 10 |
| `pages/PortfolioAttackPanel.jsx` | 9 |
| `pages/RemediationHub.jsx` | 9 |
| `components/remediation/HealTrendSparkline.jsx` | 7 |
| `pages/SlaForecastStrip.jsx` | 6 |
| `components/remediation/BatchHealPanel.jsx` | 5 |
| `components/remediation/HealReadinessPanel.jsx` | 5 |
| `components/remediation/RemediationAnalyticsPanel.jsx` | 5 |
| `pages/BacklogAgingPanel.jsx` | 5 |
| `pages/StealthOperations.jsx` | 5 |
| `pages/TargetIntelligence.jsx` | 4 |

**Remediation:** for each occurrence, add the key to `en.json` (English text from the
`defaultValue`) and `he.json` (**Hebrew translation** — requires a native/qualified
review), then delete the inline `defaultValue`. ~223 bilingual strings.

## Exit criteria (to restore hard-gating)

1. `node scripts/verify_i18n_no_default_values.mjs` exits 0.
2. Remove `continue-on-error: true` from the `i18n defaultValue gate` step in
   `.github/workflows/ci.yml`.
