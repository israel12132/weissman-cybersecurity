# Product Debt Backlog

Formal record of consciously-deferred engineering debt. Each item names the
gate it affects, why it is deferred, and where it will be resolved. Nothing here
is hidden: the CI gate stays visible (as a non-blocking warning) until cleared.
Resolved items stay in this file, marked ✅, so the exit criterion that was
actually met is on the record.

---

## 1. i18n `defaultValue` fallbacks — ✅ RESOLVED

**Gate:** `scripts/verify_i18n_no_default_values.mjs` (`i18n defaultValue gate`
step in `.github/workflows/ci.yml`) — **blocking**, and now a zero-tolerance
ratchet (`scripts/i18n-defaultvalue-baseline.json` is `{}`).

**Origin:** PR #181's "Command Center affordance campaign" landed evidence /
refresh / CSV-PDF / search affordances using inline English fallbacks —
`t('some.key', { defaultValue: 'English text' })`. At its peak the gate recorded
**223 occurrences across 19 files**. The gate forbids inline defaults: every key
must live in `frontend/src/i18n/locales/{en,he}.json`, which made this a Hebrew
translation campaign rather than a mechanical codemod.

**Resolution:** every fallback has been migrated to real `en`/`he` locale keys.
The final two (`common.clear` in `pages/RemediationHub.jsx`) were keyed as part
of the compliance-integrity branch, taking the count to **0 files, 0 occurrences**.
The ratchet baseline was previously left at the historical 223 — a loose ratchet
that silently permitted a full regression — and is now tightened to `{}` so any
new inline `defaultValue` fails the build.

**Exit criterion:** ✅ gate green with zero `defaultValue` occurrences, baseline
re-armed at zero. The companion `i18n templated-key resolution gate` and the
`Weissman UI compliance audit` (111/111 pages) remain enforced and green.

---

## 2. DAST (OWASP ZAP baseline) — informational, not yet blocking

**Gate:** `DAST — OWASP ZAP baseline against the live stack` step in
`.github/workflows/ci.yml` — **informational** (`-I`, `fail_action: false`, now
also `continue-on-error: true`).

**Origin:** the `zaproxy/action-baseline` step can exit non-zero at the step
level (report/issue plumbing, or target reachability from the ZAP container to
the host `172.17.0.1:18000`) even with `fail_action: false`, which was skipping
the real live-stack gates that run after it (live RLS, smoke, Playwright-live,
E2E). The step is designed to be informational until the baseline is tuned, so
it is made non-blocking to match that intent.

**Resolution plan (on `claude/ops-ci-stabilization`):** confirm ZAP↔host
reachability, add a tuned `.zap/rules.tsv`, get a clean baseline, then drop
`continue-on-error` (and flip `fail_action` to true) to promote DAST to a
blocking gate.
