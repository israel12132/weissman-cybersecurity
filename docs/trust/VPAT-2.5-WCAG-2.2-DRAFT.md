# Accessibility Conformance Report (VPAT® 2.5 — draft, vendor self-assessment)

**Product:** Weissman Command Center (web application)
**Standards evaluated:** WCAG 2.2 Level A and AA · Revised Section 508 · EN 301 549
**Report date:** 2026-09-22 · **Evaluation method:** internal code review + manual keyboard/AT
spot-checks. **Status: DRAFT — not yet independently audited.**

> Honesty note (required by our own trust policy): this is a **preliminary self-assessment**, not
> an audited conformance claim. The Command Center has real accessibility **foundations** but a
> known remediation backlog (approximately half of ~158 pages lack complete ARIA/role coverage;
> `frontend/eslint.config.js` currently runs jsx-a11y rules at *warn*). We publish this so buyers
> can make an informed decision and see the remediation roadmap, rather than claim conformance we
> have not verified. Conformance terms used below: **Supports**, **Partially Supports**,
> **Does Not Support**, **Not Evaluated**.

---

## Foundations already in place (evidence)

- Skip-to-content link (`SkipToContent`), programmatic focus management (`useFocusTrap`).
- `prefers-reduced-motion` honored; WCAG-tuned color-contrast design tokens; a high-contrast theme.
- Full internationalization scaffold (EN/HE) with RTL support; semantic HTML in shared primitives.

## Known gaps (honest)

- ~77 of ~158 pages lack complete `aria-*`/`role` coverage; jsx-a11y lint is **warn-only**.
- No automated accessibility testing in CI (no axe-core/jest-axe/pa11y/Playwright-a11y assertions).
- Not all interactive widgets (custom tables, charts, command bar) have verified keyboard + SR support.

## Table 1: Success Criteria, Level A (summary)

| Criterion | Conformance | Remarks |
|---|---|---|
| 1.1.1 Non-text Content | Partially Supports | Icons/charts need consistent alt/aria-label; backlog |
| 1.3.1 Info and Relationships | Partially Supports | Semantic structure good in primitives; gaps on legacy pages |
| 2.1.1 Keyboard | Partially Supports | Focus trap + skip link present; some custom widgets unverified |
| 2.4.1 Bypass Blocks | Supports | SkipToContent implemented |
| 2.4.3 Focus Order | Partially Supports | Verified on core flows; backlog pages unverified |
| 3.3.2 Labels or Instructions | Partially Supports | Forms in primitives labeled; audit remaining |
| 4.1.2 Name, Role, Value | Partially Supports | The core ARIA-coverage backlog lives here |

## Table 2: Success Criteria, Level AA (summary)

| Criterion | Conformance | Remarks |
|---|---|---|
| 1.4.3 Contrast (Minimum) | Supports | Contrast-tuned tokens + high-contrast theme |
| 1.4.10 Reflow | Partially Supports | Responsive; verify at 400% zoom across pages |
| 1.4.11 Non-text Contrast | Partially Supports | Verify UI-component/state contrast |
| 2.4.7 Focus Visible | Partially Supports | Present in primitives; audit remaining |
| 2.5.8 Target Size (Minimum) (2.2) | Not Evaluated | To be measured |
| 3.2.6 Consistent Help (2.2) | Partially Supports | Help board exists; verify placement consistency |
| 4.1.3 Status Messages | Partially Supports | Verify aria-live on async/status updates |

## Remediation roadmap (paired with code changes)

1. Flip the highest-impact jsx-a11y rules from *warn* to **error** and gate CI on them
   (`frontend/eslint.config.js`) — start with `4.1.2`-related rules (roles, names, labels).
2. Add **axe-core** assertions to the Playwright suite for the top ~20 pages; expand to all pages.
3. Burn down the ~77-page ARIA/role backlog in waves (the codebase already runs "wave" sweeps).
4. Add an **accessibility section** to `SIG_CAIQ_PREP_QA.md` so sales can answer diligence questions.
5. Commission an **independent** WCAG 2.2 AA audit and replace this draft with the audited VPAT.

*VPAT® is a registered trademark of the Information Technology Industry Council (ITI).*
