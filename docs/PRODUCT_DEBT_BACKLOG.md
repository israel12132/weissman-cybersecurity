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

---

## 3. Handler store-down dishonesty — anti-regression ratchet armed

**Gate:** `scripts/verify_handler_honesty.mjs` (`handler store-down honesty
ratchet` step in `.github/workflows/ci.yml`) — **blocking**, operating as an
anti-regression ratchet against `scripts/handler-honesty-baseline.json`
(identical in spirit to the i18n `defaultValue` ratchet). Per-file offender
counts are frozen; the build fails only when a file's count **increases** or a
**new** offender file appears. Counts may only go down.

**Origin:** HTTP handlers in `fingerprint_engine/src/server_handlers_*.inc`
turn datastore failures into fake successes and leak raw driver errors to
clients. Two banned patterns are detected:

- **(a) query-level swallow** — a sqlx query terminating in
  `.fetch_one` / `.fetch_all` / `.fetch_optional` / `.fetch` / `.execute`, then
  `.await`, then an immediate `.unwrap_or_default()` / `.unwrap_or(…)` / `.ok()`.
  When the DB is down this fabricates an empty/zero `200 {ok:true}` body instead
  of surfacing the failure — the client cannot distinguish "no data" from "store
  is down". (`fetch_optional(…).await.ok().flatten()` is the most common shape:
  it collapses a DB error and a genuinely-absent row into the same `None`.)
- **(b) raw SQL / driver-error leak** — `e.to_string()` / `err.to_string()`
  serialised into a `json!(…)` response body or next to an `"error"` / `"detail"`
  / `"message"` JSON key, shipping table names and SQL fragments to clients.

Benign lookalikes are intentionally NOT flagged: `row.try_get(col).unwrap_or_default()`
on an already-fetched row, `json.get(k).unwrap_or(0)` value parsing, and
`some_future().await.unwrap_or(…)` on non-query futures — none of these have a
query executor feeding the swallowed `.await`.

**Baseline:** **263 violations across 26 files** (230 query-level swallows + 33
error-string leaks) at arming time. Worst offenders: `server_handlers_rest4.inc`
(51), `server_handlers_sqlx.inc` (44), `server_handlers_platform.inc` (33),
`server_handlers_rest.inc` (17), `server_handlers_phase3.inc` (16). The actual
fixes are owned by a separate workstream; this gate only stops the debt growing.

**Resolution plan:** the fix for each site is to propagate the datastore error
as a real failure status (e.g. `503 SERVICE_UNAVAILABLE`) instead of a fabricated
body, and to replace client-facing `e.to_string()` with a generic message while
logging the detail server-side (`tracing::error!`). As handlers are corrected,
re-snapshot the baseline (`WEISSMAN_HONESTY_BASELINE_WRITE=1 node
scripts/verify_handler_honesty.mjs`, or `--write-baseline`) so the ratchet
tightens with each burn-down.

**Exit criterion:** baseline driven to **0 files, 0 occurrences**, at which point
the ratchet becomes an effective hard-zero gate (any new store-down swallow or
raw-error leak fails the build).
