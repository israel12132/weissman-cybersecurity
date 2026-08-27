# Live E2E runtime — bounds that must not be removed

Companion to `docs/TECH_DEBT_flaky_db_test_hang.md`. That document records a case where a
`--test-threads 2` / `timeout-minutes: 45` guard was added and later silently lost from
`ci.yml`. This file exists so the live-E2E bounds do not disappear the same way.

## What went wrong (measured, 2026-07-24)

CI job `engine-wiring-and-smoke`, step "Playwright live journey":

| Metric | Value |
|---|---|
| Step runtime | **150.9 min** (13:50:58 → 16:21:55) |
| Whole job runtime | **240 min** |
| Tests in the step | **110** (100 appNav routes + 6 named + journey + auth setup) |
| Average per test | **82.3 s** — i.e. essentially at the 90 s per-test ceiling |
| Report produced | **none** — the job died with nothing to read |

It was never a hang. It was 110 serial tests, most of them running to their per-test timeout,
with **no bound at any level** able to stop the suite and **no reporter output** naming the test
in flight.

### Root cause: the crawl's cost model

`live-ui-crawl.spec.ts` generates **one test per sidebar route**, imported from the production
nav (`src/lib/appNav.js` → `PRIMARY_NAV` + `NAV_GROUPS`, 100 unique routes today, 0 hidden).
Playwright's built-in `page` fixture creates a **fresh BrowserContext per test** — incognito-like,
so empty HTTP cache and empty V8 code cache. Each test therefore re-downloads and re-parses the
eagerly-preloaded entry graph (~1.6 MB, `vendor-react` alone ~1.09 MB) from a **debug-profile**
Rust binary on a 2-vCPU runner that is simultaneously hosting Postgres, Redis, server, worker and
Chromium.

`visitRoute()` additionally called `ensureUiSession(page)` first, whose first statement is an
unconditional `page.goto('/command-center/operations')` — the most API-chatty page in the app.
So every route test paid **two** cold SPA boots: ~200 boots to make 100 route assertions.

Because the suite is derived from `appNav`, **every new Command Center page silently adds a
~20 s serial test to a blocking gate**, forever.

## Outcome (measured, run 30129211956)

Removing the duplicate cockpit boot and the blind sleep was sufficient on its own:

| Step | Before | After | |
|---|---|---|---|
| Playwright live journey | *(bundled in one 150.9 min step)* | **12 s** | ✅ pass |
| Playwright live UI crawl (100 routes) | | **3 min 52 s** | ✅ pass |
| **Combined** | **150.9 min** | **4 min 4 s** | **−97 %** |

The worker-scoped-context refactor (below) is therefore **no longer urgent**: the measured cost
per route is now ~2.3 s, and the suite fits comfortably inside its budget. It remains the right
answer if per-route cost ever regresses or `appNav` roughly triples.

Bounds were tightened from these measurements (Phase 3) and reconciled with PR #210, which
independently added a safety net to the same step while this fix was in flight. #210 contributed
a finding this analysis had missed: **video recording spawns an ffmpeg child that orphans when a
test is SIGKILLed**, defeating the step timeout — so `video` is now `off` in CI (trace on retry +
screenshot on failure still make failures diagnosable).

Final values: `globalTimeout` **12 min**, both Playwright steps **15 min**.
`globalTimeout` MUST stay **below** the step's `timeout-minutes` so Playwright self-terminates
first and reaps its own browser/ffmpeg children, instead of GitHub SIGKILLing and orphaning them.

## The bounds now in place — do not remove without replacing

| Guard | Location | Purpose |
|---|---|---|
| `globalTimeout: 12 min` (CI) | `frontend/playwright.config.ts` | Playwright self-terminates, **flushes reporters**, exits non-zero naming the in-flight test. `timeout` bounds ONE test and can never bound the suite. ~3× headroom over the measured crawl; must stay < the step budget (15 min). |
| `maxFailures: 10` (CI) | `frontend/playwright.config.ts` | A systemically broken stack aborts in ~2 min instead of grinding 110 × 90 s × 2 retries. |
| `actionTimeout: 15s` / `navigationTimeout: 30s` | `frontend/playwright.config.ts` (`chromium-live`) | Unset, these collapse to **0 = no limit**, so a stalled `goto` ate the whole test budget and reported a generic timeout instead of naming the route. |
| `github` reporter + `PLAYWRIGHT_FORCE_TTY=1` | config + `ci.yml` | `list` prints nothing at test **start** on a non-TTY stream. Without this a killed run gives no clue which test was running. |
| `timeout-minutes: 15` (journey and crawl) | `.github/workflows/ci.yml` | Per-suite backstops, above `globalTimeout` by design. The suites are **split** so the crawl's cost is visible instead of hidden under the journey's name. |
| `video: 'off'` in CI | `frontend/playwright.config.ts` | An orphaned ffmpeg child survives the step kill and keeps the job alive (#210). |
| `continue-on-error` on **both** k6 steps | `.github/workflows/ci.yml` | The k6 SLO smoke is informational, but its **setup** step was blocking: a bad `k6-version` (`v1.8.0` → the action prepends `v`, giving a 404 on `vv1.8.0`) failed the whole engine-wiring gate after every real contract had passed. An informational feature must never be able to fail a blocking gate. |
| `timeout-minutes: 5` (browser install) | `.github/workflows/ci.yml` | An unbounded ~170 MB CDN download used to be billed to the test step. |
| `timeout-minutes: 180` (job) | `.github/workflows/ci.yml` | Last-resort backstop; the job previously inherited GitHub's 360-min default. |
| `if: always()` artifact upload | `.github/workflows/ci.yml` | Report/traces survive **cancellation**; `if: failure()` is FALSE when a job is cancelled — exactly when diagnostics matter most. |

## Still outstanding — the structural fix

The bounds above make the failure **fast, bounded and diagnosable**; they do not make the crawl
cheap. The permanent cost fix is a **worker-scoped browser context** so the HTTP + V8 cache stays
warm from the second route onward, instead of a fresh context per test.

- New fixture `frontend/tests-e2e/fixtures/live-crawl.ts`, worker-scoped `session`.
- Every route is still reached by a real `page.goto(route)` deep link, so SPA fallback and auth
  bootstrap on direct entry stay covered; a hard navigation still tears down the JS realm between
  routes, so no timers/SSE/app state leak forward. **No coverage is removed.**
- Listeners must be added *and removed* per test, since the page is shared (otherwise they
  accumulate and cross-attribute errors to the wrong route).
- Estimated ~6 h including CI iteration; expected crawl runtime ~8–12 min.

`ci.yml` now lifts `WEISSMAN_RATE_LIMIT_PER_SEC` / `_BURST` plus the tenant-scan and
login-per-minute ceilings on the live server (same clamp values as `rate_limit_metrics.rs`,
same spirit as `nightly-e2e.yml`). Postgres `fsync=off` for the CI container is still
outstanding.

## Rules

1. **Never** make a live gate `continue-on-error` to dodge a timeout. Bound it and let it fail loudly.
2. **Never** move blocking route-crash coverage to nightly to make the gate faster.
3. If you add a Command Center page, you have added a live test — check the crawl budget.
4. If you change any bound in the table above, update this table in the same commit.
