# TECH DEBT — Flaky DB-backed Rust workspace test hang (HIGH PRIORITY)

**Status:** Open · **Priority:** High · **Area:** CI / DB-backed integration tests · **Filed:** 2026-07-18

## Symptom

The `cargo test --workspace --all-targets` step that runs against a live Postgres service
intermittently **hangs indefinitely** instead of completing in its normal ~5–7 minutes.

Observed instance: CI run `29650387309` (branch `claude/detection-tool-selection-engine-pviz0u`),
job **"Engine wiring audit & API smoke"**, step **"Run Rust workspace tests (blocking gate)"** —
started `15:49:09Z`, still `in_progress` **~69 minutes later** with no output progression. The
commit under test only changed CI env vars (read in a later step), so it could not have caused the
hang. The parallel `rust-audit` job ran the *same* test invocation successfully in ~5 minutes on
the same commit — confirming the hang is **flaky / non-deterministic**, not a code regression.

Because there was no per-step timeout, the hung step was on track to ride GitHub Actions'
**360-minute default job timeout**, burning a runner for hours and masking the underlying deadlock.

## Interim mitigation (shipped)

Step-level `timeout-minutes` added to every DB-backed Rust-test step in `.github/workflows/ci.yml`
so a hang **fails fast** (fail-fast enforcement) instead of consuming a runner for 6 hours:

| Job | Step | Normal | `timeout-minutes` |
|-----|------|--------|-------------------|
| `rust-audit` | Run Rust tests (blocking gate) | ~5–7 min | **15** |
| `engine-wiring-and-smoke` | Run Rust workspace tests (blocking gate) | ~5–7 min | **15** |
| `rust-coverage` | Coverage (workspace incl. integration tests) with a floor | ~6–16 min | **30** |

Margins are >2× the legitimate upper bound (≈1.9× for the more variable instrumented coverage
step) — generous enough to never false-kill a slow-but-legit run, tight enough to kill a hang
decisively. This is a **guard, not a fix**: it converts a silent hang into a fast, visible failure
that surfaces the flake for diagnosis.

## Suspected root causes (to investigate)

`cargo test` runs test binaries **in parallel by default**, and multiple DB-backed integration
tests share the single CI Postgres. Candidate mechanisms, most→least likely:

1. **Connection-pool exhaustion / leak under parallel tests.** Several tests each open their own
   `PgPool`; run concurrently they can exceed Postgres `max_connections` (default 100) or a pool's
   own cap, and a test that acquires-and-never-releases (or holds a txn across an `.await` that
   blocks on another test's lock) deadlocks waiting on `acquire()` — which has no cheap timeout in
   test code. This mirrors the *product-side* pool-starvation class already fixed on this branch
   (dedicated control-plane pool + bounded per-finding fan-out), suggesting the test harness has the
   same latent shape.
2. **Cross-test row/advisory-lock contention.** Two tests mutating the same tenant/table (or taking
   the same Postgres advisory lock) can deadlock; Postgres breaks *some* deadlocks, but a lock held
   across an application-level wait will not be detected and hangs until timeout.
3. **`Mutex`/`OnceCell` poisoning or a global test fixture initialized under contention** — a
   panicking test holding a `std::sync::Mutex` poisons it, and other tests block forever on `lock()`.
4. **`tokio::test` runtime/task that never resolves** — e.g. awaiting a channel/lease/redis handle
   that a concurrently-running test consumes.

## Remediation directions (proper fix)

- **Reproduce deterministically:** run the DB suite with `--test-threads=1` in a loop and with high
  parallelism to bracket the flake; capture `pg_stat_activity` (state = `idle in transaction` /
  `active` waiting on locks) and `SELECT * FROM pg_locks` at hang time.
- **Bound every test-side pool acquire:** give test `PgPoolOptions` a small `acquire_timeout` so a
  starved test **fails fast with a clear error** instead of hanging (the same lesson applied to the
  product worker pools).
- **Serialize or isolate contended tests:** use `serial_test` (or per-test unique tenants/schemas)
  for tests that share global DB state; raise the CI Postgres `max_connections` only if the audit
  shows legitimate concurrent demand rather than a leak.
- **Add a test-level watchdog:** wrap DB-backed `#[tokio::test]` bodies in a `tokio::time::timeout`
  so a hung future panics with context rather than hanging the whole `cargo test` process.
- Consider running the DB-backed integration tests as a **dedicated, `--test-threads`-bounded**
  invocation separate from the unit tests, to cap concurrent DB pressure.

## Acceptance criteria

- Deterministic reproduction identified and the specific test(s) / shared resource named.
- Root cause fixed (pool acquire bounded / contended tests isolated / poisoned-lock path removed).
- DB-backed suite runs green under both `--test-threads=1` and default parallelism across ≥20 runs.
- The `timeout-minutes` guards can then be treated as a backstop rather than the primary defense.
