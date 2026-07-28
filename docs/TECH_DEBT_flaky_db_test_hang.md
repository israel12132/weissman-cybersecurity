# DB-backed Rust workspace test hang — root cause and fix

**Status:** Root-caused and fixed · **Area:** CI / DB-backed integration tests ·
**Filed:** 2026-07-18 · **Root-caused:** 2026-07-26

## Two distinct failure modes — do not conflate them

The `cargo test --workspace --all-targets` step that runs against a live Postgres service has
overrun its budget repeatedly. Investigation found **two different causes**, and earlier revisions
of this document merged them into one. They need different fixes.

| # | Failure mode | Evidence | Fix |
|---|---|---|---|
| **A** | The step's `timeout-minutes` is consumed by a **cold compile + link**, before any test runs | see below | Split compile from execution (`--no-run` step before each gate) |
| **B** | An **unbounded `pg_advisory_xact_lock()` wait** hangs a test that did start | reproduced on demand against live Postgres | `weissman_db::advisory_lock` (this document's §The fix) |

### Mode A is what the observed step-23 timeouts actually were

| Run | Observed | What the log shows |
|---|---|---|
| `30154927534` (attempt 3) | step 23 `in_progress` 14:15:02 → cancelled 15:01:52 = **46 m 50 s** | In the *same run*, `rust-audit` ran `cargo build --workspace` (12 m 05 s) **and then** `cargo test --workspace --all-targets` in **6 m 01 s**. engine-wiring has no pre-build step, so step 23 compiles every test target *inside* the gate. |
| `30188334763` | step 23 failed at **46 m 05 s** | At kill time the orphan processes were `cargo`, `rustc` ×4, `cc` ×3, `collect2` ×3 and **`rust-lld` ×3** — still linking, no test binary running. The Postgres service container was simultaneously crash-looping under I/O starvation (`database system was not properly shut down`, `issuing SIGKILL to recalcitrant children`, 180 s `fsync` stalls) while `rust-lld` linked multi-GB debug binaries. |

That is a budget/measurement problem, not a hang: the timeout was guarding the wrong thing. The
fix is to give compilation its own step and budget so the gate's timeout measures *execution*.

#### …and the compile itself was being starved by a duplicate CI run

Splitting compile from execution exposed a second layer. `on:` fires this workflow for both
`push` and `pull_request`, and the concurrency key was `github.ref` — which is
`refs/heads/<branch>` for one and `refs/pull/<n>/merge` for the other. The two keys differ, so a
branch with an open PR ran the **entire workflow twice, in parallel**, each run building the whole
workspace. Commit `a4f5ce4` (runs `30223674764` + `30223676128`) shows what that does to the
*identical* command, `cargo test --workspace --all-targets --no-run`:

| Run | rust-audit compile | engine-wiring compile |
|---|---|---|
| `30223674764` (push) | **17 m 03 s** ✅ | **41 m 49 s**, then `The runner has received a shutdown signal` ❌ |
| `30223676128` (PR) | **3 h 24 m**, still running | **8 m 01 s** ✅ |

Same command, same commit, four wildly different outcomes — and the Postgres service container
logged 352-second `fsync` stalls while it happened. That is runner I/O starvation, not a code
problem. The concurrency key is now `head_ref || ref_name`, which collapses both events onto one
key: one run per branch.

#### A wrong turn worth recording: "it must be disk"

With the duplicate run eliminated, `rust-audit`'s compile step still blew its budget. The first
theory was disk headroom — that job frees disk *before* `cargo install cargo-audit`/`cargo-deny`
and Clippy, so the heaviest link starts with the least free space. A second reclaim step was added
immediately before the link, printing `df -h /` either side.

**It was a no-op, and the timing proved it.** In run `30235471173` that step occupied the 15
seconds between 04:05:59 and 04:06:14 — because it deleted the *same paths* the job's existing
free-disk step had already deleted at startup. It could not free anything, so it never tested the
hypothesis it was meant to test. The compile then ran the full 60 minutes and was killed with four
`rust-lld` still resident.

The actual dominant cost is **debug info**, not free space: ~2300 test harnesses, and the
`fingerprint_engine` lib-test binary alone is ~2.7 GB at `debug = 2`. Four linkers each mmap'ing a
binary that size is what makes the step I/O-bound. Hence
`CARGO_PROFILE_{DEV,TEST}_DEBUG=line-tables-only` at job level. The lesson generalises: a
remediation that cannot be *observed to do something* is not evidence about the cause — check that
your fix actually changed the state you blamed.

**Confirmed.** On run `30239499487` (commit `156bcd1`) the same
`cargo test --workspace --all-targets --no-run` that had twice been SIGKILLed at the 60-minute
bound completed in **12 m 13 s** (05:37:13 → 05:49:26). Same command, same workspace, same runner
class — the only change was the debug level. The test gate that follows it ran in **7 seconds**,
which is also the cleanest evidence for the mode-A split: the tests were never the slow part.
`engine-wiring`'s own compile step, carrying the identical job-level values, took **3 m 26 s**.

Run `29650387309` (69 min, "no output progression") predates this analysis and its logs have
expired; it is **not** attributed to either mode here.

### Mode B is real, reproducible, and independently worth fixing

Mode B has not been caught red-handed in a specific CI run — but it is not speculative either. It
reproduces on demand (see the table under *The fix*), and until it is bounded, **any** contention
on these keys hangs the process forever rather than failing. The rest of this document is about
mode B.

## Mode B root cause (verified by reproduction)

**`pg_advisory_xact_lock()` waits forever, and in test binaries nothing bounded that wait.**

Four properties compose into the hang:

1. **The primitive never gives up.** `pg_advisory_xact_lock()` blocks until the holder's
   transaction ends. Postgres' deadlock detector only breaks true *cycles*; a plain
   "A holds the key, B waits" chain is not a cycle, so B is never woken and never errors.
2. **The keys are coarse and shared.** `fingerprint_engine::audit_log::insert_audit` locks on
   `tenant_id` — the coarsest key in the codebase. Its 12 call sites sit on paths every session
   and every scan crosses (login failure, SAML, OIDC, scan routing) plus SOAR, council, strategy
   and self-improve. `weissman-job-bus::events::append_event` locks per `job_id` and fires on
   every job-lifecycle transition. Tests reuse a small set of tenant ids, so unrelated test
   binaries running concurrently against the one CI Postgres contend on the *same* advisory key
   with no bound. Two further sites share the shape: `audit_log::backfill_tenant_hashes`, and —
   added later by #211 — `auto_heal_job`'s per-`(tenant, finding)` start guard.
3. **Only test connections were unbounded.** The product pools in `crates/weissman-db/src/lib.rs`
   set `statement_timeout` in `after_connect`, which *does* count lock-wait time — so in the
   server and worker a blocked advisory lock dies (crudely) after ~120 s. Every **test** pool is
   built from a bare `PgPoolOptions::new()`, inheriting `lock_timeout = 0` and
   `statement_timeout = 0` — *infinite*. The identical code path was bounded in production and
   unbounded under `cargo test`.
4. **Only one job actually runs these tests.** `rust-audit` and `rust-coverage` declare no
   `services`, so the DB-backed tests skip there; `engine-wiring-and-smoke` declares
   `postgres` + `redis`. That is precisely why the hang is specific to that job — and why the
   sibling job "passing the same command" was never the exoneration it looked like.

### The pool-exhaustion hypothesis was wrong

Earlier revisions of this document ranked **connection-pool exhaustion** as the most likely
mechanism. That is falsified: sqlx's `PoolOptions` default `acquire_timeout` is **30 seconds**
(`sqlx-core-0.8.6/src/pool/options.rs:160`), so a starved pool raises `PoolTimedOut` in 30 s. It
cannot produce a 46-minute stall — and the 46-minute stalls turned out to be mode A anyway. Pool
pressure remains a *contributing* stressor for mode B (it widens the window in which one
transaction sits on the advisory key), but it was never what made the wait unbounded.

## The fix

### 1. The bound is now intrinsic to the lock (`crates/weissman-db/src/advisory_lock.rs`)

Every advisory-lock acquisition in the workspace goes through one helper, which issues a
transaction-scoped `SET LOCAL lock_timeout` immediately before the wait. The bound therefore
travels with the *lock*, not with whichever pool the caller happened to construct — the non-local
property that made this bug possible in the first place.

| Helper | Semantics | Used by |
|---|---|---|
| `advisory_xact_lock(conn, i64)` | Bounded wait; `Err` (SQLSTATE `55P03`) on timeout | `insert_audit`, `backfill_tenant_hashes` |
| `advisory_xact_lock_text(conn, &str)` | Same, key folded via `hashtextextended(key, 0)` | `job-bus::append_event` |
| `advisory_xact_lock_text_or_skip(conn, &str)` | Bounded wait inside a **savepoint**; `Ok(false)` on timeout, transaction stays usable | `auto_heal_job` start guard |

Default bound **15 s** (`WEISSMAN_LOCK_TIMEOUT_MS` to override; the earlier name
`WEISSMAN_ADVISORY_LOCK_TIMEOUT_MS` is still honoured as a fallback so existing deployments keep
working, but it no longer describes the scope. `0` is rejected because it means *infinite* to
Postgres). Deliberately far below the 120 s app-pool `statement_timeout`, so a genuine lock
problem surfaces as a precise `lock_not_available` naming the key rather than a generic statement
timeout that could have come from anywhere.

### The same defect in different syntax: blocking row locks

Bounding advisory locks closed the call sites this workspace *noticed*, not the defect. Postgres'
`lock_timeout` is not advisory-lock-specific — it bounds any wait for any lock — and
`SELECT … FOR UPDATE` blocks indefinitely by default for exactly the same reason, with exactly the
same symptom. Four such sites existed, none of them bounded:
`auth_refresh::rotate_refresh_token`, `council_hitl`, and two in `self_improve`.

Reproduced directly (live Postgres 16, one session holding the row):

| | Result |
|---|---|
| `lock_timeout = 0` — the bare test-pool shape | never returned; killed by an external 8 s timeout |
| `lock_timeout = 1500ms` | `ERROR: canceling statement due to lock timeout` in **1580 ms** |

The bound is applied one level up rather than at each site: `set_tenant_tx` — the single funnel
every tenant transaction passes through (236 call sites across 87 files) — now sets `lock_timeout`
**in the same `SELECT`** as the RLS GUC, so it costs no extra round trip and covers every future
blocking wait rather than only the ones someone remembered to wrap.
`advisory_lock::bound_lock_wait` is public for transactions that carry no tenant GUC —
`auth_refresh` runs on the auth pool and calls it explicitly right after `begin()`.

`FOR UPDATE SKIP LOCKED` (the job-queue claim path) never waits and needed no change.

The row locks themselves are **kept**: they are what make read-then-write atomic, and in
`rotate_refresh_token` specifically they are what stops two concurrent presentations of one
refresh token from both succeeding. Bounding the wait does not weaken that — on timeout the
statement errors, the transaction aborts, and neither rotation commits.

Two design points that are easy to get wrong:

- **This does not weaken serialization.** The three correctness-critical sites protect a
  read-then-append pair on a tamper-evident hash chain. On timeout they return `Err`, the
  caller's transaction aborts, and the protected work is **never** performed unserialized.
  "Fail fast and loudly" replaces "hang forever" — not "hold the lock".
- **Callers were audited for the new error path.** All 12 `insert_audit` call sites either
  `let _ = …` and then immediately `commit()`, or log and commit — none run further statements on
  the transaction afterwards, so an aborted transaction cannot corrupt a partially-applied write.
  The one caller that propagates, `ceo::safe_mode::set_tenant_global_safe_mode`, writes
  `system_configs` *and* the audit row in one transaction: a lock timeout now rolls the toggle
  back and returns an error, rather than hanging while holding a connection. A security-relevant
  config change not being applied without its audit record is the correct outcome.
- **The `_or_skip` variant needs the savepoint.** In Postgres *any* error inside a transaction
  aborts it, so every later statement fails with `25P02 current_transaction_is_aborted`. Without
  the savepoint, `auto_heal_job`'s documented fail-open fallback would itself error out — the
  "fail-open" branch was already unreachable before this change, because a bare
  `pg_advisory_xact_lock` does not *error* when contended, it waits.

### 2. Database-level backstop (`.github/workflows/ci.yml`)

After migrations, before the Rust test step:

```sql
ALTER DATABASE weissman SET lock_timeout = '30s';
ALTER DATABASE weissman SET idle_in_transaction_session_timeout = '300s';
```

Set at the **database** level so it is inherited by every connection from every pool in every test
binary, none of which configure timeouts themselves. This catches what the helper cannot: blocking
waits we do not own (sqlx's own migration advisory lock, a plain `SELECT … FOR UPDATE`, a DDL
`ACCESS EXCLUSIVE` wait) and any future call site that forgets the helper.

- `30s` > the helper's `15s`, so a helper-mediated lock still fails with its precise error rather
  than this generic net.
- `idle_in_transaction_session_timeout` reaps the lock **holder** — the other half of the hang. A
  transaction that takes the key and then goes idle forever is cleared in 300 s, which is far above
  any legitimate in-transaction pause by the server/worker on this database and far below the
  45-minute step budget.
- It runs **after** migrations so a slow DDL lock during the migration run is never bounded.

### 3. Regression test (`crates/weissman-db/tests/advisory_lock_bound.rs`)

Three DB-backed contracts, each deliberately built on a bare `PgPoolOptions::new()` — the exact
unbounded pool shape every test in this workspace uses — so they prove the bound comes from the
helper and not from pool configuration a refactor could drop:

1. a contended lock returns `55P03` near the configured bound instead of hanging;
2. the `_or_skip` variant leaves the caller's transaction usable *and* restores `lock_timeout`;
3. the success path is unchanged — the lock is genuinely held afterwards.

## Guards that must not be removed

| Guard | Location | Purpose |
|---|---|---|
| `SET LOCAL lock_timeout` before every advisory lock | `crates/weissman-db/src/advisory_lock.rs` | The actual fix. Makes the wait bounded regardless of pool, environment or caller. |
| `no_unbounded_lock_waits` | `crates/weissman-db/tests/` | Makes Rules 1 and 2 below self-enforcing: fails the existing blocking `cargo test` gate if any Rust source takes a blocking advisory lock outside the helper, **or** a blocking row lock (any of the four modes: `FOR UPDATE` / `FOR NO KEY UPDATE` / `FOR SHARE` / `FOR KEY SHARE`) in a file not reviewed as bounded. Row-lock matching normalises whitespace across the whole file, so a `SKIP LOCKED` split onto its own line is correctly not flagged. Both tech-debt documents in this repo record guards that were added and later silently lost; a rule stated only in prose is one of those. |
| `set_config('lock_timeout', …)` in `set_tenant_tx` | `crates/weissman-db/src/lib.rs` | Bounds **every** lock wait in **every** tenant transaction, from the single funnel all 236 call sites pass through. Must stay in the same `SELECT` as the RLS GUC — that is what makes it free. Deleting it silently restores unbounded `FOR UPDATE` waits under `cargo test`; `tenant_tx_lock_bound::begin_tenant_tx_applies_a_finite_lock_timeout` is the test that catches it. |
| `tenant_tx_lock_bound` | `crates/weissman-db/tests/` | Three DB-backed contracts on deliberately bare pools: the bound is applied, a contended row lock errors instead of hanging, and the success path is unchanged. The first is the load-bearing one — a `!= 0` check alone would pass on the un-fixed code wherever the CI database backstop is present, so it asserts the exact configured value. |
| `ALTER DATABASE … lock_timeout / idle_in_transaction_session_timeout` | `.github/workflows/ci.yml` | Backstop for blocking waits we do not own and for future call sites that bypass the helper. |
| `--test-threads=2` | `.github/workflows/ci.yml` (both Rust test steps) | Contention *pressure* reducer. Not the fix — it narrows the window, it does not bound the wait. Keep it: it also keeps concurrent DB work under the pool ceiling. |
| `--no-run` compile step before each Rust gate | `.github/workflows/ci.yml` (both Rust jobs) | Fix for mode A. Keeps cold compile+link out of the gate's budget so a test-step timeout means "the tests hung" and nothing else. Deleting it silently re-arms the 46-minute overrun. |
| `timeout-minutes: 25` on the gates, `40`/`60` on the compile steps | `.github/workflows/ci.yml` | Sized to what each step actually does (~6–8 min execution; cold link ~17–20 min healthy). Only meaningful because compile and execution are separate — do not merge the steps back together and keep these numbers. **Every** long step needs a ceiling: the rust-audit compile step originally had none and was observed sitting at 3h24m, which is the same "unbounded wait" mistake as mode B, one layer up. |
| `CARGO_PROFILE_DEV_DEBUG` / `CARGO_PROFILE_TEST_DEBUG` = `line-tables-only` | `.github/workflows/ci.yml` (**both** Rust jobs, **job-level**, identical values) | Debug info is the dominant cost in the all-targets link (~2300 test harnesses; the fingerprint_engine lib-test binary alone is ~2.7 GB at `debug = 2`). Keeps file+line in backtraces, drops the rest. Must stay at **job** level: cargo fingerprints on the profile, so if the compile and run steps disagreed the run step would recompile everything and defeat the compile/execute split. Must also stay **identical across rust-audit and engine-wiring-and-smoke**: they restore the same cache key (`${{ runner.os }}-cargo-<Cargo.lock hash>`), so a mismatch makes each job's cached `target/` a total fingerprint miss for the other and forces a full rebuild in *both* — worse than no shared cache. (`rust-coverage` is exempt: it has no cache step and llvm-cov injects its own instrumentation flags, so its fingerprint differs by construction.) |
| `concurrency.group` keyed on `head_ref \|\| ref_name` | `.github/workflows/ci.yml` | One CI run per branch. Keyed on `github.ref` a branch with an open PR ran the whole workflow **twice** in parallel (`refs/heads/<branch>` vs `refs/pull/<n>/merge`), and the two runs fought for runner I/O — see the timing table below. Reverting this key silently doubles CI load and reintroduces the contention. |

## Rules

1. **Never** call `pg_advisory_xact_lock` / `pg_advisory_lock` directly from anywhere outside
   `weissman_db::advisory_lock` — the helper is the one place that issues the raw statement, and
   it does so immediately after setting the bound. An unbounded blocking primitive on a connection
   whose timeouts are set somewhere else is how this bug happened. Enforced by
   `crates/weissman-db/tests/no_unbounded_lock_waits.rs`, whose `ADVISORY_ALLOWED` list is the
   authoritative set of exemptions.
2. **Never** take a blocking row lock — all four modes (`FOR UPDATE`, `FOR NO KEY UPDATE`,
   `FOR SHARE`, `FOR KEY SHARE`) wait indefinitely by default, including the weak
   `FOR KEY SHARE` — in a
   transaction that does not carry a `lock_timeout`. In practice: begin it with
   `begin_tenant_tx`, or call `advisory_lock::bound_lock_wait` right after `begin()` when there is
   no tenant GUC, or use `SKIP LOCKED` / `NOWAIT` if the work is genuinely skippable. Enforced by
   the same test's `blocking_row_locks_live_only_in_reviewed_files`, whose `ROW_LOCK_ALLOWED` list
   requires each entry to name the mechanism that bounds it.
3. A guard whose "fail-open" branch is only reachable on *error* is not fail-open if the primitive
   it guards blocks instead of erroring. Bound it, then the fallback is real.
4. If you add a DB-backed test, it inherits the CI database's `lock_timeout` — assume any lock
   wait can fail, and let it fail rather than retrying it into a hang.
5. If you change any bound in the table above, update this table in the same commit.

## Residual work (non-blocking)

- ~~Give test-side `PgPoolOptions` an explicit small `acquire_timeout`.~~ **Done**, and the audit
  behind it is worth keeping. Of the DB-backed test pools, four already set one deliberately
  (`persist_real_pool_starvation`, `llm_metering_pool_starvation`, `findings_persist_pool_starvation`,
  `soar_playbook_e2e` — 4–5 s, since starvation is what they test); two were bare only by omission
  and now set 5 s (`tenant_quota_integration`, `rls_cross_tenant`).

  The remaining two — `advisory_lock_bound` and `tenant_tx_lock_bound` — are bare **on purpose and
  must stay bare**: they exist to prove the lock bound is intrinsic to the lock/transaction rather
  than inherited from pool configuration, so configuring their pools would delete the property
  they assert. If a future sweep "fixes" them for consistency, it has silently removed the
  regression test for this entire document.

- **Open: `std::env::set_var` races in two test files.** A different flakiness mechanism from the
  one this document root-caused, found while auditing for it, recorded here so it is not lost.

  `cargo test` runs the tests *within one binary* on multiple threads, and `set_var` is
  process-global — so it races with any concurrent reader in the same file. (Across files it is
  harmless: each integration test file is its own process.) Rust 2024 makes the call `unsafe` for
  exactly this reason. The dangerous shape is a **set/remove pair**, where one test clearing a
  variable another test depends on produces a failure that does not reproduce:

  | File | Tests | Env mutations | Risk |
  |---|---|---|---|
  | `fingerprint_engine/tests/auto_heal_roundtrip.rs` | 10 | 4 | **Real** — sets then removes `WEISSMAN_VERIFY_CLONE_URL_OVERRIDE` |
  | `fingerprint_engine/tests/tenant_quota_integration.rs` | 3 | 5 | **Real** — sets then removes `GITHUB_TOKEN` / `WEISSMAN_GITHUB_TOKEN` |
  | `fingerprint_engine/tests/benchmark_repro.rs` | 1 | 1 | None — a single test has nothing to race |
  | `fingerprint_engine/tests/persist_real_pool_starvation.rs` | 1 | 1 | None — same |

  Not fixed here deliberately. The fix is to serialize the env-touching tests (or inject the
  config instead of reading the environment), which means restructuring tests this change does not
  otherwise touch, immediately before a merge — the risk of breaking a currently-green gate
  outweighs closing a latent race. `crates/weissman-db/src/advisory_lock.rs` and its tests show the
  pattern to copy: they take an explicit `*_with_timeout` parameter precisely so the suite never
  has to mutate the environment.
