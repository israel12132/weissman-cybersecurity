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

Default bound **15 s** (`WEISSMAN_ADVISORY_LOCK_TIMEOUT_MS` to override; `0` is rejected because
it means *infinite* to Postgres). Deliberately far below the 120 s app-pool `statement_timeout`,
so a genuine lock problem surfaces as a precise `lock_not_available` naming the key rather than a
generic statement timeout that could have come from anywhere.

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
| `no_raw_advisory_locks` | `crates/weissman-db/tests/` | Makes Rule 1 below self-enforcing: fails the existing blocking `cargo test` gate if any Rust source outside the helper takes a blocking advisory lock. Both tech-debt documents in this repo record guards that were added and later silently lost; a rule stated only in prose is one of those. |
| `ALTER DATABASE … lock_timeout / idle_in_transaction_session_timeout` | `.github/workflows/ci.yml` | Backstop for blocking waits we do not own and for future call sites that bypass the helper. |
| `--test-threads=2` | `.github/workflows/ci.yml` (both Rust test steps) | Contention *pressure* reducer. Not the fix — it narrows the window, it does not bound the wait. Keep it: it also keeps concurrent DB work under the pool ceiling. |
| `--no-run` compile step before each Rust gate | `.github/workflows/ci.yml` (both Rust jobs) | Fix for mode A. Keeps cold compile+link out of the gate's budget so a test-step timeout means "the tests hung" and nothing else. Deleting it silently re-arms the 46-minute overrun. |
| `timeout-minutes: 25` on the gates, `40`/`45` on the compile steps | `.github/workflows/ci.yml` | Sized to what each step actually does (~6–8 min execution; cold link ~17–20 min). Only meaningful because compile and execution are separate — do not merge the steps back together and keep these numbers. **Every** long step needs a ceiling: the rust-audit compile step originally had none and was observed sitting at 3h24m, which is the same "unbounded wait" mistake as mode B, one layer up. |
| `concurrency.group` keyed on `head_ref \|\| ref_name` | `.github/workflows/ci.yml` | One CI run per branch. Keyed on `github.ref` a branch with an open PR ran the whole workflow **twice** in parallel (`refs/heads/<branch>` vs `refs/pull/<n>/merge`), and the two runs fought for runner I/O — see the timing table below. Reverting this key silently doubles CI load and reintroduces the contention. |

## Rules

1. **Never** call `pg_advisory_xact_lock` / `pg_advisory_lock` directly from anywhere outside
   `weissman_db::advisory_lock` — the helper is the one place that issues the raw statement, and
   it does so immediately after setting the bound. An unbounded blocking primitive on a connection
   whose timeouts are set somewhere else is how this bug happened. Enforced by
   `crates/weissman-db/tests/no_raw_advisory_locks.rs`, whose `ALLOWED` list is the authoritative
   set of exemptions.
2. A guard whose "fail-open" branch is only reachable on *error* is not fail-open if the primitive
   it guards blocks instead of erroring. Bound it, then the fallback is real.
3. If you add a DB-backed test, it inherits the CI database's `lock_timeout` — assume any lock
   wait can fail, and let it fail rather than retrying it into a hang.
4. If you change any bound in the table above, update this table in the same commit.

## Residual work (non-blocking)

- Give test-side `PgPoolOptions` an explicit small `acquire_timeout` anyway. Not needed for this
  hang (the 30 s default already bounds it) but it makes the failure message name the pool.
