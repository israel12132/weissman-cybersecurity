# Rust Coverage Deficit Analysis

**Ordered by the coverage mandate: no floor lowering, no coverage padding — measure
the truth and explain the gap.**

| Item | Value |
|---|---|
| Measurement | `cargo llvm-cov --workspace --lib` (unit tests) |
| **Measured line coverage** | **19.32%** (42,868 of 221,884 lines covered; 179,016 uncovered) |
| Region coverage | 20.15% · Function coverage: 25.37% |
| CI floor (`--fail-under-lines`) | **40%** — kept intact; **not** lowered |

> Integration/E2E coverage is **not** in this number. `--lib` measures only unit
> tests compiled into each library. The DB-backed and live-stack tests that actually
> exercise the engines (the `engine-wiring` job: server + ZAP + Playwright + live
> pipeline E2E) are excluded by `--lib` and cannot run in this single-container dev
> environment (no docker daemon / Postgres, and the full instrumented all-targets
> build exceeds the ~30 GB disk budget). **The true platform coverage can only be
> measured in CI** — see "Recommended path" below.

---

## 1. Why the number is structurally low (the root cause)

The workspace is overwhelmingly one crate of I/O-bound attack engines:

| Area | Lines | % of workspace | `--lib` line cov |
|---|---:|---:|---:|
| `fingerprint_engine/src` | 214,420 | **96.6%** | 19.5% |
| `crates/*` (db, core, job_bus, fleet_shaping, …) | 3,347 | 1.5% | 18.5% |
| `backend/weissman-server` | 3,761 | 1.7% | 10.2% |
| `fuzz_core` | 356 | 0.2% | 0.0% |

**96.6% of the code is `fingerprint_engine/src`, and it is the product: the attack
and scan engines.** These are not boilerplate or generated code — excluding them to
hit 40% would be exactly the coverage-padding the mandate forbids. **34 of 84
`*_engine.rs` files sit below 10% line coverage.**

---

## 2. Categorization of the uncovered code

### (A) Untestable-at-unit-level — I/O-bound engine probes  *(the dominant sink)*

These make live network calls, drive external cloud/OT/host APIs, or require a
running server + DB. They are validated by **integration / live-stack E2E** (the
`engine-wiring` job), which `--lib` does not observe. Representative sinks:

| File | ~Lines | Kind |
|---|---:|---|
| `src/bgp_dns_hijacking_engine.rs` | 5,138 | network routing/DNS probes |
| `src/file_upload_engine.rs` | 4,935 | live HTTP upload attack probes |
| `src/cloud_posture_engine/inc/scanners.inc.rs` | 4,497 | cloud API scanners (0%) |
| `src/email_dns_posture_engine.rs` | 4,202 | live DNS/SMTP posture probes |
| `src/graphql_attack_engine.rs` | 3,980 | live GraphQL attack probes |
| `src/mtls_grpc_engine.rs` | 3,645 | live mTLS/gRPC probes |
| `src/k8s_container_engine.rs` | 3,621 | live k8s API probes |
| `src/cicd_pipeline_engine.rs` | 3,498 | live CI/CD API probes |
| `src/{azure,gcp}_attack_engine.rs` | 2,336 / 2,219 | live cloud-provider APIs |
| `src/{smb_netbios,websocket,http_smuggling,oauth_oidc,password_spray}_engine.rs` | 2,000–2,800 ea. | live protocol probes |
| `src/server_handlers_{rest,rest4,sqlx,platform}.inc` | ~10,250 total | HTTP handlers (need running server, 0%) |
| `src/{orchestrator/mod,async_job_executor,alias_engine_runner}.rs` | ~7,000 total | async runtime orchestration |

Estimated ≈ **150k+ lines** fall in this category. They are covered by the live
E2E, not by `--lib` unit tests.

### (B) Genuine business-logic gaps — testable, worth real unit tests

Pure, deterministic logic that **can** be unit-tested and is the legitimate target
for "write genuine tests." Examples: engine taxonomy/selection scoring, target
classifier heuristics, alias dedup, stealth-queue pacing math, PDF/report builders
(`compliance_engine.rs`, `pdf_report.rs`), belief/telemetry/manifest signing (these
last three already have unit tests in `weissman_ui_provenance`). This is a **small
fraction of the 214k engine lines** — a solid campaign here adds a few points, not
twenty.

### (C) Dead-code candidates

Not machine-verified here (requires `RUSTFLAGS="-W dead_code"` / `cargo-udeps` on a
full build, which the disk budget blocked). Flagged as a follow-up; expected to be
a minor contributor.

---

## 3. The achievable ceiling (honest math)

- To reach 40% **by unit tests alone**: covered lines must go from 42,868 →
  ≥ 88,754, i.e. **~46,000 additional covered lines**. Category (B) — the genuinely
  unit-testable logic — is far smaller than that, so the remainder would have to be
  mock-heavy tests over the I/O engines: a multi-month effort producing low-value
  tests that assert against mocks rather than real behavior.
- To reach 40% **by exclusion**: you would have to drop ~115k of 221k lines from the
  denominator — i.e. more than half the codebase, the engines themselves. That is
  coverage-padding and is **rejected**.
- **Realistic honest ceiling for `--lib` alone: ~22–25%** (current 19.3% + a genuine
  category-B unit-test campaign). `--lib` will not reach 40% on an I/O-engine
  platform, by construction.

---

## 4. Recommended path (no gaming, no floor change)

**Measure coverage the way the platform is actually tested.** The engines' real
coverage lives in the integration/live-stack E2E, which `--lib` discards. The
sanctioned fix is to change the `rust-coverage` CI job to measure that:

1. **Path A — true integration coverage (primary):** add the Postgres (pgvector) +
   Redis services to the `rust-coverage` job (as `engine-wiring` already has), set
   `TEST_DATABASE_URL`, and measure `cargo llvm-cov --workspace` (drop `--lib`) so
   the DB-backed and integration tests count toward the denominator's *covered*
   side. This raises the number **legitimately** — it counts real tests exercising
   real code, excludes nothing, and does not touch the 40% floor.
2. **Path B — genuine unit tests (incremental):** add category-(B) unit tests for the
   pure-logic modules. Real, reviewable coverage gains, done in batches.

Only after Path A is measured in CI (with the DB the engines need) can we honestly
judge whether 40% is met or what the true ceiling is — and set floor policy on
**facts**, not on lowering the bar or padding the metric.

---

_Basis: `cargo llvm-cov --workspace --lib` on the workspace. The `--workspace`
(integration-inclusive) local measurement was attempted but could not complete
within this dev container's disk budget; it belongs in CI. Numbers will shift by a
point or two as `main` evolves, but the structural conclusion is base-independent._
