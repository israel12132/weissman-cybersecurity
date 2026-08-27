# Changelog

All notable changes to the Weissman Cybersecurity platform are documented here.
Versions follow CalVer (`YYYY.MM.<patch>`); each entry maps to one rollout phase.

---

## [Unreleased]

### Added

- **TenantScopeGuard (architect merge blocker).** Authenticated API tree runs
  Axum middleware `tenant_scope_guard` after `auth_guard`. JWT `cid` /
  `assigned_client_id` is the sole customer-session anchor: spoofed
  body/query/path `client_id` is overwritten. Every `begin_tenant_tx` stamps
  `SET LOCAL app.current_tenant_id` **and** `app.current_client_id` so FORCE
  RLS still holds when a handler forgets `bind_requested_client`. Impersonation
  is `POST /api/auth/scope-switch` against `user_client_scope_grants` — it
  mints a **new JWT** (never a client-side picker that keeps the old token).
  Portal users with a bound customer receive 403 `portal_scope_locked`. Every
  switch is appended to `user_scope_switch_audit`.
- **Dynamic compliance framework catalog.** `compliance_frameworks` is now the
  authoritative list of in-scope frameworks (migration
  `20260729120000_compliance_frameworks_dynamic_and_onboarding.sql`, mirrored to
  `weissman-db`). `GET /api/compliance/frameworks` reads from it and reports which
  source served the list via a `dynamic` flag, falling back to the historical list
  only when the table is unavailable. The hardcoded Rust vec is gone.
- **Six frameworks onboarded to the live control-mapping gate** — SOC2, NIS2, GDPR,
  IEC62443, PCI and CSA-CCM. Each canonical control is bound to a verified,
  audit-traceable, **evidence-only** platform source (Postgres RLS isolation,
  tamper-evident audit hash chain, distributed login lockout, startup-enforced TLS
  policy, agentless cloud posture, live vulnerability management). No engines were
  modified and no stale-engine references introduced. Previously these frameworks
  were listed in the UI but carried no live mappings, so they passed the enforcement
  gate un-evaluated.

### Changed

- **One compliance integrity gate, not two.** The parallel mapping-integrity work is
  unified into the single `report_gate` + diagonal `Tm` watermark pipeline.
  `compliance_framework_orphans` folds three signals for every official artifact
  (framework PDF report **and** signed evidence pack):
  1. coverage gap (`find_orphaned_controls`),
  2. **listed-but-unmapped** — a framework the catalog lists but that carries no live
     control mapping now voids the artifact,
  3. **dead predicate** (`find_dead_predicate_controls`) — a control in
     `compliance_mappings` whose every row is structurally dead (no cloud rule id, no
     vulnerability predicate) can never be violated, so it is silently reported
     "compliant" forever.
- **Evidence pack is gated on the enabled compliance surface**, not a hardcoded slug
  list. `find_orphaned_controls` returns *no* orphans for a framework with zero live
  mappings (it cannot tell "not onboarded" from "fully covered"), so every framework in
  the old `COMPLIANCE_UI_SLUGS` list that carried no mappings — SOC2, NIS2, GDPR,
  IEC62443, PCI, CSA-CCM, plus NIST / HIPAA / FedRAMP — passed the gate untested. That
  hole is now closed from both sides: the six product frameworks are genuinely mapped,
  and the listed-but-unmapped signal fails any framework the catalog lists without
  mappings. NIST / HIPAA / FedRAMP are deliberately not listed until their evidence
  sources exist, so they are out of scope rather than silently "compliant".

### Fixed

- **SOAR playbook E2E verifier is hermetic.** `scripts/verify_soar_playbook_e2e.mjs`
  fired against a hard-coded `tenant_id: 1` / `client_id: 1`, violating the
  `soar_action_executions.client_id → clients(id)` foreign key on any stack where
  that row was never seeded. It now takes the tenant from the login response and
  seeds its own probe client, mirroring the fix already applied to the Rust
  `soar_playbook_e2e` integration test.
- **i18n `defaultValue` ratchet re-armed at zero.** The last two inline fallbacks
  (`common.clear` in `pages/RemediationHub.jsx`) are keyed in `en`/`he`, and
  `scripts/i18n-defaultvalue-baseline.json` — still pinned at the historical 223
  occurrences long after the migration finished, so it silently permitted a full
  regression — is tightened to `{}`. Any new inline `defaultValue` now fails the
  build. Closes item 1 of `docs/PRODUCT_DEBT_BACKLOG.md`.

### Security

- **Removed the `genpdf` dependency** from `fingerprint_engine`, clearing the
  `RUSTSEC-2026-0187` `lopdf` deeply-nested-parse stack-overflow advisory (reached
  only via `genpdf → printpdf → lopdf`) and dropping the whole unmaintained subtree
  it pulled in — `time 0.2.x`, `stdweb`, `rusttype`, `stb_truetype`, `printpdf`,
  `lopdf`. The `RUSTSEC-2026-0187` `cargo audit` / `deny.toml` ignore is removed, so
  a reintroduction of `lopdf` now fails the build.
  - Also dropped the stale `RUSTSEC-2026-0049` ignore — that advisory is no longer
    detected on the current dependency lock (confirmed with `cargo audit`).
  - The `RUSTSEC-2026-0098/0099/0104` ignores are **removed**. Those `rustls-webpki
    0.101.7` advisories rode in on the AWS SDK's legacy `rustls 0.21` hyper-0.14
    connector, pulled by each `aws-sdk-*` crate's default `rustls` feature. Those crates
    are now declared `default-features = false` + the modern `rustls-aws-lc` connector
    (`rustls 0.23.40` / `rustls-webpki 0.103.13`), so the `rustls 0.21` subtree left the
    lock entirely; the advisories no longer resolve and a reintroduction now **fails** the
    `cargo audit` / `deny.toml` gate. The only advisory still ignored is
    `RUSTSEC-2023-0071` (rsa Marvin timing, via `openidconnect` for RS256 JWT
    verification — no fixed `rsa` release exists).
- **Executive/board PDFs now render natively** via the existing hand-written
  `%PDF-1.4` writer in `fingerprint_engine/src/pdf_report.rs` (base-14 Helvetica,
  no font embedding, no third-party PDF crate). `executive_pdf::render_executive_board_pdf`
  keeps the same public signature, so the report endpoint is unchanged.
- Dropped the now-obsolete `WEISSMAN_GENPDF_FONT_DIR` env var and the
  `fingerprint_engine/fonts/` Liberation-Sans staging directory.

---

## [2026.06.2] — Liminal Boundary Engine — 2026-06-10

### Added

- **`liminal_boundary`** — world-first protocol-stack fracture detector
  (`fingerprint_engine/src/liminal_boundary_engine.rs`):
  - **Protocol schism** — live HTTP/1.1-only vs HTTP/2 (ALPN) differential probing;
    flags auth bypasses (403→200), shadow-stack body divergence, entropy-based canary detection.
  - **Cache Vary oracle** — detects language/cookie-variant content that is publicly
    cacheable without a correct `Vary` header (personalized-content leak class).
  - **Trusted-header rewrite** — probes `X-Original-URL`, `X-Rewrite-URL`,
    `X-Forwarded-Prefix` for internal-path exposure via edge routing trust gaps.
  - Registered as production engine #254; included in baseline scan bundle; UI entry in
    Engine Matrix; aliases `protocol_schism_oracle`, `cache_vary_oracle`.
  - `reqwest` gains `http2` feature; `engine_probes` adds `http1_client`, `http2_client`,
    `http_get_with_headers`.

---

## [2026.06.0] — Autonomous-Defence Phase 3 — 2026-06-08

The rollout that converts Weissman from "advanced scanner" into a closed-loop
autonomous defence platform. All work is real and live; **zero simulation**.

### Added

#### 3.4 Financial blast-radius (`$-at-risk`)
- New module `fingerprint_engine/src/financial_risk.rs` with FAIR-aligned
  SLE/ALE math: `SLE = asset_value × max(CVSS/10, 0.5)`,
  `ALE = SLE × min(EPSS×12, 12) × discount`; KEV-listed CVEs floor ARO at 1.0/yr.
- New tables `client_asset_value_rules`, `client_financial_risk_snapshots`;
  new columns `risk_graph_nodes.business_value_usd / asset_replacement_cost_usd /
  tags`, `clients.default_asset_value_usd / risk_loss_discount`.
- Endpoints: `GET /api/financial-risk/:client_id[?recompute=1]`,
  `POST /api/financial-risk/:client_id/apply-tags`.
- `frontend/src/pages/Clients.jsx` rewritten — replaces "N critical findings"
  with `$-at-risk` hero band (SLE worst, ALE annualised, crown-jewel value,
  total asset value) plus a per-client card `$-at-risk` headline.

#### 3.3 Auto-pentest reinforcement loop
- New module `fingerprint_engine/src/pentest_memory.rs` with stable target
  fingerprint (`host + server + powered_by + sorted tech_stack`),
  `record_win(engine, cwe, sig, payload, evidence, status, target_fp)`,
  `prior_winners(engine, target_fp, K)` using HNSW ANN over `vector(1536)`
  target embeddings.
- New table `pentest_winning_paths` with `won_count`, `replay_count`,
  `replay_hit_count` so the reinforcement learning rate is measurable.

#### 3.1 Endpoint UEBA (User & Entity Behaviour Analytics)
- Agent: `crates/weissman-agent/src/detections/baseline.rs` — periodic sampler
  for open ports, top processes, unique users, load/memory, failed logins;
  hour-of-week bucket. New capability `ueba_baseline`.
- Server: `fingerprint_engine/src/ueba_detector.rs` — 7-day rolling baseline
  per `(agent, metric, hour_of_week)`, z-score detector (`|z| > 3` → `medium`,
  `> 6` → `high`), and new-port / new-process categorical detector. Strict
  learning-window contract: never fires before 24 samples in the bucket.
- New tables `agent_metric_samples`, `agent_metric_baselines`, `agent_anomalies`.
- Endpoints: `POST /api/ueba/ingest`, `GET /api/ueba/anomalies`.
- Hourly retention loop purges samples older than 14 days.

#### 3.2 Ask Weissman (NL → safe SQL)
- New module `fingerprint_engine/src/nl_query.rs` — LLM emits a strict JSON
  `QueryPlan` (never raw SQL); server validates against an allow-list of 6
  tables × ~50 columns × 10 operators, compiles to parameterised SQL with
  `tenant_id = $1` enforced, executes against the **dedicated read-only
  Postgres role** `weissman_ro` (SELECT-only, `statement_timeout=15s`,
  `idle_in_transaction_session_timeout=30s`).
- New table `nl_query_audit` records every question + compiled SQL + rows + ms.
- Endpoint: `POST /api/ask`. UI: `frontend/src/pages/AskWeissman.jsx`
  (chat-style transcript with collapsible SQL preview per turn).

### Changed

- Workspace `Cargo.toml` now includes `crates/weissman-agent`.
- `crates/weissman-db/Cargo.toml` gains `sha2`, `thiserror`, `tokio` (fs feature)
  for the no-transaction pre-runner (see 2026.06.1).
- Cockpit hero (`ExecKpiStrip` + `LiveActivityFeed` + `MitreCoverageHeatmap` +
  `SeverityTrendChart` + `TopMoversPanel`) is the default landing surface.
- `OpenAPI 3.1` spec at `/api/openapi.json` now lists every phase-1/2/3 endpoint
  with full descriptions; raise the crate `recursion_limit` to 512 for the
  inline spec macro.

---

## [2026.06.1] — Migration runner: out-of-transaction support — 2026-06-08

### Added

- `crates/weissman-db/src/no_tx_migrations.rs` — pre-runner that detects the
  `-- weissman:no-transaction` header on line 1 of a migration file, executes
  each statement outside any transaction (multi-statement-safe SQL splitter
  that respects single/double quotes, line/block comments, dollar-quoted
  blocks), records the file in `_sqlx_migrations` with the SHA-384 checksum
  format SQLx itself uses. Subsequent boots see those rows and skip.
- `crates/weissman-db/migrations/20260608150000_async_jobs_pending_partial_index.sql`
  — replaces `ix_weissman_async_jobs_pending(created_at) WHERE status='pending'`
  with `ix_async_jobs_pending(created_at, kind) WHERE status='pending'`. Worker
  hot-query went from 1.1–2.8 s (logged "slow statement" warnings) to a few ms
  index-only scan. Build is fully CONCURRENTLY — no lock on the live table.
- 11 unit tests covering header parsing (BOM tolerance, case insensitivity,
  first-line-only enforcement, rejection of non-directive first lines),
  filename parser, SQL splitter (dollar-quoted bodies, doubled `''` escape,
  line-comment-with-semicolon), and SHA-384 sanity (matches FIPS 180-4
  constant for empty input).

### Changed

- `weissman_db::run_migrations` is now two-phase: no-tx pre-runner →
  `sqlx::migrate!()`. Public signature unchanged.

---

## [2026.06.0-phase2] — Autonomous-Defence Phase 2 — 2026-06-08

### Added

- **pgvector RAG**: switched to `pgvector/pgvector:pg16` Docker image,
  `CREATE EXTENSION vector`, `supreme_council_memory.embedding_vec vector(1536)`
  with HNSW cosine index. `fingerprint_engine/src/embeddings.rs` provides an
  OpenAI-compatible `/v1/embeddings` client (works with vLLM / Ollama too).
  `council::fetch_supreme_memory_context` now retrieves top-K via real ANN
  (`<=>` operator) with full-text fallback when the embedding service is down.
- **Attack-path inference**: `fingerprint_engine/src/attack_path.rs` runs
  Dijkstra over the live `risk_graph_nodes`/`risk_graph_edges` graph from
  `internet_exposed=true` to `crown_jewel=true`, edge weights derived from each
  node's worst CVSS+EPSS+KEV; emits top-K paths + choke-points (nodes that
  appear in ≥50 % of the paths). Snapshots persisted in `attack_path_snapshots`.
- **SOAR playbooks**: `fingerprint_engine/src/soar_playbook.rs` — JSON DSL,
  trigger evaluator, idempotent action dispatcher (`set_status`,
  `slack_notify`, `webhook`, `http_post`, `open_pr`, `isolate_host`,
  `page_oncall`), `{{placeholder}}` template rendering, cooldown dedup, full
  audit in `weissman_playbook_runs`. Hooked into `findings_persist` so every
  new persisted finding evaluates against enabled playbooks.
- Endpoints: `GET /api/attack-paths/:client_id`, `PATCH /api/risk-graph/nodes/:id/flags`,
  `GET|POST /api/playbooks`, `PATCH|DELETE /api/playbooks/:id`,
  `POST /api/playbooks/fire`, `GET /api/playbooks/:id/runs`.
- UI: `frontend/src/pages/PlaybookBuilder.jsx` — three-pane visual editor
  (playbook list / trigger+actions editor / run history) with sample-event
  dry-run.

### Changed

- `Cockpit.jsx` mounts `ExecKpiStrip` as the sticky hero band.

---

## [2026.06.0-phase1] — Detection-integrity rollout — 2026-06-08

### Added

- **Threat-intel mirrors**: `intel_kev.rs` (CISA KEV refresh every 6 h) and
  `intel_epss.rs` (FIRST.org EPSS — on-demand on persist + back-fill every 12 h).
  New tables `kev_intel`, `epss_intel`; new columns on `vulnerabilities`:
  `epss_score`, `epss_percentile`, `kev_listed`, `kev_known_ransomware`,
  `kev_due_date`, `intel_enriched_at`.
- **Finding correlation/dedup**: `findings_correlator.rs` —
  `cluster_key = sha256(target | signature | cwe)` with URL normalisation
  (lowercases host, strips query / fragment / trailing slash). New table
  `weissman_finding_clusters` with aggregate `engines[]`, `sources[]`,
  `cves[]`, `max_severity`, `max_cvss`, `max_epss`, `kev_listed`.
  `vulnerabilities.cluster_id` FK + atomic upsert.
- **FP/TP feedback + auto-suppression**: `fp_feedback.rs` — Bayesian-shrinkage
  `confidence_multiplier = (tp+1)/(tp+fp+1)` clamped to `[0.1, 1.0]`,
  applied to `risk_score` at read time. Three FALSE_POSITIVE marks on the same
  `(engine, signature_hash)` add a row in `finding_suppressions`; next
  detection is silently flipped to `FALSE_POSITIVE` (audit-preserving).
- Endpoints: `GET /api/findings/clusters`, `GET /api/intel/status`,
  `GET /api/intel/suppressions`, `DELETE /api/intel/suppressions/:id`.
- `/api/findings` now returns `epss_score`, `epss_percentile`, `kev_listed`,
  `kev_known_ransomware`, `kev_due_date`, `cluster_id`, `signature_hash`,
  `confidence_multiplier`, `seen_count`. Default sort:
  `KEV → EPSS → discovered_at`.

### Fixed

- **Stable `finding_id` hash** — used to be SHA-256 of the entire payload
  (including timestamps), so the same vulnerability re-detected by the same
  engine on the same target produced a *new* row every scan. Now hashes only
  invariants: `engine | target | cve | cwe | mitre | signature | normalised_title`.
- **Real dedup** — `UNIQUE (tenant_id, client_id, finding_id)` enforced;
  `ON CONFLICT DO UPDATE` refreshes evidence + bumps `seen_count`. Analyst-set
  status (ACKNOWLEDGED / FIXED / FALSE_POSITIVE) is preserved across re-scans.
- **PoE job registry leak** — `serve.rs` previously kept disconnected SSE
  subscriber slots in the DashMap forever. Now removed when the entry's
  sender list becomes empty.
- **`api_audit_logs`** — paginated, filterable, server-side; previously
  hard-capped at 500 with no filter.
- **`is_scanning_active` race** — split into operator toggle vs. live
  `scan_in_progress()` derived from `ACTIVE_TENANT_CYCLES` counter; `/api/health`
  now exposes both.
- **Constant-time bearer comparison** in `cicd_interceptor` (was using `==`,
  vulnerable to timing leak). Now uses `subtle::ConstantTimeEq` with length pad.

---

## [2026.06.0-foundations] — Cockpit + onboarding polish — 2026-06-02

### Added

- Branded SVG logo + favicon set.
- Global toast notification system (`Toaster`), skeleton loaders, empty-state
  component, keyboard-shortcut overlay (`?` for help, `g+h/e/f/v/a/c/j/s`
  to navigate), profile menu (avatar + role + language + sign-out), branded
  404 page, finding-detail drawer.
- Audit-log viewer page + nav entry.
- Self-serve signup (`/api/auth/signup` → email-verify → tenant + admin user).
  Gated by `WEISSMAN_SELF_SERVE_SIGNUP=true`. UI: `deploy/public/signup.html`.
- OpenAPI 3.1 + Swagger UI at `/api/docs/`.
- Public marketing site: `/`, `/pricing.html`, `/terms.html`, `/privacy.html`,
  `/dpa.html`, `/security-policy.html`, `/.well-known/security.txt`,
  `/robots.txt`, `/sitemap.xml`.
- Production security headers across every nginx location: HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy.

---

## [2026.05.20] — Last pre-autonomous-defence release

Baseline of 47 tests + 188 routes + the original "engine-room" cockpit.
