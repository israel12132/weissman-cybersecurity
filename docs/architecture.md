# Architecture

> Current as of 2026-06-09. See [`CHANGELOG.md`](../CHANGELOG.md) for the rollout
> history that produced this shape.

## System map

```
                     ┌──────────────────────────────────────────────────────┐
                     │  Public marketing site  (deploy/public/*.html)       │
                     │  /, /pricing, /terms, /privacy, /dpa, /signup, …     │
                     └────────────────────────┬─────────────────────────────┘
                                              │
                                  ┌───────────▼─────────────┐
                                  │  Nginx gateway (`:80`)  │
                                  │  Strict CSP / HSTS,     │
                                  │  brotli + gzip,         │
                                  │  proxy → backend:8000   │
                                  └───────────┬─────────────┘
                                              │
   ┌──────────────────────────────────────────┴────────────────────────────┐
   │                                                                       │
   │  ┌──────────────────────┐    SSE / WS   ┌───────────────────────┐   │
   │  │ React Command-Center │◀─────────────▶│ weissman-server       │   │
   │  │ Vite, lazy-loaded    │   ─────▶      │ Axum :8000, 200+ rts  │   │
   │  │ ExecKpiStrip /       │   /api/...    │ JWT + TOTP MFA + RBAC │   │
   │  │ PlaybookBuilder /    │               │ Per-tenant rate-limit │   │
   │  │ AskWeissman /        │               │ OpenAPI 3.1 /api/docs/│   │
   │  │ FindingsCmdCtr / …   │               └─────────┬─────────────┘   │
   │  └──────────────────────┘                         │                  │
   │                                                   │ enqueue          │
   │                                                   ▼                  │
   │                                          ┌────────────────────────┐  │
   │                                          │ weissman_async_jobs    │  │
   │                                          │  (Postgres queue,      │  │
   │                                          │   FOR UPDATE SKIP      │  │
   │                                          │   LOCKED, ix_async_    │  │
   │                                          │   jobs_pending partial │  │
   │                                          │   idx kind+created_at) │  │
   │                                          └────────┬───────────────┘  │
   │                                                   │                  │
   │                                                   ▼                  │
   │  ┌───────────────────────┐  WSS+JWT    ┌─────────────────────────┐  │
   │  │ weissman-agent        │◀────────────│ weissman-worker         │  │
   │  │ • 15 detections       │             │ • per-kind timeouts     │  │
   │  │ • ueba_baseline       │             │ • heartbeats            │  │
   │  └─────────┬─────────────┘             │ • dispatches engines    │  │
   │            │                           └─────────┬───────────────┘  │
   │            │                                     │                  │
   │            │ POST /api/ueba/ingest               │ HTTP/TCP/DNS/TLS │
   │            │ + finding payloads                  ▼                  │
   │            ▼                           ┌──────────────────┐         │
   │            ───────────────────────────▶│ 563 engines     │         │
   │                                        │ web · cloud · OT │         │
   │                                        │ AI/LLM · supply  │         │
   │                                        │ chain · OSINT ·  │         │
   │                                        │ fuzzers · stealth│         │
   │                                        └──────────────────┘         │
   │                                                                     │
   └──────────────────────┬──────────────────────────────────────────────┘
                          │
                          ▼
                ┌──────────────────────────────────────────────────────┐
                │  PostgreSQL 16 + pgvector (`pgvector/pgvector:pg16`) │
                │  ─────────────────────────────────────────────────── │
                │  • 100 migrations (sqlx + no-tx pre-runner)          │
                │  • RLS forced on every multi-tenant table            │
                │  • 3 roles:                                          │
                │      weissman_app   — app, subject to RLS            │
                │      weissman_auth  — login plane (bypass for users) │
                │      weissman_ro    — /api/ask only, SELECT-only     │
                │  • Extensions: vector (HNSW cosine)                  │
                └──────────────────────────────────────────────────────┘

In-process background loops (`weissman-server`):
  • CISA KEV refresh                         every 6 h
  • FIRST.org EPSS back-fill                  every 12 h
  • UEBA sample retention                     hourly  (>14 d purge)
  • Sovereign self-scan (LLM audit-log review) opt-in via env
  • SOAR playbook dispatch                    fire-and-forget on finding persist
```

---

## Data flow — "a CVE finding lands"

1. **Worker** picks the next pending job
   (`ix_async_jobs_pending` partial index).
2. Calls the dispatched engine → engine returns one or more `serde_json::Value`
   findings (real probe evidence; never hard-coded).
3. **`findings_persist::persist_engine_findings`**:
   - normalises severity, computes stable `finding_id`
     (sha256 of `engine|target|cve|cwe|mitre|signature|normalised_title`),
   - calls **`intel_epss::enrich_with_epss`** if there's a CVE
     (FIRST.org → `epss_intel` cache → finding columns),
   - calls **`intel_kev::is_kev_listed`** (in-process mirror of
     `cisa.gov/.../known_exploited_vulnerabilities.json`),
   - checks **`fp_feedback::is_suppressed`** — if a 3-FP suppression rule
     exists for `(engine, signature_hash)`, the finding lands with
     `status='FALSE_POSITIVE'` (audit-preserving),
   - upserts into `vulnerabilities` with
     `ON CONFLICT (tenant_id, client_id, finding_id) DO UPDATE` —
     refreshes evidence, bumps `seen_count`, preserves analyst-set status,
   - calls **`findings_correlator::upsert_cluster_for_finding`** — keys by
     `sha256(target|signature|cwe)`, aggregates `engines[]`, `cves[]`, `max_*`,
     writes `vulnerabilities.cluster_id`,
   - spawns **`soar_playbook::dispatch_event`** off-tx so a slow webhook
     doesn't extend the DB lock — every enabled playbook is evaluated,
     matching ones execute their action chain, every dispatch lands in
     `weissman_playbook_runs`.
4. **`/api/findings`** read path: reweights `risk_score`:
   `base × (1 + 0.5×EPSS) × (KEV ? 1.4 : 1) × (ransomware ? 1.15 : 1) × confidence_multiplier`,
   default sort `KEV → EPSS → discovered_at`.
5. **`/api/dashboard/exec-kpis`** consumes the same data, produces the cockpit
   hero band: severity counts (+24h deltas), MTTR, asset/agent/job totals,
   24-hour trend, top engines/clients/CVEs/MITRE.

---

## Data flow — "Ask Weissman" (NL → safe SQL)

1. UI sends `{ question }` to `POST /api/ask`.
2. Backend calls the LLM (`OPENAI_BASE_URL` + `OPENAI_API_KEY` env vars) with a
   system prompt that *forbids* raw SQL — it must emit a strict JSON `QueryPlan`.
3. `nl_query::compile_plan` validates the plan against an allow-list of 6
   tables × ~50 columns × 10 operators. Tenant scope (`tenant_id = $1`) is
   **always** the first WHERE clause, regardless of plan content. `LIMIT` is
   capped at 200.
4. The compiled parameterised SQL is executed on a connection from
   `read_only_pool` — a dedicated `weissman_ro` Postgres role with **SELECT-only
   grants** on 13 whitelisted tables, `statement_timeout=15s`,
   `idle_in_transaction_session_timeout=30s`, `work_mem=32MB`. Defense in depth:
   even if the validator slips, Postgres physically refuses non-SELECT.
5. Results returned to UI with the compiled SQL string so the analyst can audit
   what actually ran. Every question + plan + SQL + ms is logged to
   `nl_query_audit`.

---

## Data flow — "endpoint UEBA anomaly"

1. Agent dispatches `ueba_baseline` on a 15-minute scheduler (skipped while the
   server is in CPU failsafe). `weissman-agent/src/detections/ueba/` samples:
   - Linux: listening TCP from `/proc/net/tcp{,6}` (no `netstat`/`ss`), top
     processes from `/proc/*/comm` (control chars stripped, cap 24), unique
     UIDs, uptime (reboot flagged so a drop to 0 is not a z-score spike), EMA
     load/memory, failed logins via non-blocking read of `/var/log/auth.log`
     (optional `cap_dac_read_search` from `install.sh`).
   - Windows: Event Log 4625 for `failed_logins` when the Security log is
     readable; otherwise the metric is 0 with `auth_log_readable=false`.
   - macOS: Unified Logging (`log show`, 2s timeout) for failed logons.
   Metrics are tagged with UTC `hour_of_week` (Mon-00 = 0, Sun-23 = 167;
   DST-safe because the clock is UTC), `seq`, `nonce`, `sampled_at`, and
   `hardware_id`. Optional gzip+base64 `metrics_gz` for large payloads.
   Offline: an in-memory ring of 32 samples is drained on WSS reconnect
   (exponential backoff to 5 minutes).
2. Wire path is WSS `Finding{engine:ueba_baseline}` (preferred) or
   `POST /api/ueba/ingest` with an agent JWT (requires a live WSS session) or
   an admin JWT. The HTTP handler enqueues onto a Tokio MPSC (cap 4096,
   2 samples/agent/minute). `WEISSMAN_TRUST_PROXY_HEADERS` is honoured for
   source IP. Out-of-scope IPs vs `clients.ip_ranges` return **403**.
3. `ueba_detector::ingest_sample`:
   - INSERT into `agent_metric_samples` using **`sampled_at`** (delayed
     catch-up maps to the original UTC hour, not arrival time),
   - update a Welford online baseline on **GLOBAL_BUCKET=0** (raw samples
     still store the real hour-of-week for temporal smoothing),
   - MAD fallback + winsorization so a single spike cannot poison σ,
   - `|z|` gates are per-metric (`failed_logins` at 2σ, load/memory at 3σ);
     `uptime_seconds` is a reboot delta, not a z-score,
   - **no client-facing anomaly** while `endpoint_agents.is_learning` is
     true (exit requires n≥24 **and** ≥5 distinct weekdays),
   - categorical `open_ports[]` (integer[], ephemeral ranges excluded) and
     normalised `top_processes[]` vs a 500-item learned set with 30-day aging
     and a tenant process whitelist,
   - after commit: SOAR playbook for `high`/`critical` (3s timeout, 3600s
     cooldown); `isolate_host` when critical **or** (failed_logins high + new
     ports); `page_oncall` only off-hours; FAIR ARO floor 2.0.
4. Cockpit `/ueba` reads `/api/ueba/anomalies`, `/api/ueba/fleet`,
   `/api/ueba/policy`, `/api/ueba/whitelist` (analyst+). Disposition is
   `POST /api/ueba/anomalies/:id/disposition`. `/api/health` embeds `ueba`
   ingest/retention/failsafe flags.
5. Retention (`spawn_retention_loop`) runs at minute **:45**, holds a Postgres
   advisory lock, archives then deletes samples in batches of 5000 (hot
   window 14 days, anomalies 90 days). Nightly `pg_dump` excludes
   `agent_metric_samples` data unless
   `WEISSMAN_UEBA_EXCLUDE_SAMPLES_FROM_BACKUP=false`.

---

## Migration system

- Files live in `crates/weissman-db/migrations/`.
  `sqlx::migrate!("./migrations")` runs them at boot via
  `weissman_db::run_migrations(url)`.
- Files whose first line is `-- weissman:no-transaction` are handled by
  `no_tx_migrations::apply_no_tx_migrations` **before** SQLx's runner.
  See [docs/operations.md](operations.md#no-transaction-migrations) for
  the full contract.
- The `_sqlx_migrations` table is the source of truth — both runners write here.

---

## Table inventory (80+ tables)

| Domain | Key tables |
|--------|-----------|
| Tenants / auth | `tenants`, `users`, `user_refresh_tokens`, `audit_logs` |
| Clients / scope | `clients`, `client_asset_value_rules` |
| Findings | `vulnerabilities`, `weissman_finding_clusters`, `report_runs` |
| Intel | `kev_intel`, `epss_intel`, `engine_confidence_adjustments`, `finding_suppressions` |
| Risk graph | `risk_graph_nodes`, `risk_graph_edges`, `attack_path_snapshots` |
| Financial | `client_financial_risk_snapshots`, `client_asset_value_rules` |
| Jobs | `weissman_async_jobs` (partial idx `ix_async_jobs_pending`) |
| Agent | `endpoint_agents`, `endpoint_agent_enrollment_tokens`, `endpoint_agent_tasks`, `agent_metric_samples`, `agent_metric_baselines`, `agent_anomalies` |
| SOAR | `weissman_playbooks`, `weissman_playbook_runs` |
| Council RAG | `supreme_council_memory` (embedding_vec vector(1536) + HNSW), `supreme_council_rag_hits` |
| Pentest RL | `pentest_winning_paths` (embedding vector(1536) + HNSW) |
| NL→SQL | `nl_query_audit`, role `weissman_ro` |
| Signup | `pending_signups` |
| Heal | `heal_requests`, `auto_heal_job_specs` |
| System | `system_configs`, `_sqlx_migrations` |

Full schema: run `\d` against the live DB after `docker compose up` — every
table is migration-managed.
