# Weissman Cybersecurity

> An autonomous offensive-security + active-defence platform for SOC teams and
> security service providers. One backend, **564 production engine IDs** (304 real
> live probes + 212 aliases + 48 agent-required), an endpoint
> agent with on-host UEBA, a customer-facing command center, SOAR playbooks,
> attack-path inference, and an NL→SQL "Ask Weissman" console.

**Status:** Production-ready core. Self-serve signup is implemented behind an
opt-in env flag. Billing integration (Paddle) is wired and gated by
`WEISSMAN_BILLING_STRICT`. Every living doc is in the repo root or under `docs/`.

---

## What it does

| Layer | What you get |
|-------|--------------|
| **API server** (`weissman-server`) | Axum on `:8000`, 200+ routes, JWT auth + TOTP MFA, RBAC `viewer→analyst→operator→admin→ceo + superadmin`, per-tenant rate-limit, OpenAPI 3.1 + Swagger UI at `/api/docs/` |
| **Worker** (`weissman-worker`) | Async job consumer with `SKIP LOCKED`, heartbeats, per-kind timeouts. Hot-query backed by the partial index `ix_async_jobs_pending(created_at, kind) WHERE status='pending'` |
| **Endpoint agent** (`weissman-agent`) | ~5 MB single binary, stripped release build (Linux / macOS / Windows); exact per-platform sizes are emitted into the SHA256 manifest by `scripts/package_agent_binaries.sh`. 15 on-host detections + **UEBA baseline sampler** — 7-day learning window, z-score > 3 fires `medium`, > 6 fires `high` |
| **Command center** (React/Vite) | Cockpit with live KPI strip + SSE telemetry, findings drawer with EPSS/KEV badges, **PlaybookBuilder** (visual SOAR editor), **AskWeissman** (NL→SQL chat), audit log viewer, agent management |
| **Engines** | **564 production engine IDs** — CI-verified breakdown (`scripts/engine_reality_audit.mjs`): **304 real live probes** (296 distinct implementations), **212 aliases** that resolve to a real probe, **48 agent-required** host-level techniques; web / cloud / OT-ICS / AI-LLM / supply-chain / network / mobile / OSINT / fuzzers / endpoint agent. Every one wired to a real HTTP / TCP / DNS / TLS / agent probe and verified end-to-end in CI by `scripts/verify_engine_wiring.mjs` (0 gaps, 0 no_path) — **no fabricated or randomised findings**: every persisted finding derives from a live probe, with agent-required and advisory results clearly labelled `info` / `advisory`. Breadth is proven from source too: **live probes across all 15 attack domains, **226 distinct MITRE ATT&CK techniques performed** (192 primary engine mappings + 34 code-grounded secondary — the extra techniques each engine's own implementation tags on its findings), 0 unmapped, every ID **validated current against ATT&CK v19.1** (Enterprise + Mobile + ICS, 0 stale) — see [`docs/ENGINE_COVERAGE_AND_ACCURACY.md`](docs/ENGINE_COVERAGE_AND_ACCURACY.md) and [`docs/MITRE_ATTACK_COVERAGE.md`](docs/MITRE_ATTACK_COVERAGE.md) |
| **Threat intel** | Live mirrors of **CISA KEV** (6h refresh) and **FIRST.org EPSS** (12h, on-demand). Every CVE-tagged finding is enriched at persist-time with `epss_score`, `epss_percentile`, `kev_listed`, `kev_known_ransomware`, `kev_due_date` |
| **Detection intelligence** | Finding-cluster dedup (sha256 of `target‖signature‖cwe`); FP/TP feedback loop with auto-suppression at 3 FPs; confidence multiplier on `risk_score`; reweighted ordering: `KEV → EPSS → CVSS × confidence` |
| **Attack-path inference** | Dijkstra over `risk_graph_nodes` from `internet_exposed → crown_jewel`; CVSS+EPSS+KEV-weighted edges; top-K + choke-point analysis; snapshots persisted in `attack_path_snapshots` |
| **Financial blast-radius** | FAIR-aligned SLE/ALE per client: `SLE = asset_value × max(CVSS/10, 0.5)`; `ALE = SLE × min(EPSS×12, 12) × discount`; KEV floors ARO at 1.0/yr. Per-client onboarding tag→USD rules |
| **SOAR Playbooks** | JSON DSL `when {severity, kev, epss_min, exposed, engines, cooldown_seconds} do [...]`; 7 actions: `set_status`, `slack_notify`, `webhook`, `http_post`, `open_pr`, `isolate_host`, `page_oncall`; idempotent dispatch + audit log |
| **RAG council memory** | `pgvector(1536)` + HNSW cosine index on `supreme_council_memory`. Every Supreme-Council winning strategy is embedded (OpenAI-compatible `/v1/embeddings`) and the next debate retrieves the top-K most-similar prior wins |
| **Pentest reinforcement** | "What worked last time" memory: every confirmed payload is keyed by target fingerprint (server + tech stack), embedded, ANN-retrieved on the next scan against a similar stack — replay-hit-rate tracked |
| **Ask Weissman (NL→SQL)** | LLM emits a strict JSON `QueryPlan` (NEVER raw SQL); server validates against an allow-list of 6 tables × N columns; compiles to parameterised SQL; **executes against a dedicated `weissman_ro` Postgres role** with 15 s statement timeout |

---

## Quick start (Docker, recommended)

**One command — full production stack for customers:**

```bash
git clone https://github.com/<your-fork>/weissman-cybersecurity
cd weissman-cybersecurity
./start_weissman_live.sh --url https://your-company.example
# → Postgres · Redis · API · Worker · Command Center · migrations · monitoring
# → http://127.0.0.1/command-center/login
```

`start_weissman_live.sh` generates a hardened `.env` on first boot, builds images,
runs `WEISSMAN_ENV=production` guards, and verifies `/api/health` before printing
login credentials.

**Manual compose (equivalent):**

```bash
cp PRODUCTION.env.template .env       # edit secrets + WEISSMAN_PUBLIC_BASE_URL
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile monitoring up -d --build
```

First-boot credentials are created by the migration. Change them immediately via
the admin UI or `POST /api/admin/users/:id` (CEO / Superadmin only).

> **Database image:** we now use `pgvector/pgvector:pg16` — a drop-in replacement
> for `postgres:16` with the `vector` extension pre-installed. Same data volume,
> no migration. Required for RAG retrieval (`supreme_council_memory`,
> `pentest_winning_paths`).

---

## Quick start (native, for developers)

```bash
# 1. Postgres with pgvector
docker run -d --name weissman-db -p 5432:5432 \
  -e POSTGRES_USER=weissman -e POSTGRES_PASSWORD=weissman \
  -e POSTGRES_DB=weissman pgvector/pgvector:pg16

# 2. Build (debug, ~20 min the first time)
cargo build --workspace

# 3. Env vars (minimum)
export DATABASE_URL='postgres://weissman:weissman@127.0.0.1/weissman'
export WEISSMAN_JWT_SECRET="$(openssl rand -hex 32)"
export WEISSMAN_MIGRATE_URL="$DATABASE_URL"

# 4. Run
./target/debug/weissman-server &       # API on :8000
./target/debug/weissman-worker &       # async job consumer
cd frontend && npm install && npm run dev      # UI on :5173 (proxies /api → :8000)
```

Then open <http://127.0.0.1:5173/command-center/login>.

---

## Endpoint agent (BYOD detections + UEBA)

```bash
# Linux / macOS
curl -sSL https://<server>/install/agent.sh | \
  WEISSMAN_TOKEN="<from dashboard>" WEISSMAN_SERVER=https://<server> bash

# Windows PowerShell (admin)
iwr https://<server>/install/agent.ps1 | iex
Install-WeissmanAgent -Token "<from dashboard>" -Server "https://<server>"
```

The agent runs as a service (`systemd` / `launchd` / Windows Service), connects
via WSS+JWT, and on every dispatch ships:

- **15 on-host detections** — process hollowing, DLL hijack, persistence, ARP spoof,
  USB enumeration, EDR presence, log integrity, scheduled-task tamper, timestomp,
  clipboard hijack, …
- **UEBA baseline sample** (`ueba_baseline`) — open ports, top processes, unique
  users, load/memory, failed logins, hour-of-week bucket. Server computes
  `mean ± stddev` from the last 7 days per `(agent, metric, hour_of_week)`;
  `|z| > 3` fires a `medium` finding, `|z| > 6` fires `high`. New port / new
  process never seen before fires `medium` once it's out of the learning window.

---

## Key documents

| File | What it covers |
|------|----------------|
| **[Instruction manuals (EN/HE)](docs/manuals/README-en.md)** | **Official delivery pack** — 19 topics × 2 languages, sales readiness, install, ops, QA |
| [`docs/manuals/README-he.md`](docs/manuals/README-he.md) | אינדקס ספרי הוראות בעברית |
| [`docs/architecture.md`](docs/architecture.md) | System map, data flow, table inventory |
| [`docs/operations.md`](docs/operations.md) | Env-var reference, runbooks, migration runner, intel workers, read-only role |
| [`GETTING_STARTED.md`](GETTING_STARTED.md) | End-to-end onboarding: client → scope → first scan → PDF |
| [`ONBOARDING_RUNBOOK.md`](ONBOARDING_RUNBOOK.md) | SOC operations runbook |
| [`SECURITY_AND_COMPLIANCE.md`](SECURITY_AND_COMPLIANCE.md) | Tenant isolation, MFA, RBAC, audit log, encryption, KEV/EPSS lineage |
| [`SLA_AND_STATUS.md`](SLA_AND_STATUS.md) | Finding lifecycle, SLA targets, status workflow |
| [`SIG_CAIQ_PREP_QA.md`](SIG_CAIQ_PREP_QA.md) | Pre-filled SIG / CAIQ vendor security questionnaire |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release changes (phase 1–3 of the autonomous-defence rollout) |
| [`docs/SOC_ENGINES_ARCHITECTURE.md`](docs/SOC_ENGINES_ARCHITECTURE.md) | Engine wiring + dispatch path |
| [`docs/ENGINE_COVERAGE_AND_ACCURACY.md`](docs/ENGINE_COVERAGE_AND_ACCURACY.md) | **Source-derived, CI-gated proof** — live-probe breadth across all 15 attack domains + 192 MITRE techniques, and the FP/TP accuracy mechanism (`scripts/engine_coverage_accuracy_report.mjs`) |
| [`docs/MITRE_ATTACK_COVERAGE.md`](docs/MITRE_ATTACK_COVERAGE.md) | **ATT&CK coverage matrix** — 226 techniques (192 primary + 34 code-grounded secondary extracted from the engines' own finding tags), per tactic/domain against the current release (v19.1), CI **currency gate** (no stale/revoked IDs); ships ATT&CK Navigator layers per domain (`scripts/mitre_attack_coverage.mjs`) |

The interactive **OpenAPI spec** lives at <code>/api/docs/</code> (Swagger UI)
with the raw 3.1 JSON at <code>/api/openapi.json</code>.

---

## Architecture (current)

```
┌──────────────────┐    SSE+WS    ┌─────────────────────┐
│ React (Vite)     │◀────────────▶│ Axum API :8000      │
│ command-center   │              │   200+ routes,       │
│ + AskWeissman    │              │   JWT/MFA/RBAC,      │
│ + PlaybookBuilder│              │   tenant rate-limit  │
└──────────────────┘              └────────┬────────────┘
                                           │
                                           │ enqueue / persist
                                           ▼
                                  ┌────────────────────────────────┐
                                  │ PostgreSQL 16 + pgvector       │
                                  │  • 114 migrations              │
                                  │  • RLS per-tenant on every     │
                                  │    multi-tenant table          │
                                  │  • _sqlx_migrations w/ no-tx   │
                                  │    pre-runner for CONCURRENTLY │
                                  │  • read-only role weissman_ro  │
                                  │    for /api/ask                │
                                  └────────┬───────────────────────┘
                                           │
                                  ┌────────▼───────────┐    HTTP/TCP/DNS/TLS
                                  │ weissman-worker    │──────────▶ 564 engines
                                  │  SKIP LOCKED       │
                                  │  per-kind timeouts │
                                  └────────┬───────────┘
                                           │ WSS+JWT
                                           ▼
                                  ┌────────────────────┐
                                  │ weissman-agent     │
                                  │  15 detections     │
                                  │  + UEBA baseline   │
                                  └────────────────────┘

Background workers run inside the API process:
  • CISA KEV refresh (every 6 h)
  • FIRST.org EPSS backfill (every 12 h, on-demand on persist)
  • UEBA sample retention (hourly purge of >14-day samples)
  • SOAR playbook dispatch (fire-and-forget on persist)
  • Sovereign self-scan (vLLM review of audit_logs, optional)
```

---

## Operational safety rails (all enforced server-side)

1. **Scope validation** — every scan target must resolve to an approved
   domain/IP for the client. Out-of-scope → `403`.
2. **AI quota** — default 50 AI-heavy scans/day per tenant. Exceeded → `429` +
   `Retry-After`.
3. **MFA enforcement** — when `system_configs.mfa_required=true`, login without
   enrolled MFA → `403 mfa_enrollment_required`.
4. **TLS policy** — `WEISSMAN_ALLOW_INSECURE_TLS=1` in production refuses to start.
5. **RBAC** — create/update client = `operator+`, delete = `admin+`,
   scan = `analyst+`, admin endpoints = `admin/ceo`.
6. **Audit log** — every authenticated action recorded in `audit_logs` with
   timestamp, IP, user; every `/api/ask` query in `nl_query_audit` with the
   compiled SQL.
7. **Multi-tenant isolation** — PostgreSQL row-level security forced on every
   tenant table (80+).
8. **NL→SQL safety** — LLM never emits raw SQL; allow-list of 6 tables × ~50
   columns × 10 operators; queries run as `weissman_ro` (SELECT-only) with
   `statement_timeout=15s`.
9. **Auto-suppression** — analyst marks `FALSE_POSITIVE` 3 times on the same
   signature → next detection is silently labelled FP, audit trail preserved.
10. **No-transaction migrations** — `-- weissman:no-transaction` files
    (CONCURRENTLY index builds) are applied outside any transaction by the
    pre-runner, then recorded in `_sqlx_migrations` with SHA-384 checksums.
    SQLx's regular runner sees them as already-applied and skips.

---

## Build / test

```bash
cargo check --workspace      # ~25 s incremental
cargo test  --workspace      # ~2,400 test fns (see docs/METRICS.md — code-derived, CI-gated)
cd frontend && npm run build # code-split route chunks (largest initial chunk ~290 KB gzipped)
```

CI runs migration sync checks, cargo-audit, pip-audit, ruff, cargo fmt/clippy/test,
frontend build, and engine/API smoke checks (see `.github/workflows/ci.yml`).

---

## License & support

- **License:** proprietary — contact <sales@weissman.io>.
- **Security disclosure:** <security@weissman.io>
  (see <https://weissman.io/.well-known/security.txt>).
- **Public status:** <https://your-instance/command-center/status> (no auth).
- **API docs:** <https://your-instance/api/docs/> (Swagger UI, JWT-required for
  protected endpoints).
