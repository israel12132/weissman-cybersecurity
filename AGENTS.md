# AGENTS.md

## Cursor Cloud specific instructions

### Architecture Overview
This is a Rust-first monorepo (Cargo workspace) with a React/Vite frontend and legacy Python utilities. The main product is a cybersecurity assessment platform with:
- **weissman-server** (Rust/Axum) — main HTTP API + WebSocket server on port 8000
- **weissman-worker** (Rust) — async job consumer for scan pipelines
- **Frontend** (React/Vite/Tailwind) — "Command Center" SPA under `frontend/`
- **Python layer** (`src/`, `tests/`) — legacy utilities, feeds, and test suite

### Canonical platform metrics (code-synced — run audits to verify)
| Metric | Value | Verify |
|--------|-------|--------|
| Production engines | **563** | `node scripts/verify_engine_wiring.mjs` |
| Command Center routes | **130** (target ≥112) | `node scripts/weissman-ui-audit.mjs` |
| UI pages (audit) | **111/111** — all pages meet the Weissman UI standard (exit 0) | `node scripts/weissman-ui-audit.mjs` |
| Real probes | **303** | `node scripts/engine_reality_audit.mjs` |
| Agent-required engines | **48** | same |

### Required Services
| Service | How to start | Port |
|---------|-------------|------|
| PostgreSQL 16 + pgvector | `docker start weissman-postgres` (or `docker run -d --name weissman-postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=weissman -p 5432:5432 pgvector/pgvector:pg16`) | 5432 |
| Redis 7 | `docker start weissman-redis` (or `docker run -d --name weissman-redis -p 6379:6379 redis:7-alpine`) | 6379 |
| Rust backend | `./target/debug/weissman-server` | 8000 |
| Frontend dev | `cd frontend && npm run dev` | 5173 |

### Key Gotchas
- **Build prerequisite:** `cargo build` needs OpenSSL headers (`openssl-sys`). On a bare image install them first — `sudo apt-get install -y libssl-dev pkg-config` — or the build fails with "Could not find directory of OpenSSL installation".
- `crates/weissman-agent` is a **fully implemented crate** (endpoint agent, ~27 source files). Do **not** create a placeholder `src/lib.rs` in it: the crate declares only a `[[bin]]` target, so a stray `lib.rs` makes Cargo auto-detect a phantom `weissman_agent` lib that nothing builds against.
- `pgvector` is required, not optional: `20260608130000_pgvector_rag.sql` and `20260608140100_pentest_memory.sql` create vector columns. A plain `postgres:16-alpine` image fails migrations at boot.
- The `.env` file at workspace root configures the backend. Key required vars: `DATABASE_URL`, `WEISSMAN_JWT_SECRET`, `REDIS_URL`. See `.env.example` for all options.
- **Production JWT:** `WEISSMAN_JWT_SECRET` must be **≥48 characters** (`security_startup.rs`). Metrics, destructive-confirm, and job-orchestrator secrets must be **≥32 characters**.
- Login endpoint is `POST /api/login` (not `/api/auth/login`). Credentials from `.env`: `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`.
- Frontend dev server (Vite) proxies `/api` to the Rust backend at `http://127.0.0.1:8000`.
- Docker daemon requires `sudo dockerd` to start. Socket permissions: `sudo chmod 666 /var/run/docker.sock`.
- The backend runs sqlx migrations on startup when `WEISSMAN_MIGRATE_URL` is set; no separate migration step needed.
- Rust toolchain is pinned to 1.91.1 via `rust-toolchain.toml`.
- Local E2E stack: `./scripts/run_e2e_stack.sh start` sets `WEISSMAN_E2E_STACK=1` so repo `.env` production values do not override dev exports.

### Lint & Test Commands
- **Rust lint:** `cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious`
- **Rust tests:** `cargo test --workspace --all-targets`
- **Rust format:** `cargo fmt --check`
- **Python lint:** `ruff check src/ --select E,F,W --ignore E501` (exactly what CI runs; the bare `ruff check src/ tests/` applies rules CI does not gate on and reports ~300 pre-existing findings)
- **Python tests:** `python3 -m pytest tests/unit/ -q`
- **Frontend build:** `cd frontend && npm run build`
- **Frontend unit tests:** `cd frontend && npm run test`
- **Frontend coverage (≥60% critical paths):** `cd frontend && npm run test:coverage`
- **Playwright live E2E:** `./scripts/run_playwright_live_e2e.sh` (requires live stack + `WEISSMAN_ADMIN_PASSWORD`)
- **Evidence pack:** `./scripts/generate_audit_evidence_pack.sh`
- **Full audit gate (G1–G7):** `bash scripts/full_audit_gate.sh`

### Development Flow
1. Ensure Docker daemon is running (`sudo dockerd &` if needed)
2. Start Postgres + Redis containers
3. Build Rust workspace: `cargo build`
4. Start backend: `./target/debug/weissman-server`
5. Start frontend: `cd frontend && npm run dev`
6. Access app at http://localhost:5173/command-center/

### Audit / delivery scripts
| Script | Purpose |
|--------|---------|
| `scripts/full_audit_gate.sh` | Master G1–G7 gate — must exit 0 before inspection day |
| `scripts/go_live_check.sh` | Production readiness (K8s, DR, secrets template, OT engines) |
| `scripts/generate_audit_evidence_pack.sh` | Auditor JSON + PDF (wiring, SBOM, NIST/SOC2 mapping) |
| `scripts/verify_engine_wiring.mjs` | 563 engine IDs ↔ dispatch — 0 gaps |
| `scripts/weissman-ui-audit.mjs` | 130 routes (target ≥112), 111/111 pages. **Static**: it checks page sources for the required UI affordances (`PageShell`, reality badge, refresh, search), not live API responses. Runtime proof comes from the live-stack steps in the `Engine wiring audit & API smoke` job |
| `scripts/verify_ci_production_boot_env.py` | Every production launch step in the workflows satisfies `security_startup.rs` |
| `scripts/verify_merge_queue_contract.py` | `.mergify.yml` requires every blocking `ci.yml` job |

See **`docs/operations/INSPECTION-DAY-RUNBOOK.md`** for 30+30 minute demo and CISO deep-dive scripts.  
Week 8 sign-off: **`docs/operations/INSPECTION-READY-SIGNOFF.md`**.
