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
| Production engines | **562** | `node scripts/verify_engine_wiring.mjs` |
| Command Center routes | **112** | `node scripts/weissman-ui-audit.mjs` |
| UI pages (audit target) | **95/95** | `node scripts/weissman-ui-audit.mjs` |
| Real probes | **302** | `node scripts/engine_reality_audit.mjs` |
| Agent-required engines | **48** | same |

### Required Services
| Service | How to start | Port |
|---------|-------------|------|
| PostgreSQL 16 | `docker start weissman-postgres` (or `docker run -d --name weissman-postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=weissman -p 5432:5432 postgres:16-alpine`) | 5432 |
| Redis 7 | `docker start weissman-redis` (or `docker run -d --name weissman-redis -p 6379:6379 redis:7-alpine`) | 6379 |
| Rust backend | `./target/debug/weissman-server` | 8000 |
| Frontend dev | `cd frontend && npm run dev` | 5173 |

### Key Gotchas
- The `crates/weissman-agent` directory is referenced in `Cargo.toml` workspace members but may be missing. If the workspace fails to load, create a minimal placeholder: `mkdir -p crates/weissman-agent/src && echo '' > crates/weissman-agent/src/lib.rs` with a minimal `Cargo.toml`.
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
- **Python lint:** `ruff check src/ tests/`
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
| `scripts/verify_engine_wiring.mjs` | 558 engines ↔ dispatch — 0 gaps |
| `scripts/weissman-ui-audit.mjs` | 112 routes, 95 pages — live API evidence rules |

See **`docs/operations/INSPECTION-DAY-RUNBOOK.md`** for 30+30 minute demo and CISO deep-dive scripts.  
Week 8 sign-off: **`docs/operations/INSPECTION-READY-SIGNOFF.md`**.
