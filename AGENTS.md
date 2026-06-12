# AGENTS.md

## Cursor Cloud specific instructions

### Architecture Overview
This is a Rust-first monorepo (Cargo workspace with 9 crates) with a React/Vite frontend and legacy Python utilities. The main product is a cybersecurity assessment platform with:
- **weissman-server** (Rust/Axum) — main HTTP API + WebSocket server on port 8000
- **weissman-worker** (Rust) — async job consumer for scan pipelines
- **Frontend** (React/Vite/Tailwind) — "Command Center" SPA under `frontend/`
- **Python layer** (`src/`, `tests/`) — legacy utilities, feeds, and test suite

### Required Services
| Service | How to start | Port |
|---------|-------------|------|
| PostgreSQL 16 | `docker start weissman-postgres` (or `docker run -d --name weissman-postgres -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=weissman -p 5432:5432 postgres:16-alpine`) | 5432 |
| Redis 7 | `docker start weissman-redis` (or `docker run -d --name weissman-redis -p 6379:6379 redis:7-alpine`) | 6379 |
| Rust backend | `cd /workspace && ./target/debug/weissman-server` | 8000 |
| Frontend dev | `cd /workspace/frontend && npm run dev` | 5173 |

### Key Gotchas
- The `crates/weissman-agent` directory is referenced in `Cargo.toml` workspace members but may be missing. If the workspace fails to load, create a minimal placeholder: `mkdir -p crates/weissman-agent/src && echo '' > crates/weissman-agent/src/lib.rs` with a minimal `Cargo.toml`.
- The `.env` file at workspace root configures the backend. Key required vars: `DATABASE_URL`, `WEISSMAN_JWT_SECRET`, `REDIS_URL`. See `.env.example` for all options.
- Login endpoint is `POST /api/login` (not `/api/auth/login`). Credentials from `.env`: `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`.
- Frontend dev server (Vite) proxies `/api` to the Rust backend at `http://127.0.0.1:8000`.
- Docker daemon requires `sudo dockerd` to start. Socket permissions: `sudo chmod 666 /var/run/docker.sock`.
- The backend runs sqlx migrations on startup when `WEISSMAN_MIGRATE_URL` is set; no separate migration step needed.
- Rust toolchain is pinned to 1.91.1 via `rust-toolchain.toml`.

### Lint & Test Commands
- **Rust lint:** `cargo clippy --workspace` (warnings only, no errors expected)
- **Rust tests:** `cargo test --workspace` (all pass)
- **Rust format:** `cargo fmt --check`
- **Python lint:** `ruff check src/ tests/`
- **Python tests:** `python3 -m pytest tests/unit/ -q` (3 pre-existing failures related to Redis env assumptions)
- **Frontend build:** `cd frontend && npm run build`
- **Frontend dev:** `cd frontend && npm run dev`

### Development Flow
1. Ensure Docker daemon is running (`sudo dockerd &` if needed)
2. Start Postgres + Redis containers
3. Build Rust workspace: `cargo build`
4. Start backend: `./target/debug/weissman-server`
5. Start frontend: `cd frontend && npm run dev`
6. Access app at http://localhost:5173/command-center/
