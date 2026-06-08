# Weissman Cybersecurity

A continuous offensive-security platform for SOC teams and security service providers.
One backend, ~300 live engines, an endpoint agent, a customer-facing command center.

> **Status:** Production-ready core (auth, scope, RBAC, MFA, AI quota, TLS guards, endpoint agent).
> Self-serve signup + billing are stubbed (`501 Not Implemented`) until the commercial flow ships.
> See [`docs/archive/`](docs/archive/) for historical design notes; living docs are in the root.

---

## What it does

| Layer | What you get |
|-------|--------------|
| **API server** (`weissman-server`) | Axum on `:8000`, 188 routes, JWT auth, MFA TOTP, RBAC (viewer→ceo), per-tenant rate-limit |
| **Worker** (`weissman-worker`) | Async job consumer with `SKIP LOCKED`, heartbeats, per-kind timeouts |
| **Endpoint agent** (`weissman-agent`) | 5.3 MB single binary, WSS+JWT, runs process/persistence/clipboard/USB/EDR/log detections that can't be observed remotely |
| **Command center** (React/Vite) | Per-engine pages, live SSE telemetry, findings workflow, PDF reports, MFA self-service, agent management |
| **Engines** | ~60 core (orchestrator cycle) + 245 advanced — every one is a real HTTP/TCP/DNS/TLS probe, no simulated findings |

---

## Quick start (Docker, recommended)

```bash
git clone https://github.com/<your-fork>/weissman-cybersecurity
cd weissman-cybersecurity
cp PRODUCTION.env.template .env       # edit DATABASE_URL, WEISSMAN_JWT_SECRET, ...
docker compose up -d
# wait ~30s for migrations to apply, then:
open http://localhost:8080/command-center/login
```

Default credentials are created by the first-run migration. Change them immediately via
`POST /api/admin/users/:id` (CEO/Superadmin only).

---

## Quick start (native, for developers)

```bash
# 1. Postgres
docker run -d --name weissman-db -p 5432:5432 \
  -e POSTGRES_USER=weissman -e POSTGRES_PASSWORD=weissman \
  -e POSTGRES_DB=weissman postgres:16

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

## Endpoint agent (BYOD detections)

Install on a target host:

```bash
# Linux / macOS
curl -sSL https://<server>/install/agent.sh | \
  WEISSMAN_TOKEN="<from dashboard>" WEISSMAN_SERVER=https://<server> bash

# Windows PowerShell (admin)
iwr https://<server>/install/agent.ps1 | iex
Install-WeissmanAgent -Token "<from dashboard>" -Server "https://<server>"
```

The agent runs as a service (`systemd` / `launchd` / Windows Service), connects via WSS+JWT,
and unlocks every engine marked **Requires Agent** in the Engine Room.

---

## Key documents

| File | What it covers |
|------|----------------|
| [`GETTING_STARTED.md`](GETTING_STARTED.md) | End-to-end onboarding: client → scope → first scan → PDF |
| [`ONBOARDING_RUNBOOK.md`](ONBOARDING_RUNBOOK.md) | Operations runbook for SOC teams |
| [`SECURITY_AND_COMPLIANCE.md`](SECURITY_AND_COMPLIANCE.md) | Tenant isolation, MFA, RBAC, audit log |
| [`SLA_AND_STATUS.md`](SLA_AND_STATUS.md) | Finding lifecycle, SLA targets, status workflow |
| [`SIG_CAIQ_PREP_QA.md`](SIG_CAIQ_PREP_QA.md) | Pre-filled SIG / CAIQ vendor security questionnaire |
| [`docs/SOC_ENGINES_ARCHITECTURE.md`](docs/SOC_ENGINES_ARCHITECTURE.md) | Engine wiring + dispatch |
| [`docs/archive/`](docs/archive/) | Historical design notes (24 archived audits / specs) |

---

## Architecture

```
┌────────────────┐     ┌────────────────┐     ┌────────────────┐
│ React (Vite)   │────▶│ Axum API :8000 │────▶│ Postgres + RLS │
│ command-center │ SSE │  188 routes    │     │ 48+42 migrations
└────────────────┘     └────────────────┘     └────────────────┘
                              │
                              │ enqueue
                              ▼
                        ┌───────────────┐
                        │ async_jobs Q  │
                        └───────────────┘
                              │ SKIP LOCKED
                              ▼
                        ┌───────────────┐     ┌────────────────┐
                        │ weissman-     │────▶│ ~300 engines:  │
                        │   worker      │     │ HTTP/TCP/DNS/TLS
                        └───────────────┘     │ + endpoint     │
                              │               │   agent dispatch│
                              │ WSS+JWT       └────────────────┘
                              ▼
                        ┌───────────────┐
                        │ weissman-agent│
                        │ (per host)    │
                        └───────────────┘
```

---

## Operational safety rails (all enforced server-side)

1. **Scope validation** — every scan target must resolve to an approved domain/IP for the client. Out-of-scope → `403`.
2. **AI quota** — default 50 AI-heavy scans/day per tenant. Exceeded → `429` + `Retry-After`.
3. **MFA enforcement** — when `system_configs.mfa_required=true`, login without enrolled MFA → `403 mfa_enrollment_required`.
4. **TLS policy** — `WEISSMAN_ALLOW_INSECURE_TLS=1` in production refuses to start.
5. **RBAC** — create/update client = `operator+`, delete = `admin+`, scan = `analyst+`, admin endpoints = `admin/ceo`.
6. **Audit log** — every authenticated action recorded with timestamp, IP, user.
7. **Multi-tenant isolation** — PostgreSQL row-level security on every tenant table.

---

## Build / test

```bash
cargo check --workspace      # ~3s incremental
cargo test  --workspace      # ~5s, 47 tests passing
cd frontend && npm run build # ~10s, ~400 KB initial bundle (lazy-loaded)
```

CI: see `.github/workflows/ci.yml` (pip-audit, ruff, cargo audit, cargo test, frontend build).

---

## License & support

- **License:** proprietary — contact <sales@weissman.io>.
- **Security disclosure:** <security@weissman.io> (see `/.well-known/security.txt`).
- **Status:** <https://your-instance/command-center/status> — public, no auth.
