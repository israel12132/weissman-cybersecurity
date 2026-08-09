# 01 — Platform Overview & Architecture

## What Weissman is

Weissman Cybersecurity is an **authorized offensive-security and active-defence platform** for MSSPs, SOC teams, and enterprise security groups. It combines:

- A **Rust API server** (`weissman-server`) — HTTP + WebSocket on port 8000
- An **async worker** (`weissman-worker`) — scan pipelines and long-running jobs
- A **React Command Center** — SPA at `/command-center/`
- An **endpoint agent** (`weissman-agent`) — on-host detections + UEBA
- **563 production engines** — each wired to real network/host/agent probes

**Critical principle:** Findings come from **live probes only**. Agent-required engines show an honest empty state until an agent is online — never fabricated results.

---

## Architecture diagram

```
Browser → Nginx Gateway (:80 → :8080)
            ├─ /command-center/*  → React static (SPA)
            ├─ /api/*             → weissman-server :8000
            └─ /ws/*              → WebSocket (telemetry, swarm, timing)

weissman-server
  ├─ Auth (JWT, refresh cookies, MFA, OIDC/SAML)
  ├─ RBAC (viewer → analyst → operator → admin → ceo)
  ├─ Billing gates (Paddle + monthly scan quota)
  └─ Enqueue → weissman_async_jobs (PostgreSQL)

weissman-worker
  └─ Claims jobs (SKIP LOCKED) → engine_dispatch → persist findings

PostgreSQL 16 + pgvector
  ├─ RLS on tenant data (weissman_app role)
  ├─ Auth plane (weissman_auth, BYPASSRLS for login only)
  └─ Migrations from crates/weissman-db/migrations/

Redis 7
  └─ Rate limits, login lockout, telemetry bus (required multi-replica prod)
```

---

## Engine taxonomy

| Kind | Meaning | UI behavior |
|------|---------|-------------|
| `real_probe` | Remote scan works without agent | Normal scan + findings |
| `agent_required` | Needs endpoint agent | Empty state until agent online |
| `alias` | Same logic as canonical engine | Resolved via `resolve_engine_id` |
| `special` | e.g. `poe_synthesis` via async job | Job-based execution |

API: `GET /api/engines/capabilities` — source of truth for UI badges.

---

## Major product modules

| Module | Command Center path | Backend |
|--------|---------------------|---------|
| Clients & scope | `/clients` | `clients`, scope validation |
| Engine hubs | `/jwt-lab`, `/iac-security`, … | `POST /api/command-center/scan` |
| Jobs | `/jobs` | `weissman_async_jobs` |
| Findings | `/findings` | `vulnerabilities` + KEV/EPSS |
| Agent fleet | Agent Management | `/api/agents/*`, WSS |
| Billing | Billing page | Paddle webhooks, `tenant_usage_counters` |
| SOAR | Playbook builder | `soar_playbook.rs` |
| Council / AI | Council queue | `council_debate` jobs + optional LLM |
| CEO / God mode | `/ceo` (restricted) | CEO routes + telemetry |

---

## Data flow: one scan

1. Operator clicks **Run** in Command Center
2. `POST /api/command-center/scan` with `{ engine, client_id, target }`
3. Server validates RBAC, **billing quota**, scope (authorized domains)
4. Job row inserted → worker claims it
5. `engine_dispatch` runs real probe
6. Findings upserted to `vulnerabilities` (dedup by signature)
7. UI polls job or uses WebSocket telemetry

---

## Repository layout

| Path | Role |
|------|------|
| `backend/weissman-server/` | HTTP server binary |
| `crates/weissman-worker/` | Worker binary |
| `crates/weissman-agent/` | Endpoint agent |
| `fingerprint_engine/` | Engines, handlers, billing |
| `frontend/` | Command Center React app |
| `deploy/` | Docker, nginx, k8s, systemd |
| `docs/manuals/` | This instruction pack |

---

## Related manuals

- [02-installation-docker](02-installation-docker.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- `/docs/architecture.md` (deep dive)
