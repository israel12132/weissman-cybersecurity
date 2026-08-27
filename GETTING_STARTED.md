# Getting Started — Weissman Cybersecurity

**Updated:** 2026-06-24  
**Official docs:** [docs/manuals/README-he.md](docs/manuals/README-he.md) · [docs/manuals/README-en.md](docs/manuals/README-en.md)

---

## Start here

| Audience | Document |
|----------|----------|
| **Docker install** | [docs/manuals/he/02-installation-docker.md](docs/manuals/he/02-installation-docker.md) |
| **Production secrets** | [PRODUCTION.env.template](PRODUCTION.env.template) |
| **Sales / CEO deck** | [docs/sales/viewer/index.html](docs/sales/viewer/index.html) |
| **Week 1 go-live** | [docs/sales/WEEK-1-GOLIVE-he.md](docs/sales/WEEK-1-GOLIVE-he.md) |
| **Company readiness** | [docs/sales/COMPANY-READINESS-he.md](docs/sales/COMPANY-READINESS-he.md) |

---

## Quick start

**Production / customer deploy (one command):**

```bash
./start_weissman_live.sh --url https://your-company.example
```

First boot compiles the Rust workspace and builds the frontend + WASM inside Docker, so
budget **20–40 minutes** on a fresh host (subsequent boots reuse the images and are ~1 min).
The launcher waits up to 45 min for health — raise `WEISSMAN_BOOT_TIMEOUT` (seconds) on a
slow box.

**Local / laptop (one command — Postgres, Redis, API, worker, UI):**

```bash
./start_weissman.sh --pull
# → unsticks a leftover merge, pulls main, starts the full stack
# Docker hosts (no cargo/systemd): uses start_weissman_live.sh
# Hosts with cargo: Docker Postgres/Redis + weissman-server + weissman-worker
```

Hot-reload UI only (proxies `/api` → `:8000`):

```bash
cd frontend && npm ci && npm run dev
# → http://localhost:5173/command-center/login
```

> The datastores are only reachable on the host if you publish their ports. The default
> compose file `expose`s them on the internal network only; for local bare-metal dev add a
> `ports:` mapping or run Postgres/Redis directly on the host.

**Login:** `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD` from `.env`.

**Verify:**

```bash
./scripts/go_live_check.sh
curl -s http://127.0.0.1:8000/api/health | jq '.ok, .ueba'
```

`GET /api/health` embeds a live `ueba` object (`ingest_ok`, `retention_ok`,
`failsafe`). Failsafe lite-sampling is signalled to agents on the next WSS Welcome.

---

## Important

- **Real scans only** — authorized targets in client scope.
- **Production** refuses weak secrets (`changeme`, empty JWT). See [docs/manuals/he/05-production-security.md](docs/manuals/he/05-production-security.md).
- Never commit `.env`.

---

## Full onboarding

See [ONBOARDING_RUNBOOK.md](ONBOARDING_RUNBOOK.md) and manual **09** (client onboarding).
