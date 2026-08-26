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

**Local full stack (one command):**

```bash
./start_weissman.sh
# starts Docker (dockerd if needed) → Postgres + Redis → weissman-server + weissman-worker
# → http://127.0.0.1:8000/command-center/
```

The launcher will not source empty `DATABASE_URL` / `REDIS_URL` lines from a Docker-stack
`.env` (written by `./start_weissman_live.sh`). It loads JWT/admin secrets from that file,
starts `weissman-postgres` + `weissman-redis` on localhost, and runs the host binaries.
`./start_weissman.sh stop` kills server + worker; containers keep running (data persists).

**Hot-reload UI** (optional, proxies `/api` → `:8000` while the launcher server is up):

```bash
cd frontend && npm ci && npm run dev
# → http://localhost:5173/command-center/login
```

**Login:** `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD` from `.env` or `.env.local`.

**Verify:**

```bash
./scripts/go_live_check.sh
```

---

## Important

- **Real scans only** — authorized targets in client scope.
- **Production** refuses weak secrets (`changeme`, empty JWT). See [docs/manuals/he/05-production-security.md](docs/manuals/he/05-production-security.md).
- Never commit `.env`.

---

## Full onboarding

See [ONBOARDING_RUNBOOK.md](ONBOARDING_RUNBOOK.md) and manual **09** (client onboarding).
