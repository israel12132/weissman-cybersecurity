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

**Bare metal (host processes, one command):**

```bash
./start_weissman.sh
```

It resolves the whole configuration itself: reuses the secrets already in `.env` and generates
anything missing into `.env.local` (0600), finds Postgres and Redis — a running Docker stack
container, a container it created earlier, or a datastore already listening on this host — and
creates containers only as a last resort, starting the Docker daemon first if it is installed but
down. It then builds and runs `weissman-server` **and** `weissman-worker`, so scans actually
execute, and prints the login banner once `/api/health` answers.

```bash
./start_weissman.sh --no-worker         # API only (scans enqueue but never execute)
./start_weissman.sh --no-provision      # never create containers; fail with instructions
./start_weissman.sh --debug             # cargo debug profile, for fast rebuilds
DATABASE_URL=… REDIS_URL=… PORT=9999 ./start_weissman.sh   # anything you export wins
```

**Hot-reload UI** (proxies `/api` → `:8000`) on top of that:

```bash
cd frontend && npm ci && npm run dev
# → http://localhost:5173/command-center/login
```

**Login:** `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`. On a machine with no `.env`, the
launcher generates them and prints the password once in its banner (also stored in `.env.local`).
An existing database keeps the account it already has — boot never overwrites a live password.

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
