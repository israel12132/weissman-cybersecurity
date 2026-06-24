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

## Quick start (~5 minutes)

```bash
cp PRODUCTION.env.template .env
# Edit: WEISSMAN_JWT_SECRET, WEISSMAN_ADMIN_PASSWORD, DATABASE_URL, REDIS_URL

docker start weissman-postgres weissman-redis   # or: docker compose up -d postgres redis
cargo build -p weissman-server
./target/debug/weissman-server

cd frontend && npm ci && npm run dev
# → http://localhost:5173/command-center/login
```

**Login:** `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD` from `.env`.

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
