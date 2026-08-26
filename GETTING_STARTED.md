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

**One command (full Docker stack):**

```bash
./start_weissman.sh
# or: ./start_weissman_live.sh --url https://your-company.example
```

Starts `dockerd` if needed, writes role-separated DSNs into `.env`
(`DATABASE_URL`, `WEISSMAN_AUTH_DATABASE_URL`, `WEISSMAN_READ_ONLY_DATABASE_URL`,
`WEISSMAN_MIGRATE_URL`), wires LLM env (`WEISSMAN_LLM_BASE_URL`,
`WEISSMAN_LLM_API_KEY`, `WEISSMAN_NL_QUERY_MODEL`), then:

`docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`

bringing up Postgres 16 + pgvector, Redis, weissman-server, weissman-worker, and
the Nginx gateway. First boot compiles inside Docker (**20–40 minutes** on a fresh
host). The launcher waits for `/api/health`, a running worker, and a live
`POST /api/ask` (must not 503) before printing **System Ready**.

```
http://127.0.0.1/command-center/
```

Set `WEISSMAN_LLM_BASE_URL` (and `WEISSMAN_LLM_API_KEY` if the provider needs a
bearer) in `.env` so Ask Weissman and Supreme Council RAG can call a real model.
A host Ollama/vLLM is reachable as `http://host.docker.internal:11434/v1`.

**Hot-reload UI** (optional; proxies `/api` to the gateway / backend):

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
