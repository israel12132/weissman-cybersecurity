# Getting Started — Weissman Cybersecurity

**Updated:** 2026-08-25  
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

**One command, whole stack:**

```bash
./start_weissman.sh
# equivalent:
./start_weissman_live.sh --url https://your-company.example
```

This is Docker-first. The front door starts the Docker daemon if it is installed but down,
writes `.env` from `PRODUCTION.env.template` (generating any missing secrets), then runs:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Everything shares one Compose network and reaches the others by service name:

| Service | Container | Role |
|---------|-----------|------|
| `postgres` | Postgres 16 + pgvector | `max_connections=200`, checksums |
| `redis` | Redis 7 | job bus + rate limits |
| `backend` | `weissman-server` | HTTP API `:8000` (not published; gateway proxies) |
| `worker` | `weissman-worker` | scan pipelines |
| `gateway` | Nginx | `127.0.0.1:80` → Command Center + `/api` + `/ws` |

Compose injects `DATABASE_URL` (weissman_app), `WEISSMAN_AUTH_DATABASE_URL` (weissman_auth),
`WEISSMAN_READ_ONLY_DATABASE_URL` (weissman_ro) and `REDIS_URL`. `/api/ask` is 503 without
the read-only pool — the launcher refuses to print **SYSTEM READY** until that route is armed.

First boot compiles the Rust workspace and builds the frontend + WASM inside Docker, so
budget **20–40 minutes** on a fresh host (subsequent boots reuse the images and are ~1 min).
The launcher waits up to 45 min for health — raise `WEISSMAN_BOOT_TIMEOUT` (seconds) on a
slow box.

It prints **SYSTEM READY** only after:

- `http://127.0.0.1/api/health` answers `"ok":true`
- 104+ sqlx migrations applied (`_sqlx_migrations`, including the no-tx runner)
- `weissman_app`, `weissman_auth`, and `weissman_ro` can LOGIN
- `POST /api/ask` is **not** HTTP 503

```bash
./start_weissman.sh --url https://sec.acme.com
./start_weissman.sh --no-monitoring     # skip Prometheus / Grafana / Alertmanager
./start_weissman.sh stop | status | logs | reset
./start_weissman.sh --help
```

If the daemon is down, the launcher starts it (`systemctl` → `service` → `dockerd`). Set
`WEISSMAN_DOCKER_AUTOSTART=0` to disable that. It uses `sudo` only when the socket is not
readable by this user, and never prompts for a password unless stdin is a TTY.

**Login:** `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD` at
http://127.0.0.1/command-center/login  
Production forces Secure cookies (`WEISSMAN_COOKIE_SECURE=1`) — put TLS in front of `:80`
before giving users a public URL (`--url https://your.domain`).

**Hot-reload UI** (optional). Vite proxies `/api` to `http://127.0.0.1:8000`, which the
Compose stack does not publish (the gateway is on `:80`). Either point the proxy at
`http://127.0.0.1` or use the built UI at http://127.0.0.1/command-center/login :

```bash
cd frontend && npm ci && npm run dev
# → http://localhost:5173/command-center/login  (after pointing the proxy at the gateway)
```

**Verify:**

```bash
./scripts/go_live_check.sh
curl -sf http://127.0.0.1/api/health
```

---

## Important

- **Real scans only** — authorized targets in client scope.
- **Production** refuses weak secrets (`changeme`, empty JWT). See [docs/manuals/he/05-production-security.md](docs/manuals/he/05-production-security.md).
- Never commit `.env`. The launcher comments out forbidden flags
  (`WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD`) instead of deleting them.

---

## Full onboarding

See [ONBOARDING_RUNBOOK.md](ONBOARDING_RUNBOOK.md) and manual **09** (client onboarding).
