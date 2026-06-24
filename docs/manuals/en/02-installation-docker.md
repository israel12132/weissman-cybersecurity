# 02 — Installation: Docker Compose (Recommended)

## When to use

- POC, staging, and most production deployments
- Single-node or small cluster with one compose stack
- Fastest path to a working Command Center

---

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker | 24+ |
| Docker Compose | v2 |
| RAM | 4 GB (8 GB recommended) |
| Disk | 20 GB free |
| Ports | 80 (gateway), internal 5432/6379/8000 |

---

## Step-by-step

### 1. Clone and configure secrets

```bash
git clone https://github.com/israel12132/weissman-cybersecurity.git
cd weissman-cybersecurity
cp PRODUCTION.env.template .env
```

Edit `.env` — **minimum required for compose to start:**

```bash
# Generate:
openssl rand -base64 48   # → WEISSMAN_JWT_SECRET

WEISSMAN_JWT_SECRET=<paste>
WEISSMAN_ADMIN_PASSWORD=<strong-password-min-12-chars>
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
```

For **production**, also set (see manual 05):

```bash
WEISSMAN_ENV=production
WEISSMAN_COOKIE_SECURE=1
WEISSMAN_METRICS_TOKEN=<openssl rand -base64 48>
DB_APP_PASSWORD=<strong>
DB_AUTH_PASSWORD=<strong>
POSTGRES_PASSWORD=<strong>
```

### 2. Build and start

```bash
docker compose up -d --build
```

Services started:
- `postgres` — pgvector/pgvector:pg16
- `redis` — rate limits + telemetry
- `backend` — weissman-server (migrations at boot)
- `worker` — weissman-worker
- `gateway` — nginx SPA + API proxy

### 3. Verify health

```bash
curl -sf http://localhost/api/health
curl -sf http://localhost/command-center/
docker compose ps
docker compose logs backend --tail 30
```

Expect backend healthcheck green within ~60–120 s on first build.

### 4. Log in

Open: **http://localhost/command-center/login**

- Email: `WEISSMAN_ADMIN_EMAIL`
- Password: `WEISSMAN_ADMIN_PASSWORD`

Change password immediately after first login.

---

## Optional: monitoring profile

```bash
docker compose --profile monitoring up -d
```

Starts Prometheus + Grafana (port 3000) — see manual 16.

---

## Common compose variables

| Variable | Purpose |
|----------|---------|
| `WEISSMAN_MIGRATE_URL` | Auto-set in compose; runs SQL migrations |
| `WEISSMAN_PUBLIC_BASE_URL` | Public URL for links/SSO |
| `WEISSMAN_BILLING_STRICT` | Auto-on when `WEISSMAN_ENV=production` |
| `PADDLE_*` | Billing (manual 08) |

Full list: `PRODUCTION.env.template`, manual 06.

---

## Upgrade procedure

```bash
git pull
docker compose up -d --build
docker compose logs backend | grep -i migrat
```

Migrations run idempotently at backend start.

---

## Uninstall (destroys data)

```bash
docker compose down -v   # ⚠️ deletes Postgres volume
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Compose exit 15 on start | Quote env vars with `:` in error messages; check `.env` |
| Backend unhealthy | `docker compose logs backend` — JWT secret, DB password |
| 502 on /api | Wait for backend healthcheck; check gateway depends_on |
| Worker idle, jobs queued | `docker compose ps worker`; restart worker |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- `/deploy/PRODUCTION.txt`
