# 06 — Environment Configuration

## Purpose

Reference for all Weissman environment variables. Source of truth: **`PRODUCTION.env.template`** at repository root. Rust binaries read vars via `std::env::var` / dotenvy at startup.

---

## Prerequisites

- Chosen deployment path (Docker, systemd, K8s)
- Secret storage (vault, `/etc/weissman/weissman.env` mode 600, or K8s Secret)
- Understanding of production guards (manual **05**)

---

## Configuration file locations

| Deployment | Primary file |
|------------|--------------|
| Docker Compose | `.env` at repo root (from `PRODUCTION.env.template`) |
| Bare metal (`./start_weissman.sh`) | `.env.local` at repo root, then `.env` |
| systemd | `/etc/weissman/weissman.env` |
| Kubernetes | ConfigMap + Secret (`deploy/k8s/configmap.yaml`) |
| Override chain | `WEISSMAN_ENV_FILE` loads an additional file last |

Docker Compose **requires** at minimum:

```bash
WEISSMAN_JWT_SECRET=<strong>
WEISSMAN_ADMIN_PASSWORD=<strong-min-12>
```

### How files combine

- A **blank** entry (`DATABASE_URL=`) is not a value. `PRODUCTION.env.template` ships the
  datastore URLs blank because Compose supplies them per container, so the loader ignores those
  lines completely: they never erase a value the process already has, and never define the
  variable as an empty string. That is what makes
  `DATABASE_URL=postgres://… ./start_weissman.sh` work, and what lets a blank
  `WEISSMAN_AUTH_DATABASE_URL` fall back to `DATABASE_URL` as documented below.
- Later files override earlier ones, and `WEISSMAN_ENV_FILE` is applied **last**, so an
  operator-chosen file wins over every implicit location.
- `WEISSMAN_ENV_PROCESS_WINS=1` inverts that for launchers: env files may then only fill gaps,
  never replace a value already in the process environment. `start_weissman.sh` sets it because
  it has already resolved the whole configuration itself; without it, `PORT=9999
  ./start_weissman.sh` still bound `:8000` from `.env`.

---

## Step-by-step: first-time configuration

### 1. Copy template

```bash
cp PRODUCTION.env.template .env
# or for systemd:
sudo cp deploy/systemd/weissman.env.example /etc/weissman/weissman.env
sudo chmod 600 /etc/weissman/weissman.env
```

### 2. Set core process variables

```bash
WEISSMAN_ENV=production          # Activates security_startup guards
WEISSMAN_COOKIE_SECURE=1         # Required with WEISSMAN_ENV=production
PORT=8000                        # Must match nginx upstream

DATABASE_URL=postgres://weissman_app:PASS@host:5432/weissman
WEISSMAN_AUTH_DATABASE_URL=postgres://weissman_auth:PASS@host:5432/weissman
WEISSMAN_MIGRATE_URL=postgres://postgres:PASS@host:5432/weissman
REDIS_URL=redis://host:6379/0
```

Optional separate intel DB: `WEISSMAN_INTEL_DATABASE_URL`.

### 3. Authentication and admin bootstrap

```bash
WEISSMAN_JWT_SECRET=<min-32-chars>
WEISSMAN_ACCESS_TOKEN_MINUTES=15
WEISSMAN_REFRESH_TOKEN_DAYS=30
WEISSMAN_ADMIN_EMAIL=admin@company.com
WEISSMAN_ADMIN_PASSWORD=<rotate-after-first-login>
```

Master bootstrap (one-time, tenant `default`):

```bash
WEISSMAN_MASTER_BOOTSTRAP_EMAIL=
WEISSMAN_MASTER_BOOTSTRAP_PASSWORD=
```

### 4. Public URL and static assets

```bash
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
WEISSMAN_STATIC=/opt/weissman/app/frontend/dist   # systemd override if needed
```

### 5. Worker concurrency

```bash
WEISSMAN_WORKER_LIGHT_CONCURRENCY=8
WEISSMAN_WORKER_HEAVY_CONCURRENCY=2
```

Heavy jobs: tenant scans, PoE synthesis, Docker/cloud probes. Light jobs share separate slot pool.

### 6. Billing (Paddle)

```bash
PADDLE_API_KEY=
PADDLE_ENVIRONMENT=production    # or sandbox
PADDLE_WEBHOOK_SECRET=
WEISSMAN_BILLING_STRICT=         # auto-on in production; 0 for contracted self-hosted unlimited
```

When strict billing is on, `gate_scan_enqueue` blocks scans without active subscription.

### 7. Security tokens

```bash
WEISSMAN_METRICS_TOKEN=
WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET=
```

Destructive API calls require header `X-Weissman-Destructive-Confirm`.

### 8. Optional capabilities

| Variable | Effect |
|----------|--------|
| `WEISSMAN_LLM_BASE_URL` / `OPENAI_API_KEY` | Council, NL query, General Mission |
| `WEISSMAN_ALERT_WEBHOOK_URL` | Critical alert webhook |
| `WEISSMAN_PAGER_WEBHOOK_URL` | On-call paging |
| `WEISSMAN_SMTP_*` | Signup verification + alert email |
| `WEISSMAN_INTEL_KEV_ENABLED` | CISA KEV mirror (default on) |
| `WEISSMAN_INTEL_EPSS_ENABLED` | EPSS enrichment (default on) |
| `WEISSMAN_OAST_BASE_URL` | Out-of-band interaction server |
| `WEISSMAN_LOG_FORMAT=json` | Structured logs for Loki/Datadog |

Full table: `docs/operations.md` sections 1–3.

### 9. Pool sizing (high load)

```bash
WEISSMAN_APP_POOL_MAX=48
WEISSMAN_APP_POOL_MIN=2
WEISSMAN_AUTH_POOL_MAX=12
WEISSMAN_INTEL_POOL_MAX=16
```

---

## Variable groups by concern

### Must set for production boot

- `WEISSMAN_ENV=production`
- `WEISSMAN_JWT_SECRET` (≥ 32 chars, not template placeholder)
- `DATABASE_URL`
- `WEISSMAN_COOKIE_SECURE=1`
- `WEISSMAN_MIGRATE_URL` (server)
- `WEISSMAN_METRICS_TOKEN` (server)
- `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` (server)

### Strongly recommended

- `REDIS_URL`
- `WEISSMAN_AUTH_DATABASE_URL` (separate login plane)
- `WEISSMAN_PUBLIC_BASE_URL`
- Rotated `WEISSMAN_ADMIN_PASSWORD`

### Dev-only (never in production)

- `WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1`
- `WEISSMAN_SAML_INSECURE_SKIP_VERIFY=1`
- `WEISSMAN_SIGNUP_RETURN_LINK=1`
- `WEISSMAN_ALLOW_INSECURE_TLS=1`

---

## Verification

```bash
# Docker
docker compose config | grep WEISSMAN_ENV

# systemd
sudo grep -E '^WEISSMAN_ENV|^WEISSMAN_JWT' /etc/weissman/weissman.env

# Runtime health
curl -sf https://your-domain.example/api/health

# Confirm migrations ran
journalctl -u weissman-server | grep -i migrat
```

After changes, restart server and worker processes. JWT secret rotation invalidates existing sessions.

---

## Related manuals

- [02-installation-docker](02-installation-docker.md)
- [03-installation-vps-systemd](03-installation-vps-systemd.md)
- [05-production-security](05-production-security.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- `/docs/operations.md` — operational deep dive
- `/PRODUCTION.env.template` — authoritative inline comments
