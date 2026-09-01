# 03 — Installation: VPS / Bare Metal (systemd)

## Purpose

Deploy Weissman on a single Linux VPS or bare-metal host **without Docker**, using native systemd units. Use this path when customers require direct process control, custom kernel tuning, or air-gapped builds from source.

---

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| OS | Debian 12 / Ubuntu 22.04+ (script targets systemd) |
| RAM | 8 GB recommended (4 GB minimum for pilot) |
| CPU | 4 vCPU recommended |
| Disk | 40 GB free |
| Software | Rust 1.91.1 (`rust-toolchain.toml`), Node 20+, PostgreSQL 16 + pgvector, Redis 7 |
| Network | HTTPS reverse proxy (nginx or Caddy) in front of `weissman-server` |
| Secrets | Strong `WEISSMAN_JWT_SECRET`, DB passwords, admin password |

---

## Step-by-step

### 1. Prepare the host

```bash
sudo apt update && sudo apt install -y postgresql-16 redis-server nginx
sudo bash deploy/install-build-deps-debian.sh
sudo bash deploy/apply-listen-sysctl.sh   # net.core.somaxconn=4096 — otherwise listen(4096) is silently truncated
```

Create PostgreSQL roles and database using `deploy/grant-postgres-weissman-prod.sql` (adjust passwords):

```bash
sudo -u postgres psql -f deploy/grant-postgres-weissman-prod.sql
```

### 2. Build binaries and frontend

```bash
git clone https://github.com/israel12132/weissman-cybersecurity.git
cd weissman-cybersecurity
cargo build --release -p weissman-server -p weissman-worker
cd frontend && npm ci && npm run build && cd ..
```

Release binaries land in `target/release/weissman-server` and `target/release/weissman-worker`.

### 3. Install systemd units

From repo root as root:

```bash
sudo bash deploy/systemd/install-weissman-systemd.sh
```

Default install root: `/opt/weissman/app`. Custom path:

```bash
sudo INSTALL_ROOT=/srv/weissman/app bash deploy/systemd/install-weissman-systemd.sh
```

Units installed:

| Unit | Role |
|------|------|
| `weissman-server.service` | Axum API + static Command Center from `frontend/dist` |
| `weissman-worker.service` | Claims `weissman_async_jobs` (required for scans) |
| `weissman.target` | Groups both services |

There is **no separate frontend process** — build React once and serve from `WEISSMAN_STATIC` or `WorkingDirectory/frontend/dist`.

### 4. Configure environment

```bash
sudo cp deploy/systemd/weissman.env.example /etc/weissman/weissman.env
sudo chmod 600 /etc/weissman/weissman.env
sudo nano /etc/weissman/weissman.env
```

**Minimum production values:**

```bash
WEISSMAN_ENV=production
WEISSMAN_COOKIE_SECURE=1
DATABASE_URL=postgres://weissman_app:STRONG@127.0.0.1:5432/weissman?sslmode=disable
WEISSMAN_AUTH_DATABASE_URL=postgres://weissman_auth:STRONG@127.0.0.1:5432/weissman
WEISSMAN_MIGRATE_URL=postgres://postgres:STRONG@127.0.0.1:5432/weissman
WEISSMAN_JWT_SECRET=<openssl rand -base64 48>
REDIS_URL=redis://127.0.0.1:6379/0
WEISSMAN_ADMIN_EMAIL=admin@yourcompany.com
WEISSMAN_ADMIN_PASSWORD=<strong-min-12-chars>
WEISSMAN_PUBLIC_BASE_URL=https://your-domain.example
WEISSMAN_METRICS_TOKEN=<openssl rand -base64 48>
WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET=<openssl rand -base64 48>
PORT=8000
```

See manual **06** for the full variable reference (`PRODUCTION.env.template`).

### 5. Configure reverse proxy

Copy `deploy/nginx-weissman.conf` or `deploy/Caddyfile` and point TLS termination to `127.0.0.1:8000`.

Ensure WebSocket upgrade headers for `/ws/*` using `deploy/nginx-snippet-websocket-map.conf`.

JSON Brotli belongs at nginx (not Axum). After `apt install libnginx-mod-http-brotli`:

```bash
sudo cp deploy/nginx-brotli.inc /etc/nginx/snippets/weissman-brotli.conf
# then include /etc/nginx/snippets/weissman-brotli.conf; in the TLS server{}
```

Set `WEISSMAN_PUBLIC_BASE_URL` to the public HTTPS origin — required for SSO redirects and agent installers.

### 6. Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now weissman-server weissman-worker weissman.target
```

If Postgres runs on the same VM, add a dependency override:

```bash
sudo systemctl edit weissman-server
```

```ini
[Unit]
After=postgresql.service
Requires=postgresql.service
```

### 7. Package agent binaries (if endpoint scope sold)

```bash
bash scripts/package_agent_binaries.sh
```

Agent installers are served at `GET /install/agent.sh` and `GET /install/agent.ps1`.

---

## Verification

```bash
curl -sf https://your-domain.example/api/health
curl -sf https://your-domain.example/command-center/
sudo systemctl status weissman-server weissman-worker
journalctl -u weissman-server --since "5 min ago" | tail -20
journalctl -u weissman-worker --since "5 min ago" | tail -20
```

Log in at `/command-center/login` with `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD`.

Run a smoke scan from Command Center and confirm the worker claims the job (`journalctl -u weissman-worker -f`).

Production guards (`security_startup.rs`) refuse boot if `WEISSMAN_ENV=production` is set with weak JWT secrets or missing `WEISSMAN_COOKIE_SECURE=1`.

---

## Upgrade procedure

```bash
cd /opt/weissman/app
git pull
cargo build --release -p weissman-server -p weissman-worker
cd frontend && npm ci && npm run build && cd ..
sudo systemctl restart weissman-server weissman-worker
```

Migrations run at server boot when `WEISSMAN_MIGRATE_URL` is set.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Server exits immediately | `journalctl -u weissman-server -n 50` — check JWT secret length, `WEISSMAN_ENV` guards |
| 502 from nginx | Verify `PORT` matches upstream; run `deploy/fix-weissman-502.sh` |
| Jobs stuck queued | Worker not running — `systemctl start weissman-worker` |
| Static UI 404 | Rebuild frontend; set `WEISSMAN_STATIC` |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [02-installation-docker](02-installation-docker.md) — alternative Docker path
- [05-production-security](05-production-security.md) — hardening checklist
- [06-environment-configuration](06-environment-configuration.md) — all env vars
- [16-operations-monitoring](16-operations-monitoring.md) — logs, metrics, backups
- `deploy/systemd/README.md` — upstream systemd notes
