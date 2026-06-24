# 16 — Operations & Monitoring

## Purpose

Day-2 operations for Weissman: health checks, metrics, Prometheus/Grafana, backups, log retention, and capacity planning for production SOC workloads.

---

## Prerequisites

- Deployment running (manual 02–04)
- Admin or operator access
- `WEISSMAN_METRICS_TOKEN` set in production
- Optional: Docker `--profile monitoring` or external Prometheus

---

## Service health matrix

| Component | Check |
|-----------|-------|
| Gateway | `curl -sf https://host/api/health` |
| Backend | `docker compose ps backend` or `systemctl status weissman-server` |
| Worker | Jobs processing; `journalctl -u weissman-worker` |
| Postgres | `pg_isready`; connection from app pool |
| Redis | `redis-cli ping` when `REDIS_URL` set |
| Frontend | `curl -sf https://host/command-center/` |

Health endpoint returns JSON with subsystem status. Gateway returns 502 if backend unhealthy — use `deploy/fix-weissman-502.sh`.

---

## Step-by-step: daily operations

### 1. Morning health sweep

```bash
curl -sf https://your-domain.example/api/health | jq .
docker compose ps   # or systemctl status weissman.target
docker compose logs worker --since 24h | grep -i error | tail -20
```

### 2. Review job queue depth

Command Center → **Jobs** — check for stuck `queued` or `running` jobs older than SLA.

SQL spot check:

```sql
SELECT status, count(*) FROM weissman_async_jobs
WHERE created_at > now() - interval '24 hours'
GROUP BY status;
```

### 3. Check disk and database size

```bash
df -h /var/lib/postgresql
psql -c "SELECT pg_size_pretty(pg_database_size('weissman'));"
```

### 4. Review audit logs

Command Center → Admin → Audit Logs. Filter failed logins, role changes, destructive actions.

Structured logs: set `WEISSMAN_LOG_FORMAT=json` for Loki/ELK/Datadog.

### 5. Verify backups completed

See backup section below.

---

## Metrics and Prometheus

### Protected metrics endpoint

```bash
curl -sf https://your-domain.example/api/metrics \
  -H "Authorization: Bearer $WEISSMAN_METRICS_TOKEN"
```

Production **requires** `WEISSMAN_METRICS_TOKEN` — unauthenticated scrape blocked.

Metrics include:

- HTTP request counts and latency
- Job queue depth and claim rates
- Engine execution duration histograms
- Pool connection stats

### Docker monitoring profile

```bash
docker compose --profile monitoring up -d
```

Starts Prometheus + Grafana (Grafana port 3000). Scrape config targets backend metrics with Bearer token.

### Grafana dashboards

Import operational dashboards or build panels for:

- Scan throughput per hour
- Worker utilization (light vs heavy pools)
- Error rate by engine
- Login failure rate

---

## Logging

| Source | Command |
|--------|---------|
| Docker backend | `docker compose logs backend -f` |
| Docker worker | `docker compose logs worker -f` |
| systemd | `journalctl -u weissman-server -u weissman-worker -f` |
| nginx | `/var/log/nginx/error.log` |

Recommended production:

```bash
WEISSMAN_LOG_FORMAT=json
RUST_LOG=info,weissman_server=info,fingerprint_engine=warn
```

Forward to centralized SIEM with tenant/client IDs in structured fields.

---

## Backups

### PostgreSQL

```bash
pg_dump -Fc -h localhost -U postgres weissman > weissman_$(date +%F).dump
```

Schedule daily with retention policy (30/90 days per contract).

Test restore quarterly:

```bash
pg_restore -d weissman_restore test.dump
```

Grant scripts: `deploy/grant-postgres-weissman-prod.sql`, `deploy/grant-postgres-weissman-ro.sql`

### Redis

Redis holds ephemeral state (rate limits, sessions cache). Snapshot optional; not primary data store.

### Configuration secrets

Backup `/etc/weissman/weissman.env` or vault export — encrypted offsite.

---

## Retention and cleanup

Configure per contract:

- Findings retention period
- Job history pruning
- Audit log archival

Document in customer DPA (`deploy/public/dpa.html`).

Intel tables (`dynamic_payloads`, etc.) may grow — monitor `WEISSMAN_INTEL_DATABASE_URL` disk.

---

## Capacity planning

| Signal | Action |
|--------|--------|
| Job queue backlog growing | Scale worker replicas or increase concurrency env vars |
| DB pool exhausted | Raise `WEISSMAN_APP_POOL_MAX`; add Postgres resources |
| Scan latency high | Separate heavy workers; schedule off-peak |
| Redis memory high | Review TTL; scale Redis instance |

Worker env tuning:

```bash
WEISSMAN_WORKER_LIGHT_CONCURRENCY=8
WEISSMAN_WORKER_HEAVY_CONCURRENCY=2
```

---

## Outage recovery

Scripts:

- `deploy/verify-outage-recovery.sh` — post-incident validation
- `deploy/verify-weissman-origin.sh` — origin/TLS check

Procedure:

1. Restore Postgres if needed
2. Start Redis → backend → worker → gateway
3. Verify migrations current
4. Run manual **18** smoke tests

---

## Verification

```bash
# Metrics auth works
curl -s -o /dev/null -w "%{http_code}" https://localhost/api/metrics
# Expect: 401 without token, 200 with Bearer

# Prometheus target UP (if monitoring profile)
curl -sf http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'

# Backup file non-zero
ls -lh /backups/weissman_*.dump
```

---

## Related manuals

- [02-installation-docker](02-installation-docker.md) — monitoring profile
- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [17-troubleshooting](17-troubleshooting.md)
- [18-qa-verification](18-qa-verification.md)
- `/docs/operations.md`
