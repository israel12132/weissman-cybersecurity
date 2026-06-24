# 16 — תפעול & Monitoring

## מטרה

תפעול יום-2: health, metrics, Prometheus/Grafana, גיבויים, retention, capacity לעומס SOC.

---

## דרישות מקדימות

- פריסה פעילה (ספרים 02–04)
- `WEISSMAN_METRICS_TOKEN` ב-production
- אופציוני: `docker compose --profile monitoring`

---

## מטריצת health

| רכיב | בדיקה |
|------|--------|
| Gateway | `curl -sf https://host/api/health` |
| Backend | `docker compose ps` / `systemctl status weissman-server` |
| Worker | jobs מתקדמים; `journalctl -u weissman-worker` |
| Postgres | `pg_isready` |
| Redis | `redis-cli ping` |
| Frontend | `curl -sf https://host/command-center/` |

502 → `deploy/fix-weissman-502.sh`.

---

## שלב אחר שלב: תפעול יומי

### 1. Health sweep

```bash
curl -sf https://your-domain.example/api/health | jq .
docker compose ps
docker compose logs worker --since 24h | grep -i error | tail -20
```

### 2. עומק תור jobs

**Jobs** — `queued`/`running` ישנים מ-SLA.

```sql
SELECT status, count(*) FROM weissman_async_jobs
WHERE created_at > now() - interval '24 hours'
GROUP BY status;
```

### 3. דיסק / DB

```bash
df -h /var/lib/postgresql
psql -c "SELECT pg_size_pretty(pg_database_size('weissman'));"
```

### 4. Audit logs

Admin → Audit Logs. `WEISSMAN_LOG_FORMAT=json` ל-Loki/ELK.

### 5. גיבויים

ראו למטה.

---

## Metrics / Prometheus

```bash
curl -sf https://your-domain.example/api/metrics \
  -H "Authorization: Bearer $WEISSMAN_METRICS_TOKEN"
```

production דורש token.

Metrics: HTTP latency, queue depth, engine duration, pool stats.

### Monitoring profile

```bash
docker compose --profile monitoring up -d
```

Prometheus + Grafana (3000).

---

## Logging

| מקור | פקודה |
|------|-------|
| Docker | `docker compose logs backend -f` |
| systemd | `journalctl -u weissman-server -f` |
| nginx | `/var/log/nginx/error.log` |

```bash
WEISSMAN_LOG_FORMAT=json
RUST_LOG=info,weissman_server=info
```

---

## גיבויים

### PostgreSQL

```bash
pg_dump -Fc -h localhost -U postgres weissman > weissman_$(date +%F).dump
```

restore רבעוני:

```bash
pg_restore -d weissman_restore test.dump
```

Grants: `deploy/grant-postgres-weissman-prod.sql`, `grant-postgres-weissman-ro.sql`.

### Redis

ephemeral — snapshot אופציוני.

### Secrets

`/etc/weissman/weissman.env` — מוצפן offsite.

---

## Retention

לפי חוזה: findings, jobs, audit. DPA: `deploy/public/dpa.html`.

Intel DB — ניטור גודל.

---

## Capacity

| אות | פעולה |
|-----|--------|
| backlog jobs | scale workers; concurrency |
| pool exhausted | `WEISSMAN_APP_POOL_MAX`; Postgres |
| latency | heavy workers; off-peak |
| Redis memory | TTL; scale |

```bash
WEISSMAN_WORKER_LIGHT_CONCURRENCY=8
WEISSMAN_WORKER_HEAVY_CONCURRENCY=2
```

---

## התאושות מ outage

- `deploy/verify-outage-recovery.sh`
- `deploy/verify-weissman-origin.sh`

1. Restore Postgres
2. Redis → backend → worker → gateway
3. migrations
4. QA (ספר 18)

---

## אימות

```bash
curl -s -o /dev/null -w "%{http_code}" https://localhost/api/metrics
# 401 ללא Bearer, 200 עם
ls -lh /backups/weissman_*.dump
```

---

## ספרים קשורים

- [02-installation-docker](02-installation-docker.md)
- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [17-troubleshooting](17-troubleshooting.md)
- [18-qa-verification](18-qa-verification.md)
- `/docs/operations.md`
