# Weissman Cybersecurity — Monitoring & Observability

Prometheus + Alertmanager + Grafana stack for production observability. The metrics are
emitted by the Rust backend (`fingerprint_engine/src/observability.rs`), **not** by any
Python process — earlier revisions of this file documented a Python `src.metrics`
integration that no longer exists.

## Metrics endpoint

`weissman-server` exposes Prometheus metrics at **`/api/metrics` on the API port (8000 in
`docker-compose.yml`)** — not on `:9090` and not at `/metrics`. The endpoint requires a
Bearer token and returns `401` without one, so it is safe to expose alongside the API.

```bash
# 401 without a token (expected):
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8000/api/metrics

# With the scrape token:
curl -sS -H "Authorization: Bearer $(cat metrics_token)" http://localhost:8000/api/metrics | head
```

Prometheus scrapes it with a `credentials_file` (see `monitoring/prometheus.yml`,
job `weissman-backend`).

## Available metrics (real names)

### HTTP / request
- `http_requests_total{method, path, status}` — request counter (5xx = `status=~"5.."`).
  Note the label is `path` (a normalized route bucket), not `endpoint`.
- `http_request_duration_seconds_bucket{method, path, status, le}` — latency histogram (use
  `histogram_quantile(0.99, …)` for P99).

### Database & runtime
- `weissman_db_pool_size`, `weissman_db_pool_idle` — connection-pool gauges.
- `weissman_async_task_panic_total`, `weissman_panic_circuit_open_total` — panic isolation.

### Engines & scanning
- `weissman_engine_*` — per-engine execution counters/telemetry.
- `weissman_engine_waf_block_total` — engine attempts classified as WAF/rate-limit blocked
  (drives adaptive retry escalation).

### SOAR / closed-loop verification
- `weissman_soar_verify_leader` — 1 when this pod holds the verify leader lock.
- `weissman_soar_verify_cycles_total{outcome}` — verification cycle outcomes.

### Agent fleet
- `weissman_agents_registered`, `weissman_agents_online`, `weissman_agents_stale`.

### Deception / active defense
- `weissman_deception_hit_total` — OAST/canary trap interactions (drives the
  trap-hit → targeted re-scan feedback loop).

### Backup / DR
- `weissman_backup_last_success_unix_timestamp` — last successful backup (and restore-verify).

> The Rust process is the source of truth. To confirm a metric exists before writing a
> dashboard/alert query, grep the live scrape output rather than this list.

## Alert rules

Loaded by Prometheus via the glob `rule_files: /etc/prometheus/alerts/*.yml`:

- `monitoring/alerts/application-alerts.yml` — error rate, P99 latency, DB pool, backend/
  worker down, SOAR, agent-fleet staleness.
- `monitoring/alerts/slo-recording-rules.yml` — 99.9% availability SLO recording rules +
  multi-window multi-burn-rate alerts (`SLOErrorBudgetBurn{Fast,Medium,Slow,Trickle}`) and
  the always-firing **`Watchdog`** dead-man's switch.

Validate locally:

```bash
promtool check rules monitoring/alerts/*.yml
amtool check-config monitoring/alertmanager.yml
```

## Alertmanager routing

`monitoring/alertmanager.yml`:
- `critical-alerts` → Slack `#security-alerts` **and PagerDuty** (`PAGERDUTY_ROUTING_KEY`).
- `warning-alerts` → Slack `#security-warnings`.
- `watchdog-heartbeat` → external heartbeat monitor (`WATCHDOG_HEARTBEAT_URL`) — its
  **absence** is the alarm (dead-man's switch).

Secrets are read from files via Alertmanager's native `*_file` options
(`slack_api_url` / `pagerduty_routing_key` / `watchdog_url` under
`/etc/alertmanager/secrets/`) — the minimal `prom/alertmanager` image ships no
envsubst. Committed placeholders in `monitoring/secrets/` let the stack start;
operators overwrite them with real values (see `monitoring/secrets/README.md`).

## Grafana dashboards

Provisioned from `monitoring/grafana/dashboards/`:
- `platform-overview.json` — request rate, error rate, latency, DB pool.
- `agent-fleet-health.json` — registered/online/stale agents.
- `soar-verification.json` — SOAR closed-loop verification health.

## Optional exporters

`monitoring/prometheus.yml` scrapes the `redis` / `postgres` / `node` exporters, and
`monitoring/alerts/infra-alerts.yml` alerts on `up{job=~"node|postgres|redis|blackbox-http"} == 0`.
These jobs are **active**, so the matching exporter services (`redis-exporter`,
`postgres-exporter`, `node-exporter`) must be deployed — bring them up with the
`monitoring` compose profile — or the targets stay "down" and fire `TargetDown`.

## Distributed tracing (OpenTelemetry)

The server and worker export OTLP spans when `WEISSMAN_OTLP_ENDPOINT` is set
(`fingerprint_engine/src/observability.rs::build_otel_layer`). Each component labels its
spans via `WEISSMAN_SERVICE_NAME` (e.g. `weissman-server` / `weissman-worker`) plus
`service.version` and `deployment.environment` (`WEISSMAN_ENV`).

Bring up the Tempo backend and point the apps at it:

```bash
docker compose --profile monitoring --profile tracing up -d tempo
# on backend + worker:
export WEISSMAN_OTLP_ENDPOINT=http://tempo:4318/v1/traces
export WEISSMAN_SERVICE_NAME=weissman-server   # or weissman-worker
```

Traces are queryable in Grafana via the provisioned **Tempo** datasource. Leave
`WEISSMAN_OTLP_ENDPOINT` unset to run logs-only (no tracing overhead).

## Further reading

- [Prometheus](https://prometheus.io/docs/) · [Alertmanager](https://prometheus.io/docs/alerting/latest/configuration/) · [Grafana](https://grafana.com/docs/)
- SLO objective: `SLA_AND_STATUS.md`
