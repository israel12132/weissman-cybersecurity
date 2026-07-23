# Weissman Observability — dashboards, alerts & runbook

The API server already emits a rich Prometheus metric set from
`fingerprint_engine::observability` (HTTP histograms, DB-pool / job / agent /
dependency / self-healing gauges) at **`GET /api/metrics`**, and exports
distributed traces over OTLP when `WEISSMAN_OTLP_ENDPOINT` is set. This directory
adds the **dashboards, alert rules, and scrape config** to consume them — the
Grafana/Prometheus layer that the code comments already reference but that was
missing from `deploy/`.

## Contents

| File | Purpose |
|------|---------|
| `prometheus/scrape-config.yml` | Scrape snippet for the token-guarded `/api/metrics` endpoint + rule-file wiring. |
| `prometheus/weissman-alerts.yml` | Alerting rules: 5xx ratio, p95 latency, error/rate-limit spikes, DB-pool exhaustion, job backlog, dependency down, agents offline, self-healing degraded. |
| `grafana/weissman-overview.json` | Importable Grafana dashboard: traffic/latency/errors, DB pools, jobs, dependencies, agents, self-healing. |

## Wiring it up

1. **Expose metrics**: ensure `WEISSMAN_METRICS_TOKEN` is set on `weissman-server`; Prometheus authenticates to `/api/metrics` with it (see `scrape-config.yml`).
2. **Prometheus**: merge `scrape-config.yml` into `prometheus.yml` and mount `weissman-alerts.yml` at `/etc/prometheus/rules/`.
3. **Grafana**: import `grafana/weissman-overview.json` and pick your Prometheus data source when prompted.
4. **Tracing (already built in)**: set `WEISSMAN_OTLP_ENDPOINT` (e.g. an OTel Collector) to ship spans; the server initializes the OTLP batch exporter at startup (`init_tracing_from_env`).

## Metric reference (source of truth: `fingerprint_engine/src/observability.rs`)

- `http_requests_total{method,path,status}` — request counter.
- `http_request_duration_seconds_bucket{method,path,status}` — latency histogram.
- `weissman_errors_total{path}` — 5xx counter · `weissman_rate_limit_violations_total{path}` — 429 counter.
- `weissman_db_pool_size{pool}` / `weissman_db_pool_idle{pool}` — pools: `app`, `auth`, `intel`.
- `weissman_async_jobs_pending` · `weissman_orchestrator_active_tenant_cycles` · `weissman_scanning_flag_active`.
- `weissman_agents_registered` / `weissman_agents_online` / `weissman_agents_stale`.
- `weissman_dependency_up{dependency}` — tracked dependency health.
- `weissman_heal_total_requests` / `weissman_heal_success_rate` / `weissman_heal_by_verdict`.

## On-call quick reference

| Alert | First checks |
|-------|--------------|
| `WeissmanHigh5xxRatio` | Recent deploy? Check server logs (trace-id correlation), DB reachability, dependency alerts. |
| `WeissmanHighRequestLatencyP95` | DB-pool idle (contention), downstream latency, `weissman_scanning_flag_active` (heavy scans). |
| `WeissmanDbPoolExhausted` | Long-running queries, pool sizing, a stuck migration or lock. |
| `WeissmanJobBacklog` | Worker health/scale, poison messages in the job bus. |
| `WeissmanDependencyDown` | The `dependency` label names it; check its own health + network policy. |
| `WeissmanAllAgentsOffline` | Agent gateway / job-bus connectivity, auth token rotation. |
| `WeissmanSelfHealingDegraded` | Inspect `weissman_heal_by_verdict` for the failing class of remediations. |

Thresholds are conservative defaults — tune to your SLOs.
