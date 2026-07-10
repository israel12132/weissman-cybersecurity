# Runbook — Incident Response & On-Call (English)

English counterpart of [`INCIDENT-ONCALL-RUNBOOK-he.md`](INCIDENT-ONCALL-RUNBOOK-he.md).
Keep the two in sync when either changes.

## 1. Purpose

How on-call engineers detect, triage, mitigate, and communicate production incidents for the
Weissman platform (API, worker, database, Redis, agents), and how we run the post-incident
review.

## 2. Severity levels

| Sev | Definition | Response | Comms cadence |
|-----|------------|----------|---------------|
| **SEV-1** | Full outage or confirmed data breach; customers cannot use the platform. | Immediate page, all-hands. | Every 30 min until mitigated. |
| **SEV-2** | Major degradation (scans failing, DB failover, elevated 5xx / SLO fast-burn). | Page primary on-call. | Every 60 min. |
| **SEV-3** | Minor / single-tenant / cosmetic; no SLO impact. | Next business day. | On resolution. |

Alert → severity mapping: `BackendDown` / `WorkerDown` / `SLOErrorBudgetBurnFast` /
`SyntheticProbeFailing` → SEV-1/2; `RedisEvictingKeys` / `PostgresReplicationLagHigh` →
SEV-2; agent-fleet / slow-scan warnings → SEV-3.

## 3. Contacts (fill in for production)

| Role | Name | Channel | Escalation |
|------|------|---------|------------|
| Primary on-call | _TODO_ | _TODO_ (PagerDuty `PAGERDUTY_ROUTING_KEY`) | → Secondary after 15 min |
| Secondary on-call | _TODO_ | _TODO_ | → Eng lead after 30 min |
| Engineering lead | _TODO_ | _TODO_ | → CTO |
| Security lead (breach) | _TODO_ | security@weissman.io | → Legal/DPO |
| Status page owner | _TODO_ | `/command-center/status` | — |

Alerting routes to Slack `#security-alerts` and PagerDuty; the always-firing `Watchdog`
dead-man's switch goes to `WATCHDOG_HEARTBEAT_URL` (its **absence** pages).

## 4. Flow — SEV-1 / SEV-2

1. **Acknowledge** the page (stops escalation).
2. **Declare** severity + open an incident channel; assign an Incident Commander.
3. **Assess** — run the quick commands below; check Grafana (platform-overview,
   SLO burn-rate, Tempo traces) and `/api/health`.
4. **Mitigate** — prefer the fastest safe action: roll back the last deploy, scale out
   (HPA already elastic), fail over the DB (CNPG), or enable `global_safe_mode`.
5. **Communicate** — update the status page + customers on the cadence above.
6. **Resolve** — confirm SLOs recovered (burn-rate alerts cleared, synthetic probes green).
7. **Post-mortem** — within 3 business days (template below).

## 5. Quick commands

```bash
# Health
curl -sf https://<host>/api/health | jq .

# Stack (compose)
docker compose ps
docker compose logs -f backend worker

# Stack (k8s)
kubectl -n weissman get pods,hpa,pdb
kubectl -n weissman logs deploy/weissman-backend --tail=200

# DB connectivity + replication (CNPG)
kubectl -n weissman get cluster weissman-pg
kubectl -n weissman exec -it weissman-pg-1 -- psql -c 'SELECT * FROM pg_stat_replication;'

# Redis
kubectl -n weissman exec -it weissman-redis-0 -- redis-cli info replication

# Prove a backup is restorable (DR drill)
WEISSMAN_PITR_BASE_DIR=/var/backups/weissman/base ./scripts/backup_restore_verify.sh
```

## 6. Security — suspected breach

1. Do **not** destroy evidence; snapshot logs (`audit_logs`, `nl_query_audit`) and volumes.
2. Rotate credentials: `scripts/rotate_auth_db_password.sh`, regenerate JWT/metrics secrets,
   revoke API keys.
3. Contain: enable `global_safe_mode`, tighten NetworkPolicies, block offending IPs at the
   gateway/WAF.
4. Notify the security lead → legal/DPO; follow the disclosure policy in
   [`SECURITY.md`](../../SECURITY.md).
5. Preserve the timeline for the post-mortem and any regulator notification clock.

## 7. Post-mortem template (blameless)

```
Incident: <title>            Severity: SEV-<n>       Date: <UTC>
Duration: <detected> → <mitigated> → <resolved>
Impact: <who/what, tenants, data>
Detection: <alert / customer / synthetic probe>
Timeline (UTC):
  - <t> <event>
Root cause: <the actual cause, 5-whys>
What went well / poorly:
Action items (owner, due):
  - [ ] <preventive>
  - [ ] <detective>
```

## 8. Appendix — audited hot paths

- **`run_pipeline_analysis_sync`** (the synchronous `reqwest::blocking` LLM path) is invoked
  under `tokio::task::spawn_blocking` (`async_job_executor.rs`), so its blocking retry sleeps
  run on the blocking thread pool — they never stall the async runtime. All async engine
  jitter uses `tokio::time::sleep` (non-blocking).

## 9. Links

- Grafana dashboards + Tempo traces (see [`monitoring/README.md`](../../monitoring/README.md)).
- SLA / SLO objective: [`SLA_AND_STATUS.md`](../../SLA_AND_STATUS.md).
- Disaster recovery: [`DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md).
- Auth/DB rotation: [`AUTH-DB-ROTATION.md`](AUTH-DB-ROTATION.md).
