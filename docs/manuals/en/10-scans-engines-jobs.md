# 10 — Scans, Engines & Jobs

## Purpose

Operate Weissman's **545 production security engines**, understand job queue mechanics, Command Center hubs, agent-required gates, and scan scheduling for SOC operators.

---

## Prerequisites

- Operator role or higher
- `weissman-worker` running (required — scans do not execute on server alone)
- Client with authorized scope configured (manual 09)
- Billing quota available when `WEISSMAN_BILLING_STRICT=1`

---

## Engine catalog overview

Weissman ships **545+ production engines** registered in `PRODUCTION_ENGINE_IDS` (`backend/weissman-core/src/models/engine.rs`).

Each engine is wired to a **real execution path** verified by CI script `scripts/verify_engine_wiring.mjs` (build fails on gaps).

### Engine kinds

| Kind | Meaning | UI behavior |
|------|---------|-------------|
| `real_probe` | Remote scan without agent | Normal scan + live findings |
| `agent_required` | Needs endpoint agent on target | Empty state + install prompt until agent online |
| `alias` | Retag of canonical engine | Resolved via `resolve_engine_id` |
| `special` | e.g. `poe_synthesis` | Async job path, not direct dispatch |

API source of truth: `GET /api/engines/capabilities`

~45 engines require an endpoint agent. UI shows **honest empty states** — never fabricated findings.

---

## Architecture: scan to finding

```
Operator → Command Center Run
    → POST /api/command-center/scan
    → RBAC check (operator+)
    → gate_scan_enqueue (billing)
    → Scope validation (authorized domains)
    → INSERT weissman_async_jobs
    → Worker claims (SKIP LOCKED)
    → engine_dispatch.rs → real probe
    → Findings upserted to vulnerabilities
    → UI polls job / WebSocket telemetry
```

---

## Step-by-step: run a scan

### 1. Select client and engine

Command Center engine hubs (examples):

| Hub path | Domain |
|----------|--------|
| `/command-center/domain-discovery` | ASM / DNS |
| `/command-center/jwt-lab` | JWT attacks |
| `/command-center/iac-security` | IaC misconfig |
| `/command-center/cloud-control-tower` | Cloud posture |

Or use **Engine Matrix** for catalog search.

### 2. Configure target

Target must fall within client's **authorized domains** or IP ranges. Out-of-scope targets are rejected server-side.

### 3. Execute

Click **Run** or call API:

```bash
curl -X POST -b cookies.txt https://localhost/api/command-center/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "engine": "dns_recon",
    "client_id": 1,
    "target": "authorized.example.com"
  }'
```

Response includes job UUID.

### 4. Monitor job

**Jobs** page (`/jobs`) shows status: queued → running → completed/failed.

```bash
journalctl -u weissman-worker -f
```

Heavy jobs (tenant scans, PoE, cloud Docker probes) use separate concurrency pool:

- `WEISSMAN_WORKER_LIGHT_CONCURRENCY` (default 8)
- `WEISSMAN_WORKER_HEAVY_CONCURRENCY` (default 2)

### 5. Review results

Findings appear in hub panel and global **Findings** view. Job result JSON includes engine metadata and timing.

---

## Agent-required engines

Before running agent-gated engines:

1. Confirm agent online in **Agent Management**
2. UI route gates block Run button with install instructions
3. Engine returns informational finding pointing to agent if run without fleet coverage

Install scripts: `GET /install/agent.sh`, `GET /install/agent.ps1` (manual 12).

---

## Scheduled scans

Command Center → **Schedules**

- Cron expression + engine + client + target
- Worker `scan_schedule_worker` enqueues jobs on schedule
- Batch enqueue uses `gate_scan_enqueue_n` for quota pre-check

---

## Bulk and pipeline scans

- **Run All** on client dashboard — respects monthly quota
- **PoE Synthesis** (`poe_synthesis`) — special async job synthesizing proof-of-exploit chains
- **Tenant scan** — heavy job class; tune worker heavy concurrency

---

## Engine Room and DAG

Advanced operators use Engine Room for chained engine DAGs. Extra engine IDs accepted via `scan_routing.rs` beyond strict production list for DAG compositions.

---

## Verification

```bash
# Engine capabilities API
curl -sf -b cookies.txt https://localhost/api/engines/capabilities | jq '.engines | length'

# CI wiring check (from repo)
node scripts/verify_engine_wiring.mjs
node scripts/engine_reality_audit.mjs

# Live scan smoke
# 1. POST /api/command-center/scan
# 2. Poll GET /api/jobs/{uuid}
# 3. Confirm findings count > 0 or honest empty for agent engines
```

Expect `verify_engine_wiring.mjs` exit 0 and zero `no_path` engines in reality audit.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Jobs stuck queued | Start/restart `weissman-worker` |
| "Subscription/quota" error | Billing gate — see manual 08 |
| Empty findings on real_probe | Check target scope; review worker logs |
| Agent engine shows empty | Expected until agent online |
| Engine 404 | ID not in production registry — update deployment |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [09-client-onboarding](09-client-onboarding.md)
- [11-findings-reports](11-findings-reports.md)
- [12-endpoint-agent](12-endpoint-agent.md)
- [08-billing-multitenancy](08-billing-multitenancy.md)
- [01-platform-overview](01-platform-overview.md)
