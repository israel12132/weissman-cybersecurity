# Platform Self-Healing

**Status:** shipped (basics — detect → diagnose → signal). **Module:** `fingerprint_engine::self_healing`.

## Why

The platform must keep itself healthy under real-world faults — DB connection blips, a Redis
outage, pool saturation, an async-worker stall, agents going stale. The pieces to survive these
already exist, but were **disconnected**:

- **Detection** — `observability::spawn_pool_metrics_loop` samples every 10s: DB pool size/idle,
  async-job backlog, agents registered/online/stale, and dependency up/down (postgres, redis).
- **Recovery primitives** — `resilience::CircuitBreaker` (open/half-open/closed) + jittered
  exponential backoff; per-service breakers (LLM, crt.sh, webhook); the agent presence pruner.

What was missing is the **brain in the middle**: something that reads the detection signals,
**diagnoses** which subsystem is unhealthy and how urgently, and names the **recovery action**.
This module is that brain.

## Model: detect → diagnose → recover

```
observability 10s loop (DETECT)
   pg_up / redis_up / pool size+idle / agents online+stale / async backlog
                          │
                          ▼
   self_healing::diagnose(HealthSnapshot, Thresholds)  (DIAGNOSE — pure, tested)
                          │  Vec<Diagnosis { subsystem, severity, action, detail }>
                          ▼
   record_diagnoses → weissman_self_heal_diagnosis_total{subsystem,severity,action}
                          │
                          ▼
   RECOVER: resilience::CircuitBreaker + backoff, agent pruner  (primitives — wired next)
```

### Diagnosis rules

| Signal | Severity | Recovery action |
|---|---|---|
| Postgres unreachable | critical | `reconnect_dependency` (trip circuit, let pool re-establish) |
| Redis required but unreachable | critical | `reconnect_dependency` |
| DB pool grown but 0 idle (saturated) | warning | `shed_load` |
| ≥ `stale_agent_ratio` of agents stale | warning | `prune_stale_agents` |
| Async backlog ≥ critical | critical | `shed_load` |
| Async backlog ≥ warn | warning | `backoff` |

`diagnose` is **pure** (same snapshot ⇒ same diagnoses; empty ⇒ healthy) and unit-tested across
every rule and boundary (including "empty pool is not saturation" and the warn→critical backlog
step). Per-tenant-safe (operates on process-wide platform signals, not tenant data). Fail-open:
the diagnosis never blocks the health loop.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `WEISSMAN_SELFHEAL_STALE_AGENT_RATIO` | `0.5` | Fraction of registered agents allowed stale before flagging. |
| `WEISSMAN_SELFHEAL_ASYNC_WARN` | `500` | Async-job backlog that raises a warning. |
| `WEISSMAN_SELFHEAL_ASYNC_CRITICAL` | `5000` | Async-job backlog that raises a critical. |

## Observability

| Metric | Labels | Meaning |
|---|---|---|
| `weissman_self_heal_diagnosis_total` | `subsystem`, `severity`, `action` | Incremented each 10s round a subsystem is diagnosed unhealthy, tagged with the recommended recovery. |

Add to the Grafana/Prometheus layer (`deploy/observability`). A sustained nonzero rate for a
`{subsystem, action}` is the platform telling you what it would self-heal.

## Runbook — reading the platform's self-diagnosis

1. **`postgres` / `reconnect_dependency` firing** ⇒ DB blips. Confirm with `weissman_dependency_up{dep="postgres"}`. Transient ⇒ the pool + circuit recover; sustained ⇒ investigate the DB (failover, connection cap).
2. **`db_pool` / `shed_load`** ⇒ pool saturation. Check `weissman_db_pool_idle`. Raise pool max or shed/queue heavy work; a persistent 0-idle is a capacity or leak problem.
3. **`agents` / `prune_stale_agents`** ⇒ many agents past their 90s presence TTL. Confirm with `weissman_agents_stale`. Expected during a rollout; sustained ⇒ agent connectivity/enrollment issue.
4. **`async_jobs` / `backoff|shed_load`** ⇒ worker backlog. Check `weissman_async_jobs_pending` and worker health; scale workers or shed intake.

## Scope & follow-ups

- **This milestone = detect → diagnose → signal** (the brain + its metric), wired into the
  existing 10s loop using the observability already present.
- **Next**: *execute* the recommended actions automatically — drive `resilience` circuit
  breakers on `reconnect_dependency`, call the agent pruner on `prune_stale_agents`, apply
  intake backoff on `shed_load` — each behind a bounded, per-action safety guard, plus a
  `weissman_self_heal_recovery_total` counter for actions actually taken.
- Diagnosis is intentionally a **pure function** so the recovery-execution layer can be added
  and tested independently of the sampling loop.
