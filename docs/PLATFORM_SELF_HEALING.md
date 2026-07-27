# Platform Self-Healing

**Status:** shipped (detect → diagnose → **recover**). **Modules:** `fingerprint_engine::self_healing`
(diagnose) + `fingerprint_engine::self_heal_recovery` (execute).

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
   self_heal_recovery::run_recovery(HealthSnapshot, &[Diagnosis])  (RECOVER — bounded, tested)
     • feed dependency circuits (pg/redis) so they open on outage, close on recovery
     • plan_recovery (pure) → cooldown-gate each (subsystem, action)
     • apply effect: engage shed / backoff gate · raise prune signal · fail-fast circuit
                          │
                          ▼
   weissman_self_heal_recovery_total{subsystem,action,outcome=executed|cooldown}
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

### Recovery execution (`self_heal_recovery`)

Each diagnosis names a [`RecoveryAction`]; `run_recovery` turns that recommendation into a
**bounded, reversible effect** and exposes the resulting state for the rest of the platform to
consult:

| Action | Effect | How callers consume it |
|---|---|---|
| `shed_load` | engage a process-wide **load-shed gate** for `SHED_TTL_SECS` | `self_heal_recovery::load_shed_active()` → reject/queue heavy new work |
| `backoff` | engage a softer **backoff gate** for `BACKOFF_TTL_SECS` | `self_heal_recovery::backoff_active()` → add delay before heavy work |
| `reconnect_dependency` | drive that dependency's **circuit breaker** (fed from the snapshot every round) | `self_heal_recovery::dependency_available(dep)` → fail fast while open; auto-probes (half-open) after cooldown so the pool re-establishes without a herd |
| `prune_stale_agents` | raise a **prune-request** signal | `self_heal_recovery::prune_requests()`; the presence pruner reaps on its own 30s cadence |

Two guard rails keep execution safe:

- **Cooldown gate** — each `(subsystem, action)` fires at most once per
  `ACTION_COOLDOWN_SECS`, so a *sustained* fault engages recovery once per window rather than
  re-firing every 10s round. Suppressed rounds are still counted (`outcome=cooldown`).
- **Master switch** — `WEISSMAN_SELFHEAL_RECOVERY_ENABLED=0` disables all execution; the gates
  then read "healthy" (`load_shed_active()`/`backoff_active()` → false, `dependency_available()`
  → true) so consumers degrade to normal behavior.

The decision core `plan_recovery` is **pure** (`diagnoses + last-fired ledger + clock ⇒ plan`) and
the gates take an injected `now`, so the whole state machine — engage/expire, cooldown
suppression, circuit trip/recover — is unit-tested without a live stack. The load-shed and
backoff gates **auto-expire**: if the fault clears, no new engagement refreshes them and they
lapse on their own. All state is process-wide and tenant-agnostic.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `WEISSMAN_SELFHEAL_STALE_AGENT_RATIO` | `0.5` | Fraction of registered agents allowed stale before flagging. |
| `WEISSMAN_SELFHEAL_ASYNC_WARN` | `500` | Async-job backlog that raises a warning. |
| `WEISSMAN_SELFHEAL_ASYNC_CRITICAL` | `5000` | Async-job backlog that raises a critical. |
| `WEISSMAN_SELFHEAL_RECOVERY_ENABLED` | `true` | Master switch for recovery **execution** (`0`/`false`/`no`/`off` disables all effects). |
| `WEISSMAN_SELFHEAL_ACTION_COOLDOWN_SECS` | `60` | Min seconds between the same `(subsystem, action)` firing. |
| `WEISSMAN_SELFHEAL_SHED_TTL_SECS` | `30` | How long a `shed_load` gate stays engaged before auto-clearing. |
| `WEISSMAN_SELFHEAL_BACKOFF_TTL_SECS` | `20` | How long a `backoff` gate stays engaged before auto-clearing. |
| `WEISSMAN_SELFHEAL_DEP_CIRCUIT_THRESHOLD` | `3` | Consecutive dependency failures before its circuit opens (fail-fast). |
| `WEISSMAN_SELFHEAL_DEP_CIRCUIT_COOLDOWN_SECS` | `15` | Seconds an open dependency circuit waits before probing (half-open). |

## Observability

| Metric | Labels | Meaning |
|---|---|---|
| `weissman_self_heal_diagnosis_total` | `subsystem`, `severity`, `action` | Incremented each 10s round a subsystem is diagnosed unhealthy, tagged with the recommended recovery. |
| `weissman_self_heal_recovery_total` | `subsystem`, `action`, `outcome` | Incremented per round a recovery is considered: `outcome=executed` when the effect ran, `outcome=cooldown` when suppressed by the per-action window. |
| `weissman_self_heal_scan_shed_total` | — | Incremented each time a scan-trigger POST is rejected with 503 because the load-shed gate is engaged (the intake edge honoring `load_shed_active()`). |
| `weissman_self_heal_cron_backoff_total` | — | Incremented each cron tick the scan-schedule worker defers because `backoff_active()` is engaged (transient pressure). |

Add to the Grafana/Prometheus layer (`deploy/observability`). A sustained nonzero
`diagnosis`/`executed` rate for a `{subsystem, action}` is the platform actively self-healing; a
high `cooldown` rate means the fault is *sustained* (recovery already engaged, waiting out the
window) — escalate to the runbook below.

## Runbook — reading the platform's self-diagnosis

1. **`postgres` / `reconnect_dependency` firing** ⇒ DB blips. Confirm with `weissman_dependency_up{dep="postgres"}`. Transient ⇒ the pool + circuit recover; sustained ⇒ investigate the DB (failover, connection cap).
2. **`db_pool` / `shed_load`** ⇒ pool saturation. Check `weissman_db_pool_idle`. Raise pool max or shed/queue heavy work; a persistent 0-idle is a capacity or leak problem.
3. **`agents` / `prune_stale_agents`** ⇒ many agents past their 90s presence TTL. Confirm with `weissman_agents_stale`. Expected during a rollout; sustained ⇒ agent connectivity/enrollment issue.
4. **`async_jobs` / `backoff|shed_load`** ⇒ worker backlog. Check `weissman_async_jobs_pending` and worker health; scale workers or shed intake.

## Scope & follow-ups

- **Shipped = detect → diagnose → recover.** The diagnose brain (`self_healing`) and the
  bounded recovery executor (`self_heal_recovery`) are both wired into the existing 10s loop,
  each with its own metric, over the observability already present.
- **Adoption at the intake edge — all three gates now consumed.** The recovery *state* is only
  worth the win when heavy paths honor it, and every gate now has a real consumer:
  - **`load_shed_active()`** — scan-trigger POST admission (`http::tenant_scan_limit`) returns
    **503 + Retry-After** (`weissman_self_heal_scan_shed_total`) when the platform is shedding, so
    critical saturation sheds *new* scan intake instead of piling on.
  - **`backoff_active()`** — the cron scan-schedule worker (`scan_schedule_worker`) defers its tick
    (`weissman_self_heal_cron_backoff_total`) under transient pressure. Due scans stay due (their
    `next_run_at` only advances once launched), so nothing is lost — new cron intake just waits for
    a healthy tick, without starving the async worker that drains the backlog.
  - **`dependency_available(Redis)`** — the distributed rate-limit hot path (`rate_limit_redis::
    incr_window`) fast-fails to the local limiter when the Redis circuit is open, instead of paying
    the connect/op timeout on every request during an outage.

  All three are guarded by the master switch and auto-clear when the fault passes.
- **Later** — durable cross-replica recovery state (today each replica self-heals from its own
  in-memory gates; a Postgres-backed shared gate would coordinate a fleet), and auto-restart of
  stuck background workers (the diagnosis + prune-request signals already exist; a supervised
  restart wrapper is the remaining piece). Both are deliberately deferred: they change failure
  semantics across replicas/processes and warrant their own design + soak, whereas the in-replica
  loop above is complete and safe today.
- Both `diagnose` and `plan_recovery` are intentionally **pure functions** so new rules and new
  effects can be added and tested independently of the sampling loop.
