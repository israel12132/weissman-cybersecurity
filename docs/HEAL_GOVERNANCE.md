# Auto-Heal Governance — per-tenant rate limit

**Status:** shipped. **Module:** `fingerprint_engine::heal_rate_limit`. Gate in `run_auto_heal_job`.

## Why

The auto-heal subsystem is **autonomous**: from a finding it generates a patch, verifies it in
an ephemeral Docker container, and can open a pull request — no human in the loop (auto-merge
itself stays opt-in behind `WEISSMAN_HEAL_AUTO_MERGE`). Autonomy without a bound is a liability:
a noisy scanner, a retry storm, or a compromised trigger could **flood a tenant's repository
with heal PRs** and **burn LLM budget**. Existing policy (`heal_policy`) governs *whether a fix
auto-merges* and *how many attempts* per fix — but nothing capped **how many heals a tenant
starts**. This adds that governance control.

## What

A **per-tenant sliding-window rate limit** on heal *starts*. Every `run_auto_heal_job` first
calls `heal_rate_limit::check_and_record(tenant_id)`; if the tenant has already started
`WEISSMAN_HEAL_MAX_PER_HOUR` heals in the last hour, the job **defers immediately** — no patch
generation, no container, no PR, **no DB mutation** (the finding stays un-healed and can be
retried in a later window). Otherwise the start is recorded and the heal proceeds.

- **In-memory, per-replica** sliding window (same shape as the LLM circuit breaker) — cheap,
  dependency-free.
- **Fail-open** on internal lock poisoning: a governance bug must never wedge the heal path shut.
- **Per-tenant isolation**: one tenant exhausting its budget never affects another.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `WEISSMAN_HEAL_MAX_PER_HOUR` | `20` | Max auto-heal *starts* per tenant per rolling hour. |

Sits alongside the existing heal knobs (`WEISSMAN_HEAL_AUTO_MERGE`, `WEISSMAN_HEAL_MAX_ATTEMPTS`,
`WEISSMAN_HEAL_DEDUP_HOURS`, `WEISSMAN_HEAL_TOURNAMENT_SIZE`).

## Observability

| Metric | Meaning |
|---|---|
| `weissman_heal_rate_limited_total` | Incremented each time a heal is deferred by the rate limit. |

A sustained nonzero rate means a tenant is generating heals faster than the budget allows —
investigate the trigger source (scanner loop, retry storm) before raising the limit.

## Runbook — "heals are being deferred / a tenant isn't getting fixes"

1. Check `weissman_heal_rate_limited_total`. Flat ⇒ not a governance issue.
2. Rising for one tenant ⇒ that tenant is starting >`WEISSMAN_HEAL_MAX_PER_HOUR` heals/hour.
   - **Expected burst** (large first-time scan of a big estate)? Temporarily raise
     `WEISSMAN_HEAL_MAX_PER_HOUR`, then restore it.
   - **Unexpected**? Find the trigger — a scanner re-emitting the same findings, a webhook loop,
     or a misconfigured schedule — and fix the source rather than lifting the cap.
3. The deferred heals are not lost work in flight; they simply weren't started. Re-triggering
   the finding after the window rolls will heal it.

## Limitations & follow-ups

- **Per-replica** window: the effective global limit scales with replica count. A durable
  cross-replica budget (Postgres-counted, like `heal_dedup`) is the planned follow-up; the
  `check_and_record` API is intentionally small so it can be swapped without touching callers.
- **Fixed window length** (1 hour). A configurable window and a burst allowance are possible
  extensions if operational data calls for them.
