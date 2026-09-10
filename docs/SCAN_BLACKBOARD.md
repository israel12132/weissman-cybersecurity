# Scan blackboard

Shared session state so planner / runner / verifier / helper do not talk past each other.
Schema: `fingerprint_engine/migrations/20260910140000_scan_blackboard.sql`.

## Tables

| Table | Role |
|-------|------|
| `scan_blackboard` | One authorized scan session (scope, allowed engines/targets) |
| `scan_bb_tasks` | Work items with lease + blocked/help |
| `scan_bb_facts` | Observations; `verified=true` only after verifier |
| `scan_bb_events` | Audit of claimed / blocked / helped |

## Claim a queued task

```sql
UPDATE scan_bb_tasks
SET status = 'running',
    lease_owner = $agent,
    lease_until = now() + interval '2 minutes',
    attempt = attempt + 1,
    updated_at = now()
WHERE id = (
    SELECT id FROM scan_bb_tasks
    WHERE board_id = $board
      AND status = 'queued'
      AND (lease_until IS NULL OR lease_until < now())
    ORDER BY id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;
```

## Rules

- Agents may only set `engine_id` / `target` values present on the parent board lists.
- `run_engine` writes `observation` or `dead_end`. Never flip `verified`.
- Only `assigned_role = verifier` may set `scan_bb_facts.verified = true`.
- High/critical findings still go through `findings_gate` with real proof.
- This is coordination only. It does not add exploit engines.
