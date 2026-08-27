-- Physical progress (distinct from lease heartbeat) + precise Force-Abort stuck_reason.
-- tenant_full_scan chunks and fuzz jobs must prove progress every 60s or the worker
-- returns the lease and marks the row failed — no silent Self-DoS of the fleet.

ALTER TABLE weissman_async_jobs
    ADD COLUMN IF NOT EXISTS progress_at timestamptz,
    ADD COLUMN IF NOT EXISTS stuck_reason text,
    ADD COLUMN IF NOT EXISTS progress_note text;

COMMENT ON COLUMN weissman_async_jobs.progress_at IS
    'Last physical progress (engine/probe/chunk). Distinct from heartbeat_at (lease keep-alive).';
COMMENT ON COLUMN weissman_async_jobs.stuck_reason IS
    'Precise Force-Abort class, e.g. no_progress_60s or lease_heartbeat_timeout.';
COMMENT ON COLUMN weissman_async_jobs.progress_note IS
    'Last progress mark (engine id, fuzz probe, chunk index) for operator triage.';

CREATE INDEX IF NOT EXISTS ix_weissman_async_jobs_scan_run
    ON weissman_async_jobs ((payload->>'scan_run_id'))
    WHERE kind IN ('tenant_full_scan', 'onboarding_tenant_scan', 'tenant_scan_chunk');
