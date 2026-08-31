-- Crown-jewel isolate requires human approval (HITL). SEV-2 fires when a
-- SOAR execution or verification task stays non-terminal for > 5 minutes.

ALTER TABLE soar_action_executions
    ADD COLUMN IF NOT EXISTS hitl_required BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS hitl_approved_by BIGINT,
    ADD COLUMN IF NOT EXISTS hitl_approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS stale_alerted_at TIMESTAMPTZ;

ALTER TABLE soar_verification_tasks
    ADD COLUMN IF NOT EXISTS stale_alerted_at TIMESTAMPTZ;

ALTER TABLE soar_action_executions DROP CONSTRAINT IF EXISTS soar_action_executions_status_check;
ALTER TABLE soar_action_executions
    ADD CONSTRAINT soar_action_executions_status_check CHECK (status IN (
        'queued', 'acquired', 'executing', 'verifying',
        'resolved', 'failed', 'blocked_blast_radius', 'duplicate_skipped',
        'pending_hitl'
    ));

CREATE INDEX IF NOT EXISTS ix_soar_exec_pending_hitl
    ON soar_action_executions (tenant_id, created_at)
    WHERE status = 'pending_hitl';

CREATE INDEX IF NOT EXISTS ix_soar_exec_stale
    ON soar_action_executions (tenant_id, updated_at)
    WHERE status IN ('queued', 'acquired', 'executing', 'verifying', 'pending_hitl');

CREATE INDEX IF NOT EXISTS ix_soar_verify_stale
    ON soar_verification_tasks (tenant_id, created_at)
    WHERE status IN ('pending', 'running');
