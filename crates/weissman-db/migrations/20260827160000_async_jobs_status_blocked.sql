-- First-class job status for Rules-of-Engagement / policy denials.
-- OT/ICS probes that are not authorized must never look like completed empty success.

ALTER TABLE weissman_async_jobs DROP CONSTRAINT IF EXISTS weissman_async_jobs_status_chk;
ALTER TABLE weissman_async_jobs ADD CONSTRAINT weissman_async_jobs_status_chk
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'dead', 'blocked'));

COMMENT ON CONSTRAINT weissman_async_jobs_status_chk ON weissman_async_jobs IS
    'Queue lifecycle. blocked = RoE/policy denied the probe (terminal, not a clean scan).';
