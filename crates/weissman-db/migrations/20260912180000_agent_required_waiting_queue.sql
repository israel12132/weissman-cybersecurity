-- Honest agent-required queue: park scan jobs until an endpoint agent runs them.
-- Previously agent-required engines completed immediately with invented info findings
-- (or empty success). waiting_for_agent is a real queue state — not a finding.

ALTER TABLE weissman_async_jobs DROP CONSTRAINT IF EXISTS weissman_async_jobs_status_chk;
ALTER TABLE weissman_async_jobs ADD CONSTRAINT weissman_async_jobs_status_chk CHECK (
    status IN ('pending', 'running', 'completed', 'failed', 'dead', 'waiting_for_agent')
);

COMMENT ON CONSTRAINT weissman_async_jobs_status_chk ON weissman_async_jobs IS
  'waiting_for_agent: host-resident engine queued an endpoint_agent_tasks row; the job is not complete and must not invent host findings.';

-- Operators may enroll an agent hours after queueing. 15 minutes was a reconnect window,
-- not an enrollment window.
ALTER TABLE endpoint_agent_tasks
    ALTER COLUMN expires_at SET DEFAULT (now() + interval '7 days');

UPDATE endpoint_agent_tasks
   SET expires_at = now() + interval '7 days'
 WHERE status IN ('pending', 'running')
   AND expires_at < now() + interval '1 day';

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_tasks_live_queue
    ON endpoint_agent_tasks (tenant_id, client_id, status, created_at DESC)
 WHERE status IN ('pending', 'running');

CREATE INDEX IF NOT EXISTS ix_weissman_async_jobs_waiting_for_agent
    ON weissman_async_jobs (tenant_id, created_at DESC)
 WHERE status = 'waiting_for_agent';
