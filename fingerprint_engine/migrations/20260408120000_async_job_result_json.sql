ALTER TABLE weissman_async_jobs
    ADD COLUMN IF NOT EXISTS result_json jsonb;

COMMENT ON COLUMN weissman_async_jobs.result_json IS 'Serialized outcome when status = completed (findings, messages, etc.).';
