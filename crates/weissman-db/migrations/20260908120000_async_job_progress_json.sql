-- Durable in-flight checkpoint for async jobs.
--
-- scan_all_engines writes progress after every engine so a wall-clock timeout or
-- worker crash can resume. Previously this lived only in result_json, which
-- complete_job overwrites and which health queries could not treat as a checkpoint.
-- progress_json is independent: fail_job / reclaim leave it intact.

ALTER TABLE weissman_async_jobs
    ADD COLUMN IF NOT EXISTS progress_json jsonb;

COMMENT ON COLUMN weissman_async_jobs.progress_json IS
    'In-flight checkpoint (completed_engines, last_engine). Survives timeout/retry; not cleared by fail_job.';
