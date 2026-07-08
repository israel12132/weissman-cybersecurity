-- ─── Autonomous self-improvement proposal queue ───────────────────────────────
--
-- The hourly self-improvement engine (`fingerprint_engine::self_improve`) analyses
-- the platform and inserts structured improvement proposals here as
-- PENDING_APPROVAL. An owner reviews them in the Command Center and approves/rejects.
--
-- Safety: approval never mutates the codebase in-process. It enqueues a
-- `self_improvement_apply` job that opens a PULL REQUEST for human review + CI;
-- main is never written directly. RLS scopes every row to its tenant.

CREATE TABLE IF NOT EXISTS system_improvement_queue (
    id                    BIGSERIAL PRIMARY KEY,
    tenant_id             BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- new_engine | improve_engine | new_module | improve_module | wiring | sync | gap | cleanliness
    category              TEXT        NOT NULL,
    title                 TEXT        NOT NULL,
    rationale             TEXT        NOT NULL DEFAULT '',
    risk                  TEXT        NOT NULL DEFAULT 'low',      -- low|medium|high
    impact                TEXT        NOT NULL DEFAULT 'medium',   -- low|medium|high
    effort                TEXT        NOT NULL DEFAULT 'medium',   -- low|medium|high
    proposed_diff_summary TEXT        NOT NULL DEFAULT '',
    affected_files        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- PENDING_APPROVAL | APPROVED | REJECTED | APPLIED
    status                TEXT        NOT NULL DEFAULT 'PENDING_APPROVAL',
    source                TEXT        NOT NULL DEFAULT 'analyzer', -- analyzer|llm|deterministic
    cycle_id              UUID,                                    -- groups proposals from one run
    reviewed_by           BIGINT,
    review_note           TEXT,
    pr_url                TEXT,
    apply_job_id          UUID,
    proposed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_sysimprove_status
    ON system_improvement_queue (tenant_id, status, proposed_at DESC);
CREATE INDEX IF NOT EXISTS ix_sysimprove_cycle
    ON system_improvement_queue (tenant_id, cycle_id);

ALTER TABLE system_improvement_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_improvement_queue FORCE  ROW LEVEL SECURITY;

CREATE POLICY system_improvement_queue_tenant ON system_improvement_queue FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
