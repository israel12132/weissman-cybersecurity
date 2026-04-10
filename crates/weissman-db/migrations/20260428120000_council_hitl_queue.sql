-- Human-In-The-Loop (HITL) approval queue for Council-proposed attack chains.
--
-- Workflow:  Council debate produces a proposal  →  row inserted with status='PENDING_APPROVAL'
--            Operator reviews chain_steps + payload preview  →  APPROVED (fires async job) or REJECTED
--            Fired rows record the resulting job_id in fired_job_id
--
-- Safety invariant: safety_rails_no_shells is ALWAYS true for fired payloads (enforced in application layer).

CREATE TABLE council_hitl_queue (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    client_id       BIGINT REFERENCES clients (id) ON DELETE SET NULL,

    -- Council output
    target_brief    TEXT NOT NULL DEFAULT '',
    chain_steps     JSONB NOT NULL DEFAULT '[]'::jsonb,   -- string array from ProposedAttackChain
    payload_preview TEXT NOT NULL DEFAULT '',             -- truncated, safe excerpt (no weaponized content)
    rationale       TEXT NOT NULL DEFAULT '',
    estimated_severity TEXT NOT NULL DEFAULT 'medium'
        CHECK (estimated_severity IN ('low', 'medium', 'high', 'critical')),
    council_job_id  UUID,                                 -- originating council_debate async job

    -- Approval workflow
    status          TEXT NOT NULL DEFAULT 'PENDING_APPROVAL'
        CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'FIRED', 'FAILED')),
    reviewed_by     BIGINT,                               -- user id from JWT (operators only)
    review_note     TEXT,
    fired_job_id    UUID,                                 -- async job enqueued when status transitions to FIRED

    -- Timestamps
    proposed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at     TIMESTAMPTZ,
    fired_at        TIMESTAMPTZ
);

CREATE INDEX ix_council_hitl_tenant_status ON council_hitl_queue (tenant_id, status, proposed_at DESC);
CREATE INDEX ix_council_hitl_client        ON council_hitl_queue (client_id, proposed_at DESC);
CREATE INDEX ix_council_hitl_council_job   ON council_hitl_queue (council_job_id);

-- Tenant-scoped row-level security
ALTER TABLE council_hitl_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE council_hitl_queue FORCE ROW LEVEL SECURITY;

CREATE POLICY council_hitl_queue_tenant ON council_hitl_queue FOR ALL
    USING  (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE ON council_hitl_queue TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE council_hitl_queue_id_seq TO weissman_app;

COMMENT ON TABLE  council_hitl_queue IS 'Operator approval gate for Council-proposed attack chains. status=PENDING_APPROVAL until an operator approves or rejects; FIRED once the async job is enqueued.';
COMMENT ON COLUMN council_hitl_queue.payload_preview IS 'Safe excerpt of the Council payload — weaponized shells are never stored here. safety_rails_no_shells is always ON.';
