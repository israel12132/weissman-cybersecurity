-- SOAR action execution engine — idempotent executions, verification loop, revert runbooks.

CREATE TABLE IF NOT EXISTS soar_action_executions (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           BIGINT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT          REFERENCES clients(id) ON DELETE SET NULL,
    playbook_id         BIGINT,
    action_kind         TEXT            NOT NULL,
    idempotency_key     TEXT            NOT NULL,
    target_id           TEXT            NOT NULL,
    provider            TEXT            NOT NULL DEFAULT 'unknown',
    status              TEXT            NOT NULL DEFAULT 'queued'
        CHECK (status IN (
            'queued', 'acquired', 'executing', 'verifying',
            'resolved', 'failed', 'blocked_blast_radius', 'duplicate_skipped'
        )),
    blast_radius        JSONB           NOT NULL DEFAULT '{}'::jsonb,
    evidence            JSONB           NOT NULL DEFAULT '{}'::jsonb,
    execution_payload   JSONB           NOT NULL DEFAULT '{}'::jsonb,
    result_detail       TEXT            NOT NULL DEFAULT '',
    external_ref        TEXT,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS ix_soar_exec_tenant_status
    ON soar_action_executions (tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_soar_exec_target
    ON soar_action_executions (tenant_id, target_id, action_kind);

CREATE TABLE IF NOT EXISTS soar_verification_tasks (
    id                  BIGSERIAL       PRIMARY KEY,
    tenant_id           BIGINT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    execution_id        UUID            NOT NULL REFERENCES soar_action_executions(id) ON DELETE CASCADE,
    probe_type          TEXT            NOT NULL,
    target              TEXT            NOT NULL,
    status              TEXT            NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'verified', 'failed')),
    attempts            INT             NOT NULL DEFAULT 0,
    max_attempts        INT             NOT NULL DEFAULT 8,
    next_attempt_at     TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_result         TEXT            NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    verified_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_soar_verify_pending
    ON soar_verification_tasks (status, next_attempt_at)
    WHERE status IN ('pending', 'running');

CREATE TABLE IF NOT EXISTS soar_revert_runbooks (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           BIGINT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    execution_id        UUID            NOT NULL REFERENCES soar_action_executions(id) ON DELETE CASCADE,
    action_kind         TEXT            NOT NULL,
    steps               JSONB           NOT NULL DEFAULT '[]'::jsonb,
    status              TEXT            NOT NULL DEFAULT 'ready'
        CHECK (status IN ('ready', 'reverting', 'reverted', 'failed')),
    reverted_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_soar_revert_per_execution
    ON soar_revert_runbooks (execution_id);

ALTER TABLE soar_action_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_action_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soar_action_executions_tenant ON soar_action_executions;
CREATE POLICY soar_action_executions_tenant ON soar_action_executions FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE soar_verification_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_verification_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soar_verification_tasks_tenant ON soar_verification_tasks;
CREATE POLICY soar_verification_tasks_tenant ON soar_verification_tasks FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE soar_revert_runbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_revert_runbooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS soar_revert_runbooks_tenant ON soar_revert_runbooks;
CREATE POLICY soar_revert_runbooks_tenant ON soar_revert_runbooks FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON soar_action_executions TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_verification_tasks TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON soar_revert_runbooks TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE soar_verification_tasks_id_seq TO weissman_app;

COMMENT ON TABLE soar_action_executions IS 'Durable SOAR action state machine — idempotent per (tenant, idempotency_key).';
COMMENT ON TABLE soar_verification_tasks IS 'Closed-loop verification queue (isolate connectivity probes, PR existence checks).';
COMMENT ON TABLE soar_revert_runbooks IS 'One-click rollback steps persisted at execution time.';
