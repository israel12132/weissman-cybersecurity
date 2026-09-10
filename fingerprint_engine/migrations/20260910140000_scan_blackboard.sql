-- Scan blackboard: shared session state for planner/runner/verifier/helper.
-- RLS FORCE on every table. weissman_app writes; weissman_ro SELECT only.
-- Engines stay in Rust; agents only claim tasks and write facts/events.

CREATE TABLE IF NOT EXISTS scan_blackboard (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    run_id          BIGINT,
    scope_hash      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'paused', 'needs_human', 'closed', 'aborted')),
    objective       TEXT NOT NULL,
    allowed_engines TEXT[] NOT NULL DEFAULT '{}',
    allowed_targets TEXT[] NOT NULL DEFAULT '{}',
    denied_actions  TEXT[] NOT NULL DEFAULT '{}',
    planner_agent   TEXT,
    critic_agent    TEXT,
    verifier_agent  TEXT,
    helper_agent    TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_scan_bb_tenant_status
    ON scan_blackboard (tenant_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS ix_scan_bb_client
    ON scan_blackboard (tenant_id, client_id, created_at DESC);

ALTER TABLE scan_blackboard ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_blackboard FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_blackboard_tenant ON scan_blackboard;
CREATE POLICY scan_blackboard_tenant ON scan_blackboard FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_blackboard TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scan_blackboard_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS scan_bb_tasks (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    board_id        BIGINT NOT NULL REFERENCES scan_blackboard(id) ON DELETE CASCADE,
    parent_task_id  BIGINT REFERENCES scan_bb_tasks(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL
                    CHECK (kind IN ('plan', 'run_engine', 'verify', 'help', 'summarize', 'human_gate')),
    engine_id       TEXT,
    target          TEXT,
    assigned_role   TEXT NOT NULL
                    CHECK (assigned_role IN ('planner', 'runner', 'verifier', 'helper', 'critic', 'human')),
    assigned_agent  TEXT,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN (
                        'queued', 'running', 'blocked', 'helping',
                        'verified', 'rejected', 'done', 'cancelled'
                    )),
    blocked_reason  TEXT,
    help_needed     TEXT,
    input           JSONB NOT NULL DEFAULT '{}'::jsonb,
    output          JSONB NOT NULL DEFAULT '{}'::jsonb,
    finding_id      TEXT,
    lease_owner     TEXT,
    lease_until     TIMESTAMPTZ,
    attempt         INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scan_bb_tasks_claim
    ON scan_bb_tasks (tenant_id, board_id, status, kind)
    WHERE status IN ('queued', 'blocked');
CREATE INDEX IF NOT EXISTS ix_scan_bb_tasks_lease
    ON scan_bb_tasks (lease_until)
    WHERE status = 'running';
CREATE INDEX IF NOT EXISTS ix_scan_bb_tasks_parent
    ON scan_bb_tasks (tenant_id, parent_task_id);

ALTER TABLE scan_bb_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_bb_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_bb_tasks_tenant ON scan_bb_tasks;
CREATE POLICY scan_bb_tasks_tenant ON scan_bb_tasks FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_bb_tasks TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scan_bb_tasks_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS scan_bb_facts (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    board_id        BIGINT NOT NULL REFERENCES scan_blackboard(id) ON DELETE CASCADE,
    task_id         BIGINT REFERENCES scan_bb_tasks(id) ON DELETE SET NULL,
    fact_type       TEXT NOT NULL
                    CHECK (fact_type IN ('observation', 'evidence', 'dead_end', 'scope_note', 'asset')),
    target          TEXT,
    engine_id       TEXT,
    confidence      REAL NOT NULL DEFAULT 0.5
                    CHECK (confidence >= 0 AND confidence <= 1),
    verified        BOOLEAN NOT NULL DEFAULT false,
    body            JSONB NOT NULL DEFAULT '{}'::jsonb,
    content_hash    TEXT NOT NULL,
    created_by_role TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, board_id, content_hash)
);

CREATE INDEX IF NOT EXISTS ix_scan_bb_facts_board
    ON scan_bb_facts (tenant_id, board_id, fact_type, verified);

ALTER TABLE scan_bb_facts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_bb_facts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_bb_facts_tenant ON scan_bb_facts;
CREATE POLICY scan_bb_facts_tenant ON scan_bb_facts FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_bb_facts TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scan_bb_facts_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS scan_bb_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    board_id        BIGINT NOT NULL REFERENCES scan_blackboard(id) ON DELETE CASCADE,
    task_id         BIGINT REFERENCES scan_bb_tasks(id) ON DELETE SET NULL,
    actor_role      TEXT NOT NULL,
    actor_agent     TEXT,
    event_type      TEXT NOT NULL
                    CHECK (event_type IN (
                        'claimed', 'blocked', 'helped', 'unblocked',
                        'verified', 'rejected', 'escalated', 'closed'
                    )),
    message         TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_scan_bb_events_board
    ON scan_bb_events (tenant_id, board_id, created_at DESC);

ALTER TABLE scan_bb_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_bb_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS scan_bb_events_tenant ON scan_bb_events;
CREATE POLICY scan_bb_events_tenant ON scan_bb_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_bb_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE scan_bb_events_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON scan_blackboard TO weissman_ro;
        GRANT SELECT ON scan_bb_tasks TO weissman_ro;
        GRANT SELECT ON scan_bb_facts TO weissman_ro;
        GRANT SELECT ON scan_bb_events TO weissman_ro;
    END IF;
END $$;
