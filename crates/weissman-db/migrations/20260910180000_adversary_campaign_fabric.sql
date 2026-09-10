-- Adversary Campaign Fabric (P0): tenant/client-scoped campaigns that chain
-- evidence-grounded STRIPS plans into real engine jobs. RLS FORCE. Never
-- widens scan scope. Novel findings stay in-product (no extra disclosure).

CREATE TABLE IF NOT EXISTS weissman_campaigns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    goal_fact       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft',
    profile_stub    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    asset_key       TEXT NOT NULL DEFAULT '',
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT weissman_campaigns_status_chk CHECK (
        status IN ('draft', 'running', 'paused', 'completed', 'blocked', 'failed')
    ),
    CONSTRAINT weissman_campaigns_goal_chk CHECK (goal_fact ~ '^[a-z0-9_]+:[a-z0-9_]+$')
);

CREATE INDEX IF NOT EXISTS ix_weissman_campaigns_client_status
    ON weissman_campaigns (tenant_id, client_id, status, updated_at DESC);

COMMENT ON TABLE weissman_campaigns IS
    'P0 adversary campaign: one client-scoped engagement toward a grounded planner goal fact.';

CREATE TABLE IF NOT EXISTS weissman_campaign_world_states (
    id              BIGSERIAL PRIMARY KEY,
    campaign_id    UUID NOT NULL REFERENCES weissman_campaigns(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    facts           JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    asset_key       TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_weissman_campaign_ws_latest
    ON weissman_campaign_world_states (campaign_id, created_at DESC);

COMMENT ON TABLE weissman_campaign_world_states IS
    'Append-only WorldState snapshots. Facts are grounded in finding ids; never invented.';

CREATE TABLE IF NOT EXISTS weissman_campaign_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id    UUID NOT NULL REFERENCES weissman_campaigns(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    seq             INT NOT NULL,
    technique_id   TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    mitre           TEXT NOT NULL DEFAULT '',
    engine_id      TEXT NOT NULL,
    job_id          UUID,
    status          TEXT NOT NULL DEFAULT 'planned',
    planned_gained  JSONB NOT NULL DEFAULT '[]'::jsonb,
    outcome_facts   JSONB NOT NULL DEFAULT '[]'::jsonb,
    target          TEXT NOT NULL DEFAULT '',
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT weissman_campaign_steps_status_chk CHECK (
        status IN ('planned', 'dispatched', 'succeeded', 'failed', 'skipped')
    ),
    CONSTRAINT weissman_campaign_steps_seq_chk CHECK (seq >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_weissman_campaign_steps_seq
    ON weissman_campaign_steps (campaign_id, seq);

CREATE INDEX IF NOT EXISTS ix_weissman_campaign_steps_job
    ON weissman_campaign_steps (job_id)
    WHERE job_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_weissman_campaign_steps_inflight
    ON weissman_campaign_steps (campaign_id, status)
    WHERE status IN ('planned', 'dispatched');

COMMENT ON TABLE weissman_campaign_steps IS
    'Planned STRIPS technique → dispatched command_center_engine job → outcome facts from live findings.';

CREATE TABLE IF NOT EXISTS weissman_campaign_audit (
    id              BIGSERIAL PRIMARY KEY,
    campaign_id    UUID NOT NULL REFERENCES weissman_campaigns(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    actor_user_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    reason          TEXT NOT NULL DEFAULT '',
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_weissman_campaign_audit_time
    ON weissman_campaign_audit (campaign_id, created_at DESC);

COMMENT ON TABLE weissman_campaign_audit IS
    'Append-only campaign state-transition audit. In-product only; no auto external disclosure.';

-- RLS: tenant + client visibility. FORCE so owners cannot skip quals.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'weissman_campaigns',
        'weissman_campaign_world_states',
        'weissman_campaign_steps',
        'weissman_campaign_audit'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', t || '_tenant', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I FOR ALL
               USING (
                 tenant_id = public.app_current_tenant_id()
                 AND public.weissman_client_row_visible(client_id)
               )
               WITH CHECK (
                 tenant_id = public.app_current_tenant_id()
                 AND public.weissman_client_row_visible(client_id)
               )',
            t || '_tenant', t
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO weissman_app',
            t
        );
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
            EXECUTE format(
                'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO weissman_worker',
                t
            );
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
            EXECUTE format('GRANT SELECT ON %I TO weissman_ro', t);
        END IF;
    END LOOP;
END $$;

GRANT USAGE, SELECT ON SEQUENCE weissman_campaign_world_states_id_seq TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_campaign_audit_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        GRANT USAGE, SELECT ON SEQUENCE weissman_campaign_world_states_id_seq TO weissman_worker;
        GRANT USAGE, SELECT ON SEQUENCE weissman_campaign_audit_id_seq TO weissman_worker;
    END IF;
END $$;
