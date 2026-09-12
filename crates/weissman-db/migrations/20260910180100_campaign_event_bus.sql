-- Versioned campaign event log (P0 fabric spine). Durable in Postgres;
-- CEM-DAGO blackboard is the live Redis projection. Job-bus envelopes
-- already carry campaign_id on dispatched engine jobs. This is not a fourth
-- generic bus — it is the campaign-scoped event chain.

CREATE TABLE IF NOT EXISTS weissman_campaign_events (
    id              BIGSERIAL PRIMARY KEY,
    campaign_id    UUID NOT NULL REFERENCES weissman_campaigns(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    event_version   INT NOT NULL DEFAULT 1,
    kind            TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_hash      TEXT NOT NULL,
    prev_hash       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT weissman_campaign_events_kind_chk CHECK (kind ~ '^[a-z_]+$'),
    CONSTRAINT weissman_campaign_events_ver_chk CHECK (event_version >= 1)
);

CREATE INDEX IF NOT EXISTS ix_weissman_campaign_events_time
    ON weissman_campaign_events (campaign_id, created_at DESC, id DESC);

COMMENT ON TABLE weissman_campaign_events IS
    'Append-only versioned campaign events (FindingObserved, TechniqueDispatched, TechniqueProven, …). In-product only.';

ALTER TABLE weissman_campaign_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_campaign_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_campaign_events_tenant ON weissman_campaign_events;
CREATE POLICY weissman_campaign_events_tenant ON weissman_campaign_events FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_campaign_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE weissman_campaign_events_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_campaign_events TO weissman_worker;
        GRANT USAGE, SELECT ON SEQUENCE weissman_campaign_events_id_seq TO weissman_worker;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON weissman_campaign_events TO weissman_ro;
    END IF;
END $$;
