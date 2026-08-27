-- UEBA engine hardening: learning state, replay, policy, archive, FAIR, suppressions.
-- Additive. Existing ingest rows keep working; new columns are NULLable or defaulted.

-- ─── endpoint_agents ────────────────────────────────────────────────────────
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS is_learning BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS learning_completed_at TIMESTAMPTZ;
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS hardware_id TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS last_sample_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS last_sample_at TIMESTAMPTZ;
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS session_secret_salt TEXT NOT NULL DEFAULT '';

-- ─── agent_metric_samples ───────────────────────────────────────────────────
ALTER TABLE agent_metric_samples
    ADD COLUMN IF NOT EXISTS ingested_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE agent_metric_samples
    ADD COLUMN IF NOT EXISTS seq BIGINT;
ALTER TABLE agent_metric_samples
    ADD COLUMN IF NOT EXISTS nonce TEXT;
ALTER TABLE agent_metric_samples
    ADD COLUMN IF NOT EXISTS open_ports INTEGER[];
ALTER TABLE agent_metric_samples
    ADD COLUMN IF NOT EXISTS source_ip INET;

-- ─── agent_metric_baselines (PK already (tenant_id, agent_id, metric_name, hour_of_week))
ALTER TABLE agent_metric_baselines
    ADD COLUMN IF NOT EXISTS mad DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines
    ADD COLUMN IF NOT EXISTS welford_m2 DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines
    ADD COLUMN IF NOT EXISTS stability_index DOUBLE PRECISION NOT NULL DEFAULT 0;

-- ─── agent_anomalies ────────────────────────────────────────────────────────
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
UPDATE agent_anomalies SET created_at = detected_at WHERE created_at IS NULL;
ALTER TABLE agent_anomalies
    ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS hour_of_week SMALLINT;
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS weighted_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS disposition_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS disposition_by BIGINT;
ALTER TABLE agent_anomalies
    ADD COLUMN IF NOT EXISTS playbook_dispatched BOOLEAN NOT NULL DEFAULT false;

-- ─── Tenant policy (business hours, holidays, learn window) ─────────────────
CREATE TABLE IF NOT EXISTS ueba_tenant_policy (
    tenant_id                   BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    learn_window_days           INTEGER NOT NULL DEFAULT 7,
    business_hours_start        SMALLINT NOT NULL DEFAULT 8,
    business_hours_end          SMALLINT NOT NULL DEFAULT 18,
    treat_holidays_as_weekend   BOOLEAN NOT NULL DEFAULT true,
    holiday_dates               DATE[] NOT NULL DEFAULT ARRAY[]::date[],
    isolate_on_critical         BOOLEAN NOT NULL DEFAULT true,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE ueba_tenant_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_tenant_policy FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_tenant_policy_tenant ON ueba_tenant_policy;
CREATE POLICY ueba_tenant_policy_tenant ON ueba_tenant_policy FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, UPDATE, DELETE ON ueba_tenant_policy TO weissman_app;

-- ─── Global / per-client process whitelist ──────────────────────────────────
CREATE TABLE IF NOT EXISTS ueba_process_whitelist (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT REFERENCES clients(id) ON DELETE CASCADE,
    process_name    TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    created_by      BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ueba_whitelist_tenant
    ON ueba_process_whitelist (tenant_id, client_id);
ALTER TABLE ueba_process_whitelist ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_process_whitelist FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_process_whitelist_tenant ON ueba_process_whitelist;
CREATE POLICY ueba_process_whitelist_tenant ON ueba_process_whitelist FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, UPDATE, DELETE ON ueba_process_whitelist TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ueba_process_whitelist_id_seq TO weissman_app;

-- ─── Replay nonces ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ueba_ingest_nonces (
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id    TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    seq         BIGINT NOT NULL DEFAULT 0,
    seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, nonce)
);
ALTER TABLE ueba_ingest_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_ingest_nonces FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_ingest_nonces_tenant ON ueba_ingest_nonces;
CREATE POLICY ueba_ingest_nonces_tenant ON ueba_ingest_nonces FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, DELETE ON ueba_ingest_nonces TO weissman_app;

-- ─── Retention run log (replaces stuffing nl_query_audit) ───────────────────
CREATE TABLE IF NOT EXISTS ueba_retention_runs (
    id                  BIGSERIAL PRIMARY KEY,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at         TIMESTAMPTZ,
    samples_deleted     BIGINT NOT NULL DEFAULT 0,
    samples_archived    BIGINT NOT NULL DEFAULT 0,
    anomalies_deleted   BIGINT NOT NULL DEFAULT 0,
    elapsed_ms          BIGINT NOT NULL DEFAULT 0,
    emergency           BOOLEAN NOT NULL DEFAULT false,
    lock_skipped        BOOLEAN NOT NULL DEFAULT false
);
GRANT SELECT, INSERT ON ueba_retention_runs TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ueba_retention_runs_id_seq TO weissman_app;

-- ─── Per-(agent, metric) FP auto-suppress ───────────────────────────────────
CREATE TABLE IF NOT EXISTS ueba_metric_suppressions (
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL,
    metric_name     TEXT NOT NULL,
    fp_count        INTEGER NOT NULL DEFAULT 0,
    auto_suppressed BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, metric_name)
);
ALTER TABLE ueba_metric_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_metric_suppressions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_metric_suppressions_tenant ON ueba_metric_suppressions;
CREATE POLICY ueba_metric_suppressions_tenant ON ueba_metric_suppressions FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, UPDATE, DELETE ON ueba_metric_suppressions TO weissman_app;

-- ─── FAIR ARO floor events ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ueba_fair_events (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    aro_floor   DOUBLE PRECISION NOT NULL DEFAULT 2.0,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ueba_fair_client
    ON ueba_fair_events (tenant_id, client_id, created_at DESC);
ALTER TABLE ueba_fair_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ueba_fair_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ueba_fair_events_tenant ON ueba_fair_events;
CREATE POLICY ueba_fair_events_tenant ON ueba_fair_events FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT ON ueba_fair_events TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE ueba_fair_events_id_seq TO weissman_app;

-- ─── Partitioned archive (forensic recovery after 14-day hot purge) ─────────
CREATE TABLE IF NOT EXISTS agent_metric_samples_archive (
    id              BIGINT NOT NULL,
    tenant_id       BIGINT NOT NULL,
    agent_id        TEXT NOT NULL,
    client_id       BIGINT NOT NULL,
    sampled_at      TIMESTAMPTZ NOT NULL,
    hour_of_week    SMALLINT NOT NULL,
    metrics         JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw_size_bytes  INTEGER NOT NULL DEFAULT 0,
    seq             BIGINT,
    nonce           TEXT,
    ingested_at     TIMESTAMPTZ,
    open_ports      INTEGER[],
    source_ip       INET,
    PRIMARY KEY (id, sampled_at)
) PARTITION BY RANGE (sampled_at);

CREATE TABLE IF NOT EXISTS agent_metric_samples_archive_2026_h2
    PARTITION OF agent_metric_samples_archive
    FOR VALUES FROM ('2026-07-01') TO ('2027-01-01');
CREATE TABLE IF NOT EXISTS agent_metric_samples_archive_2027_h1
    PARTITION OF agent_metric_samples_archive
    FOR VALUES FROM ('2027-01-01') TO ('2027-07-01');
CREATE TABLE IF NOT EXISTS agent_metric_samples_archive_default
    PARTITION OF agent_metric_samples_archive DEFAULT;

ALTER TABLE agent_metric_samples_archive ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_metric_samples_archive FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_metric_samples_archive_tenant ON agent_metric_samples_archive;
CREATE POLICY agent_metric_samples_archive_tenant ON agent_metric_samples_archive FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT, DELETE ON agent_metric_samples_archive TO weissman_app;
GRANT SELECT, INSERT, DELETE ON agent_metric_samples_archive_2026_h2 TO weissman_app;
GRANT SELECT, INSERT, DELETE ON agent_metric_samples_archive_2027_h1 TO weissman_app;
GRANT SELECT, INSERT, DELETE ON agent_metric_samples_archive_default TO weissman_app;

-- ─── Cascade: deleting an endpoint agent wipes its UEBA rows ────────────────
CREATE OR REPLACE FUNCTION ueba_cascade_agent_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM agent_metric_samples
     WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.agent_uuid::text;
    DELETE FROM agent_metric_baselines
     WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.agent_uuid::text;
    DELETE FROM agent_anomalies
     WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.agent_uuid::text;
    DELETE FROM ueba_ingest_nonces
     WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.agent_uuid::text;
    DELETE FROM ueba_metric_suppressions
     WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.agent_uuid::text;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_ueba_cascade_agent_delete ON endpoint_agents;
CREATE TRIGGER trg_ueba_cascade_agent_delete
    BEFORE DELETE ON endpoint_agents
    FOR EACH ROW EXECUTE FUNCTION ueba_cascade_agent_delete();

-- ─── weissman_ro: SELECT only on UEBA tables (no INSERT/UPDATE/DELETE) ──────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON agent_metric_samples TO weissman_ro;
        GRANT SELECT ON agent_metric_baselines TO weissman_ro;
        GRANT SELECT ON agent_anomalies TO weissman_ro;
        GRANT SELECT ON ueba_tenant_policy TO weissman_ro;
        GRANT SELECT ON ueba_process_whitelist TO weissman_ro;
        GRANT SELECT ON ueba_fair_events TO weissman_ro;
        GRANT SELECT ON ueba_metric_suppressions TO weissman_ro;
        GRANT SELECT ON agent_metric_samples_archive TO weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON agent_metric_samples FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON agent_metric_baselines FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON agent_anomalies FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON ueba_tenant_policy FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON ueba_process_whitelist FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON ueba_fair_events FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON ueba_metric_suppressions FROM weissman_ro;
        REVOKE INSERT, UPDATE, DELETE ON agent_metric_samples_archive FROM weissman_ro;
    END IF;
END $$;

-- ─── Query indexes (hot table is bounded by 14-day retention; CREATE INDEX is cheap)
CREATE INDEX IF NOT EXISTS ix_agent_samples_baseline
    ON agent_metric_samples (agent_id, hour_of_week, sampled_at DESC);
CREATE INDEX IF NOT EXISTS ix_agent_anomalies_active
    ON agent_anomalies (tenant_id, created_at DESC)
    WHERE severity IN ('medium', 'high', 'critical');
CREATE INDEX IF NOT EXISTS ix_agent_samples_nonce
    ON agent_metric_samples (tenant_id, agent_id, seq DESC NULLS LAST);
