-- ─── UEBA (User & Entity Behavior Analytics) on endpoint agents ─────────────
--
-- Two tables:
--   1. agent_metric_samples    — raw hourly samples shipped by the agent
--                                (open ports, top processes, login hours, network bytes).
--   2. agent_metric_baselines  — running mean/stddev per (agent, metric) computed
--                                from the last 7 days of samples.
--   3. agent_anomalies         — z-score >3 detections, ready for the orchestrator
--                                to turn into a medium-severity finding.
--
-- We do not store full process lists / port lists per sample — only counts +
-- top-N. That keeps daily ingest under 100 KB/agent and protects PII.

CREATE TABLE IF NOT EXISTS agent_metric_samples (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        TEXT        NOT NULL,                 -- weissman-agent uuid
    client_id       BIGINT      NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    sampled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Coarse hour-bucket for the "by hour of week" baseline.
    hour_of_week    SMALLINT    NOT NULL,
    metrics         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- e.g. {
    --   "open_ports":      [22, 80, 443],
    --   "open_port_count": 3,
    --   "process_count":   142,
    --   "top_processes":   ["nginx","postgres","weissman-agent"],
    --   "unique_users":    1,
    --   "outbound_bytes":  234567,
    --   "failed_logins":   0,
    --   "new_processes":   ["weird.sh"]            // only when changed from baseline
    -- }
    raw_size_bytes  INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_ams_agent_time
    ON agent_metric_samples (tenant_id, agent_id, sampled_at DESC);
-- Retention deletes use `sampled_at < now() - interval '14 days'`; btree on sampled_at
-- is sufficient. Partial indexes cannot use volatile functions like now().
CREATE INDEX IF NOT EXISTS ix_ams_sampled_at
    ON agent_metric_samples (sampled_at);

ALTER TABLE agent_metric_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_metric_samples FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_metric_samples_tenant ON agent_metric_samples;
CREATE POLICY agent_metric_samples_tenant ON agent_metric_samples FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_metric_samples TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE agent_metric_samples_id_seq TO weissman_app;

-- ─── Computed baselines (one row per agent × metric × hour-of-week) ──────────
CREATE TABLE IF NOT EXISTS agent_metric_baselines (
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        TEXT        NOT NULL,
    metric_name     TEXT        NOT NULL,                 -- e.g. "open_port_count"
    hour_of_week    SMALLINT    NOT NULL,
    n               INTEGER     NOT NULL DEFAULT 0,       -- sample count contributing
    mean            DOUBLE PRECISION NOT NULL DEFAULT 0,
    stddev          DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- The actual port/process list seen during training — used for "new process"
    -- detection alongside numeric anomalies.
    learned_set     JSONB       NOT NULL DEFAULT '[]'::jsonb,
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, metric_name, hour_of_week)
);

CREATE INDEX IF NOT EXISTS ix_amb_agent
    ON agent_metric_baselines (tenant_id, agent_id);

ALTER TABLE agent_metric_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_metric_baselines FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_metric_baselines_tenant ON agent_metric_baselines;
CREATE POLICY agent_metric_baselines_tenant ON agent_metric_baselines FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_metric_baselines TO weissman_app;

-- ─── Anomalies (z-score > 3 detections) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_anomalies (
    id              BIGSERIAL   PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        TEXT        NOT NULL,
    client_id       BIGINT      NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    sample_id       BIGINT      REFERENCES agent_metric_samples(id) ON DELETE SET NULL,
    metric_name     TEXT        NOT NULL,
    observed        DOUBLE PRECISION NOT NULL,
    baseline_mean   DOUBLE PRECISION NOT NULL,
    baseline_stddev DOUBLE PRECISION NOT NULL,
    z_score         DOUBLE PRECISION NOT NULL,
    severity        TEXT        NOT NULL DEFAULT 'medium',
    detail          TEXT        NOT NULL DEFAULT '',
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_aa_recent ON agent_anomalies (tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS ix_aa_agent  ON agent_anomalies (tenant_id, agent_id, detected_at DESC);

ALTER TABLE agent_anomalies ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_anomalies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_anomalies_tenant ON agent_anomalies;
CREATE POLICY agent_anomalies_tenant ON agent_anomalies FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_anomalies TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE agent_anomalies_id_seq TO weissman_app;
