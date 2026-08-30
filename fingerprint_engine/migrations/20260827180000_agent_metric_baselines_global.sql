-- Rolling 7-day (agent, metric) baselines live in a dedicated table so
-- hour_of_week stays a physical 0..167 clock bucket. A negative sentinel
-- in that column poisoned analytics queries and collided with Monday 00:00.

CREATE TABLE IF NOT EXISTS agent_metric_baselines_global (
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        TEXT        NOT NULL,
    metric_name     TEXT        NOT NULL,
    n               INTEGER     NOT NULL DEFAULT 0,
    mean            DOUBLE PRECISION NOT NULL DEFAULT 0,
    stddev          DOUBLE PRECISION NOT NULL DEFAULT 0,
    learned_set     JSONB       NOT NULL DEFAULT '[]'::jsonb,
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, metric_name)
);

CREATE INDEX IF NOT EXISTS ix_ambg_agent
    ON agent_metric_baselines_global (tenant_id, agent_id);

ALTER TABLE agent_metric_baselines_global ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_metric_baselines_global FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_metric_baselines_global_tenant ON agent_metric_baselines_global;
-- Cast-safe: empty worker GUC must not raise. Never current_setting(...)::bigint
-- (see 20260811000000_rls_tenant_guc_cast_safety).
CREATE POLICY agent_metric_baselines_global_tenant ON agent_metric_baselines_global FOR ALL
    USING       (tenant_id = public.app_current_tenant_id())
    WITH CHECK  (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_metric_baselines_global TO weissman_app;

INSERT INTO agent_metric_baselines_global
        (tenant_id, agent_id, metric_name, n, mean, stddev, learned_set, last_updated_at)
SELECT tenant_id, agent_id, metric_name, n, mean, stddev, learned_set, last_updated_at
  FROM agent_metric_baselines
 WHERE hour_of_week < 0
ON CONFLICT (tenant_id, agent_id, metric_name) DO NOTHING;

DELETE FROM agent_metric_baselines WHERE hour_of_week < 0 OR hour_of_week > 167;

ALTER TABLE agent_metric_baselines DROP CONSTRAINT IF EXISTS agent_metric_baselines_hour_range;
ALTER TABLE agent_metric_baselines
    ADD CONSTRAINT agent_metric_baselines_hour_range
    CHECK (hour_of_week >= 0 AND hour_of_week <= 167);
