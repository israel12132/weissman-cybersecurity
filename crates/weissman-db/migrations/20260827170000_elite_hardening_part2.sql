-- Elite hardening Part 2: restore Ask Weissman 13-table GRANT, staging
-- table for evidence-doubt, FAIR multi-currency columns, hour-of-week overlay.

-- ── Restore weissman_ro to the original 13-table allow-list ──────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON
            risk_graph_edges,
            client_financial_risk_snapshots,
            endpoint_agents,
            weissman_async_jobs,
            epss_intel,
            kev_intel,
            audit_logs
        TO weissman_ro;
    END IF;
END $$;

-- ── Evidence-doubt staging (dual-probe corroboration) ────────────────────────
CREATE TABLE IF NOT EXISTS finding_candidates (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    engine_id           TEXT NOT NULL,
    corroboration_key   TEXT NOT NULL,
    severity            TEXT NOT NULL DEFAULT 'info',
    title               TEXT NOT NULL DEFAULT '',
    finding_json        JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0,
    reason              TEXT NOT NULL DEFAULT 'awaiting_corroboration',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_candidates_engine_key
    ON finding_candidates (tenant_id, client_id, corroboration_key, engine_id);
CREATE INDEX IF NOT EXISTS ix_finding_candidates_key
    ON finding_candidates (tenant_id, corroboration_key);

ALTER TABLE finding_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_candidates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_candidates_tenant ON finding_candidates;
CREATE POLICY finding_candidates_tenant ON finding_candidates FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON finding_candidates TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE finding_candidates_id_seq TO weissman_app;

-- ── Operator-visible elite-hardening events (block/pause, tamper, HMAC) ──────
CREATE TABLE IF NOT EXISTS elite_hardening_events (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   BIGINT,
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ehe_recent ON elite_hardening_events (tenant_id, created_at DESC);
ALTER TABLE elite_hardening_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE elite_hardening_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS elite_hardening_events_tenant ON elite_hardening_events;
CREATE POLICY elite_hardening_events_tenant ON elite_hardening_events FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);
GRANT SELECT, INSERT ON elite_hardening_events TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE elite_hardening_events_id_seq TO weissman_app;

-- ── FAIR multi-currency + remediation / BI transparency ─────────────────────
ALTER TABLE client_financial_risk_snapshots
    ADD COLUMN IF NOT EXISTS currency_code TEXT NOT NULL DEFAULT 'USD',
    ADD COLUMN IF NOT EXISTS fx_rate_to_usd DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    ADD COLUMN IF NOT EXISTS remediation_cost_usd BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS business_interruption_usd BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS data_sources JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS reporting_currency TEXT NOT NULL DEFAULT 'USD';

-- Hour-of-week overlay for UEBA (samples already store hour_of_week).
CREATE OR REPLACE VIEW agent_metric_hour_baselines AS
SELECT tenant_id,
       agent_id,
       key AS metric_name,
       hour_of_week,
       COUNT(*)::bigint AS n,
       AVG((value)::double precision) AS mean,
       STDDEV_SAMP((value)::double precision) AS stddev
  FROM agent_metric_samples
       CROSS JOIN LATERAL jsonb_each_text(metrics) AS e(key, value)
 WHERE jsonb_typeof(metrics -> e.key) = 'number'
 GROUP BY tenant_id, agent_id, key, hour_of_week;
GRANT SELECT ON agent_metric_hour_baselines TO weissman_app;
