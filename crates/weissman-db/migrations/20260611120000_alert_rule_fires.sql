-- Alert rule fire history (deduped per rule + finding).

CREATE TABLE IF NOT EXISTS weissman_alert_rule_fires (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id     BIGINT NOT NULL REFERENCES weissman_alert_rules(id) ON DELETE CASCADE,
    finding_id  BIGINT NOT NULL,
    channels    JSONB NOT NULL DEFAULT '[]'::jsonb,
    delivered   BOOLEAN NOT NULL DEFAULT false,
    fired_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_rule_fires_rule_finding
    ON weissman_alert_rule_fires (rule_id, finding_id);
CREATE INDEX IF NOT EXISTS ix_alert_rule_fires_tenant
    ON weissman_alert_rule_fires (tenant_id, fired_at DESC);

ALTER TABLE weissman_alert_rule_fires ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_alert_rule_fires FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_alert_rule_fires_tenant ON weissman_alert_rule_fires;
CREATE POLICY weissman_alert_rule_fires_tenant ON weissman_alert_rule_fires
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE ON weissman_alert_rule_fires TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_alert_rule_fires_id_seq TO weissman_app;
