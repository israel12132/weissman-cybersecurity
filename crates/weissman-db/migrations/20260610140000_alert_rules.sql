-- Tenant-defined alert rules for the Alert Rules Engine cockpit page.
-- `condition` holds match criteria (severity, CVE pattern, engines, threshold, etc.).
-- `actions` holds notification channels and delivery config.

CREATE TABLE IF NOT EXISTS weissman_alert_rules (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    condition   JSONB       NOT NULL DEFAULT '{}'::jsonb,
    actions     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_alert_rules_name
    ON weissman_alert_rules (tenant_id, lower(name));
CREATE INDEX IF NOT EXISTS ix_alert_rules_enabled
    ON weissman_alert_rules (tenant_id) WHERE enabled = TRUE;

ALTER TABLE weissman_alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_alert_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_alert_rules_tenant ON weissman_alert_rules;
CREATE POLICY weissman_alert_rules_tenant ON weissman_alert_rules
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_alert_rules TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_alert_rules_id_seq TO weissman_app;
