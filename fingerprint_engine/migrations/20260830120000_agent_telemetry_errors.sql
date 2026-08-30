-- Consecutive UEBA sampling failures (NtQuerySystemInformation blocked,
-- empty /proc, etc.). Three in a row is Telemetry Blinding — alert SOC / SOAR
-- without inserting a zero-count sample that would poison z-score.

CREATE TABLE IF NOT EXISTS agent_telemetry_errors (
    tenant_id              BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id               TEXT        NOT NULL,
    client_id              BIGINT      NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    consecutive_failures   INTEGER     NOT NULL DEFAULT 0,
    last_error             TEXT        NOT NULL DEFAULT '',
    last_failed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_alerted_at        TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, agent_id)
);

CREATE INDEX IF NOT EXISTS ix_ate_alert
    ON agent_telemetry_errors (tenant_id, consecutive_failures DESC, last_failed_at DESC);

ALTER TABLE agent_telemetry_errors ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_telemetry_errors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_telemetry_errors_tenant ON agent_telemetry_errors;
CREATE POLICY agent_telemetry_errors_tenant ON agent_telemetry_errors FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_telemetry_errors TO weissman_app;
