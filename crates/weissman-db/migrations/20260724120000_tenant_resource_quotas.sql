-- Per-tenant resource quotas: period-scoped consumption accounting enforced against
-- plan limits (e.g. monthly scan quota). Distinct from the short-horizon rate limiters
-- (per-IP / per-minute token buckets) — this is the longer-horizon budget that protects
-- plan boundaries and cost. One row per (tenant, resource, period) with an atomic
-- upsert-increment. Tenant-isolated under forced RLS.

CREATE TABLE IF NOT EXISTS weissman_tenant_quota_usage (
    id          BIGSERIAL    PRIMARY KEY,
    tenant_id   BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Logical resource being metered, e.g. 'scans', 'api_requests'.
    resource    TEXT         NOT NULL,
    -- Period bucket key: 'YYYY-MM' (monthly) or 'YYYY-MM-DD' (daily), UTC.
    period_key  TEXT         NOT NULL,
    used        BIGINT       NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, resource, period_key)
);

CREATE INDEX IF NOT EXISTS ix_tenant_quota_usage_lookup
    ON weissman_tenant_quota_usage (tenant_id, resource, period_key);

ALTER TABLE weissman_tenant_quota_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_tenant_quota_usage FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_tenant_quota_usage_tenant ON weissman_tenant_quota_usage;
CREATE POLICY weissman_tenant_quota_usage_tenant ON weissman_tenant_quota_usage
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_tenant_quota_usage TO weissman_app;

COMMENT ON TABLE weissman_tenant_quota_usage IS
    'Per-tenant period-scoped resource consumption (plan quota enforcement), forced RLS.';
