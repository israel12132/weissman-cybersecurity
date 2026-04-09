-- B2B SaaS: billing catalog, per-tenant Stripe linkage, subscriptions, usage counters, webhook idempotency.
-- RLS on tenant-scoped rows; stripe_webhook_events is service-role only (no weissman_app access).

CREATE TABLE billing_plans (
    slug            TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    max_clients     INTEGER NOT NULL CHECK (max_clients > 0),
    max_scans_month INTEGER NOT NULL CHECK (max_scans_month > 0),
    active          BOOLEAN NOT NULL DEFAULT true
);

INSERT INTO billing_plans (slug, display_name, max_clients, max_scans_month, active) VALUES
    ('starter', 'Starter', 5, 30, true),
    ('professional', 'Professional', 25, 300, true),
    ('enterprise', 'Enterprise', 500, 5000, true);

CREATE TABLE tenant_stripe_customers (
    tenant_id           BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_customer_id  TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tenant_subscriptions (
    tenant_id               BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_subscription_id  TEXT UNIQUE,
    stripe_price_id         TEXT,
    plan_slug               TEXT NOT NULL REFERENCES billing_plans(slug) ON UPDATE CASCADE,
    status                  TEXT NOT NULL DEFAULT 'incomplete',
    current_period_start    TIMESTAMPTZ,
    current_period_end      TIMESTAMPTZ,
    cancel_at_period_end    BOOLEAN NOT NULL DEFAULT false,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_tenant_subscriptions_stripe ON tenant_subscriptions (stripe_subscription_id);

CREATE TABLE tenant_usage_counters (
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_ym       TEXT NOT NULL,
    scans_started   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, period_ym)
);

CREATE TABLE stripe_webhook_events (
    id              TEXT PRIMARY KEY,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      TEXT NOT NULL,
    processed_ok    BOOLEAN NOT NULL DEFAULT false,
    error_detail    TEXT
);

ALTER TABLE tenant_stripe_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_stripe_customers FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_stripe_customers_scope ON tenant_stripe_customers FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE tenant_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_subscriptions_scope ON tenant_subscriptions FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE tenant_usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_usage_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_usage_counters_scope ON tenant_usage_counters FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

-- Catalog readable by all app sessions (no tenant filter needed on this table).
-- No RLS on billing_plans.

REVOKE ALL ON stripe_webhook_events FROM weissman_app;

-- weissman_auth: onboarding + Stripe webhook persistence
GRANT SELECT ON billing_plans TO weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_stripe_customers TO weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_subscriptions TO weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_usage_counters TO weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON stripe_webhook_events TO weissman_auth;

GRANT SELECT, INSERT ON tenants TO weissman_auth;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE tenants_id_seq TO weissman_auth;

-- Repair app grants for objects created before default privileges (explicit)
GRANT SELECT ON billing_plans TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_stripe_customers TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_subscriptions TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_usage_counters TO weissman_app;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO weissman_app;

-- Existing deployments: grant every current tenant an active enterprise subscription so enforcement joins succeed.
INSERT INTO tenant_subscriptions (tenant_id, plan_slug, status)
SELECT t.id, 'enterprise', 'active'
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM tenant_subscriptions s WHERE s.tenant_id = t.id);
