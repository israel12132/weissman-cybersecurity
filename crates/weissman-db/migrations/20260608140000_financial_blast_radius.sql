-- ─── Financial blast-radius scoring ──────────────────────────────────────────
--
-- We already track `asset_value` (a 0..3 multiplier) on risk_graph_nodes. To talk
-- to executives in their language we add a real US-dollar valuation:
--
--   * `business_value_usd` (BIGINT, nullable). Filled at onboarding from
--     `client_asset_value_rules`, or directly by the analyst from the UI.
--   * `asset_replacement_cost_usd` — what it costs to rebuild the asset from
--     scratch. Defaults to 0 (data loss only — RPO/RTO costs handled separately).
--
-- We also add a per-client default for unknown assets so a client that hasn't
-- enriched every node still gets a defensible $-at-risk number.
--
-- `client_asset_value_rules` is a small lookup the operator fills during
-- onboarding: tag → dollar value. Examples:
--   "tier:prod"    => 50_000
--   "pii:hr"       => 250_000
--   "kms"          => 1_000_000
--   "stripe"       => 500_000
-- When a new node lands in risk_graph_nodes, the platform applies the rules
-- and stores the result in `business_value_usd`. Re-runnable in case rules change.

ALTER TABLE risk_graph_nodes
    ADD COLUMN IF NOT EXISTS business_value_usd          BIGINT,
    ADD COLUMN IF NOT EXISTS asset_replacement_cost_usd  BIGINT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS tags                        TEXT[]  NOT NULL DEFAULT ARRAY[]::TEXT[];

CREATE INDEX IF NOT EXISTS ix_risk_nodes_value
    ON risk_graph_nodes(tenant_id, business_value_usd DESC NULLS LAST)
    WHERE business_value_usd IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_risk_nodes_tags
    ON risk_graph_nodes USING GIN (tags);

-- ─── Per-client onboarding tag→value rules ──────────────────────────────────
CREATE TABLE IF NOT EXISTS client_asset_value_rules (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT      NOT NULL REFERENCES clients(id)  ON DELETE CASCADE,
    tag                 TEXT        NOT NULL,
    business_value_usd  BIGINT      NOT NULL,
    note                TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cavr_unique
    ON client_asset_value_rules (tenant_id, client_id, lower(tag));

ALTER TABLE client_asset_value_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_asset_value_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS client_asset_value_rules_tenant ON client_asset_value_rules;
CREATE POLICY client_asset_value_rules_tenant ON client_asset_value_rules FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON client_asset_value_rules TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE client_asset_value_rules_id_seq TO weissman_app;

-- Per-client default for unknown assets (configurable via API).
ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS default_asset_value_usd  BIGINT NOT NULL DEFAULT 10000,
    -- "$X at risk" computation discount factor (0..1) — how aggressively to
    -- multiply by likelihood. Industry-standard FAIR uses ~0.3 for "Likely".
    -- Higher = more conservative number.
    ADD COLUMN IF NOT EXISTS risk_loss_discount       REAL   NOT NULL DEFAULT 0.30;

-- ─── Snapshot table for the $-at-risk roll-up (one per client per refresh) ──
CREATE TABLE IF NOT EXISTS client_financial_risk_snapshots (
    id                        BIGSERIAL   PRIMARY KEY,
    tenant_id                 BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id                 BIGINT      NOT NULL REFERENCES clients(id)  ON DELETE CASCADE,
    computed_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    total_asset_value_usd     BIGINT      NOT NULL DEFAULT 0,
    -- "Single Loss Expectancy" if the worst current finding fired today.
    sle_worst_usd             BIGINT      NOT NULL DEFAULT 0,
    -- "Annualised Loss Expectancy" — SLE × annualised-rate-of-occurrence,
    -- approximated via EPSS (probability of exploit in next 30 days × 12).
    ale_annualised_usd        BIGINT      NOT NULL DEFAULT 0,
    -- Crown-jewel subtotal (assets flagged crown_jewel).
    crown_jewel_value_usd     BIGINT      NOT NULL DEFAULT 0,
    -- Detailed breakdown — top contributors to $-at-risk, JSON.
    top_contributors          JSONB       NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_cfrs_recent
    ON client_financial_risk_snapshots (tenant_id, client_id, computed_at DESC);

ALTER TABLE client_financial_risk_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_financial_risk_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cfrs_tenant ON client_financial_risk_snapshots;
CREATE POLICY cfrs_tenant ON client_financial_risk_snapshots FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON client_financial_risk_snapshots TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE client_financial_risk_snapshots_id_seq TO weissman_app;
