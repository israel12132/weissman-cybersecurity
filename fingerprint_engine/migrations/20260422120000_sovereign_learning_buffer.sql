-- Sovereign Evolution: recursive WAF-learning buffer (Critic → Hacker polymorphic synthesis).

CREATE TABLE sovereign_learning_buffer (
    id                         BIGSERIAL PRIMARY KEY,
    tenant_id                  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_fingerprint         TEXT NOT NULL,
    failure_context            JSONB NOT NULL DEFAULT '{}'::jsonb,
    critic_waf_analysis        JSONB,
    hacker_polymorphic_payload JSONB,
    status                     TEXT NOT NULL DEFAULT 'pending',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_sovereign_learning_tenant ON sovereign_learning_buffer(tenant_id);
CREATE INDEX ix_sovereign_learning_fp ON sovereign_learning_buffer(tenant_id, target_fingerprint);
CREATE INDEX ix_sovereign_learning_status ON sovereign_learning_buffer(tenant_id, status);

ALTER TABLE sovereign_learning_buffer ENABLE ROW LEVEL SECURITY;
ALTER TABLE sovereign_learning_buffer FORCE ROW LEVEL SECURITY;
CREATE POLICY sovereign_learning_buffer_tenant ON sovereign_learning_buffer FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON sovereign_learning_buffer TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE sovereign_learning_buffer_id_seq TO weissman_app;
