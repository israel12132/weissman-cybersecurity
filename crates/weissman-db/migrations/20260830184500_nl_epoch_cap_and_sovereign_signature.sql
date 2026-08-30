-- Fail-closed Ask Weissman when a fourth parallel audit epoch would be created
-- (epoch fragmentation), plus Ed25519 sovereign_signature on the UEBA allow-list.

CREATE TABLE IF NOT EXISTS nl_ask_fail_closed (
    tenant_id    BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    locked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason       TEXT NOT NULL,
    hole_id      BIGINT,
    tip_id       BIGINT,
    epoch_count  INTEGER NOT NULL,
    details      JSONB NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE nl_ask_fail_closed ENABLE ROW LEVEL SECURITY;
ALTER TABLE nl_ask_fail_closed FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS nl_ask_fail_closed_tenant ON nl_ask_fail_closed;
CREATE POLICY nl_ask_fail_closed_tenant ON nl_ask_fail_closed FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, DELETE ON nl_ask_fail_closed TO weissman_app;

COMMENT ON TABLE nl_ask_fail_closed IS
    'Ask Weissman fail-closed lock. Set when a late BIGSERIAL hole would open a fourth parallel chain_epoch (MAX_CONCURRENT_AUDIT_EPOCHS). SOC is paged via security_events + audit_logs.';

ALTER TABLE ueba_sovereign_binary_allowlist
    ADD COLUMN IF NOT EXISTS sovereign_signature TEXT NOT NULL DEFAULT '';

ALTER TABLE ueba_sovereign_binary_allowlist
    DROP CONSTRAINT IF EXISTS ueba_sovereign_binary_allowlist_sig_hex;
ALTER TABLE ueba_sovereign_binary_allowlist
    ADD CONSTRAINT ueba_sovereign_binary_allowlist_sig_hex
    CHECK (sovereign_signature = '' OR sovereign_signature ~ '^[0-9a-f]{128}$');

COMMENT ON COLUMN ueba_sovereign_binary_allowlist.sovereign_signature IS
    'Ed25519 signature (128 hex) over the lowercase SHA-256 hex, verified against the public key compiled into the server. Empty signatures never grant Learn.';

GRANT SELECT, INSERT, UPDATE ON ueba_sovereign_binary_allowlist TO weissman_app;

-- SOC path for epoch-fragmentation alerts (RLS WITH CHECK still applies).
GRANT INSERT ON security_events TO weissman_app;
