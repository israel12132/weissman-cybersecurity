-- Parallel hash-chain epochs for Ask Weissman (DoS cap on late-id re-hash)
-- plus offline-first sovereign UEBA binary allow-list (air-gapped, no HTTP).

ALTER TABLE nl_query_audit
    ADD COLUMN IF NOT EXISTS chain_epoch INTEGER NOT NULL DEFAULT 1;

COMMENT ON COLUMN nl_query_audit.chain_epoch IS
    'Hash-chain generation. A late BIGSERIAL hole deeper than WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE freezes the current epoch and stamps unchained rows on a new epoch instead of rewriting the tip history.';

CREATE INDEX IF NOT EXISTS ix_nlqa_chain_epoch
    ON nl_query_audit (tenant_id, chain_epoch, id);

DO $$
BEGIN
    IF to_regclass('public.nl_query_audit') IS NOT NULL THEN
        GRANT UPDATE (prev_hash, event_hash, chain_epoch) ON TABLE nl_query_audit TO weissman_app;
    END IF;
END $$;

-- Weissman catalog of approved process SHA-256 hex (not tenant PII).
-- Populated from the packaged update file, env, and USB/offline drop — never from the internet.
CREATE TABLE IF NOT EXISTS ueba_sovereign_binary_allowlist (
    sha256         CHAR(64) PRIMARY KEY,
    source         TEXT NOT NULL,
    introduced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ueba_sovereign_binary_allowlist_sha256_hex
        CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ueba_sovereign_binary_allowlist_source_chk
        CHECK (source IN ('packaged', 'env', 'offline_file'))
);

ALTER TABLE ueba_sovereign_binary_allowlist DISABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT ON ueba_sovereign_binary_allowlist TO weissman_app;

COMMENT ON TABLE ueba_sovereign_binary_allowlist IS
    'Offline-first sovereign SHA-256 allow-list for UEBA onboarding Learn. No tenant isolation; catalog data shipped with platform updates.';
