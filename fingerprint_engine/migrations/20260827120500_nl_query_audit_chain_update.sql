-- Background hash-chain worker UPDATEs prev_hash/event_hash after POST /api/ask
-- inserts an unchained (empty-hash) row. weissman_app originally had INSERT+SELECT
-- only. Column-level UPDATE keeps question/SQL append-only from the app role.

DO $$
BEGIN
    IF to_regclass('public.nl_query_audit') IS NOT NULL THEN
        GRANT UPDATE (prev_hash, event_hash) ON TABLE nl_query_audit TO weissman_app;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_nlqa_unchained
    ON nl_query_audit (tenant_id, id)
    WHERE event_hash = '';

COMMENT ON INDEX ix_nlqa_unchained IS
    'Unchained Ask Weissman audit rows waiting for the background hash-chain worker.';
