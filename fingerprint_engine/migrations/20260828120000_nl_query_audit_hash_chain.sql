-- NL Ask audit hash chain.
--
-- HTTP inserts remain append-only and fast (no chain computation on the request
-- path). The worker seals rows in BIGSERIAL `id` order — the monotonic sequence
-- is the chain order, never `asked_at`. Concurrent Ask inserts can finish out of
-- wall-clock order; sorting by `id` keeps SHA-256 linkage unforkable.

ALTER TABLE nl_query_audit
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS event_hash TEXT,
    ADD COLUMN IF NOT EXISTS chained_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_nlqa_unchained
    ON nl_query_audit (tenant_id, id)
    WHERE event_hash IS NULL;

COMMENT ON COLUMN nl_query_audit.id IS
    'Monotonic chain sequence (BIGSERIAL). Hash-chain workers MUST ORDER BY id, never asked_at.';
COMMENT ON COLUMN nl_query_audit.event_hash IS
    'SHA-256 of canonical payload linked to prev_hash. NULL = awaiting async seal.';

-- Sealer UPDATEs only these columns (HTTP path remains INSERT). Least-privilege:
-- weissman_app already had SELECT, INSERT; chain seal needs UPDATE on hash fields.
GRANT UPDATE (prev_hash, event_hash, chained_at) ON nl_query_audit TO weissman_app;
