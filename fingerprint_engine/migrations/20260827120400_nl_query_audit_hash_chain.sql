-- Tamper-evident hash chain for Ask Weissman audit rows.
-- Each insert stores SHA-256(nlqa1|prev|tenant|user|sealed_q|sealed_sql|rows|elapsed|error).
-- Application encrypts question/SQL before hashing so the chain never covers plaintext.

ALTER TABLE nl_query_audit
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS ix_nlqa_chain
    ON nl_query_audit (tenant_id, id DESC);

COMMENT ON COLUMN nl_query_audit.prev_hash IS
    'SHA-256 hex of the previous tenant row (empty = genesis).';
COMMENT ON COLUMN nl_query_audit.event_hash IS
    'SHA-256 hex of this row''s canonical payload (nlqa1 chain).';
