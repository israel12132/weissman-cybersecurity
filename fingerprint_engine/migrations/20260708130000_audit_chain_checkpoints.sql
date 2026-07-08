-- Keyed, append-only checkpoints over the audit-log hash-chain head.
--
-- The per-row event_hash is an UNKEYED SHA-256 over public canonical bytes, so a Postgres
-- superuser (or a DISABLE TRIGGER / backup restore) who edits a historical row could recompute
-- every downstream event_hash and still pass verify_chain(). These checkpoints defeat that:
-- each stores an HMAC over the current chain head, keyed by a secret held OUTSIDE the DB
-- (WEISSMAN_AUDIT_CHECKPOINT_SECRET). Recomputing SHA-256 hashes cannot forge the HMAC without
-- the key, so any post-hoc rewrite of history is detectable against the last checkpoint.

CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    id              bigserial PRIMARY KEY,
    tenant_id       bigint NOT NULL REFERENCES tenants (id),
    head_event_id   bigint NOT NULL,
    head_hash       text   NOT NULL,
    checkpoint_hmac text   NOT NULL,
    hmac_alg        text   NOT NULL DEFAULT 'HMAC-SHA256/v1',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_audit_checkpoints_tenant_created
    ON audit_chain_checkpoints (tenant_id, created_at DESC);

ALTER TABLE audit_chain_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_checkpoints FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_checkpoints_tenant ON audit_chain_checkpoints;
CREATE POLICY audit_checkpoints_tenant ON audit_chain_checkpoints FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

-- Append-only: no UPDATE or DELETE (same immutability contract as audit_logs).
CREATE OR REPLACE FUNCTION audit_checkpoints_reject_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_chain_checkpoints is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_checkpoints_block_update ON audit_chain_checkpoints;
CREATE TRIGGER audit_checkpoints_block_update
    BEFORE UPDATE ON audit_chain_checkpoints
    FOR EACH ROW
    EXECUTE PROCEDURE audit_checkpoints_reject_mutate();

DROP TRIGGER IF EXISTS audit_checkpoints_block_delete ON audit_chain_checkpoints;
CREATE TRIGGER audit_checkpoints_block_delete
    BEFORE DELETE ON audit_chain_checkpoints
    FOR EACH ROW
    EXECUTE PROCEDURE audit_checkpoints_reject_mutate();
