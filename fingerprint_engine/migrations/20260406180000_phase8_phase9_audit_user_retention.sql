-- Phase 9: audit_logs actor user id + append-only enforcement; optional intel/job retention helpers.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_user ON audit_logs(actor_user_id);

COMMENT ON COLUMN audit_logs.actor_user_id IS 'Authenticated user who performed the action (nullable for legacy rows).';

-- Append-only: no UPDATE or DELETE on audit rows (immutable trail).
CREATE OR REPLACE FUNCTION audit_logs_reject_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_block_update ON audit_logs;
CREATE TRIGGER audit_logs_block_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE PROCEDURE audit_logs_reject_mutate();

DROP TRIGGER IF EXISTS audit_logs_block_delete ON audit_logs;
CREATE TRIGGER audit_logs_block_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE PROCEDURE audit_logs_reject_mutate();
