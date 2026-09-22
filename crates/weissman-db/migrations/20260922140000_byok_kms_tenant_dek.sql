-- BYOK / KMS envelope encryption: per-tenant KEK->DEK hierarchy.
--
-- Two tenant-scoped tables back the pluggable KeyProvider (fingerprint_engine::tenant_kms):
--
--   tenant_kms_keys  — the tenant's customer-managed KMS key (CMK) ARN, used by the
--                      AwsKmsKeyProvider to wrap/unwrap that tenant's DEK. Absent row =
--                      that tenant has not enrolled a BYOK key (the caller falls back to
--                      the local provider / legacy global vault key).
--   tenant_dek       — the tenant's data-encryption key, stored WRAPPED (never plaintext):
--                      AES-256-GCM under the local KEK (provider=local) or KMS-encrypted
--                      under the tenant CMK (provider=aws). The unwrapped DEK lives only in
--                      process memory (TTL cache); crypto-shredding the CMK renders every
--                      wzt1:-tagged secret for that tenant permanently undecryptable.
--
-- Both are per-tenant and MUST be fail-closed RLS (see rls_live_schema_contract): a missing
-- begin_tenant_tx yields zero rows, never a cross-tenant key leak. wrapped_dek is ciphertext,
-- so RLS isolation (not plaintext secrecy) is the guarantee these policies provide.

CREATE TABLE IF NOT EXISTS tenant_kms_keys (
    tenant_id    BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    kms_key_arn  TEXT NOT NULL,
    provider     TEXT NOT NULL DEFAULT 'aws',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE tenant_kms_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_kms_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_kms_keys_tenant ON tenant_kms_keys;
CREATE POLICY tenant_kms_keys_tenant ON tenant_kms_keys FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_kms_keys TO weissman_app;

CREATE TABLE IF NOT EXISTS tenant_dek (
    tenant_id    BIGINT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    wrapped_dek  BYTEA NOT NULL,
    provider     TEXT NOT NULL DEFAULT 'local',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE tenant_dek ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_dek FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_dek_tenant ON tenant_dek;
CREATE POLICY tenant_dek_tenant ON tenant_dek FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_dek TO weissman_app;
