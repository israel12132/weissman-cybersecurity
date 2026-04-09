-- Phase 6: sealed PoE payloads, LLM fuzz telemetry, optional CI/CD scan audit.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS poc_sealed BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS poc_ciphertext_b64 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS poc_nonce_b64 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS poc_commitment_sha256 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS poc_zkp_hmac TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS llm_fuzz_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    endpoint_url    TEXT NOT NULL,
    attack_vector   TEXT NOT NULL,
    request_preview TEXT NOT NULL DEFAULT '',
    response_excerpt TEXT NOT NULL DEFAULT '',
    leakage_score   DOUBLE PRECISION NOT NULL DEFAULT 0,
    hallucination_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    blocked         BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_llm_fuzz_tenant ON llm_fuzz_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_llm_fuzz_client ON llm_fuzz_events (client_id);
CREATE INDEX IF NOT EXISTS ix_llm_fuzz_created ON llm_fuzz_events (created_at DESC);

ALTER TABLE llm_fuzz_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_fuzz_events FORCE ROW LEVEL SECURITY;
CREATE POLICY llm_fuzz_events_tenant ON llm_fuzz_events FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON llm_fuzz_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE llm_fuzz_events_id_seq TO weissman_app;

CREATE TABLE IF NOT EXISTS cicd_scan_events (
    id           BIGSERIAL PRIMARY KEY,
    provider     TEXT NOT NULL,
    ref_name     TEXT NOT NULL DEFAULT '',
    commit_sha   TEXT NOT NULL DEFAULT '',
    blocked      BOOLEAN NOT NULL DEFAULT false,
    findings_json TEXT NOT NULL DEFAULT '[]',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Platform-wide hook log (no tenant on webhook); restrict via DB role in production.
GRANT INSERT, SELECT ON cicd_scan_events TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE cicd_scan_events_id_seq TO weissman_app;
