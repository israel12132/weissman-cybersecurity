-- Ask Weissman audit is encrypted at rest by the application (AES-256-GCM,
-- prefix wzi1: / nl_audit_crypto). New writes never store the raw question or
-- compiled SQL in plaintext. Existing rows stay readable until rotated.

COMMENT ON TABLE nl_query_audit IS
    'Ask Weissman audit. question / plan_json / compiled_sql are ciphertext at rest (wzi1:).';
COMMENT ON COLUMN nl_query_audit.question IS
    'Encrypted question (wzi1: AES-256-GCM). Legacy plaintext only for pre-encryption rows.';
COMMENT ON COLUMN nl_query_audit.compiled_sql IS
    'Encrypted compiled SQL (wzi1:).';
COMMENT ON COLUMN nl_query_audit.plan_json IS
    'Encrypted plan as {"_enc":"wzi1:..."}.';
