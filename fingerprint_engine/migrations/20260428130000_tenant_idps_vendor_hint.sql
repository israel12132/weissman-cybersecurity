-- Enterprise SSO management additions to tenant_idps.
--
-- `vendor_hint`  — display / routing hint for the SSO dashboard UI.
--                  Matches the provider card the operator selected.
--                  Values: okta | azure_ad | google | ping | saml_custom | oidc_custom
--
-- `sp_entity_id` — SAML SP Entity ID (used in AuthnRequests / ACS metadata).
--                  Defaults to the public base URL when blank.
--
-- `azure_tenant_id` — Azure AD tenant GUID (populated only when vendor_hint = 'azure_ad').
-- `okta_domain`     — Okta domain (e.g. company.okta.com), vendor_hint = 'okta'.
-- `last_test_at`    — Timestamp of most recent Test Connection attempt.
-- `last_test_ok`    — Boolean result of the most recent Test Connection.
-- `last_test_error` — Error message from the most recent failed Test Connection.

ALTER TABLE tenant_idps
    ADD COLUMN IF NOT EXISTS vendor_hint       TEXT NOT NULL DEFAULT 'oidc_custom',
    ADD COLUMN IF NOT EXISTS sp_entity_id      TEXT,
    ADD COLUMN IF NOT EXISTS azure_tenant_id   TEXT,
    ADD COLUMN IF NOT EXISTS okta_domain       TEXT,
    ADD COLUMN IF NOT EXISTS last_test_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_test_ok      BOOLEAN,
    ADD COLUMN IF NOT EXISTS last_test_error   TEXT;

-- Add check constraint for vendor_hint values
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'tenant_idps_vendor_hint_check'
    ) THEN
        ALTER TABLE tenant_idps
            ADD CONSTRAINT tenant_idps_vendor_hint_check
            CHECK (vendor_hint IN ('okta','azure_ad','google','ping','saml_custom','oidc_custom'));
    END IF;
END$$;
