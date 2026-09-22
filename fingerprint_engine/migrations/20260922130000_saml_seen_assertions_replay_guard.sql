-- SAML assertion anti-replay + per-IdP unsolicited opt-in (enterprise SSO hardening).
--
-- WHY
-- The SAML ACS (fingerprint_engine/src/saml_auth.rs) accepts an IdP-signed bearer assertion and
-- mints a session. Without a one-shot check, a captured-but-still-valid assertion (its Conditions
-- window has not elapsed) can be POSTed to /api/auth/saml/acs a second time and replayed into a new
-- session. `saml_seen_assertions` records each accepted assertion ID until its validity horizon so a
-- second use collides on the primary key and is rejected.
--
-- ACCESS MODEL
-- The ACS runs on the auth pool as `weissman_auth` (BYPASSRLS; see 20250328120004). Every statement
-- names the tenant explicitly. RLS below is fail-CLOSED defense-in-depth: if a future code path ever
-- reaches this table as `weissman_app` without begin_tenant_tx, public.app_current_tenant_id() IS NULL
-- (see 20260811000000) so `tenant_id = NULL` matches no rows — zero rows, never a cross-tenant leak.

CREATE TABLE IF NOT EXISTS saml_seen_assertions (
    assertion_id  TEXT         PRIMARY KEY,
    tenant_id     BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Drives the opportunistic GC (`DELETE ... WHERE expires_at < now()`) and bounds table growth.
CREATE INDEX IF NOT EXISTS ix_saml_seen_assertions_expires ON saml_seen_assertions (expires_at);
CREATE INDEX IF NOT EXISTS ix_saml_seen_assertions_tenant  ON saml_seen_assertions (tenant_id);

ALTER TABLE saml_seen_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_seen_assertions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS saml_seen_assertions_tenant ON saml_seen_assertions;
CREATE POLICY saml_seen_assertions_tenant ON saml_seen_assertions
    FOR ALL
    USING      (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

-- Least privilege: only the SAML auth-plane role touches this table (SELECT via ON CONFLICT insert,
-- INSERT to record, DELETE for the expired-row GC). weissman_app is deliberately NOT granted.
GRANT SELECT, INSERT, DELETE ON saml_seen_assertions TO weissman_auth;

-- Per-IdP opt-in for unsolicited (IdP-initiated) SAML responses that carry no InResponseTo.
-- Default false => the ACS rejects any assertion whose InResponseTo does not match an AuthnRequest
-- ID we issued, closing the unsolicited-response acceptance hole.
ALTER TABLE tenant_idps
    ADD COLUMN IF NOT EXISTS saml_allow_unsolicited BOOLEAN NOT NULL DEFAULT false;

