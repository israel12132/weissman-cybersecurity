-- Fix auth.v_user_lookup to include mfa_enabled and mfa_secret columns required by login handler.

CREATE OR REPLACE VIEW auth.v_user_lookup AS
SELECT id,
       tenant_id,
       email,
       password_hash,
       is_active,
       role,
       COALESCE(is_superadmin, false) AS is_superadmin,
       COALESCE(mfa_enabled, false) AS mfa_enabled,
       COALESCE(mfa_secret, '') AS mfa_secret
FROM users;

COMMENT ON VIEW auth.v_user_lookup IS 'Narrow columns for weissman_auth login/JIT; includes role, is_superadmin, and MFA fields for authentication.';

GRANT SELECT ON auth.v_user_lookup TO weissman_auth;
