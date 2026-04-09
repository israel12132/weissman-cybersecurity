-- CEO Command Center RBAC: super-admin flag + expose role in auth lookup view.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN NOT NULL DEFAULT false;

CREATE OR REPLACE VIEW auth.v_user_lookup AS
SELECT id,
       tenant_id,
       email,
       password_hash,
       is_active,
       role,
       COALESCE(is_superadmin, false) AS is_superadmin
FROM users;

COMMENT ON COLUMN users.is_superadmin IS 'Platform/tenant break-glass: full access including CEO APIs when true.';
COMMENT ON VIEW auth.v_user_lookup IS 'Narrow columns for weissman_auth login/JIT; includes role + is_superadmin for JWT.';

GRANT SELECT ON auth.v_user_lookup TO weissman_auth;
