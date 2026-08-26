-- Classified platform keyring — deployment secrets the CEO / superadmin cockpit
-- can inspect (status only) and fill. Values are AES-256-GCM ciphertext (wzv1:),
-- never plaintext. This table is PLATFORM-GLOBAL (one row per env var), not
-- tenant-scoped: process environment is process-wide. Access control is the
-- /api/ceo/* RBAC middleware (role=ceo or is_superadmin), not RLS.
--
-- weissman_ro (Ask Weissman NL→SQL) and weissman_auth MUST NOT read this table.

CREATE TABLE IF NOT EXISTS public.platform_keyring (
    env_name     TEXT PRIMARY KEY,
    ciphertext   TEXT NOT NULL,
    last4        TEXT NOT NULL DEFAULT '',
    value_len    INTEGER NOT NULL DEFAULT 0,
    category     TEXT NOT NULL DEFAULT 'custom',
    is_secret    BOOLEAN NOT NULL DEFAULT TRUE,
    custom       BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   TEXT NOT NULL DEFAULT '',
    writer_tenant_id BIGINT REFERENCES public.tenants(id) ON DELETE SET NULL
);

COMMENT ON TABLE public.platform_keyring IS
    'Encrypted deployment env keys for the CEO classified key cockpit. No RLS — CEO API only.';

CREATE INDEX IF NOT EXISTS ix_platform_keyring_category
    ON public.platform_keyring (category);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.platform_keyring TO weissman_app;
REVOKE ALL ON TABLE public.platform_keyring FROM PUBLIC;
REVOKE ALL ON TABLE public.platform_keyring FROM weissman_ro;
REVOKE ALL ON TABLE public.platform_keyring FROM weissman_auth;
