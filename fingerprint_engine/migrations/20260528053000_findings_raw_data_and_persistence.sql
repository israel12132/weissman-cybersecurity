-- E2E follow-ups: make scan findings observable end-to-end.
--
-- Adds the `raw_data` JSONB column the read-side handler (`api_findings`) already references
-- via COALESCE(raw_data, '{}'::jsonb). Without this column the SELECT silently errors out
-- (errors are swallowed and the API returns an empty list), so the customer never sees any
-- scan output even when an engine produced findings.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS raw_data JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS ix_vuln_raw_data_gin
    ON vulnerabilities USING gin (raw_data jsonb_path_ops);

-- /api/admin/users uses the auth_pool (weissman_auth) per `admin_users.rs`, but the original
-- migration only granted CRUD on `public.users` to `weissman_app`, so every admin-pane query
-- 500'd with `permission denied for table users`. Grant the auth role what it needs.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON public.users TO weissman_auth';
        EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO weissman_auth';
    END IF;
END
$$;
