-- Customer (client) isolation for the MSSP command center.
--
-- Tenant RLS already walls org A from org B. This migration walls *customers*
-- inside a tenant:
--
--   * Owner (CEO / superadmin) and staff (unscoped users) keep tenant-wide
--     visibility — they do not pick a client at login.
--   * A portal user has users.assigned_client_id set. Request code stamps
--     app.current_client_id; RLS then hides every other customer's rows.
--   * Empty/unset app.current_client_id ⇒ staff/owner/worker: all clients
--     in the tenant remain visible (cast-safe, same pattern as
--     app_current_tenant_id).
--
-- Fail-closed: a scoped GUC never returns another customer's row, even if a
-- handler forgets a WHERE client_id = $1 filter.
--
-- ALTER POLICY: INSERT-only policies have WITH CHECK and no USING. Never
-- synthesize a USING clause (Postgres: "only WITH CHECK expression allowed
-- for INSERT").

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS assigned_client_id BIGINT REFERENCES clients(id) ON DELETE RESTRICT;

CREATE INDEX IF NOT EXISTS ix_users_assigned_client
    ON users (tenant_id, assigned_client_id)
    WHERE assigned_client_id IS NOT NULL;

COMMENT ON COLUMN users.assigned_client_id IS
    'When set, this user is a customer-portal identity locked to that client. NULL = owner/staff with tenant-wide visibility.';

-- Portal users must be bound to a client; owner/staff must not be.
-- Superadmin and CEO cannot be portal-scoped.
DO $$
BEGIN
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_client_scope_consistency;
    ALTER TABLE users ADD CONSTRAINT users_client_scope_consistency CHECK (
        (
            lower(trim(COALESCE(role, ''))) = 'client'
            AND assigned_client_id IS NOT NULL
            AND COALESCE(is_superadmin, false) = false
        )
        OR
        (
            lower(trim(COALESCE(role, ''))) <> 'client'
            AND assigned_client_id IS NULL
        )
    );
EXCEPTION
    WHEN others THEN
        RAISE NOTICE 'users_client_scope_consistency: %', SQLERRM;
END $$;

CREATE OR REPLACE VIEW auth.v_user_lookup AS
SELECT id,
       tenant_id,
       email,
       password_hash,
       is_active,
       role,
       COALESCE(is_superadmin, false) AS is_superadmin,
       COALESCE(mfa_enabled, false) AS mfa_enabled,
       COALESCE(mfa_secret, '') AS mfa_secret,
       assigned_client_id
FROM users;

COMMENT ON VIEW auth.v_user_lookup IS
    'Narrow columns for weissman_auth login/JIT; includes role, is_superadmin, MFA, and assigned_client_id for client-portal JWT claims.';

GRANT SELECT ON auth.v_user_lookup TO weissman_auth;

-- Cast-safe client GUC (mirrors app_current_tenant_id). Empty/unset → NULL,
-- never `''::bigint` which Postgres may evaluate eagerly inside OR guards.
CREATE OR REPLACE FUNCTION public.app_current_client_id() RETURNS bigint
    LANGUAGE sql
    STABLE
    PARALLEL SAFE
AS $fn$
    SELECT NULLIF(current_setting('app.current_client_id', true), '')::bigint
$fn$;

COMMENT ON FUNCTION public.app_current_client_id() IS
    'Current RLS customer-client scope, or NULL when unset/empty (owner/staff/worker: all clients in the tenant).';

CREATE OR REPLACE FUNCTION public.weissman_client_row_visible(row_client_id bigint) RETURNS boolean
    LANGUAGE sql
    STABLE
    PARALLEL SAFE
AS $fn$
    SELECT public.app_current_client_id() IS NULL
        OR (row_client_id IS NOT NULL AND row_client_id = public.app_current_client_id())
$fn$;

COMMENT ON FUNCTION public.weissman_client_row_visible(bigint) IS
    'TRUE when the session is unscoped (staff/owner/worker) or the row belongs to app.current_client_id.';

CREATE OR REPLACE FUNCTION public.weissman_client_row_visible_text(row_client_id text) RETURNS boolean
    LANGUAGE sql
    STABLE
    PARALLEL SAFE
AS $fn$
    SELECT public.app_current_client_id() IS NULL
        OR (
            row_client_id IS NOT NULL
            AND btrim(row_client_id) <> ''
            AND btrim(row_client_id) = public.app_current_client_id()::text
        )
$fn$;

COMMENT ON FUNCTION public.weissman_client_row_visible_text(text) IS
    'Text client_id variant (pipeline_run_state stores numeric ids as text plus __global__).';

-- clients: the row's id *is* the customer. Scoped users see only their row.
DO $$
DECLARE
    r RECORD;
    vis text := 'public.weissman_client_row_visible(id)';
    new_qual text;
    new_check text;
BEGIN
    FOR r IN
        SELECT p.polname,
               pg_get_expr(p.polqual, p.polrelid) AS qual,
               pg_get_expr(p.polwithcheck, p.polrelid) AS with_check
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'clients'
    LOOP
        CONTINUE WHEN position('weissman_client_row_visible' IN coalesce(r.qual, '') || coalesce(r.with_check, '')) > 0;
        IF r.qual IS NOT NULL THEN
            new_qual := '(' || r.qual || ') AND ' || vis;
            EXECUTE format('ALTER POLICY %I ON public.clients USING (%s)', r.polname, new_qual);
        END IF;
        IF r.with_check IS NOT NULL THEN
            new_check := '(' || r.with_check || ') AND ' || vis;
            EXECUTE format('ALTER POLICY %I ON public.clients WITH CHECK (%s)', r.polname, new_check);
        END IF;
    END LOOP;
END $$;

-- users: scoped portal users see only identities bound to the same client.
DO $$
DECLARE
    r RECORD;
    vis text := '(public.app_current_client_id() IS NULL OR assigned_client_id = public.app_current_client_id())';
    new_qual text;
    new_check text;
BEGIN
    FOR r IN
        SELECT p.polname,
               pg_get_expr(p.polqual, p.polrelid) AS qual,
               pg_get_expr(p.polwithcheck, p.polrelid) AS with_check
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = 'users'
    LOOP
        CONTINUE WHEN position('app_current_client_id' IN coalesce(r.qual, '') || coalesce(r.with_check, '')) > 0;
        IF r.qual IS NOT NULL THEN
            new_qual := '(' || r.qual || ') AND ' || vis;
            EXECUTE format('ALTER POLICY %I ON public.users USING (%s)', r.polname, new_qual);
        END IF;
        IF r.with_check IS NOT NULL THEN
            -- Inserts/updates of staff users (assigned_client_id NULL) must still
            -- succeed for owner/staff sessions (GUC empty). Portal sessions cannot
            -- create users; WITH CHECK matching USING is correct.
            new_check := '(' || r.with_check || ') AND ' || vis;
            EXECUTE format('ALTER POLICY %I ON public.users WITH CHECK (%s)', r.polname, new_check);
        END IF;
    END LOOP;
END $$;

-- Every relation with a client_id column: AND the visibility predicate onto
-- existing tenant policies so a missed handler filter cannot leak rows.
DO $$
DECLARE
    r RECORD;
    vis text;
    new_qual text;
    new_check text;
BEGIN
    FOR r IN
        SELECT n.nspname AS schema_name,
               c.relname AS table_name,
               p.polname AS policy_name,
               pg_get_expr(p.polqual, p.polrelid) AS qual,
               pg_get_expr(p.polwithcheck, p.polrelid) AS with_check,
               col.data_type
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN information_schema.columns col
          ON col.table_schema = n.nspname
         AND col.table_name = c.relname
         AND col.column_name = 'client_id'
        WHERE n.nspname = 'public'
          AND c.relkind = 'r'
          AND c.relname <> 'tenant_idps'
    LOOP
        CONTINUE WHEN position('weissman_client_row_visible' IN coalesce(r.qual, '') || coalesce(r.with_check, '')) > 0;
        IF r.data_type IN ('bigint', 'integer', 'smallint', 'numeric') THEN
            vis := 'public.weissman_client_row_visible(client_id)';
        ELSE
            vis := 'public.weissman_client_row_visible_text(client_id::text)';
        END IF;
        IF r.qual IS NOT NULL THEN
            new_qual := '(' || r.qual || ') AND ' || vis;
            EXECUTE format(
                'ALTER POLICY %I ON %I.%I USING (%s)',
                r.policy_name, r.schema_name, r.table_name, new_qual
            );
        END IF;
        IF r.with_check IS NOT NULL THEN
            new_check := '(' || r.with_check || ') AND ' || vis;
            EXECUTE format(
                'ALTER POLICY %I ON %I.%I WITH CHECK (%s)',
                r.policy_name, r.schema_name, r.table_name, new_check
            );
        END IF;
    END LOOP;
END $$;

-- tenant_idps.client_id is an OAuth client id, not a customer id — excluded above.
-- Tenant-wide tables with no customer-client column must not leak to a portal session.
DO $$
DECLARE
    t text;
    r RECORD;
    vis text := '(public.app_current_client_id() IS NULL)';
    new_qual text;
    new_check text;
BEGIN
    FOREACH t IN ARRAY ARRAY['report_runs', 'audit_logs', 'tenant_idps']
    LOOP
        FOR r IN
            SELECT p.polname,
                   pg_get_expr(p.polqual, p.polrelid) AS qual,
                   pg_get_expr(p.polwithcheck, p.polrelid) AS with_check
            FROM pg_policy p
            JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relname = t
        LOOP
            CONTINUE WHEN position('app_current_client_id' IN coalesce(r.qual, '') || coalesce(r.with_check, '')) > 0;
            IF r.qual IS NOT NULL THEN
                new_qual := '(' || r.qual || ') AND ' || vis;
                EXECUTE format('ALTER POLICY %I ON public.%I USING (%s)', r.polname, t, new_qual);
            END IF;
            IF r.with_check IS NOT NULL THEN
                new_check := '(' || r.with_check || ') AND ' || vis;
                EXECUTE format('ALTER POLICY %I ON public.%I WITH CHECK (%s)', r.polname, t, new_check);
            END IF;
        END LOOP;
    END LOOP;
END $$;
