-- Follow-up to 20260826120000_client_scope_isolation (frozen).
--
-- 2a960be edited 20260826120000 in place after live volumes had already
-- applied it. sqlx then refused to boot: checksum mismatch /
-- _sqlx_migrations_pkey. The original file is restored so existing volumes
-- match _sqlx_migrations. This new version carries the INSERT-only policy fix:
--
--   ALTER POLICY: INSERT-only policies have WITH CHECK and no USING. Never
--   synthesize a USING clause (Postgres: "only WITH CHECK expression allowed
--   for INSERT").
--
-- Idempotent: policies that already include the visibility predicate are skipped.

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

-- Recreate the INSERT-only policies dropped by 20260826115900, now with the
-- customer-visibility predicate on WITH CHECK (never USING).
DO $$
BEGIN
    IF to_regclass('public.risk_graph_nodes') IS NOT NULL THEN
        DROP POLICY IF EXISTS risk_graph_nodes_insert ON public.risk_graph_nodes;
        CREATE POLICY risk_graph_nodes_insert ON public.risk_graph_nodes
            FOR INSERT WITH CHECK (
                tenant_id = public.app_current_tenant_id()
                AND EXISTS (
                    SELECT 1 FROM clients c
                    WHERE c.id = risk_graph_nodes.client_id
                      AND c.tenant_id = risk_graph_nodes.tenant_id
                )
                AND public.weissman_client_row_visible(client_id)
            );
    END IF;
    IF to_regclass('public.risk_graph_edges') IS NOT NULL THEN
        DROP POLICY IF EXISTS risk_graph_edges_insert ON public.risk_graph_edges;
        CREATE POLICY risk_graph_edges_insert ON public.risk_graph_edges
            FOR INSERT WITH CHECK (
                tenant_id = public.app_current_tenant_id()
                AND EXISTS (
                    SELECT 1 FROM risk_graph_nodes fn
                    WHERE fn.id = risk_graph_edges.from_node_id
                      AND fn.tenant_id = risk_graph_edges.tenant_id
                      AND fn.client_id = risk_graph_edges.client_id
                )
                AND EXISTS (
                    SELECT 1 FROM risk_graph_nodes tn
                    WHERE tn.id = risk_graph_edges.to_node_id
                      AND tn.tenant_id = risk_graph_edges.tenant_id
                      AND tn.client_id = risk_graph_edges.client_id
                )
                AND public.weissman_client_row_visible(client_id)
            );
    END IF;
END $$;
