-- Make every tenant RLS policy cast-safe when `app.current_tenant_id` is the empty string.
--
-- THE BUG THIS FIXES (production outage, 2026-08-06 -> 2026-08-10, 4+ days):
--
-- The worker dequeues across tenants by opening a transaction and setting the RLS GUC to the
-- empty string (`job_queue.rs::begin_worker_tx`, `swarm.rs::tick`). Every tenant policy in the
-- tree was written as:
--
--     tenant_id = current_setting('app.current_tenant_id', true)::bigint
--
-- and the three job-bus tables additionally guarded it with an OR branch:
--
--     NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
--     OR tenant_id = current_setting('app.current_tenant_id', true)::bigint
--
-- That guard does NOT work. Postgres does not guarantee short-circuit evaluation of `OR`: on a
-- real (non-trivial) table scan the planner evaluates the stable `current_setting(...)::bigint`
-- subexpression eagerly, and `''::bigint` raises
--
--     ERROR:  invalid input syntax for type bigint: ""
--
-- before the NULLIF branch can spare it. Reproduced directly against the production database:
-- the guarded form errors on `SELECT count(*) FROM weissman_async_jobs`, while the form this
-- migration installs returns every row. Consequence in production: `claim/reserve failed` on
-- every worker poll for four days, 2111 jobs stuck `pending`, zero scans executed, while
-- `/api/health` still reported `scanning_active: true`.
--
-- THE FIX: move the cast inside the NULLIF, via a helper so the correct form is stated once.
-- `NULLIF('', '')` is NULL and `NULL::bigint` is NULL — never an error — so the expression is
-- safe no matter when the planner chooses to evaluate it.
--
-- Resulting semantics, unchanged for the scoped case and now correct for the unscoped one:
--
--   GUC = '7'        -> app_current_tenant_id() = 7    -> rows of tenant 7 (as before)
--   GUC = '' / unset -> app_current_tenant_id() IS NULL
--                       * plain tenant policy: `tenant_id = NULL` is NULL -> no rows -> FAILS CLOSED
--                       * job-bus policy: the `IS NULL` branch matches   -> unrestricted dequeue
--   GUC = 'abc'      -> still errors, which is the intended contract for a malformed scope.
--
-- The rewrite below is textual over `pg_get_expr` output so that compound policies keep their
-- extra predicates verbatim (e.g. `risk_graph_edges_select`, which also joins risk_graph_nodes).

CREATE OR REPLACE FUNCTION public.app_current_tenant_id() RETURNS bigint
    LANGUAGE sql
    STABLE
    PARALLEL SAFE
    -- NOT SECURITY DEFINER on purpose: this must read the *caller's* GUC.
    AS $fn$
    SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::bigint
$fn$;

COMMENT ON FUNCTION public.app_current_tenant_id() IS
    'Current RLS tenant scope, or NULL when unset/empty. Cast-safe: never raises on an empty GUC, '
    'unlike current_setting(...)::bigint, which Postgres may evaluate eagerly inside an OR guard.';

DO $$
DECLARE
    r            RECORD;
    new_qual     text;
    new_check    text;
    stmt         text;
    rewritten    int := 0;
    -- Both renderings pg_get_expr can produce for the unsafe cast: parenthesised (what pg16
    -- emits today) and bare (older//future deparse, and hand-written policies).
    pat_a  CONSTANT text := '(current_setting(''app.current_tenant_id''::text, true))::bigint';
    pat_b  CONSTANT text := 'current_setting(''app.current_tenant_id''::text, true)::bigint';
    repl   CONSTANT text := 'public.app_current_tenant_id()';
BEGIN
    FOR r IN
        SELECT n.nspname                                AS schema_name,
               c.relname                                AS table_name,
               p.polname                                AS policy_name,
               pg_get_expr(p.polqual, p.polrelid)       AS qual,
               pg_get_expr(p.polwithcheck, p.polrelid)  AS with_check
        FROM pg_policy p
        JOIN pg_class c     ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
    LOOP
        -- Skip policies that never reference the unsafe cast.
        CONTINUE WHEN position(pat_a IN coalesce(r.qual, '')) = 0
                  AND position(pat_a IN coalesce(r.with_check, '')) = 0
                  AND position(pat_b IN coalesce(r.qual, '')) = 0
                  AND position(pat_b IN coalesce(r.with_check, '')) = 0;

        new_qual  := replace(replace(coalesce(r.qual, ''),       pat_a, repl), pat_b, repl);
        new_check := replace(replace(coalesce(r.with_check, ''), pat_a, repl), pat_b, repl);

        -- Only re-state the clauses the policy actually has: an INSERT-only policy has no USING
        -- clause, and ALTER POLICY rejects one.
        stmt := format('ALTER POLICY %I ON %I.%I', r.policy_name, r.schema_name, r.table_name);
        IF r.qual IS NOT NULL THEN
            stmt := stmt || format(' USING (%s)', new_qual);
        END IF;
        IF r.with_check IS NOT NULL THEN
            stmt := stmt || format(' WITH CHECK (%s)', new_check);
        END IF;

        EXECUTE stmt;
        rewritten := rewritten + 1;
    END LOOP;

    RAISE NOTICE 'rls_tenant_guc_cast_safety: rewrote % policies', rewritten;
END $$;

-- Self-check: fail the migration rather than ship a half-rewritten policy set.
DO $$
DECLARE
    leftover int;
    detail   text;
BEGIN
    SELECT count(*),
           string_agg(format('%s.%s', c.relname, p.polname), ', ' ORDER BY c.relname, p.polname)
      INTO leftover, detail
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    WHERE coalesce(pg_get_expr(p.polqual, p.polrelid), '')
              LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%'
       OR coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
              LIKE '%current_setting(''app.current_tenant_id''::text, true))::bigint%';

    IF leftover > 0 THEN
        RAISE EXCEPTION
            'rls_tenant_guc_cast_safety: % policies still use the unsafe cast: %', leftover, detail;
    END IF;
END $$;
