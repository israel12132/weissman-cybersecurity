-- Clear per-role `app.current_tenant_id` defaults so an unscoped connection fails CLOSED.
--
-- 20260809120000_reset_tenant_guc_default.sql resets the *database-wide* default:
--
--     ALTER DATABASE <db> RESET app.current_tenant_id
--
-- That statement only clears the row in `pg_db_role_setting` whose `setrole = 0`. It does NOT
-- clear per-role-per-database defaults installed by `ALTER ROLE <r> IN DATABASE <db> SET ...`,
-- which live in separate rows and take precedence over the database-wide default at login.
--
-- The production database was found carrying exactly that drift — set operationally, not by any
-- migration in this tree:
--
--     setdatabase | setrole        | setconfig
--     ------------+----------------+---------------------------
--     weissman    | weissman_app   | {app.current_tenant_id=1}
--     weissman    | weissman_auth  | {app.current_tenant_id=1}
--
-- Effect: every pooled connection begins its session already scoped to tenant 1. The failure
-- mode this inverts is the important one — 20260809120000 documents that tenant tables "fail
-- CLOSED" when the GUC is unset, but with a role default of '1' any code path that forgets to
-- call `begin_tenant_tx` silently reads and writes *tenant 1's* rows instead of returning
-- nothing. On a single-tenant deployment that is invisible; the moment a second tenant exists it
-- is a cross-tenant data leak. It also masks the missing-scope bug class in every test that runs
-- against a database with this drift.
--
-- Resetting is safe: `current_setting('app.current_tenant_id', true)` returns NULL when unset,
-- `public.app_current_tenant_id()` maps that to NULL, tenant policies evaluate `tenant_id = NULL`
-- (no rows), and the job-bus escape-hatch policies take their `IS NULL` branch. Handlers that
-- scope explicitly via `begin_tenant_tx` are unaffected.

DO $$
DECLARE
    r       RECORD;
    cleared int := 0;
BEGIN
    FOR r IN
        SELECT rol.rolname
        FROM pg_db_role_setting s
        JOIN pg_roles rol    ON rol.oid = s.setrole
        JOIN pg_database d   ON d.oid   = s.setdatabase
        WHERE d.datname = current_database()
          AND EXISTS (
              SELECT 1 FROM unnest(s.setconfig) AS cfg
              WHERE cfg LIKE 'app.current_tenant_id=%'
          )
    LOOP
        EXECUTE format(
            'ALTER ROLE %I IN DATABASE %I RESET app.current_tenant_id',
            r.rolname, current_database()
        );
        cleared := cleared + 1;
        RAISE NOTICE 'reset_role_tenant_guc_defaults: cleared default for role %', r.rolname;
    END LOOP;

    RAISE NOTICE 'reset_role_tenant_guc_defaults: cleared % role default(s)', cleared;
END $$;

-- Self-check: no role-level or database-level default may survive this migration.
DO $$
DECLARE
    leftover int;
BEGIN
    SELECT count(*)
      INTO leftover
    FROM pg_db_role_setting s
    LEFT JOIN pg_database d ON d.oid = s.setdatabase
    WHERE (s.setdatabase = 0 OR d.datname = current_database())
      AND EXISTS (
          SELECT 1 FROM unnest(s.setconfig) AS cfg
          WHERE cfg LIKE 'app.current_tenant_id=%'
      );

    IF leftover > 0 THEN
        RAISE EXCEPTION
            'reset_role_tenant_guc_defaults: % app.current_tenant_id default(s) still set', leftover;
    END IF;
END $$;
