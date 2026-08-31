-- Dashboard HTML + Command Center summary reads go through weissman_ro
-- (WEISSMAN_READ_ONLY_DATABASE_URL). The original NL grant list omitted
-- report_runs, which the legacy dashboard scores from.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON report_runs TO weissman_ro;
        -- Already granted in 20260608140300; re-assert so a later REVOKE cannot
        -- silently drop dashboard tables without a follow-on migration.
        GRANT SELECT ON vulnerabilities, clients TO weissman_ro;
    END IF;
END $$;

COMMENT ON ROLE weissman_ro IS
    'SELECT-only: Ask Weissman NL→SQL + dashboard reads. App wraps NL SQL in LIMIT 200.';
