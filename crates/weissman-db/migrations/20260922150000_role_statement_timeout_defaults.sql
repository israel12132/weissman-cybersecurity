-- Pooler-independent per-role statement_timeout (+ analytics read-only) defaults.
--
-- Rationale: under PgBouncer transaction pooling (deploy/k8s/pgbouncer.yaml POOL_MODE=transaction)
-- a client holds a server backend only for one transaction, so a session-level `SET` issued in the
-- sqlx after_connect hook binds just the first backend and does NOT survive transaction reuse. The
-- durable, pooler-independent mechanism is a role-level default, which Postgres applies on every
-- backend regardless of pooling. This mirrors the existing
-- `ALTER ROLE weissman_ro SET statement_timeout = '15s'` block in
-- 20260827115800_hermetic_db_roles.sql. The Rust after_connect SETs are kept as belt-and-suspenders
-- for direct / session-mode connections.
--
-- Idempotent: re-running just re-asserts the same values. IF EXISTS so it is a no-op where a role
-- is absent (dev/superuser-only volumes).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
        ALTER ROLE weissman_app SET statement_timeout = '120s';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_auth') THEN
        ALTER ROLE weissman_auth SET statement_timeout = '30s';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        ALTER ROLE weissman_worker SET statement_timeout = '30s';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_analytics') THEN
        ALTER ROLE weissman_analytics SET statement_timeout = '15s';
        ALTER ROLE weissman_analytics SET default_transaction_read_only = on;
    END IF;
END
$$;
