-- Phase 1: isolate global intel/payload tables in dedicated schema (retention & operational clarity).
-- Phase 2: durable async job registry (UUID ids, worker dequeue, dead-letter via status).

CREATE SCHEMA IF NOT EXISTS intel;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'dynamic_payloads'
  ) THEN
    ALTER TABLE public.dynamic_payloads SET SCHEMA intel;
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'ephemeral_payloads'
  ) THEN
    ALTER TABLE public.ephemeral_payloads SET SCHEMA intel;
  END IF;
END $$;

GRANT USAGE ON SCHEMA intel TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA intel TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA intel TO weissman_app;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA intel
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA intel
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO weissman_app;

GRANT USAGE ON SCHEMA intel TO weissman_auth;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA intel TO weissman_auth;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA intel TO weissman_auth;

-- Global job queue: no RLS (workers dequeue across tenants; tenant_id is carried for downstream RLS).
CREATE TABLE IF NOT EXISTS weissman_async_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id bigint NOT NULL REFERENCES tenants (id),
    kind text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending',
    attempt_count int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 5,
    run_after timestamptz,
    locked_until timestamptz,
    worker_id text,
    heartbeat_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT weissman_async_jobs_status_chk CHECK (
        status IN ('pending', 'running', 'completed', 'failed', 'dead')
    )
);

CREATE INDEX IF NOT EXISTS ix_weissman_async_jobs_pending
    ON weissman_async_jobs (created_at)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS ix_weissman_async_jobs_running_heartbeat
    ON weissman_async_jobs (heartbeat_at)
    WHERE status = 'running';

COMMENT ON TABLE weissman_async_jobs IS 'Durable job queue (no RLS — worker dequeues across tenants; downstream work must call begin_tenant_tx). Inserts only via trusted server code.';

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_async_jobs TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_async_jobs TO weissman_auth;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO weissman_app;
