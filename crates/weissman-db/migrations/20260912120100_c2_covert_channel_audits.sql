-- Advanced C2 & Covert Exfiltration assessment audit trail.
-- Tenant-isolated (FORCE RLS). Analysts read via weissman_ro. 14-day retention
-- is expressed as expires_at so a scheduled sweeper can DELETE expired rows
-- without touching live findings. SHA-256 finding_signature supports idempotent
-- dispatch (same target||title||mitre is not double-inserted per job).

CREATE TABLE IF NOT EXISTS c2_covert_channel_audits (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL,
    client_id           BIGINT,
    job_id              TEXT,
    target              TEXT NOT NULL,
    engine_id           TEXT NOT NULL DEFAULT 'advanced_c2_covert_exfil',
    layer               TEXT NOT NULL,
    finding_signature   TEXT NOT NULL,
    severity            TEXT NOT NULL,
    mitre               TEXT,
    evidence            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '14 days')
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_c2_covert_audits_job_sig
    ON c2_covert_channel_audits (tenant_id, job_id, finding_signature)
    WHERE job_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_c2_covert_audits_tenant_created
    ON c2_covert_channel_audits (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_c2_covert_audits_expires
    ON c2_covert_channel_audits (expires_at);

CREATE TABLE IF NOT EXISTS dns_covert_query_audits (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL,
    client_id       BIGINT,
    job_id          TEXT,
    target          TEXT NOT NULL,
    qtype           TEXT NOT NULL,
    query_host      TEXT NOT NULL,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '14 days')
);

CREATE INDEX IF NOT EXISTS ix_dns_covert_audits_tenant_created
    ON dns_covert_query_audits (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_dns_covert_audits_host
    ON dns_covert_query_audits (tenant_id, query_host);

COMMENT ON TABLE c2_covert_channel_audits IS
    'Live C2/covert-channel assessment findings. RLS-enforced. Directive 361 / tenant isolation.';
COMMENT ON TABLE dns_covert_query_audits IS
    'DNS TXT/CNAME/A observations from the covert-channel engine. Live queries only; no fabricated rows.';

ALTER TABLE c2_covert_channel_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE c2_covert_channel_audits FORCE ROW LEVEL SECURITY;
ALTER TABLE dns_covert_query_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_covert_query_audits FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS c2_covert_audits_tenant ON c2_covert_channel_audits;
CREATE POLICY c2_covert_audits_tenant ON c2_covert_channel_audits
    USING (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = public.app_current_tenant_id()
    )
    WITH CHECK (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = public.app_current_tenant_id()
    );

DROP POLICY IF EXISTS dns_covert_audits_tenant ON dns_covert_query_audits;
CREATE POLICY dns_covert_audits_tenant ON dns_covert_query_audits
    USING (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = public.app_current_tenant_id()
    )
    WITH CHECK (
        NULLIF(current_setting('app.current_tenant_id', true), '') IS NULL
        OR tenant_id = public.app_current_tenant_id()
    );

GRANT SELECT, INSERT ON c2_covert_channel_audits TO weissman_app;
GRANT SELECT, INSERT ON dns_covert_query_audits TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE c2_covert_channel_audits_id_seq TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE dns_covert_query_audits_id_seq TO weissman_app;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON c2_covert_channel_audits TO weissman_ro;
        GRANT SELECT ON dns_covert_query_audits TO weissman_ro;
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relname = 'c2_covert_channel_audits'
           AND c.relrowsecurity
           AND c.relforcerowsecurity
    ) THEN
        RAISE EXCEPTION 'c2_covert_channel_audits RLS was not applied';
    END IF;
END $$;
