-- Auto-heal durable specs + verification step log (worker-isolated; replaces API-process RAM/DashMap).

CREATE TABLE auto_heal_job_specs (
    id UUID PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    client_id BIGINT NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    vuln_id BIGINT NOT NULL,
    finding_id TEXT NOT NULL,
    git_token TEXT NOT NULL,
    repo_slug TEXT NOT NULL,
    base_branch TEXT NOT NULL,
    patch_text TEXT NOT NULL,
    poc_curl TEXT NOT NULL,
    docker_socket TEXT NOT NULL DEFAULT '/var/run/docker.sock',
    image TEXT NOT NULL DEFAULT 'node:20-bookworm',
    container_port INT NOT NULL DEFAULT 3000,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_auto_heal_job_specs_tenant ON auto_heal_job_specs (tenant_id);
CREATE INDEX ix_auto_heal_job_specs_created ON auto_heal_job_specs (created_at DESC);

CREATE TABLE heal_verification_steps (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    job_id UUID NOT NULL,
    step_index INT NOT NULL,
    step_label TEXT NOT NULL,
    detail TEXT,
    step_ts BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, job_id, step_index)
);

CREATE INDEX ix_heal_verification_steps_lookup ON heal_verification_steps (tenant_id, job_id, step_index);

ALTER TABLE auto_heal_job_specs ENABLE ROW LEVEL SECURITY;
ALTER TABLE auto_heal_job_specs FORCE ROW LEVEL SECURITY;
CREATE POLICY auto_heal_job_specs_tenant ON auto_heal_job_specs FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

ALTER TABLE heal_verification_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE heal_verification_steps FORCE ROW LEVEL SECURITY;
CREATE POLICY heal_verification_steps_tenant ON heal_verification_steps FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

COMMENT ON TABLE auto_heal_job_specs IS 'Queued auto-heal parameters; processed only by weissman-worker (git_token cleared after run).';
COMMENT ON TABLE heal_verification_steps IS 'Per-step 200% verification log for GET /api/heal-verify/:job_id/steps.';

GRANT SELECT, INSERT, UPDATE, DELETE ON auto_heal_job_specs TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON heal_verification_steps TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE heal_verification_steps_id_seq TO weissman_app;
