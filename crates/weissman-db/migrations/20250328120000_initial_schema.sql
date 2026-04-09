-- Weissman Phase 2: PostgreSQL canonical schema (SQLite parity + strict multi-tenant keys)
-- All tenant-scoped tables: tenant_id BIGINT NOT NULL REFERENCES tenants(id)

CREATE TABLE tenants (
    id          BIGSERIAL PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    password_hash   TEXT,
    role            TEXT NOT NULL DEFAULT 'viewer',
    mfa_secret      TEXT NOT NULL DEFAULT '',
    mfa_enabled     BOOLEAN NOT NULL DEFAULT false,
    sso_provider    TEXT,
    sso_id          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX ix_users_tenant ON users(tenant_id);

CREATE TABLE clients (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    domains                 TEXT NOT NULL DEFAULT '[]',
    ip_ranges               TEXT NOT NULL DEFAULT '[]',
    tech_stack              TEXT NOT NULL DEFAULT '[]',
    auto_detect_tech_stack  BOOLEAN NOT NULL DEFAULT true,
    contact_email           TEXT NOT NULL DEFAULT '',
    client_configs          TEXT NOT NULL DEFAULT '{"enabled_engines":["osint","asm","supply_chain","leak_hunter","bola_idor","ollama_fuzz","semantic_ai_fuzz","microsecond_timing","ai_adversarial_redteam"],"roe_mode":"safe_proofs","stealth_level":50}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_clients_tenant ON clients(tenant_id);

CREATE TABLE report_runs (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    region          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    findings_json   TEXT NOT NULL DEFAULT '[]',
    summary         TEXT NOT NULL DEFAULT '{}',
    pdf_path        TEXT,
    audit_root_hash TEXT
);

CREATE INDEX ix_report_runs_tenant ON report_runs(tenant_id);
CREATE INDEX ix_report_runs_created ON report_runs(created_at);

CREATE TABLE vulnerabilities (
    id              BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    finding_id      TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'medium',
    source          TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'OPEN',
    proof           TEXT,
    poc_exploit     TEXT,
    generated_patch TEXT,
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_vuln_run ON vulnerabilities(run_id);
CREATE INDEX ix_vuln_client ON vulnerabilities(client_id);
CREATE INDEX ix_vuln_tenant ON vulnerabilities(tenant_id);
CREATE INDEX ix_vuln_status ON vulnerabilities(status);

-- Per-tenant configuration (replaces global-only system_configs for isolation)
CREATE TABLE system_configs (
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, key)
);

CREATE TABLE asm_graph_nodes (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id          BIGINT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    node_id         TEXT NOT NULL,
    label           TEXT NOT NULL,
    node_type       TEXT NOT NULL,
    status          TEXT NOT NULL,
    cname_target    TEXT,
    raw_finding     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_asm_nodes_run_client ON asm_graph_nodes(run_id, client_id);
CREATE INDEX ix_asm_nodes_tenant ON asm_graph_nodes(tenant_id);

CREATE TABLE asm_graph_edges (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id          BIGINT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    from_id         TEXT NOT NULL,
    to_id           TEXT NOT NULL,
    edge_type       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_asm_edges_tenant ON asm_graph_edges(tenant_id);

CREATE TABLE semantic_fuzz_log (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id   BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    run_id      BIGINT REFERENCES report_runs(id) ON DELETE SET NULL,
    log_text    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_semantic_fuzz_client ON semantic_fuzz_log(client_id);
CREATE INDEX ix_semantic_fuzz_tenant ON semantic_fuzz_log(tenant_id);

CREATE TABLE poe_jobs (
    job_id          TEXT PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    target          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running',
    findings_json   TEXT NOT NULL DEFAULT '[]',
    run_id          BIGINT REFERENCES report_runs(id) ON DELETE SET NULL,
    message         TEXT,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_poe_jobs_status ON poe_jobs(status);
CREATE INDEX ix_poe_jobs_tenant ON poe_jobs(tenant_id);

-- Platform-global threat intel payloads (no tenant isolation — shared intel)
CREATE TABLE dynamic_payloads (
    id              BIGSERIAL PRIMARY KEY,
    target_library  TEXT NOT NULL,
    payload_data    TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_url      TEXT NOT NULL DEFAULT '',
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_dynamic_payloads_library ON dynamic_payloads(target_library);
CREATE INDEX ix_dynamic_payloads_added ON dynamic_payloads(added_at);

CREATE TABLE ephemeral_payloads (
    id              BIGSERIAL PRIMARY KEY,
    target_library  TEXT NOT NULL,
    payload_data    TEXT NOT NULL,
    source          TEXT NOT NULL,
    first_used_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_ephemeral_library ON ephemeral_payloads(target_library);

CREATE TABLE attack_chain (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id          BIGINT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    step_order      INTEGER NOT NULL,
    step_label      TEXT NOT NULL,
    finding_ref     TEXT,
    payload_or_action TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_attack_chain_run_client ON attack_chain(run_id, client_id);
CREATE INDEX ix_attack_chain_tenant ON attack_chain(tenant_id);

CREATE TABLE identity_contexts (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    role_name           TEXT NOT NULL,
    privilege_order     INTEGER NOT NULL DEFAULT 0,
    token_type          TEXT NOT NULL DEFAULT 'bearer',
    token_value         TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_id, role_name)
);

CREATE INDEX ix_identity_contexts_client ON identity_contexts(client_id);

CREATE TABLE privilege_escalation_events (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id                  BIGINT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    client_id               BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    from_context            TEXT NOT NULL,
    to_context              TEXT NOT NULL,
    method                  TEXT NOT NULL,
    url                     TEXT NOT NULL,
    request_headers_body    TEXT,
    response_status         INTEGER,
    severity                TEXT NOT NULL DEFAULT 'critical',
    kill_chain_step_order   INTEGER NOT NULL DEFAULT 0,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_priv_esc_client_run ON privilege_escalation_events(client_id, run_id);
CREATE INDEX ix_priv_esc_tenant ON privilege_escalation_events(tenant_id);

CREATE TABLE risk_graph_nodes (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    node_type       TEXT NOT NULL,
    label           TEXT NOT NULL,
    external_id     TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE risk_graph_edges (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    from_node_id    BIGINT NOT NULL REFERENCES risk_graph_nodes(id) ON DELETE CASCADE,
    to_node_id      BIGINT NOT NULL REFERENCES risk_graph_nodes(id) ON DELETE CASCADE,
    edge_type       TEXT NOT NULL,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_risk_nodes_client ON risk_graph_nodes(client_id);
CREATE INDEX ix_risk_edges_client ON risk_graph_edges(client_id);

CREATE TABLE runtime_traces (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    run_id          BIGINT REFERENCES report_runs(id) ON DELETE SET NULL,
    finding_id      TEXT,
    trace_id        TEXT,
    source_file     TEXT,
    line_number     INTEGER,
    function_name   TEXT,
    payload_hash    TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_runtime_traces_client ON runtime_traces(client_id);
CREATE INDEX ix_runtime_traces_tenant ON runtime_traces(tenant_id);

CREATE TABLE heal_requests (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id               BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    finding_id              TEXT NOT NULL,
    vulnerability_id        BIGINT REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    branch_name             TEXT,
    pr_url                  TEXT,
    pr_number               INTEGER,
    diff_summary            TEXT,
    verification_status     TEXT NOT NULL DEFAULT 'pending',
    verification_payload    TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_heal_requests_client ON heal_requests(client_id);

CREATE TABLE deception_assets (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id               BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    asset_type              TEXT NOT NULL,
    token_value             TEXT NOT NULL,
    deployment_location     TEXT,
    status                  TEXT NOT NULL DEFAULT 'active',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE deception_triggers (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        BIGINT NOT NULL REFERENCES deception_assets(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    fingerprint     TEXT,
    request_meta    TEXT NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_deception_assets_client ON deception_assets(client_id);
CREATE INDEX ix_deception_triggers_asset ON deception_triggers(asset_id);

CREATE TABLE pipeline_run_state (
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    run_id          BIGINT NOT NULL REFERENCES report_runs(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    current_stage   INTEGER NOT NULL DEFAULT 0,
    paused          BOOLEAN NOT NULL DEFAULT false,
    skip_to_stage   INTEGER,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, run_id, client_id)
);

CREATE INDEX ix_pipeline_run_state_run ON pipeline_run_state(run_id);
CREATE INDEX ix_pipeline_run_state_tenant ON pipeline_run_state(tenant_id);

CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_label      TEXT NOT NULL DEFAULT '',
    action_type     TEXT NOT NULL,
    details         TEXT NOT NULL DEFAULT '',
    ip_address      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX ix_audit_logs_created ON audit_logs(created_at);
CREATE INDEX ix_audit_logs_tenant ON audit_logs(tenant_id);

-- OIDC / SAML IdP registry per tenant (multiple IdPs)
CREATE TABLE tenant_idps (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL CHECK (provider IN ('oidc', 'saml')),
    name                TEXT NOT NULL,
    issuer_url          TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    client_secret       TEXT,
    redirect_path       TEXT NOT NULL DEFAULT '/api/auth/oidc/callback',
    saml_idp_sso_url    TEXT,
    saml_idp_cert_pem   TEXT,
    email_claim         TEXT NOT NULL DEFAULT 'email',
    jwks_uri_override   TEXT,
    active              BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX ix_tenant_idps_tenant ON tenant_idps(tenant_id);
