-- Discovery Lab v1: AI-assisted novel vulnerability discovery on authorized
-- tenant assets, plus a responsible-disclosure pack lifecycle.
-- Candidates are stored distinctly from ordinary `vulnerabilities` inbox rows.

CREATE TABLE IF NOT EXISTS discovery_lab_runs (
    id              TEXT PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    job_id          UUID,
    target_url      TEXT NOT NULL,
    target_host     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued',
    intensity        TEXT NOT NULL DEFAULT 'normal',
    llm_used        BOOLEAN NOT NULL DEFAULT false,
    probes_sent     INTEGER NOT NULL DEFAULT 0,
    anomalies_seen  INTEGER NOT NULL DEFAULT 0,
    candidates_count INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_by_user_id BIGINT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT discovery_lab_runs_status_chk CHECK (
        status IN ('queued', 'running', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT discovery_lab_runs_intensity_chk CHECK (
        intensity IN ('light', 'normal', 'aggressive')
    ),
    CONSTRAINT discovery_lab_runs_target_len CHECK (
        char_length(target_url) BETWEEN 1 AND 2048
    )
);

CREATE INDEX IF NOT EXISTS ix_discovery_lab_runs_tenant_created
    ON discovery_lab_runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_discovery_lab_runs_tenant_client
    ON discovery_lab_runs (tenant_id, client_id, created_at DESC);

COMMENT ON TABLE discovery_lab_runs IS
    'Authorized-tenant Discovery Lab runs. Never used for arbitrary internet scanning.';

CREATE TABLE IF NOT EXISTS discovery_lab_candidates (
    id                  TEXT PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    run_id              TEXT NOT NULL REFERENCES discovery_lab_runs(id) ON DELETE CASCADE,
    status              TEXT NOT NULL DEFAULT 'candidate',
    title               TEXT NOT NULL,
    technical_summary  TEXT NOT NULL DEFAULT '',
    impact              TEXT NOT NULL DEFAULT '',
    recommended_fix    TEXT NOT NULL DEFAULT '',
    anomaly_type       TEXT NOT NULL DEFAULT '',
    payload_class       TEXT NOT NULL DEFAULT '',
    signature_hash     TEXT NOT NULL,
    novelty_score      DOUBLE PRECISION NOT NULL DEFAULT 0,
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0,
    kev_listed          BOOLEAN NOT NULL DEFAULT false,
    epss_score          DOUBLE PRECISION,
    cve_id              TEXT,
    fp_routed           BOOLEAN NOT NULL DEFAULT false,
    llm_hypothesis      BOOLEAN NOT NULL DEFAULT false,
    oob_confirmed       BOOLEAN NOT NULL DEFAULT false,
    target_url          TEXT NOT NULL DEFAULT '',
    evidence            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT discovery_lab_candidates_status_chk CHECK (
        status IN (
            'candidate',
            'validated',
            'suppressed',
            'customer_remediation',
            'disclosure_ready',
            'disclosed'
        )
    ),
    CONSTRAINT discovery_lab_candidates_scores_chk CHECK (
        novelty_score BETWEEN 0 AND 1 AND confidence BETWEEN 0 AND 1
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_discovery_lab_candidates_run_sig
    ON discovery_lab_candidates (tenant_id, run_id, signature_hash);
CREATE INDEX IF NOT EXISTS ix_discovery_lab_candidates_tenant_status
    ON discovery_lab_candidates (tenant_id, status, novelty_score DESC);
CREATE INDEX IF NOT EXISTS ix_discovery_lab_candidates_client
    ON discovery_lab_candidates (tenant_id, client_id, created_at DESC);

COMMENT ON TABLE discovery_lab_candidates IS
    'Novel-vuln candidates with their own lifecycle, distinct from vulnerabilities inbox.';

CREATE TABLE IF NOT EXISTS discovery_disclosure_packs (
    id                      TEXT PRIMARY KEY,
    tenant_id               BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id               BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    candidate_id            TEXT NOT NULL REFERENCES discovery_lab_candidates(id) ON DELETE CASCADE,
    status                  TEXT NOT NULL DEFAULT 'draft',
    title                   TEXT NOT NULL,
    technical_summary      TEXT NOT NULL DEFAULT '',
    impact                  TEXT NOT NULL DEFAULT '',
    reproduction            TEXT NOT NULL DEFAULT '',
    recommended_fix        TEXT NOT NULL DEFAULT '',
    timeline                TEXT NOT NULL DEFAULT '',
    recipient               TEXT NOT NULL DEFAULT '',
    recipient_kind          TEXT NOT NULL DEFAULT 'national_cert',
    redact_payloads         BOOLEAN NOT NULL DEFAULT true,
    redact_internal_hosts   BOOLEAN NOT NULL DEFAULT true,
    redact_customer_ids     BOOLEAN NOT NULL DEFAULT true,
    created_by_user_id     BIGINT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT discovery_disclosure_packs_status_chk CHECK (
        status IN ('draft', 'ready', 'submitted', 'disclosed', 'withdrawn')
    ),
    CONSTRAINT discovery_disclosure_packs_recipient_kind_chk CHECK (
        recipient_kind IN (
            'national_cert',
            'government_cyber',
            'vendor',
            'coordinator',
            'other'
        )
    )
);

CREATE INDEX IF NOT EXISTS ix_discovery_disclosure_packs_tenant
    ON discovery_disclosure_packs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_discovery_disclosure_packs_candidate
    ON discovery_disclosure_packs (tenant_id, candidate_id);

COMMENT ON TABLE discovery_disclosure_packs IS
    'Responsible-disclosure drafts for previously-unknown findings (authorized scope only).';

CREATE TABLE IF NOT EXISTS discovery_disclosure_events (
    id              TEXT PRIMARY KEY,
    tenant_id       BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id       BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    pack_id         TEXT NOT NULL REFERENCES discovery_disclosure_packs(id) ON DELETE CASCADE,
    actor_user_id   BIGINT,
    from_status     TEXT,
    to_status       TEXT NOT NULL,
    action          TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_discovery_disclosure_events_pack
    ON discovery_disclosure_events (tenant_id, pack_id, occurred_at);

COMMENT ON TABLE discovery_disclosure_events IS
    'Append-only audit of disclosure pack state changes.';

-- RLS: tenant + client portal isolation
ALTER TABLE discovery_lab_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_lab_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_lab_runs_tenant ON discovery_lab_runs;
CREATE POLICY discovery_lab_runs_tenant ON discovery_lab_runs
    FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

ALTER TABLE discovery_lab_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_lab_candidates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_lab_candidates_tenant ON discovery_lab_candidates;
CREATE POLICY discovery_lab_candidates_tenant ON discovery_lab_candidates
    FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

ALTER TABLE discovery_disclosure_packs ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_disclosure_packs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_disclosure_packs_tenant ON discovery_disclosure_packs;
CREATE POLICY discovery_disclosure_packs_tenant ON discovery_disclosure_packs
    FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

ALTER TABLE discovery_disclosure_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_disclosure_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS discovery_disclosure_events_tenant ON discovery_disclosure_events;
CREATE POLICY discovery_disclosure_events_tenant ON discovery_disclosure_events
    FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_lab_runs TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_lab_candidates TO weissman_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_disclosure_packs TO weissman_app;
GRANT SELECT, INSERT ON discovery_disclosure_events TO weissman_app;
REVOKE UPDATE, DELETE ON discovery_disclosure_events FROM weissman_app;
REVOKE UPDATE, DELETE ON discovery_disclosure_events FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_ro') THEN
        GRANT SELECT ON discovery_lab_runs TO weissman_ro;
        GRANT SELECT ON discovery_lab_candidates TO weissman_ro;
        GRANT SELECT ON discovery_disclosure_packs TO weissman_ro;
        GRANT SELECT ON discovery_disclosure_events TO weissman_ro;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION discovery_disclosure_events_reject_mutate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'discovery_disclosure_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS discovery_disclosure_events_block_update ON discovery_disclosure_events;
CREATE TRIGGER discovery_disclosure_events_block_update
    BEFORE UPDATE ON discovery_disclosure_events
    FOR EACH ROW
    EXECUTE PROCEDURE discovery_disclosure_events_reject_mutate();

DROP TRIGGER IF EXISTS discovery_disclosure_events_block_delete ON discovery_disclosure_events;
CREATE TRIGGER discovery_disclosure_events_block_delete
    BEFORE DELETE ON discovery_disclosure_events
    FOR EACH ROW
    EXECUTE PROCEDURE discovery_disclosure_events_reject_mutate();
