-- ─── SOAR Playbook engine ─────────────────────────────────────────────────────
--
-- Stores tenant-defined automation rules: `when { ... } do [ ... ]`.
-- The trigger DSL and action DSL are JSONB so the cockpit's PlaybookBuilder.jsx
-- can read/write them without serialisation surprises.
--
-- A playbook runs once per matching event (idempotency via run_dedup_key).
-- Every dispatch produces a row in `weissman_playbook_runs` so the analyst can
-- inspect "why did playbook X fire 4 times last hour, and what actions did it take?".

CREATE TABLE IF NOT EXISTS weissman_playbooks (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL,
    description         TEXT        NOT NULL DEFAULT '',
    enabled             BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Trigger conditions — see `soar_playbook::PlaybookTrigger`.
    -- Shape (all keys optional; AND-combined):
    --   {
    --     "severity":   ["critical","high"],   // OR-combined list
    --     "kev":        true,                  // require kev_listed
    --     "epss_min":   0.5,                   // require epss_score >= 0.5
    --     "exposed":    true,                  // require internet_exposed asset
    --     "engines":    ["asm","leak_hunter"], // OR-combined list
    --     "tags":       ["pci","prod"],        // any tag in client config
    --     "cooldown_seconds": 3600             // dedupe window per signature
    --   }
    trigger_dsl         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Actions — ordered list, executed sequentially with per-action retry/timeout.
    -- Each item: { "kind": "open_pr|slack_notify|...", "params": { ... } }
    actions_dsl         JSONB       NOT NULL DEFAULT '[]'::jsonb,
    -- Audit + ops counters.
    last_run_at         TIMESTAMPTZ,
    last_run_status     TEXT        NOT NULL DEFAULT '',
    run_count           INTEGER     NOT NULL DEFAULT 0,
    failure_count       INTEGER     NOT NULL DEFAULT 0,
    created_by_user_id  BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_playbooks_name
    ON weissman_playbooks (tenant_id, lower(name));
CREATE INDEX IF NOT EXISTS ix_playbooks_enabled
    ON weissman_playbooks (tenant_id) WHERE enabled = TRUE;

ALTER TABLE weissman_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_playbooks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_playbooks_tenant ON weissman_playbooks;
CREATE POLICY weissman_playbooks_tenant ON weissman_playbooks
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON weissman_playbooks TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_playbooks_id_seq TO weissman_app;

-- ─── Run history (immutable audit) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weissman_playbook_runs (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id         BIGINT      NOT NULL REFERENCES weissman_playbooks(id) ON DELETE CASCADE,
    triggered_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The trigger event we matched on. Could be finding insert, cluster status
    -- change, attack-path computed, etc.
    trigger_kind        TEXT        NOT NULL,                -- e.g. "finding_persisted"
    trigger_event       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    -- Stable dedupe key — same (playbook, signature) won't re-fire in cooldown.
    run_dedup_key       TEXT        NOT NULL DEFAULT '',
    -- One row per ACTION dispatched. Aggregate at read time.
    actions_total       INTEGER     NOT NULL DEFAULT 0,
    actions_succeeded   INTEGER     NOT NULL DEFAULT 0,
    actions_failed      INTEGER     NOT NULL DEFAULT 0,
    action_results      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    status              TEXT        NOT NULL DEFAULT 'success' -- success|partial|failed|dry_run
);

CREATE INDEX IF NOT EXISTS ix_playbook_runs_pb
    ON weissman_playbook_runs (playbook_id, triggered_at DESC);
CREATE INDEX IF NOT EXISTS ix_playbook_runs_dedup
    ON weissman_playbook_runs (tenant_id, playbook_id, run_dedup_key, triggered_at DESC);

ALTER TABLE weissman_playbook_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE weissman_playbook_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_playbook_runs_tenant ON weissman_playbook_runs;
CREATE POLICY weissman_playbook_runs_tenant ON weissman_playbook_runs
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT ON weissman_playbook_runs TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE weissman_playbook_runs_id_seq TO weissman_app;
