-- ─── False-positive feedback loop ─────────────────────────────────────────────
--
-- When an analyst marks a finding FALSE_POSITIVE we:
--   1. increment `fp_count` on `engine_confidence_adjustments(engine, signature_hash)`
--      so we know that engine+signature combo has been wrong N times for this tenant
--   2. when fp_count >= 3, add an entry to `finding_suppressions` so future detections
--      of the same (engine, signature_hash, target) on this tenant are auto-marked
--      FALSE_POSITIVE on insert (no noise in the inbox)
--
-- When the analyst marks a finding FIXED or ACKNOWLEDGED, we increment `tp_count`
-- (the engine got it right) and decay any prior fp_count by 1 (an engine that
-- bounces between TP and FP should hover near 0, not climb forever).
--
-- The confidence multiplier is exposed via [confidence_multiplier()] and applied
-- to `risk_score` at read time so the UI can use the same numbers.

CREATE TABLE IF NOT EXISTS engine_confidence_adjustments (
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engine              TEXT        NOT NULL,
    signature_hash      TEXT        NOT NULL,           -- sha256(target | sig | cwe)
    tp_count            INTEGER     NOT NULL DEFAULT 0,
    fp_count            INTEGER     NOT NULL DEFAULT 0,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_label_at       TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, engine, signature_hash)
);

CREATE INDEX IF NOT EXISTS ix_eca_fp ON engine_confidence_adjustments(tenant_id, fp_count DESC);
CREATE INDEX IF NOT EXISTS ix_eca_seen ON engine_confidence_adjustments(last_seen_at DESC);

ALTER TABLE engine_confidence_adjustments ENABLE ROW LEVEL SECURITY;
ALTER TABLE engine_confidence_adjustments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS engine_confidence_adjustments_tenant ON engine_confidence_adjustments;
CREATE POLICY engine_confidence_adjustments_tenant ON engine_confidence_adjustments
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON engine_confidence_adjustments TO weissman_app;

-- ─── Auto-suppression list ────────────────────────────────────────────────────
-- When a (tenant, engine, signature_hash) accumulates >= 3 FPs, we add a row
-- here. New findings matching this row are silently labelled FALSE_POSITIVE at
-- persist time, removing them from the live inbox without losing the audit trail.

CREATE TABLE IF NOT EXISTS finding_suppressions (
    id                  BIGSERIAL   PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    engine              TEXT        NOT NULL,
    signature_hash      TEXT        NOT NULL,
    target_glob         TEXT,                              -- NULL = applies to any target
    reason              TEXT        NOT NULL DEFAULT 'auto:3_fp_marks',
    fp_count_at_create  INTEGER     NOT NULL DEFAULT 0,
    created_by_user_id  BIGINT,                            -- NULL = system auto
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ,                       -- NULL = no expiry
    last_hit_at         TIMESTAMPTZ,
    hit_count           INTEGER     NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_fs_unique
    ON finding_suppressions (tenant_id, engine, signature_hash, COALESCE(target_glob, ''));

CREATE INDEX IF NOT EXISTS ix_fs_tenant ON finding_suppressions(tenant_id);

ALTER TABLE finding_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_suppressions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_suppressions_tenant ON finding_suppressions;
CREATE POLICY finding_suppressions_tenant ON finding_suppressions
    FOR ALL
    USING       (tenant_id = current_setting('app.current_tenant_id', true)::bigint)
    WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::bigint);

GRANT SELECT, INSERT, UPDATE, DELETE ON finding_suppressions TO weissman_app;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE finding_suppressions_id_seq TO weissman_app;

-- ─── Add the signature_hash column on vulnerabilities for cheap joins ────────
-- (Without this we'd have to recompute the hash on every read.)
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS signature_hash TEXT;

CREATE INDEX IF NOT EXISTS ix_vuln_signature_hash
    ON vulnerabilities (tenant_id, source, signature_hash);

-- Note: existing rows have signature_hash = NULL; they will be back-filled on
-- their next persist (next scan re-fires the same finding and updates the row).
