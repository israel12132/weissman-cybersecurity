-- Persist FP/TP confidence multiplier and effective risk at insert time (not only on read).

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS confidence_multiplier DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS effective_risk DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS ix_vuln_effective_risk
    ON vulnerabilities (tenant_id, effective_risk DESC NULLS LAST);

COMMENT ON COLUMN vulnerabilities.confidence_multiplier IS
    'FP/TP Bayesian shrinkage multiplier in [0.1, 1.0] from engine_confidence_adjustments.';
COMMENT ON COLUMN vulnerabilities.effective_risk IS
    'base_risk * confidence_multiplier (clamped 0..10), written at persist time.';
