-- EWMV state for weighted Bessel variance (West 1979 / Finch).
-- welford_m2 stores S_t (weighted sum of squared deviations).
-- ewmv_w = W_t (accumulated weight). ewmv_v2 = V₂ = Σ wᵢ² after decay.
-- Naive "multiply σ by λ" collapses σ → 0 and storms the detector.

ALTER TABLE agent_metric_baselines
    ADD COLUMN IF NOT EXISTS ewmv_w DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines
    ADD COLUMN IF NOT EXISTS ewmv_v2 DOUBLE PRECISION NOT NULL DEFAULT 0;

-- Pre-EWMV rows used classical unit weights: W = n, V₂ = n, S = welford_m2.
UPDATE agent_metric_baselines
   SET ewmv_w = n::double precision,
       ewmv_v2 = n::double precision
 WHERE ewmv_w = 0 AND n > 0;
