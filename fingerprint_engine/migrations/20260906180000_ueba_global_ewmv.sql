-- EWMV columns on the dedicated rolling-7d table so live ingest can persist
-- global baselines without writing hour_of_week = -1 (CHECK 0..167 on
-- agent_metric_baselines, see 20260905172000). Welcome compact snapshots
-- read this table.

ALTER TABLE agent_metric_baselines_global
    ADD COLUMN IF NOT EXISTS mad DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines_global
    ADD COLUMN IF NOT EXISTS welford_m2 DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines_global
    ADD COLUMN IF NOT EXISTS stability_index DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines_global
    ADD COLUMN IF NOT EXISTS ewmv_w DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE agent_metric_baselines_global
    ADD COLUMN IF NOT EXISTS ewmv_v2 DOUBLE PRECISION NOT NULL DEFAULT 0;

UPDATE agent_metric_baselines_global
   SET ewmv_w = n::double precision,
       ewmv_v2 = n::double precision
 WHERE ewmv_w = 0 AND n > 0;
