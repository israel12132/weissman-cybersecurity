-- HFV closed-cycle flag: VERIFIED_FIXED freezes native watermark for SLA/FAIR
-- history aggregations instead of NULL (which dropped closed findings from
-- yearly MAX/COUNT). A later REOPENED row clears the flag so the next lifecycle
-- starts at live severity without inheriting the previous peak.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS is_cycle_closed BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN vulnerabilities.is_cycle_closed IS
    'True after a live-verified close. watermark_severity then holds native severity at close for SLA history; a regression (REOPENED) clears this and starts a new cycle.';

UPDATE vulnerabilities
   SET is_cycle_closed = TRUE,
       watermark_severity = COALESCE(NULLIF(watermark_severity, ''), severity)
 WHERE COALESCE(status, 'OPEN') = 'VERIFIED_FIXED';
