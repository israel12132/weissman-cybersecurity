-- Architect pre-merge: HFV watermark_severity + Ask Weissman SHA-256 audit chain.
--
-- watermark_severity is the high-water finding value (worst severity ever seen
-- while the finding is open). A verified close (VERIFIED_FIXED) MUST NULL it so
-- a later regression starts a clean lifecycle at the actual new threat level.
--
-- nl_query_audit gains prev_hash/event_hash so the MPSC worker can append a
-- per-tenant SHA-256 chain under advisory_xact_lock_text without blocking HTTP.

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS watermark_severity TEXT;

COMMENT ON COLUMN vulnerabilities.watermark_severity IS
    'HFV: peak severity while the finding is open. NULL after VERIFIED_FIXED so a regression is scored from a clean watermark.';

UPDATE vulnerabilities
   SET watermark_severity = severity
 WHERE watermark_severity IS NULL
   AND COALESCE(status, 'OPEN') NOT IN ('VERIFIED_FIXED');

ALTER TABLE nl_query_audit
    ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS event_hash TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN nl_query_audit.prev_hash IS
    'SHA-256 hex of the previous nl_query_audit row for this tenant (empty = genesis).';
COMMENT ON COLUMN nl_query_audit.event_hash IS
    'SHA-256 hex of canonical v1 nl-audit payload (prev_hash || tenant || user || question || sql || error || asked_at).';

CREATE INDEX IF NOT EXISTS ix_nlqa_tenant_id_desc
    ON nl_query_audit (tenant_id, id DESC);
