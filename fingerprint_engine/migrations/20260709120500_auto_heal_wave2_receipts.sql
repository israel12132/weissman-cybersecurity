-- ─── Auto-Heal Wave 2: self-repair attempts + signed verification receipts ────────
--
-- The healer now iterates (self-repair loop) and signs a tamper-evident receipt over the
-- verified proof. Record how many attempts a heal took and the receipt/digest so the fix is
-- provably verified. Additive + idempotent; inherits the existing RLS/grants on heal_requests.

ALTER TABLE heal_requests ADD COLUMN IF NOT EXISTS attempts             INTEGER NOT NULL DEFAULT 1;
ALTER TABLE heal_requests ADD COLUMN IF NOT EXISTS verification_receipt TEXT;
ALTER TABLE heal_requests ADD COLUMN IF NOT EXISTS verification_digest  TEXT;
