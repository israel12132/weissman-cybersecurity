-- Add sector/industry classification to clients.
-- This allows the platform to categorise clients (government, energy, healthcare,
-- finance, technology, manufacturing, retail, education, defense, telecom, other)
-- so that sector-specific compliance frameworks (IEC 62443 for energy,
-- HIPAA for healthcare, FedRAMP/NIST for government, PCI for finance, etc.)
-- can be surfaced automatically in the UI and in generated reports.

ALTER TABLE clients
    ADD COLUMN IF NOT EXISTS sector TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN clients.sector IS
    'Industry/sector classification: government, energy, healthcare, finance, technology, manufacturing, retail, education, defense, telecom, other, or empty string for unclassified.';
