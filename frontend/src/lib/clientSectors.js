/**
 * Client industry/sector classification.
 *
 * Mirrors `CLIENT_SECTORS` in
 * `backend/weissman-core/src/models/client_sector.rs`. The API rejects any value
 * outside this list with `code: "invalid_sector"`, so the two must stay in sync —
 * `clientSectors.parity.test.js` fails the build on drift.
 */
export const CLIENT_SECTORS = [
  'government',
  'energy',
  'healthcare',
  'finance',
  'technology',
  'manufacturing',
  'retail',
  'education',
  'defense',
  'telecom',
  'other',
]

/** Stored representation of "unclassified" — matches the column's `DEFAULT ''`. */
export const CLIENT_SECTOR_UNCLASSIFIED = ''
