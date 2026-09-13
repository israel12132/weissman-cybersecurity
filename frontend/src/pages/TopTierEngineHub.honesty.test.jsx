import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'TopTierEngineHub.jsx'),
  'utf8',
)

describe('TopTierEngineHub live-only truth', () => {
  it('does not paint an empty tenant picker when GET /api/clients fails', () => {
    expect(src).toMatch(/data-testid="top-tier-engine-hub-clients-unavailable"/)
    expect(src).toMatch(/clients_unavailable/)
    expect(src).toMatch(/setClientsUnavailable\(true\)/)
    expect(src).not.toMatch(/clients load failed — leave list unchanged/)
  })

  it('does not paint 0 connected when GET /api/engines/top-tier/audit fails', () => {
    expect(src).toMatch(/data-testid="top-tier-engine-hub-audit-unavailable"/)
    expect(src).toMatch(/audit_unavailable/)
    expect(src).toMatch(/setAuditUnavailable\(true\)/)
    expect(src).toMatch(/auditUnavailable\s*\?\s*t\('pages\.topTierEngineHub\.audit_unavailable'\)/)
  })
})
