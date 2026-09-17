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

  it('does not dump leftover leftover-audit CSV after a failed top-tier audit GET', () => {
    expect(src).toMatch(/function exportAuditCsv\(\) \{\n {4}if \(auditUnavailable\) return/)
    expect(src).toMatch(/exportDisabled=\{loading \|\| auditUnavailable \|\| !audit\?\.engines\?\.length\}/)
  })

  it('mutes leftover leftover-GET Export CSV after a failed top-tier audit GET', () => {
    expect(src).toMatch(/apiFetch\('\/api\/engines\/top-tier\/audit'\)/)
    expect(src).toMatch(/onExport=\{auditUnavailable \? undefined : exportAuditCsv\}/)
    expect(src).toMatch(/onRefresh=\{reloadAudit\}/)
    expect(src).toMatch(/setAuditUnavailable\(true\)/)
    expect(src).toMatch(/method: 'POST'/)
    expect(src).not.toMatch(/probe_failed[\s\S]{0,200}setAuditUnavailable/)
  })
})
