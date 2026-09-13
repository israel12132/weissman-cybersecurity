import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'AuditLog.jsx'),
  'utf8',
)

describe('AuditLog live-only truth', () => {
  it('does not paint audit KPI zeros when GET /api/audit-logs fails', () => {
    expect(src).toMatch(/data-testid="audit-log-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/loading \|\| error \? '—'/)
  })
})
