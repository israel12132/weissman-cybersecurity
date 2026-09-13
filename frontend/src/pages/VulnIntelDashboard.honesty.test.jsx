import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'VulnIntelDashboard.jsx'),
  'utf8',
)

describe('VulnIntelDashboard live-only truth', () => {
  it('does not paint severity KPI zeros when GET /api/findings fails', () => {
    expect(src).toMatch(/data-testid="vuln-intel-unavailable"/)
    expect(src).toMatch(/loading \|\| error \? '—'/)
    expect(src).toMatch(/!error && \(/)
  })
})
