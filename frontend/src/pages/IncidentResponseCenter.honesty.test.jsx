import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IncidentResponseCenter.jsx'),
  'utf8',
)

describe('IncidentResponseCenter live-only truth', () => {
  it('does not paint IR MetricCard zeros when GET /api/soc/incidents fails', () => {
    expect(src).toMatch(/data-testid="incident-response-unavailable"/)
    expect(src).toMatch(/unavailable_title/)
    expect(src).toMatch(/!Array\.isArray\(data\?\.incidents\)/)
    expect(src).toMatch(/error \? \(/)
  })

  it('does not paint leftover leftover-incident counts after a failed incidents GET', () => {
    expect(src).toMatch(/count: error \? '—' : incidents\.length/)
    expect(src).toMatch(/if \(error\) return; exportIncidentsCsv\(incidents\)/)
    expect(src).toMatch(/exportDisabled=\{\!\!error \|\| !filteredFindings\.length\}/)
  })
})
