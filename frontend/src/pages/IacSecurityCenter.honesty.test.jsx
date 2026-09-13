import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'IacSecurityCenter.jsx'),
  'utf8',
)

describe('IacSecurityCenter live-only truth', () => {
  it('does not paint a green risk-0 gauge when GET /api/engines/history fails', () => {
    expect(src).toMatch(/data-testid="iac-security-history-unavailable"/)
    expect(src).toMatch(/history_unavailable/)
    expect(src).toMatch(/setHistoryUnavailable\(true\)/)
    expect(src).toMatch(/const hasScore = score != null/)
    expect(src).not.toMatch(/Math\.min\(100, Math\.max\(0, score \?\? 0\)\)/)
    expect(src).not.toMatch(/no fabricated history/)
  })

  it('does not paint unmeasured attack-paths when a live summary has zero chains', () => {
    expect(src).toMatch(/historyUnavailable \? '—' : \(summary \? attackChains\.length : '—'\)/)
    expect(src).not.toMatch(/attackChains\.length \|\| '—'/)
  })
})
