import { describe, it, expect } from 'vitest'
import { catalogSearchRows, domainRows, scoreFromFindings } from './StealthyPersistenceEvasion'

describe('StealthyPersistenceEvasion helpers', () => {
  it('extracts composite score from summary finding', () => {
    expect(scoreFromFindings([])).toBeNull()
    expect(scoreFromFindings([
      { title: 'Intelligence-grade evasion score: 82/100 (3 gaps / 500 checks)', evidence: { intelligence_grade_evasion_score: 82 } },
    ])).toBe(82)
  })

  it('filters domain scorecards', () => {
    const rows = domainRows([
      { title: 'Domain 1: PEB/TEB — score 90/100' },
      { title: 'Intelligence-grade evasion score: 82/100' },
      { title: 'Domain 7: WSS — score 70/100' },
    ])
    expect(rows).toHaveLength(2)
  })

  it('searches the 500-check catalog', () => {
    const checks = [
      { id: 1, title: 'Low-level GS/FS TEB access', mitre: 'T1083', domain: 1 },
      { id: 51, title: 'HalosGate neighbor SSN recovery', mitre: 'T1106', domain: 2 },
    ]
    expect(catalogSearchRows(checks, 'halos')).toHaveLength(1)
    expect(catalogSearchRows(checks, '')).toHaveLength(2)
    expect(catalogSearchRows(null, 'x')).toHaveLength(0)
  })
})
