import { describe, it, expect } from 'vitest'
import { filterEngines, filterGaps, spineCsvRows, SPINE_CSV_HEADER } from './scanFindingSpine'

const sample = {
  gaps: [{ id: 'unverified_critical', severity: 'critical', count: 2, detail: '2 open critical/high' }],
  engines: [
    { source: 'asm', reality_kind: 'real_probe', findings: 4, evidence: 3, proven: 1, unverified_critical: 1 },
    { source: 'wifi_attack_engine', reality_kind: 'agent_required', findings: 1, evidence: 0, proven: 0, unverified_critical: 0 },
  ],
  scans: [{ id: 'job-1', kind: 'tenant_full_scan', status: 'completed', target: 'example.com' }],
}

describe('scanFindingSpine', () => {
  it('exports a stable CSV header', () => {
    expect(SPINE_CSV_HEADER[0]).toBe('row_kind')
    expect(SPINE_CSV_HEADER.length).toBe(8)
  })

  it('flattens gaps, engines, and scans into CSV rows', () => {
    const rows = spineCsvRows(sample)
    expect(rows.some((r) => r[0] === 'gap' && r[1] === 'unverified_critical')).toBe(true)
    expect(rows.some((r) => r[0] === 'engine' && r[1] === 'asm')).toBe(true)
    expect(rows.some((r) => r[0] === 'scan' && r[1] === 'job-1')).toBe(true)
  })

  it('filters engines by source or reality kind', () => {
    expect(filterEngines(sample.engines, 'asm')).toHaveLength(1)
    expect(filterEngines(sample.engines, 'agent_required')).toHaveLength(1)
    expect(filterEngines(sample.engines, '')).toHaveLength(2)
  })

  it('filters gaps by detail text', () => {
    expect(filterGaps(sample.gaps, 'critical')).toHaveLength(1)
    expect(filterGaps(sample.gaps, 'ot-ics')).toHaveLength(0)
  })
})
