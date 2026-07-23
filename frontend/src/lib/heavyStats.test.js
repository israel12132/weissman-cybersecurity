import { describe, it, expect } from 'vitest'
import { percentile, countBy, computeRiskSummary, STATS_TASKS } from './heavyStats.js'

describe('heavyStats', () => {
  it('computes nearest-rank percentile', () => {
    expect(percentile([1, 2, 3, 4, 5], 100)).toBe(5)
    expect(percentile([1, 2, 3, 4, 5], 50)).toBe(3)
    expect(percentile([], 50)).toBe(0)
  })

  it('counts by a key', () => {
    expect(countBy([{ s: 'a' }, { s: 'a' }, { s: 'b' }], 's')).toEqual({ a: 2, b: 1 })
  })

  it('summarizes a finding set into a risk score', () => {
    const findings = [
      { severity: 'critical', status: 'open' },
      { severity: 'low', status: 'resolved' },
      { severity: 'high', status: 'open' },
    ]
    const s = computeRiskSummary(findings)
    expect(s.total).toBe(3)
    expect(s.bySeverity).toEqual({ critical: 1, low: 1, high: 1 })
    expect(s.riskScore).toBeGreaterThan(0)
    expect(s.riskScore).toBeLessThanOrEqual(100)
    expect(s.openRatio).toBeCloseTo(0.67, 1)
  })

  it('handles an empty set without dividing by zero', () => {
    const s = computeRiskSummary([])
    expect(s.total).toBe(0)
    expect(s.riskScore).toBe(0)
    expect(s.openRatio).toBe(0)
  })

  it('exposes a task dispatch table', () => {
    expect(STATS_TASKS.percentile({ values: [10, 20], p: 100 })).toBe(20)
    expect(typeof STATS_TASKS.computeRiskSummary).toBe('function')
  })
})
