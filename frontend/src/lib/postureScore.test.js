import { describe, it, expect } from 'vitest'
import { summarizePostureChecks, orderPostureChecks } from './postureScore'

describe('summarizePostureChecks', () => {
  it('counts passes and sums weighted pass ratio', () => {
    const checks = [
      { passed: true, weight: 30 },
      { passed: false, weight: 20 },
      { passed: true, weight: 10 },
    ]
    expect(summarizePostureChecks(checks)).toEqual({
      passed: 2,
      total: 3,
      passedWeight: 40,
      totalWeight: 60,
    })
  })

  it('treats missing/non-numeric weights as 0 and truthy passed only', () => {
    const checks = [
      { passed: true }, // no weight
      { passed: true, weight: 'oops' }, // NaN → 0
      { passed: false, weight: 15 },
    ]
    expect(summarizePostureChecks(checks)).toEqual({
      passed: 2,
      total: 3,
      passedWeight: 0,
      totalWeight: 15,
    })
  })

  it('is safe on empty/invalid input', () => {
    expect(summarizePostureChecks([])).toEqual({ passed: 0, total: 0, passedWeight: 0, totalWeight: 0 })
    expect(summarizePostureChecks(null)).toEqual({ passed: 0, total: 0, passedWeight: 0, totalWeight: 0 })
    expect(summarizePostureChecks(undefined)).toEqual({ passed: 0, total: 0, passedWeight: 0, totalWeight: 0 })
  })
})

describe('orderPostureChecks', () => {
  it('orders failed-first, then by descending weight, without mutating input', () => {
    const checks = [
      { id: 'a', passed: true, weight: 50 },
      { id: 'b', passed: false, weight: 10 },
      { id: 'c', passed: false, weight: 40 },
      { id: 'd', passed: true, weight: 5 },
    ]
    const ordered = orderPostureChecks(checks)
    expect(ordered.map((c) => c.id)).toEqual(['c', 'b', 'a', 'd'])
    // input not mutated
    expect(checks.map((c) => c.id)).toEqual(['a', 'b', 'c', 'd'])
  })

  it('is safe on empty/invalid input', () => {
    expect(orderPostureChecks(null)).toEqual([])
    expect(orderPostureChecks(undefined)).toEqual([])
  })
})
