import { describe, it, expect } from 'vitest'
import { maxBucketTotal } from './BacklogAgingPanel.jsx'

describe('BacklogAgingPanel helpers', () => {
  describe('maxBucketTotal', () => {
    it('returns the largest bucket total', () => {
      expect(maxBucketTotal([{ total: 2 }, { total: 9 }, { total: 4 }])).toBe(9)
    })

    it('never returns below 1 (safe bar denominator)', () => {
      expect(maxBucketTotal([])).toBe(1)
      expect(maxBucketTotal(null)).toBe(1)
      expect(maxBucketTotal([{ total: 0 }, { total: 0 }])).toBe(1)
    })
  })
})
