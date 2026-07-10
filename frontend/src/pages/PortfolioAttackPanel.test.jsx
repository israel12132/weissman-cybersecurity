import { describe, it, expect } from 'vitest'
import { maxFindingCount } from './PortfolioAttackPanel.jsx'

describe('PortfolioAttackPanel helpers', () => {
  describe('maxFindingCount', () => {
    it('returns the largest fleet finding_count', () => {
      expect(maxFindingCount([{ finding_count: 4 }, { finding_count: 17 }, { finding_count: 2 }])).toBe(17)
    })

    it('never returns below 1 (safe bar denominator)', () => {
      expect(maxFindingCount([])).toBe(1)
      expect(maxFindingCount(null)).toBe(1)
      expect(maxFindingCount([{ finding_count: 0 }])).toBe(1)
    })
  })
})
