import { describe, it, expect } from 'vitest'
import { maxBreached } from './SlaForecastStrip.jsx'

describe('SlaForecastStrip helpers', () => {
  describe('maxBreached', () => {
    it('returns the largest cumulative breach count', () => {
      expect(maxBreached([{ breached: 0 }, { breached: 3 }, { breached: 12 }])).toBe(12)
    })

    it('never returns below 1 (safe bar denominator)', () => {
      expect(maxBreached([])).toBe(1)
      expect(maxBreached(null)).toBe(1)
      expect(maxBreached([{ breached: 0 }])).toBe(1)
    })
  })
})
