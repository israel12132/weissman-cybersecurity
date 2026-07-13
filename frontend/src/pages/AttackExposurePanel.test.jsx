import { describe, it, expect } from 'vitest'
import { techniqueCsvRows, maxTacticCount, EXPOSURE_CSV_HEADER } from './AttackExposurePanel.jsx'

describe('AttackExposurePanel helpers', () => {
  describe('techniqueCsvRows', () => {
    it('flattens a technique stat aligned with the header', () => {
      const rows = techniqueCsvRows([
        {
          technique: 'T1190',
          name: 'Exploit Public-Facing Application',
          tactic: 'Initial Access',
          count: 5,
          critical: 2,
          high: 2,
          medium: 1,
          low: 0,
          info: 0,
          other: 0,
        },
      ])
      expect(rows).toHaveLength(1)
      expect(rows[0]).toHaveLength(EXPOSURE_CSV_HEADER.length)
      expect(rows[0][0]).toBe('T1190')
      expect(rows[0][2]).toBe('Initial Access')
      expect(rows[0][3]).toBe(5)
    })

    it('is robust to missing fields and non-array input', () => {
      expect(techniqueCsvRows(null)).toEqual([])
      expect(techniqueCsvRows(undefined)).toEqual([])
      const rows = techniqueCsvRows([{}])
      expect(rows[0]).toHaveLength(EXPOSURE_CSV_HEADER.length)
      expect(rows[0][1]).toBe('') // name defaults to empty
      expect(rows[0][3]).toBe(0) // count defaults to 0
    })
  })

  describe('maxTacticCount', () => {
    it('returns the largest finding_count', () => {
      expect(maxTacticCount([{ finding_count: 3 }, { finding_count: 8 }, { finding_count: 1 }])).toBe(8)
    })

    it('never returns below 1 (safe bar denominator)', () => {
      expect(maxTacticCount([])).toBe(1)
      expect(maxTacticCount(null)).toBe(1)
      expect(maxTacticCount([{ finding_count: 0 }])).toBe(1)
    })
  })
})
