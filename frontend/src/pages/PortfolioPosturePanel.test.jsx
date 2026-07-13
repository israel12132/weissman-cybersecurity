import { describe, it, expect } from 'vitest'
import { gradeTotal, gradeColor } from './PortfolioPosturePanel.jsx'

describe('PortfolioPosturePanel helpers', () => {
  describe('gradeTotal', () => {
    it('sums the A–F distribution', () => {
      expect(gradeTotal({ A: 2, B: 1, C: 0, D: 3, F: 4 })).toBe(10)
    })

    it('never returns below 1 and tolerates junk', () => {
      expect(gradeTotal({})).toBe(1)
      expect(gradeTotal(null)).toBe(1)
      expect(gradeTotal({ A: 0, F: 0 })).toBe(1)
    })
  })

  describe('gradeColor', () => {
    it('maps each grade to a distinct colour, case-insensitively', () => {
      const colors = ['A', 'B', 'C', 'D', 'F'].map(gradeColor)
      expect(new Set(colors).size).toBe(5)
      expect(gradeColor('f')).toBe(gradeColor('F'))
    })

    it('falls back to neutral for unknown grades', () => {
      expect(gradeColor('Z')).toBe('#94a3b8')
      expect(gradeColor(null)).toBe('#94a3b8')
    })
  })
})
