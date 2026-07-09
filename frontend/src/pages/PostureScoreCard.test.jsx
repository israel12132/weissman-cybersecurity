import { describe, it, expect } from 'vitest'
import { gradeColor, scoreColor } from './PostureScoreCard.jsx'

describe('PostureScoreCard helpers', () => {
  describe('gradeColor', () => {
    it('maps each grade to a distinct colour', () => {
      const colors = ['A', 'B', 'C', 'D', 'F'].map(gradeColor)
      expect(new Set(colors).size).toBe(5)
      expect(gradeColor('a')).toBe(gradeColor('A')) // case-insensitive
    })

    it('falls back to a neutral colour for unknown grades', () => {
      expect(gradeColor('Z')).toBe('#94a3b8')
      expect(gradeColor(null)).toBe('#94a3b8')
      expect(gradeColor(undefined)).toBe('#94a3b8')
    })
  })

  describe('scoreColor', () => {
    it('greens high scores and reds low scores', () => {
      expect(scoreColor(95)).toBe('#34d399')
      expect(scoreColor(85)).toBe('#a3e635')
      expect(scoreColor(75)).toBe('#fbbf24')
      expect(scoreColor(65)).toBe('#fb923c')
      expect(scoreColor(40)).toBe('#f43f5e')
    })

    it('is neutral for non-numeric input', () => {
      expect(scoreColor('nope')).toBe('#94a3b8')
      expect(scoreColor(undefined)).toBe('#94a3b8')
    })
  })
})
