import { describe, it, expect } from 'vitest'
import { coverageTone, deployList, parseFirstDomain } from './ArsenalConsole.jsx'

describe('ArsenalConsole helpers', () => {
  describe('coverageTone', () => {
    it('greens high coverage and reds low', () => {
      expect(coverageTone(95)).toBe('#34d399')
      expect(coverageTone(75)).toBe('#a3e635')
      expect(coverageTone(50)).toBe('#fbbf24')
      expect(coverageTone(10)).toBe('#f43f5e')
    })
    it('is neutral for non-numeric', () => {
      expect(coverageTone('nope')).toBe('#94a3b8')
      expect(coverageTone(undefined)).toBe('#94a3b8')
    })
  })

  describe('deployList', () => {
    it('takes distinct engine ids, capped', () => {
      const rec = [
        { engine_id: 'a' }, { engine_id: 'b' }, { engine_id: 'a' }, // dup
        { engine_id: 'c' }, { engine_id: 'd' },
      ]
      expect(deployList(rec, 3)).toEqual(['a', 'b', 'c'])
    })
    it('ignores blank/invalid ids and non-array input', () => {
      expect(deployList([{ engine_id: '' }, { engine_id: '  ' }, {}, { engine_id: 'x' }])).toEqual(['x'])
      expect(deployList(null)).toEqual([])
      expect(deployList(undefined)).toEqual([])
    })
  })

  describe('parseFirstDomain', () => {
    it('parses a JSON-string array', () => {
      expect(parseFirstDomain('["a.example.com","b.example.com"]')).toBe('a.example.com')
    })
    it('accepts a real array and trims', () => {
      expect(parseFirstDomain([' x.example.com '])).toBe('x.example.com')
    })
    it('falls back to a bare string and tolerates junk', () => {
      expect(parseFirstDomain('plain.example.com')).toBe('plain.example.com')
      expect(parseFirstDomain('')).toBe('')
      expect(parseFirstDomain(null)).toBe('')
      expect(parseFirstDomain([1, 2])).toBe('')
    })
  })
})
