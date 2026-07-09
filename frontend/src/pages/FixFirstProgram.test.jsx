import { describe, it, expect } from 'vitest'
import { deriveSlaView, scoreFraction, formatUsd } from './FixFirstProgram.jsx'

describe('FixFirstProgram helpers', () => {
  describe('deriveSlaView', () => {
    it('overdue reports absolute days past due and danger tone', () => {
      expect(deriveSlaView({ state: 'overdue', due_in_days: -16 })).toEqual({
        tone: 'danger',
        key: 'overdue',
        days: 16,
      })
    })

    it('due_soon keeps remaining days and warn tone', () => {
      expect(deriveSlaView({ state: 'due_soon', due_in_days: 5 })).toEqual({
        tone: 'warn',
        key: 'due_soon',
        days: 5,
      })
    })

    it('on_track keeps remaining days and ok tone', () => {
      expect(deriveSlaView({ state: 'on_track', due_in_days: 40 })).toEqual({
        tone: 'ok',
        key: 'on_track',
        days: 40,
      })
    })

    it('unknown/absent age has no days and muted tone', () => {
      expect(deriveSlaView({ state: 'unknown', due_in_days: null })).toEqual({
        tone: 'muted',
        key: 'unknown',
        days: null,
      })
      expect(deriveSlaView(null)).toEqual({ tone: 'muted', key: 'unknown', days: null })
      expect(deriveSlaView(undefined)).toEqual({ tone: 'muted', key: 'unknown', days: null })
    })
  })

  describe('scoreFraction', () => {
    it('maps 0..100 onto 0..1', () => {
      expect(scoreFraction(0)).toBe(0)
      expect(scoreFraction(50)).toBe(0.5)
      expect(scoreFraction(100)).toBe(1)
    })

    it('clamps out-of-range and non-numeric input', () => {
      expect(scoreFraction(150)).toBe(1)
      expect(scoreFraction(-10)).toBe(0)
      expect(scoreFraction('nope')).toBe(0)
      expect(scoreFraction(undefined)).toBe(0)
    })
  })

  describe('formatUsd', () => {
    it('formats billions, millions, thousands, and units', () => {
      expect(formatUsd(5_000_000_000)).toBe('$5B')
      expect(formatUsd(2_500_000)).toBe('$2.5M')
      expect(formatUsd(5_000_000)).toBe('$5M')
      expect(formatUsd(250_000)).toBe('$250K')
      expect(formatUsd(900)).toBe('$900')
    })

    it('returns null for non-positive or invalid input', () => {
      expect(formatUsd(0)).toBeNull()
      expect(formatUsd(-100)).toBeNull()
      expect(formatUsd(null)).toBeNull()
      expect(formatUsd(undefined)).toBeNull()
      expect(formatUsd('nope')).toBeNull()
    })
  })
})
