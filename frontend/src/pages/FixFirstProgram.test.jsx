import { describe, it, expect } from 'vitest'
import { deriveSlaView, scoreFraction, formatUsd, programToCsvRows, PROGRAM_CSV_HEADER } from './FixFirstProgram.jsx'

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

  describe('programToCsvRows', () => {
    it('flattens an action into a row aligned with the header', () => {
      const rows = programToCsvRows([
        {
          rank: 1,
          title: 'SQL injection',
          asset: 'app.example.com',
          priority_score: 92.5,
          max_effective_risk: 9.1,
          closes_findings: 3,
          kev: true,
          kev_ransomware: false,
          on_choke_point: true,
          crown_jewel: true,
          business_value_usd: 5000000,
          sla: { state: 'overdue', due_in_days: -4, target_days: 14 },
          compliance: [
            { framework: 'OWASP Top 10 2021', control: 'A03:2021' },
            { framework: 'NIST 800-53r5', control: 'SI-10' },
          ],
          rationale: 'base risk 9.1/10; KEV',
        },
      ])
      expect(rows).toHaveLength(1)
      expect(rows[0]).toHaveLength(PROGRAM_CSV_HEADER.length)
      expect(rows[0][0]).toBe(1) // rank
      expect(rows[0][6]).toBe('yes') // kev
      expect(rows[0][7]).toBe('no') // kev_ransomware
      expect(rows[0][11]).toBe('overdue') // sla_state
      expect(rows[0][14]).toBe('OWASP Top 10 2021:A03:2021 | NIST 800-53r5:SI-10') // frameworks
    })

    it('is robust to missing fields and non-array input', () => {
      expect(programToCsvRows(null)).toEqual([])
      expect(programToCsvRows(undefined)).toEqual([])
      const rows = programToCsvRows([{}])
      expect(rows[0]).toHaveLength(PROGRAM_CSV_HEADER.length)
      expect(rows[0][6]).toBe('no') // kev defaults to no
      expect(rows[0][14]).toBe('') // no compliance
    })
  })
})
