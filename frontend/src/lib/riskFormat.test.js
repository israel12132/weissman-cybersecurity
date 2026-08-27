import { describe, it, expect } from 'vitest'
import { fmtUsd, fairAleLabel, fairSleLabel, postureGradeColor, postureScoreColor } from './riskFormat'

describe('fmtUsd', () => {
  it('formats millions, thousands, and plain values', () => {
    expect(fmtUsd(2_500_000)).toBe('$2.50M')
    expect(fmtUsd(4_500)).toBe('$4.5K')
    expect(fmtUsd(678)).toBe('$678')
  })
  it('handles negatives by magnitude and coerces junk to $0', () => {
    expect(fmtUsd(-1_200_000)).toBe('$-1.20M')
    expect(fmtUsd(null)).toBe('$0')
    expect(fmtUsd('nope')).toBe('$0')
  })
})

describe('fairAleLabel / fairSleLabel', () => {
  it('formats priced FAIR ALE/SLE and never treats Micro-Severity as USD', () => {
    const fair = {
      method: 'fair_usd_blast_radius',
      priced: true,
      ale_annualised_usd: 180_000,
      sle_worst_usd: 98_000,
    }
    expect(fairAleLabel(fair)).toBe('$180.0K')
    expect(fairSleLabel(fair)).toBe('$98.0K')
    expect(fairAleLabel({ method: 'micro_severity_product', score: 25 })).toBeNull()
  })
  it('fail-visible cannot-price never invents $0', () => {
    expect(fairAleLabel({ priced: false, cannot_price_reason: 'Cannot price' })).toBeNull()
    expect(fairAleLabel({ priced: true, ale_annualised_usd: 0 })).toBeNull()
    expect(fairAleLabel(null)).toBeNull()
    expect(fairSleLabel({ priced: false })).toBeNull()
  })
})

describe('postureGradeColor', () => {
  it('maps A–F case-insensitively', () => {
    expect(postureGradeColor('A')).toBe('#4ade80')
    expect(postureGradeColor('f')).toBe('#ef4444')
    expect(postureGradeColor('C')).toBe('#facc15')
  })
  it('falls back to cyan for unknown/missing grades', () => {
    expect(postureGradeColor('Z')).toBe('#22d3ee')
    expect(postureGradeColor(null)).toBe('#22d3ee')
  })
})

describe('postureScoreColor', () => {
  it('bands the 0–100 score green→rose at 90/75/60/40', () => {
    expect(postureScoreColor(95)).toBe('#4ade80')
    expect(postureScoreColor(90)).toBe('#4ade80')
    expect(postureScoreColor(80)).toBe('#84cc16')
    expect(postureScoreColor(65)).toBe('#facc15')
    expect(postureScoreColor(45)).toBe('#f97316')
    expect(postureScoreColor(10)).toBe('#ef4444')
  })
  it('treats junk as 0 (rose)', () => {
    expect(postureScoreColor(undefined)).toBe('#ef4444')
  })
})
