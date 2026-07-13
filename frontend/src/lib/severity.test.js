import { describe, it, expect } from 'vitest'
import {
  SEV_ORDER,
  SEV_COLOR,
  normalizeSeverity,
  sevRank,
  sevColor,
  compareSeverity,
} from './severity'

describe('severity vocabulary', () => {
  it('ranks severities from critical (highest) to info (lowest)', () => {
    expect(SEV_ORDER.critical).toBeGreaterThan(SEV_ORDER.high)
    expect(SEV_ORDER.high).toBeGreaterThan(SEV_ORDER.medium)
    expect(SEV_ORDER.medium).toBeGreaterThan(SEV_ORDER.low)
    expect(SEV_ORDER.low).toBeGreaterThan(SEV_ORDER.info)
  })

  it('has a colour for every ranked severity', () => {
    for (const key of Object.keys(SEV_ORDER)) {
      expect(SEV_COLOR[key]).toMatch(/^#[0-9a-f]{6}$/i)
    }
  })

  it('normalises case, whitespace, and unknowns', () => {
    expect(normalizeSeverity('CRITICAL')).toBe('critical')
    expect(normalizeSeverity('  High ')).toBe('high')
    expect(normalizeSeverity('bogus')).toBe('info')
    expect(normalizeSeverity(null)).toBe('info')
    expect(normalizeSeverity(undefined)).toBe('info')
  })

  it('sevRank maps values (unknown → 0)', () => {
    expect(sevRank('critical')).toBe(4)
    expect(sevRank('Low')).toBe(1)
    expect(sevRank('nope')).toBe(0)
  })

  it('sevColor falls back to the info colour for unknowns', () => {
    expect(sevColor('critical')).toBe(SEV_COLOR.critical)
    expect(sevColor('mystery')).toBe(SEV_COLOR.info)
  })

  it('compareSeverity orders ascending and can be negated for descending', () => {
    const rows = ['low', 'critical', 'info', 'high', 'medium']
    const asc = [...rows].sort(compareSeverity)
    expect(asc).toEqual(['info', 'low', 'medium', 'high', 'critical'])
    const desc = [...rows].sort((a, b) => -compareSeverity(a, b))
    expect(desc).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })

  it('the exported maps are frozen (shared constants must not be mutated)', () => {
    expect(Object.isFrozen(SEV_ORDER)).toBe(true)
    expect(Object.isFrozen(SEV_COLOR)).toBe(true)
  })
})
