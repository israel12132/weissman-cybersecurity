import { describe, it, expect } from 'vitest'
import { encodeFindingsFilters, decodeFindingsFilters, hasAnyFilter } from './findingsUrlState'

describe('findings URL state', () => {
  it('encodes only non-empty params', () => {
    expect(encodeFindingsFilters({})).toEqual({})
    expect(encodeFindingsFilters({ globalFilter: '', severityFilter: 'critical' })).toEqual({ sev: 'critical' })
    expect(encodeFindingsFilters({
      globalFilter: 'sqli', severityFilter: 'high', statusFilter: 'OPEN', engineFilter: 'sqli_advanced', kevFilter: true, proofFilter: true,
    })).toEqual({ q: 'sqli', sev: 'high', status: 'OPEN', engine: 'sqli_advanced', kev: '1', proof: '1' })
  })

  it('omits kev and proof when falsey', () => {
    expect(encodeFindingsFilters({ kevFilter: false }).kev).toBeUndefined()
    expect(encodeFindingsFilters({ proofFilter: false }).proof).toBeUndefined()
  })

  it('round-trips through URLSearchParams', () => {
    const state = { globalFilter: 'xss', severityFilter: 'critical', statusFilter: '', engineFilter: '', kevFilter: true, proofFilter: true }
    const params = new URLSearchParams(encodeFindingsFilters(state))
    const decoded = decodeFindingsFilters(params)
    expect(decoded.globalFilter).toBe('xss')
    expect(decoded.severityFilter).toBe('critical')
    expect(decoded.kevFilter).toBe(true)
    expect(decoded.proofFilter).toBe(true)
    expect(decoded.statusFilter).toBe('')
  })

  it('decodes from a plain object too', () => {
    expect(decodeFindingsFilters({ sev: 'low' }).severityFilter).toBe('low')
  })

  it('hasAnyFilter reflects active filters', () => {
    expect(hasAnyFilter({})).toBe(false)
    expect(hasAnyFilter({ severityFilter: 'high' })).toBe(true)
    expect(hasAnyFilter({ kevFilter: true })).toBe(true)
    expect(hasAnyFilter({ proofFilter: true })).toBe(true)
  })
})
