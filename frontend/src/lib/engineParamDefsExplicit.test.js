import { describe, it, expect } from 'vitest'
import { EXPLICIT_PARAM_DEFS } from './engineParamDefsExplicit.js'
describe('engineParamDefsExplicit', () => {
  it('has profiles', () => expect(Object.keys(EXPLICIT_PARAM_DEFS).length).toBeGreaterThan(10))
  it('dominion_fusion only exposes honored stealth and max_findings', () => {
    const keys = (EXPLICIT_PARAM_DEFS.dominion_fusion || []).map((p) => p.key)
    expect(keys).toEqual(['stealth_mode', 'max_findings'])
  })
})