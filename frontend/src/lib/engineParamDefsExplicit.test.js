import { describe, it, expect } from 'vitest'
import { EXPLICIT_PARAM_DEFS } from './engineParamDefsExplicit.js'
import { GENERATED_PARAM_DEFS } from './engineParamDefs.generated.js'
describe('engineParamDefsExplicit', () => {
  it('has profiles', () => expect(Object.keys(EXPLICIT_PARAM_DEFS).length).toBeGreaterThan(10))
  it('adversary_exposure_delta only exposes live max_findings', () => {
    const keys = EXPLICIT_PARAM_DEFS.adversary_exposure_delta.map((p) => p.key)
    expect(keys).toEqual(['max_findings'])
    expect(EXPLICIT_PARAM_DEFS.adversary_exposure_delta[0].max).toBe(50)
    expect(GENERATED_PARAM_DEFS.adversary_exposure_delta).toBeUndefined()
  })
})