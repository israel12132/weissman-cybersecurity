import { describe, it, expect } from 'vitest'
import { EXPLICIT_PARAM_DEFS } from './engineParamDefsExplicit.js'
describe('engineParamDefsExplicit', () => {
  it('has profiles', () => expect(Object.keys(EXPLICIT_PARAM_DEFS).length).toBeGreaterThan(10))
})