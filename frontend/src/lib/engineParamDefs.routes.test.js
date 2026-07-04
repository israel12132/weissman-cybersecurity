import { describe, it, expect } from 'vitest'
import { ENGINE_COMMAND_CENTER_ROUTES, getEngineParamKeys } from './engineParamDefs.js'
describe('engineParamDefs routes', () => {
  it('routes map', () => expect(Object.keys(ENGINE_COMMAND_CENTER_ROUTES).length).toBeGreaterThan(50))
  it('param keys', () => expect(Array.isArray(getEngineParamKeys('osint'))).toBe(true))
})