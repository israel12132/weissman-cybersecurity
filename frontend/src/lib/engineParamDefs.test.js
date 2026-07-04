import { describe, it, expect } from 'vitest'
import { getEngineParams, getCommandCenterRoute } from './engineParamDefs.js'
describe('engineParamDefs', () => {
  it('osint params', () => {
    const p = getEngineParams('osint')
    expect(Array.isArray(p)).toBe(true)
  })
  it('command center route', () => {
    expect(getCommandCenterRoute('osint')).toContain('/engines')
  })
})