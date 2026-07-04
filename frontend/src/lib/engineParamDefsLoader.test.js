import { describe, it, expect } from 'vitest'
import { loadGeneratedParamDefs, getGeneratedParamDefsSync } from './engineParamDefsLoader.js'
describe('engineParamDefsLoader', () => {
  it('loads defs', async () => {
    const d = await loadGeneratedParamDefs()
    expect(d && typeof d === 'object').toBe(true)
  })
  it('sync getter after load', async () => {
    await loadGeneratedParamDefs()
    expect(getGeneratedParamDefsSync()).toBeTruthy()
  })
})
