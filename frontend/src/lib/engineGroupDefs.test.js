import { describe, it, expect } from 'vitest'
import { ENGINE_GROUP_DEFS, ENGINE_GROUPS } from './engineGroupDefs.js'
describe('engineGroupDefs', () => {
  it('groups defined', () => {
    expect(ENGINE_GROUP_DEFS.length).toBeGreaterThan(5)
    expect(ENGINE_GROUPS.recon.label).toBeTruthy()
  })
})