import { describe, it, expect } from 'vitest'
import { ENGINE_GROUP_DEFS } from './engineGroupDefs.js'
describe('ENGINE_GROUP_DEFS ids', () => {
  it('unique', () => {
    const ids = ENGINE_GROUP_DEFS.map((g) => g.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})