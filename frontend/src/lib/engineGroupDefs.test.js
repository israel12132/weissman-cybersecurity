import { describe, it, expect } from 'vitest'
import { ENGINE_GROUP_DEFS, ENGINE_GROUPS } from './engineGroupDefs.js'
import { ENGINES_REGISTRY } from './enginesRegistry.js'

describe('engineGroupDefs', () => {
  it('groups defined', () => {
    expect(ENGINE_GROUP_DEFS.length).toBeGreaterThan(5)
    expect(ENGINE_GROUPS.recon.label).toBeTruthy()
    expect(ENGINE_GROUPS.deception.label).toBeTruthy()
  })

  it('covers every ENGINES_REGISTRY group so the matrix cannot hide an engine', () => {
    const known = new Set(ENGINE_GROUP_DEFS.map((g) => g.id))
    const missing = [...new Set(ENGINES_REGISTRY.map((e) => e.group))].filter((g) => !known.has(g))
    expect(missing).toEqual([])
  })
})