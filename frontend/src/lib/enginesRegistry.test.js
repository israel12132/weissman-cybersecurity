import { describe, it, expect } from 'vitest'
import { ENGINES_REGISTRY, getEngine, getEnginesByGroup } from './enginesRegistry.js'
describe('enginesRegistry', () => {
  it('non-empty', () => expect(ENGINES_REGISTRY.length).toBeGreaterThan(100))
  it('getEngine', () => expect(getEngine('osint')?.id).toBe('osint'))
  it('exposure schism fusion is registered', () => {
    expect(getEngine('exposure_schism_fusion')?.id).toBe('exposure_schism_fusion')
    expect(getEngine('exposure_schism_fusion')?.requiresTarget).toBe(true)
  })
  it('by group', () => expect(getEnginesByGroup('recon').length).toBeGreaterThan(0))
  it('registers OT safety interlock engines as live catalog ids', () => {
    expect(getEngine('ot_passive_active_safety')?.group).toBe('ot')
    expect(getEngine('ot_crown_jewel_path')?.group).toBe('ot')
  })
})