import { describe, it, expect } from 'vitest'
import { ENGINES_REGISTRY, getEngine, getEnginesByGroup } from './enginesRegistry.js'
describe('enginesRegistry', () => {
  it('non-empty', () => expect(ENGINES_REGISTRY.length).toBeGreaterThan(100))
  it('getEngine', () => expect(getEngine('osint')?.id).toBe('osint'))
  it('by group', () => expect(getEnginesByGroup('recon').length).toBeGreaterThan(0))
})