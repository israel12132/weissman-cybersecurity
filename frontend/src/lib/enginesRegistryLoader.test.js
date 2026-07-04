import { describe, it, expect } from 'vitest'
import { loadEnginesRegistry, getEnginesRegistrySync } from './enginesRegistryLoader.js'
describe('enginesRegistryLoader', () => {
  it('loads registry', async () => {
    const r = await loadEnginesRegistry()
    expect(r.ENGINES_REGISTRY.length).toBeGreaterThan(100)
  })
  it('sync getter after load', async () => {
    await loadEnginesRegistry()
    expect(getEnginesRegistrySync()?.ENGINES_REGISTRY?.length).toBeGreaterThan(100)
  })
})
