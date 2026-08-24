import { describe, it, expect } from 'vitest'
import { ENGINES_REGISTRY } from './enginesRegistry'
import { PRODUCTION_ENGINE_COUNT } from './platformScale'

/**
 * Guard: the engine count shown before login must equal the real catalog.
 *
 * The login brand panel advertised "254 engines" long after the registry passed 500 — nothing tied
 * the copy to the catalog, so the headline number for the whole platform silently rotted. This test
 * is that tie. `scripts/verify_engine_wiring.mjs` separately holds the registry equal to the
 * backend's `PRODUCTION_ENGINE_IDS`, so pinning to the registry pins to production dispatch.
 */
describe('platform scale constants', () => {
  it('matches the engines registry length exactly', () => {
    expect(PRODUCTION_ENGINE_COUNT).toBe(ENGINES_REGISTRY.length)
  })

  it('counts unique engine ids, not duplicated registry rows', () => {
    const uniqueIds = new Set(ENGINES_REGISTRY.map((engine) => engine.id))
    expect(uniqueIds.size).toBe(PRODUCTION_ENGINE_COUNT)
  })
})
