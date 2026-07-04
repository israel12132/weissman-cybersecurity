import { describe, it, expect } from 'vitest'
import { TOP_TIER_ENGINE_IDS, getTopTierProfile, isTopTierEngine } from './topTierEngineProfiles.js'
describe('topTierEngineProfiles', () => {
  it('ids non-empty', () => expect(TOP_TIER_ENGINE_IDS.length).toBeGreaterThan(0))
  it('profile lookup', () => {
    const id = TOP_TIER_ENGINE_IDS[0]
    expect(getTopTierProfile(id)).toBeTruthy()
    expect(isTopTierEngine(id)).toBe(true)
  })
})