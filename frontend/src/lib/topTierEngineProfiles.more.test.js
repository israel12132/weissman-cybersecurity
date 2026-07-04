import { describe, it, expect } from 'vitest'
import { isTopTierEngine } from './topTierEngineProfiles.js'
describe('topTierEngineProfiles more', () => {
  it('non top tier', () => expect(isTopTierEngine('osint')).toBe(false))
})