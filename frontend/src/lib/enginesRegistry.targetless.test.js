import { describe, it, expect } from 'vitest'
import { TARGETLESS_ENGINE_IDS } from './enginesRegistry.js'
describe('targetless engines', () => {
  it('set non-empty', () => expect(TARGETLESS_ENGINE_IDS.size).toBeGreaterThan(0))
})