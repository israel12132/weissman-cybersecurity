import { describe, it, expect } from 'vitest'
import { invalidateEngineCapabilitiesCache } from './useEngineCapabilities.js'
describe('useEngineCapabilities cache', () => {
  it('invalidate noop', () => expect(() => invalidateEngineCapabilitiesCache()).not.toThrow())
})