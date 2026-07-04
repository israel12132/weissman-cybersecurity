import { describe, it, expect } from 'vitest'
import { invalidateProductionEnginesCache } from './useProductionEngines.js'
describe('useProductionEngines cache', () => {
  it('invalidate noop', () => expect(() => invalidateProductionEnginesCache()).not.toThrow())
})