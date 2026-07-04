import { describe, it, expect } from 'vitest'
import { invalidateEngineHistorySummary } from './engineHistorySummary.js'
describe('engineHistorySummary', () => {
  it('invalidate noop', () => expect(() => invalidateEngineHistorySummary()).not.toThrow())
})