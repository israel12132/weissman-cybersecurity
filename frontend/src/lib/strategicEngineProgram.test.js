import { describe, it, expect } from 'vitest'
import { STRATEGIC_ENGINE_PROGRAM, strategicEnginesNeedingDedicatedPage } from './strategicEngineProgram.js'
describe('strategicEngineProgram', () => {
  it('phases', () => expect(STRATEGIC_ENGINE_PROGRAM.length).toBeGreaterThan(0))
  it('dedicated pages', () => expect(strategicEnginesNeedingDedicatedPage().length).toBeGreaterThan(0))
})