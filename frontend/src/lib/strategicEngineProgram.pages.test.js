import { describe, it, expect } from 'vitest'
import { strategicEnginesNeedingDedicatedPage } from './strategicEngineProgram.js'
describe('strategic dedicated pages', () => {
  it('unique ids', () => {
    const ids = strategicEnginesNeedingDedicatedPage()
    expect(new Set(ids).size).toBe(ids.length)
  })
})