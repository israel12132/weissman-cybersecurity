import { describe, it, expect } from 'vitest'
import { computeEngineIntegrationReadiness } from './engineIntegrationReadiness.js'
describe('engineIntegrationReadiness', () => {
  it('osint readiness', () => {
    const r = computeEngineIntegrationReadiness('osint', {})
    expect(r).toHaveProperty('ready')
  })
})