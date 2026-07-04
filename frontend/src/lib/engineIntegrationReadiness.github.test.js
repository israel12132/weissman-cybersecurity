import { describe, it, expect } from 'vitest'
import { computeEngineIntegrationReadiness } from './engineIntegrationReadiness.js'
describe('integration readiness github', () => {
  it('leak_hunter with github', () => {
    const r = computeEngineIntegrationReadiness('leak_hunter', { github: { connected: true } })
    expect(r.percent).toBeGreaterThanOrEqual(0)
  })
})