import { describe, it, expect } from 'vitest'
import { computeLocalReadiness, buildClientPayload, defaultOnboardingForm, ALL_MODULE_IDS } from './useEngineRequirements.js'
describe('useEngineRequirements helpers', () => {
  it('default form', () => expect(defaultOnboardingForm().contact_email).toBe(''))
  it('modules', () => expect(ALL_MODULE_IDS.length).toBeGreaterThan(0))
  it('readiness empty catalog', () => {
    expect(computeLocalReadiness(null, null, {}, []).ready).toBe(false)
  })
  it('readiness partial integrations form', () => {
    const catalog = {
      requirements: { llm_secops_endpoints: { scope: 'client' } },
      modules: { ai_redteam: { requirements: ['llm_secops_endpoints'] } },
    }
    const r = computeLocalReadiness(catalog, null, {
      llm_endpoints: [{ url: 'https://llm.example/v1' }],
    }, ['ai_redteam'])
    expect(r.items.find((i) => i.id === 'llm_secops_endpoints')?.satisfied).toBe(true)
  })
  it('buildClientPayload', () => {
    const p = buildClientPayload({ ...defaultOnboardingForm(), name: 'Acme', scope_domains: 'a.com' })
    expect(p.name).toBe('Acme')
  })
})