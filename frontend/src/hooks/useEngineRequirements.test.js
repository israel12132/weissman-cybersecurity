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
  it('buildClientPayload carries the eBPF runtime-probe fields', () => {
    const p = buildClientPayload({ ...defaultOnboardingForm(), ebpf_ssh_host: '10.0.0.5', ebpf_ssh_user: 'root' })
    expect(p.onboarding.ebpf_ssh_host).toBe('10.0.0.5')
    expect(p.onboarding.ebpf_ssh_user).toBe('root')
  })
  it('tenant-scoped requirement never hard-blocks client onboarding', () => {
    const catalog = {
      requirements: { tenant_llm: { scope: 'tenant' } },
      modules: { ai_redteam: { requirements: ['tenant_llm'] } },
    }
    // Tenant LLM NOT configured → requirement unsatisfied, but tenant-scoped.
    const r = computeLocalReadiness(catalog, { llm_configured: false }, {}, ['ai_redteam'])
    expect(r.items.find((i) => i.id === 'tenant_llm')?.hard).toBe(false)
    expect(r.ready).toBe(true) // onboarding not blocked by a global tenant setting
    expect(r.percent).toBe(100) // no hard reqs → 100%, not the old contradictory 0%
  })
})