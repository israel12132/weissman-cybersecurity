import { describe, it, expect } from 'vitest'
import { resolveRouteEvidence, ROUTE_EVIDENCE } from './routeEvidence.js'
describe('routeEvidence extra', () => {
  it('engines key', () => expect(ROUTE_EVIDENCE['/engines']).toBeTruthy())
  it('resolve clients route', () => {
    const t = resolveRouteEvidence('/clients', (k) => (k === 'clients_page.evidence_notice' ? 'Clients evidence' : k))
    expect(t).toBe('Clients evidence')
  })
})