import { describe, it, expect } from 'vitest'
import { buildScanPayload, normalizeIntegrations, mergeScanBody } from './engineClientPrefill.js'
describe('engineClientPrefill', () => {
  it('buildScanPayload', () => {
    const b = buildScanPayload('osint', { clientId: 1, target: 'https://x.test' })
    expect(b.engine).toBe('osint')
  })
  it('normalizeIntegrations empty', () => {
    expect(normalizeIntegrations(null)).toBeNull()
  })
  it('buildScanPayload omits empty target so the server can fill the client default', () => {
    const b = buildScanPayload('leak_hunter', { clientId: 7, target: '  ' })
    expect(b.engine).toBe('leak_hunter')
    expect(b.client_id).toBe(7)
    expect(b.target).toBeUndefined()
  })
  it('mergeScanBody', () => {
    const m = mergeScanBody('osint', { target: 'https://a.test' })
    expect(m.target).toBeTruthy()
  })
})
