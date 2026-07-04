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
  it('mergeScanBody', () => {
    const m = mergeScanBody('osint', { target: 'https://a.test' })
    expect(m.target).toBeTruthy()
  })
})