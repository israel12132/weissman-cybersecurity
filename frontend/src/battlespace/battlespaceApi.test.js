import { describe, it, expect, vi, beforeEach } from 'vitest'

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import { fetchNodeEvidence } from './battlespaceApi.js'

describe('fetchNodeEvidence', () => {
  beforeEach(() => apiFetch.mockReset())

  it('does not treat a findings store-down as empty evidence', async () => {
    apiFetch.mockRejectedValue(new Error('store down'))
    await expect(fetchNodeEvidence(7, 'n1')).rejects.toThrow('store down')
  })

  it('does not treat an unavailable envelope as a confirmed miss', async () => {
    apiFetch.mockResolvedValue({ ok: false, unavailable: true, findings: [], detail: 'store down' })
    await expect(fetchNodeEvidence(7, 'n1')).rejects.toThrow(/store down|unavailable/)
  })

  it('filters live findings by risk node id', async () => {
    apiFetch.mockResolvedValue({
      findings: [
        { id: 1, risk_node_id: 'n1', title: 'hit' },
        { id: 2, risk_node_id: 'n2', title: 'miss' },
      ],
    })
    const ev = await fetchNodeEvidence(7, 'n1')
    expect(ev).toHaveLength(1)
    expect(ev[0].title).toBe('hit')
  })
})
