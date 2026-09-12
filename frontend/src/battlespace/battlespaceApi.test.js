import { describe, it, expect, vi, beforeEach } from 'vitest'

const apiFetch = vi.fn()
vi.mock('../utils/apiFetch', () => ({
  apiFetch: (...args) => apiFetch(...args),
}))

import { fetchNodeEvidence, findingMatchesNode } from './battlespaceApi.js'

describe('fetchNodeEvidence', () => {
  beforeEach(() => apiFetch.mockReset())

  it('does not treat a findings store-down as empty evidence', async () => {
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

  it('uses topology-cached findings instead of refetching the KEV-ordered page', async () => {
    const cached = [
      { id: 9, risk_node_id: 42, title: 'from topology' },
      { id: 8, risk_node_id: 7, title: 'other' },
    ]
    const ev = await fetchNodeEvidence(7, 42, { cachedFindings: cached })
    expect(ev).toEqual([{ id: 9, risk_node_id: 42, title: 'from topology' }])
    expect(apiFetch).not.toHaveBeenCalled()
  })
})

describe('findingMatchesNode', () => {
  it('matches live /api/findings raw blob as well as risk_node_id', () => {
    expect(findingMatchesNode({ raw: { risk_node_id: 'n1' } }, 'n1')).toBe(true)
    expect(findingMatchesNode({ raw_data: { risk_node_id: 'n1' } }, 'n1')).toBe(true)
    expect(findingMatchesNode({ risk_node_id: 'n1' }, 'n1')).toBe(true)
    expect(findingMatchesNode({ title: 'no node' }, 'n1')).toBe(false)
  })
})

describe('findingMatchesNode', () => {
  it('matches nested raw_data.risk_node_id', () => {
    expect(findingMatchesNode({ raw_data: { risk_node_id: 12 } }, '12')).toBe(true)
    expect(findingMatchesNode({ raw: { risk_node_id: '12' } }, 12)).toBe(true)
    expect(findingMatchesNode({ risk_node_id: 1 }, 2)).toBe(false)
  })
})
