import { describe, it, expect, vi } from 'vitest'
import { bulkUpdateFindingStatus } from './bulkFindingStatus'

function okResponse(status = 'false_positive') {
  return { ok: true, json: () => Promise.resolve({ ok: true, status }) }
}
function rejectResponse() {
  return { ok: true, json: () => Promise.resolve({ ok: false, detail: 'nope' }) }
}

describe('bulkUpdateFindingStatus', () => {
  it('returns zero work for empty inputs', async () => {
    const apiFetch = vi.fn()
    expect(await bulkUpdateFindingStatus([], 'x', { apiFetch })).toEqual({ ok: 0, failed: [] })
    expect(await bulkUpdateFindingStatus([1, 2], '', { apiFetch })).toEqual({ ok: 0, failed: [] })
    expect(apiFetch).not.toHaveBeenCalled()
  })

  it('PATCHes each finding and reports full success', async () => {
    const apiFetch = vi.fn(() => Promise.resolve(okResponse('resolved')))
    const seen = []
    const res = await bulkUpdateFindingStatus([1, 2, 3], 'resolved', {
      apiFetch,
      onSuccess: (id, s) => seen.push([id, s]),
    })
    expect(res).toEqual({ ok: 3, failed: [] })
    expect(apiFetch).toHaveBeenCalledTimes(3)
    // correct endpoint + payload
    expect(apiFetch).toHaveBeenCalledWith('/api/findings/1/status', expect.objectContaining({
      method: 'PATCH',
      body: JSON.stringify({ status: 'resolved' }),
    }))
    expect(seen).toEqual([[1, 'resolved'], [2, 'resolved'], [3, 'resolved']])
  })

  it('aggregates partial failures (rejected + thrown)', async () => {
    const apiFetch = vi.fn((url) => {
      if (url.includes('/2/')) return Promise.resolve(rejectResponse())
      if (url.includes('/3/')) return Promise.reject(new Error('network'))
      return Promise.resolve(okResponse())
    })
    const res = await bulkUpdateFindingStatus([1, 2, 3, 4], 'false_positive', { apiFetch })
    expect(res.ok).toBe(2)
    expect(res.failed.sort()).toEqual([2, 3])
  })

  it('drops null ids and honours the concurrency cap', async () => {
    let inFlight = 0
    let maxInFlight = 0
    const apiFetch = vi.fn(() => {
      inFlight += 1
      maxInFlight = Math.max(maxInFlight, inFlight)
      return Promise.resolve().then(() => { inFlight -= 1; return okResponse() })
    })
    const res = await bulkUpdateFindingStatus([1, null, 2, 3, 4, 5], 'x', { apiFetch, concurrency: 2 })
    expect(res.ok).toBe(5)
    expect(maxInFlight).toBeLessThanOrEqual(2)
  })
})
