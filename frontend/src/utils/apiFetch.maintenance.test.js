import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'

// Keep the REAL maintenance registry + detector from lib/apiBase, but replace the
// transport so this file proves utils/apiFetch raises the signal on its own —
// even when the underlying client did not (e.g. a swapped transport in tests).
const { baseApiFetch } = vi.hoisted(() => ({ baseApiFetch: vi.fn() }))
vi.mock('../lib/apiBase', async (importOriginal) => ({
  ...(await importOriginal()),
  apiFetch: baseApiFetch,
}))

import { apiFetch, setMaintenanceCallback } from './apiFetch'
import { getMaintenanceCallback } from '../lib/apiBase'
import { getCircuitBreaker, originKeyOf, _resetCircuitBreakers } from '../lib/resilience'

function res(status, { headers = {}, body, contentType = 'application/json' } = {}) {
  const h = new Headers({ ...(body !== undefined ? { 'content-type': contentType } : {}), ...headers })
  const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body)
  return new Response(text, { status, headers: h })
}

const branded = { 'x-weissman-maintenance': '1', 'retry-after': '30' }
const cb = vi.fn()

beforeEach(() => {
  _resetCircuitBreakers()
  baseApiFetch.mockReset()
  cb.mockReset()
  setMaintenanceCallback(cb)
})
afterEach(() => setMaintenanceCallback(null))

describe('utils/apiFetch → maintenance callback', () => {
  it('re-exports setMaintenanceCallback from lib/apiBase (same registry)', () => {
    expect(getMaintenanceCallback()).toBe(cb)
  })

  it('fires on a header-branded 503 and still throws the usual HTTP error', async () => {
    baseApiFetch.mockResolvedValueOnce(
      res(503, {
        headers: branded,
        body: { status: 'maintenance', message: 'Scheduled platform update in progress' },
      }),
    )
    const err = await apiFetch('/api/findings').catch((e) => e)
    expect(err).toBeInstanceOf(Error)
    expect(err.status).toBe(503)
    expect(err.message).toBe('Scheduled platform update in progress')
    expect(err.body).toEqual({ status: 'maintenance', message: 'Scheduled platform update in progress' })
    expect(err.response).toBeInstanceOf(Response)
    expect(cb).toHaveBeenCalledTimes(1)
    expect(cb).toHaveBeenCalledWith({ status: 503, retryAfter: 30 })
  })

  it('fires on a body-only marker (dist/api.json shape, no header) for 504', async () => {
    baseApiFetch.mockResolvedValueOnce(res(504, { body: { status: 'maintenance', code: 503 } }))
    await expect(apiFetch('/api/x')).rejects.toMatchObject({ status: 504 })
    expect(cb).toHaveBeenCalledWith({ status: 504, retryAfter: 60 })
  })

  it('does NOT fire on a legitimate upstream 503 or an unbranded 502', async () => {
    baseApiFetch.mockResolvedValueOnce(res(503, { body: { ok: false, error: 'smtp_unconfigured' } }))
    await expect(apiFetch('/api/public/demo-request', { method: 'POST', body: {} })).rejects.toMatchObject({
      status: 503,
    })
    baseApiFetch.mockResolvedValueOnce(res(502, { body: '<html>Bad Gateway</html>', contentType: 'text/html' }))
    await expect(apiFetch('/api/x')).rejects.toMatchObject({ status: 502 })
    expect(cb).not.toHaveBeenCalled()
  })

  it('still counts the maintenance answer against the circuit breaker', async () => {
    const breaker = getCircuitBreaker(originKeyOf('/api/x'))
    for (let i = 0; i < breaker.failureThreshold; i += 1) {
      baseApiFetch.mockResolvedValueOnce(res(503, { headers: branded }))
      await expect(apiFetch('/api/x')).rejects.toMatchObject({ status: 503 })
    }
    expect(breaker.canRequest()).toBe(false)
    expect(cb).toHaveBeenCalledTimes(breaker.failureThreshold)
  })

  it('signals on the FIRST branded answer, before the retry budget is spent', async () => {
    baseApiFetch
      .mockResolvedValueOnce(res(503, { headers: branded }))
      .mockResolvedValueOnce(res(200, { body: { ok: true } }))
    await expect(apiFetch('/api/x', { retries: 1, retryBaseMs: 1, retryMaxMs: 1 })).resolves.toEqual({
      ok: true,
    })
    expect(baseApiFetch).toHaveBeenCalledTimes(2)
    expect(cb).toHaveBeenCalledTimes(1)
  })

  it('a throwing callback never changes the thrown error', async () => {
    cb.mockImplementation(() => {
      throw new Error('ui exploded')
    })
    baseApiFetch.mockResolvedValueOnce(res(503, { headers: branded, body: { detail: 'updating' } }))
    const err = await apiFetch('/api/x').catch((e) => e)
    expect(err.status).toBe(503)
    expect(err.message).toBe('updating')
  })

  it('no callback registered → plain failure path', async () => {
    setMaintenanceCallback(null)
    baseApiFetch.mockResolvedValueOnce(res(503, { headers: branded }))
    await expect(apiFetch('/api/x')).rejects.toMatchObject({ status: 503 })
  })
})
