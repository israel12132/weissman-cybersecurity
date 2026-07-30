import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { apiFetch } from './apiBase'
import { apiFetchScanIntake } from './scanIntakeRetry'

vi.mock('./apiBase', () => ({ apiFetch: vi.fn() }))

function res(status, headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => lower[String(k).toLowerCase()] ?? null },
  }
}

describe('apiFetchScanIntake', () => {
  beforeEach(() => {
    apiFetch.mockReset()
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('passes a 202 straight through without retrying', async () => {
    apiFetch.mockResolvedValueOnce(res(202))
    const p = apiFetchScanIntake('/api/command-center/scan', { method: 'POST', body: '{}' })
    await vi.runAllTimersAsync()
    expect((await p).status).toBe(202)
    expect(apiFetch).toHaveBeenCalledTimes(1)
  })

  it('rides out a 503 load_shed and returns the eventual 202', async () => {
    apiFetch
      .mockResolvedValueOnce(res(503, { 'Retry-After': '1' }))
      .mockResolvedValueOnce(res(202))
    const p = apiFetchScanIntake('/api/command-center/scan', { method: 'POST', body: '{}' })
    await vi.runAllTimersAsync()
    expect((await p).status).toBe(202)
    expect(apiFetch).toHaveBeenCalledTimes(2)
  })

  it('also retries a 429 rate_limited', async () => {
    apiFetch
      .mockResolvedValueOnce(res(429, { 'Retry-After': '1' }))
      .mockResolvedValueOnce(res(202))
    const p = apiFetchScanIntake('/api/command-center/scan', { method: 'POST', body: '{}' })
    await vi.runAllTimersAsync()
    expect((await p).status).toBe(202)
    expect(apiFetch).toHaveBeenCalledTimes(2)
  })

  it('gives up after the retry budget and returns the last shed response', async () => {
    apiFetch.mockResolvedValue(res(503, { 'Retry-After': '1' }))
    const p = apiFetchScanIntake('/api/command-center/scan', { method: 'POST', body: '{}' })
    await vi.runAllTimersAsync()
    expect((await p).status).toBe(503)
    expect(apiFetch).toHaveBeenCalledTimes(4) // initial + 3 retries
  })

  it('does not retry a terminal 400', async () => {
    apiFetch.mockResolvedValueOnce(res(400))
    const p = apiFetchScanIntake('/api/command-center/scan', { method: 'POST', body: '{}' })
    await vi.runAllTimersAsync()
    expect((await p).status).toBe(400)
    expect(apiFetch).toHaveBeenCalledTimes(1)
  })
})
