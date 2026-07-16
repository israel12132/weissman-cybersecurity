import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock the low-level transport so we exercise the hardening logic in isolation.
const { baseApiFetch } = vi.hoisted(() => ({ baseApiFetch: vi.fn() }))
vi.mock('../lib/apiBase', () => ({
  apiFetch: baseApiFetch,
  setRateLimitToastCallback: vi.fn(),
  getRateLimitToastCallback: () => null,
}))

import { apiFetch, v } from './apiFetch'
import { CircuitOpenError, BoundaryValidationError, _resetCircuitBreakers } from '../lib/resilience'

function jsonResponse(body, { status = 200 } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (h) => (h.toLowerCase() === 'content-type' ? 'application/json' : null) },
    json: async () => body,
    clone() {
      return this
    },
  }
}

beforeEach(() => {
  _resetCircuitBreakers()
  baseApiFetch.mockReset()
})

describe('apiFetch success + boundary validation', () => {
  it('returns parsed JSON on success', async () => {
    baseApiFetch.mockResolvedValueOnce(jsonResponse({ ok: true, value: 42 }))
    await expect(apiFetch('/api/thing')).resolves.toEqual({ ok: true, value: 42 })
  })

  it('validates the decoded payload and returns it when well-formed', async () => {
    baseApiFetch.mockResolvedValueOnce(jsonResponse({ id: 'f1', severity: 'high' }))
    const schema = v.shape({ id: v.string(), severity: v.string() })
    await expect(apiFetch('/api/finding', { validate: schema })).resolves.toEqual({
      id: 'f1',
      severity: 'high',
    })
  })

  it('rejects a tampered payload before returning it to the caller', async () => {
    baseApiFetch.mockResolvedValueOnce(jsonResponse({ id: 'f1', severity: 999 }))
    const schema = v.shape({ id: v.string(), severity: v.string() })
    await expect(apiFetch('/api/finding', { validate: schema })).rejects.toBeInstanceOf(
      BoundaryValidationError,
    )
  })

  it('runs the attestation hook and can drop unverified data', async () => {
    baseApiFetch.mockResolvedValueOnce(jsonResponse({ finding: 'x', verified: false }))
    const attestVerify = async (data) => {
      if (!data.verified) throw new Error('unverified finding')
      return data
    }
    await expect(apiFetch('/api/finding', { attestVerify })).rejects.toThrow('unverified finding')
  })
})

describe('apiFetch retries with backoff', () => {
  it('retries a retryable 503 then resolves', async () => {
    baseApiFetch
      .mockResolvedValueOnce(jsonResponse({ detail: 'overloaded' }, { status: 503 }))
      .mockResolvedValueOnce(jsonResponse({ ok: true }))
    const out = await apiFetch('/api/thing', { retries: 2, retryBaseMs: 1, retryMaxMs: 1 })
    expect(out).toEqual({ ok: true })
    expect(baseApiFetch).toHaveBeenCalledTimes(2)
  })

  it('does not retry a non-retryable 400', async () => {
    baseApiFetch.mockResolvedValueOnce(jsonResponse({ detail: 'bad request' }, { status: 400 }))
    await expect(apiFetch('/api/thing', { retries: 3, retryBaseMs: 1 })).rejects.toMatchObject({
      status: 400,
    })
    expect(baseApiFetch).toHaveBeenCalledTimes(1)
  })
})

describe('apiFetch circuit breaker', () => {
  it('opens after sustained failures and short-circuits further calls', async () => {
    // Default threshold is 6 consecutive failures on the shared (localhost) origin.
    baseApiFetch.mockResolvedValue(jsonResponse({ detail: 'down' }, { status: 500 }))
    for (let i = 0; i < 6; i++) {
      await expect(apiFetch('/api/thing')).rejects.toMatchObject({ status: 500 })
    }
    const callsBefore = baseApiFetch.mock.calls.length
    // Breaker is now open — the next call must short-circuit without hitting transport.
    await expect(apiFetch('/api/thing')).rejects.toBeInstanceOf(CircuitOpenError)
    expect(baseApiFetch.mock.calls.length).toBe(callsBefore)
  })

  it('a successful response keeps the breaker closed', async () => {
    baseApiFetch.mockResolvedValue(jsonResponse({ ok: true }))
    for (let i = 0; i < 10; i++) {
      await expect(apiFetch('/api/thing')).resolves.toEqual({ ok: true })
    }
  })
})
