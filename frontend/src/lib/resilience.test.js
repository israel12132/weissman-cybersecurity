import { describe, it, expect, beforeEach } from 'vitest'
import {
  isRetryableStatus,
  computeBackoffDelay,
  CircuitBreaker,
  CircuitOpenError,
  BoundaryValidationError,
  getCircuitBreaker,
  _resetCircuitBreakers,
  originKeyOf,
  validateAtBoundary,
  v,
} from './resilience'

describe('isRetryableStatus', () => {
  it('retries transient server / rate-limit / timeout statuses', () => {
    for (const s of [408, 425, 429, 500, 502, 503, 504]) expect(isRetryableStatus(s)).toBe(true)
  })
  it('does not retry client errors or success', () => {
    for (const s of [200, 201, 400, 401, 403, 404, 422]) expect(isRetryableStatus(s)).toBe(false)
  })
})

describe('computeBackoffDelay', () => {
  it('grows exponentially and is capped by maxMs (no jitter)', () => {
    const opts = { baseMs: 100, factor: 2, maxMs: 800, jitter: 'none' }
    expect(computeBackoffDelay(0, opts)).toBe(100)
    expect(computeBackoffDelay(1, opts)).toBe(200)
    expect(computeBackoffDelay(2, opts)).toBe(400)
    expect(computeBackoffDelay(3, opts)).toBe(800)
    expect(computeBackoffDelay(4, opts)).toBe(800) // capped
  })

  it('full jitter stays within [0, exp] using injected RNG', () => {
    const opts = { baseMs: 100, factor: 2, maxMs: 10000, jitter: 'full' }
    expect(computeBackoffDelay(3, { ...opts, random: () => 0 })).toBe(0)
    expect(computeBackoffDelay(3, { ...opts, random: () => 1 })).toBe(800)
    expect(computeBackoffDelay(3, { ...opts, random: () => 0.5 })).toBe(400)
  })

  it('equal jitter stays within [exp/2, exp]', () => {
    const opts = { baseMs: 100, factor: 2, maxMs: 10000, jitter: 'equal' }
    expect(computeBackoffDelay(2, { ...opts, random: () => 0 })).toBe(200) // exp=400 -> 200
    expect(computeBackoffDelay(2, { ...opts, random: () => 1 })).toBe(400)
  })

  it('treats negative attempts as attempt 0', () => {
    expect(computeBackoffDelay(-5, { baseMs: 100, jitter: 'none' })).toBe(100)
  })
})

describe('CircuitBreaker', () => {
  it('opens after the failure threshold and short-circuits', () => {
    let t = 0
    const b = new CircuitBreaker({ failureThreshold: 3, cooldownMs: 1000, now: () => t })
    expect(b.canRequest()).toBe(true)
    b.onFailure()
    b.onFailure()
    expect(b.state).toBe('closed')
    b.onFailure() // 3rd -> trip
    expect(b.state).toBe('open')
    expect(b.canRequest()).toBe(false)
  })

  it('a success resets the failure count', () => {
    const b = new CircuitBreaker({ failureThreshold: 3 })
    b.onFailure()
    b.onFailure()
    b.onSuccess()
    b.onFailure()
    b.onFailure()
    expect(b.state).toBe('closed') // never reached 3 consecutive
  })

  it('transitions open -> half-open after cooldown, and closes on trial success', () => {
    let t = 0
    const b = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 1000, now: () => t })
    b.onFailure() // open
    expect(b.canRequest()).toBe(false)
    t = 999
    expect(b.canRequest()).toBe(false) // still cooling
    t = 1000
    expect(b.canRequest()).toBe(true) // -> half-open
    expect(b.state).toBe('half-open')
    b.onTrialStart()
    expect(b.canRequest()).toBe(false) // trial slot consumed (halfOpenMax=1)
    b.onSuccess()
    expect(b.state).toBe('closed')
  })

  it('a failed half-open trial re-opens the breaker', () => {
    let t = 0
    const b = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 100, now: () => t })
    b.onFailure()
    t = 100
    b.canRequest() // -> half-open
    b.onTrialStart()
    b.onFailure() // re-trip
    expect(b.state).toBe('open')
    expect(b.openedAt).toBe(100)
  })
})

describe('getCircuitBreaker registry', () => {
  beforeEach(() => _resetCircuitBreakers())
  it('returns the same instance per key and resets on demand', () => {
    const a1 = getCircuitBreaker('https://a.test')
    const a2 = getCircuitBreaker('https://a.test')
    expect(a1).toBe(a2)
    expect(getCircuitBreaker('https://b.test')).not.toBe(a1)
    _resetCircuitBreakers()
    expect(getCircuitBreaker('https://a.test')).not.toBe(a1)
  })
})

describe('originKeyOf', () => {
  it('extracts the origin from absolute URLs', () => {
    expect(originKeyOf('https://api.example.com/v1/health')).toBe('https://api.example.com')
  })
  it('resolves relative URLs against the current origin', () => {
    // jsdom default origin is http://localhost:3000
    expect(originKeyOf('/api/health')).toBe('http://localhost:3000')
  })
})

describe('boundary validation', () => {
  const findingSchema = v.shape({
    id: v.string(),
    severity: v.string(),
    verified: v.boolean(),
    cve: v.optional(v.string()),
    tags: v.arrayOf(v.string()),
  })

  it('accepts and returns a well-formed payload', () => {
    const input = { id: 'f1', severity: 'high', verified: true, tags: ['a', 'b'] }
    expect(validateAtBoundary(input, findingSchema)).toEqual(input)
  })

  it('rejects a tampered payload (wrong field type) before it reaches the UI', () => {
    const bad = { id: 'f1', severity: 'high', verified: 'yes', tags: [] }
    expect(() => validateAtBoundary(bad, findingSchema)).toThrow(BoundaryValidationError)
  })

  it('rejects a missing required field with a path', () => {
    try {
      validateAtBoundary({ id: 'f1', severity: 'high', tags: [] }, findingSchema)
      throw new Error('should have thrown')
    } catch (e) {
      expect(e).toBeInstanceOf(BoundaryValidationError)
      expect(e.path).toBe('response.verified')
    }
  })

  it('rejects a non-string array element', () => {
    const bad = { id: 'f1', severity: 'high', verified: true, tags: ['ok', 3] }
    expect(() => validateAtBoundary(bad, findingSchema)).toThrow(/tags\[1\]/)
  })

  it('optional fields may be absent but are validated when present', () => {
    expect(() =>
      validateAtBoundary(
        { id: 'f1', severity: 'high', verified: true, cve: 123, tags: [] },
        findingSchema,
      ),
    ).toThrow(BoundaryValidationError)
  })

  it('is a no-op when no validator is supplied', () => {
    const raw = { anything: true }
    expect(validateAtBoundary(raw, undefined)).toBe(raw)
  })
})

describe('error types carry stable codes', () => {
  it('CircuitOpenError', () => {
    expect(new CircuitOpenError().code).toBe('CIRCUIT_OPEN')
  })
  it('BoundaryValidationError', () => {
    expect(new BoundaryValidationError('x', 'a.b').code).toBe('BOUNDARY_VALIDATION')
  })
})
