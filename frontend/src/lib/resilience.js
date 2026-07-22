/**
 * Network resilience primitives for the unified API layer: full-jitter
 * exponential backoff, a per-origin circuit breaker, and runtime boundary
 * validation.
 *
 * Design goals:
 *  - Deterministic + unit-testable: every source of nondeterminism (`Date.now`,
 *    `Math.random`) is injectable, so backoff and breaker transitions are tested
 *    without timers or flakiness.
 *  - Graceful degradation under backend distress: the circuit breaker stops the
 *    frontend from hammering an overloaded/attacked server (self-inflicted DDoS),
 *    then probes for recovery with a single half-open trial.
 *  - Strict boundary validation: this is a JavaScript codebase (no static types),
 *    so the security control is *runtime* validation — a tampered or malformed
 *    payload is rejected before it reaches the React render cycle.
 */

/** Statuses worth retrying: transient server / rate-limit / timeout conditions. */
export function isRetryableStatus(status) {
  return (
    status === 408 || // Request Timeout
    status === 425 || // Too Early
    status === 429 || // Too Many Requests
    status === 500 ||
    status === 502 ||
    status === 503 ||
    status === 504
  )
}

/**
 * Full-jitter exponential backoff (AWS "Exponential Backoff And Jitter").
 * Returns a delay in ms bounded by `maxMs`. Full jitter picks uniformly in
 * `[0, exp]`, which minimizes retry collisions across many clients better than
 * fixed or "equal" jitter.
 *
 * @param {number} attempt 0-based retry attempt index
 * @param {{baseMs?:number,maxMs?:number,factor?:number,jitter?:'full'|'equal'|'none',random?:()=>number}} [opts]
 */
export function computeBackoffDelay(attempt, opts = {}) {
  const { baseMs = 300, maxMs = 15000, factor = 2, jitter = 'full', random = Math.random } = opts
  const n = Math.max(0, attempt | 0)
  const exp = Math.min(maxMs, baseMs * Math.pow(factor, n))
  if (jitter === 'none') return exp
  if (jitter === 'equal') return exp / 2 + random() * (exp / 2)
  return random() * exp // full jitter
}

/** Thrown when the circuit breaker is open and short-circuits a request. */
export class CircuitOpenError extends Error {
  constructor(message = 'circuit open: backend temporarily unavailable') {
    super(message)
    this.name = 'CircuitOpenError'
    this.code = 'CIRCUIT_OPEN'
  }
}

/** Thrown when a response fails boundary validation (shape mismatch / tamper). */
export class BoundaryValidationError extends Error {
  constructor(message, path) {
    super(message)
    this.name = 'BoundaryValidationError'
    this.code = 'BOUNDARY_VALIDATION'
    this.path = path
  }
}

/**
 * Per-origin circuit breaker with the standard three states:
 *   closed  → requests flow; consecutive failures accumulate.
 *   open    → requests short-circuit until `cooldownMs` elapses.
 *   half-open → a limited number of trial requests probe recovery; any failure
 *               re-opens, a success closes.
 */
export class CircuitBreaker {
  constructor({ failureThreshold = 6, cooldownMs = 10000, halfOpenMax = 1, now = () => Date.now() } = {}) {
    this.failureThreshold = failureThreshold
    this.cooldownMs = cooldownMs
    this.halfOpenMax = halfOpenMax
    this._now = now
    this.state = 'closed'
    this.failures = 0
    this.openedAt = 0
    this.halfOpenInFlight = 0
  }

  /** Whether a request may proceed now (transitions open→half-open when cooled down). */
  canRequest() {
    if (this.state === 'closed') return true
    if (this.state === 'open') {
      if (this._now() - this.openedAt >= this.cooldownMs) {
        this.state = 'half-open'
        this.halfOpenInFlight = 0
        return true
      }
      return false
    }
    return this.halfOpenInFlight < this.halfOpenMax
  }

  /** Record that a trial (half-open) request is now in flight. */
  onTrialStart() {
    if (this.state === 'half-open') this.halfOpenInFlight += 1
  }

  onSuccess() {
    this.failures = 0
    this.halfOpenInFlight = 0
    this.state = 'closed'
  }

  onFailure() {
    if (this.state === 'half-open') {
      this.trip()
      return
    }
    this.failures += 1
    if (this.failures >= this.failureThreshold) this.trip()
  }

  trip() {
    this.state = 'open'
    this.openedAt = this._now()
    this.halfOpenInFlight = 0
  }
}

/** Registry of per-origin breakers so one struggling backend can't cascade. */
const breakers = new Map()

/** Get (or lazily create) the circuit breaker for an origin key. */
export function getCircuitBreaker(originKey, opts) {
  let b = breakers.get(originKey)
  if (!b) {
    b = new CircuitBreaker(opts)
    breakers.set(originKey, b)
  }
  return b
}

/** Test/reset hook — clears all registered breakers. */
export function _resetCircuitBreakers() {
  breakers.clear()
}

/** Derive a stable origin key from a URL (falls back to the raw string). */
export function originKeyOf(url) {
  try {
    return new URL(url, typeof window !== 'undefined' ? window.location?.href : 'http://localhost').origin
  } catch {
    return String(url)
  }
}

/**
 * Minimal validator combinators — the JS analog of typed boundaries. Each
 * validator is `(value, path) => value` and throws `BoundaryValidationError`
 * on mismatch. Compose with `shape`/`arrayOf`/`optional`.
 */
export const v = {
  string:
    () =>
    (x, p = 'value') => {
      if (typeof x !== 'string') throw new BoundaryValidationError(`expected string at ${p}`, p)
      return x
    },
  number:
    () =>
    (x, p = 'value') => {
      if (typeof x !== 'number' || Number.isNaN(x))
        throw new BoundaryValidationError(`expected number at ${p}`, p)
      return x
    },
  boolean:
    () =>
    (x, p = 'value') => {
      if (typeof x !== 'boolean') throw new BoundaryValidationError(`expected boolean at ${p}`, p)
      return x
    },
  literal:
    (lit) =>
    (x, p = 'value') => {
      if (x !== lit) throw new BoundaryValidationError(`expected ${JSON.stringify(lit)} at ${p}`, p)
      return x
    },
  optional:
    (inner) =>
    (x, p = 'value') =>
      x === undefined || x === null ? x : inner(x, p),
  arrayOf:
    (inner) =>
    (x, p = 'value') => {
      if (!Array.isArray(x)) throw new BoundaryValidationError(`expected array at ${p}`, p)
      return x.map((el, i) => inner(el, `${p}[${i}]`))
    },
  shape:
    (fields) =>
    (x, p = 'value') => {
      if (x === null || typeof x !== 'object' || Array.isArray(x))
        throw new BoundaryValidationError(`expected object at ${p}`, p)
      const out = {}
      for (const key of Object.keys(fields)) {
        out[key] = fields[key](x[key], `${p}.${key}`)
      }
      return out
    },
}

/**
 * Validate a decoded payload at the trust boundary. Returns the (possibly
 * normalized) value, or throws `BoundaryValidationError`. A non-function
 * validator is a no-op so callers can opt in per endpoint.
 */
export function validateAtBoundary(data, validator, label = 'response') {
  if (typeof validator !== 'function') return data
  return validator(data, label)
}
