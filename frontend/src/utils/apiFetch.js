/**
 * Unified JSON API client built on lib/apiBase (apiUrl, auth, token refresh),
 * hardened with the resilience primitives in lib/resilience:
 *
 *  - Per-origin circuit breaker: under sustained backend failure the client
 *    short-circuits instead of piling on load (no self-inflicted DDoS), then
 *    probes for recovery with a single half-open trial.
 *  - Full-jitter exponential backoff for opt-in retries (idempotent calls).
 *  - Runtime boundary validation: pass `options.validate` (a resilience `v.*`
 *    schema) and a tampered/malformed payload is rejected before it reaches the
 *    React render cycle. This is the JS analog of typed boundaries.
 *  - Attestation hook: pass `options.attestVerify` (async) to verify a payload's
 *    cryptographic provenance (see forensic/forensicProvenanceClient) so the UI
 *    never renders unverified findings.
 *
 * All new behavior is opt-in; existing callers keep their exact semantics.
 * 429 toast handling shares the callback registered by RateLimitProvider via
 * lib/apiBase so both clients show the same global rate-limit toast.
 */

import { apiFetch as baseApiFetch, setRateLimitToastCallback } from '../lib/apiBase.js'
import {
  isRetryableStatus,
  computeBackoffDelay,
  getCircuitBreaker,
  originKeyOf,
  validateAtBoundary,
  CircuitOpenError,
} from '../lib/resilience'

export { setRateLimitToastCallback }
export { CircuitOpenError, BoundaryValidationError, v } from '../lib/resilience'

function parseRetryAfter(retryAfterHeader) {
  if (!retryAfterHeader) return 60
  const seconds = parseInt(retryAfterHeader, 10)
  if (!Number.isNaN(seconds)) return seconds
  try {
    const date = new Date(retryAfterHeader)
    const diff = Math.floor((date - new Date()) / 1000)
    return diff > 0 ? diff : 60
  } catch {
    return 60
  }
}

async function readErrorMessage(response) {
  let errorMessage = `HTTP ${response.status}: ${response.statusText}`
  try {
    const errorData = await response.clone().json()
    errorMessage = errorData.detail || errorData.message || errorData.error || errorMessage
  } catch {
    // ignore JSON parse errors
  }
  return errorMessage
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/**
 * Fetch JSON from API paths (relative or absolute). Throws on non-OK responses.
 *
 * @param {string} url
 * @param {object} [options] fetch init plus:
 *   retries        {number}   opt-in retry budget for retryable statuses (default 0)
 *   retryBaseMs    {number}   backoff base ms (default 300)
 *   retryMaxMs     {number}   backoff cap ms (default 15000)
 *   validate       {Function} resilience validator run on the decoded JSON
 *   attestVerify   {Function} async (data) => data | throws — provenance check
 *   breaker        {boolean}  set false to bypass the circuit breaker (default true)
 */
export async function apiFetch(url, options = {}) {
  const {
    method = 'GET',
    body,
    headers = {},
    credentials = 'include',
    // Explicit binary/raw bypass: when true, a 2xx response is returned unparsed
    // (the caller reads .blob()/.text()/.headers itself) instead of relying on the
    // content-type sniff below. Used by PDF/CSV downloads and by tolerant-parse
    // callers (e.g. useApiQuery) that must not throw on an empty/malformed body.
    raw = false,
    retries = 0,
    retryDelay, // legacy: fixed base delay (still honored if provided)
    retryBaseMs = 300,
    retryMaxMs = 15000,
    validate,
    attestVerify,
    breaker = true,
    _attempt = 0,
    ...restOptions
  } = options

  const finalHeaders = { ...headers }
  const init = {
    method,
    headers: finalHeaders,
    credentials,
    ...restOptions,
  }

  if (body != null && typeof body === 'object' && !(body instanceof FormData)) {
    if (!finalHeaders['Content-Type'] && !finalHeaders['content-type']) {
      init.headers = { ...finalHeaders, 'Content-Type': 'application/json' }
    }
    init.body = JSON.stringify(body)
  } else if (body != null) {
    init.body = body
  }

  // Circuit breaker: short-circuit a backend that is failing hard.
  const cb = breaker ? getCircuitBreaker(originKeyOf(url)) : null
  if (cb && !cb.canRequest()) {
    throw new CircuitOpenError()
  }
  if (cb) cb.onTrialStart()

  const retryOrThrow = async (error) => {
    if (cb) cb.onFailure()
    const status = error?.status
    const retryable = status === undefined || isRetryableStatus(status)
    // 429 is surfaced immediately (apiBase fired the shared toast + Retry-After
    // drives the wait), never auto-retried.
    if (status !== 429 && retryable && _attempt < retries) {
      const base = typeof retryDelay === 'number' ? retryDelay : retryBaseMs
      const delay = computeBackoffDelay(_attempt, { baseMs: base, maxMs: retryMaxMs })
      await sleep(delay)
      return apiFetch(url, { ...options, _attempt: _attempt + 1 })
    }
    throw error
  }

  let response
  try {
    response = await baseApiFetch(url, init)
  } catch (networkError) {
    // Transport-level failure (offline, DNS, TLS): retryable + counts against breaker.
    return retryOrThrow(networkError)
  }

  if (response.status === 429) {
    // apiBase.apiFetch already fired the shared rate-limit toast for this 429
    // (apiBase.js line ~226); do NOT re-fire it here or every rate-limited
    // request double-toasts. Attach the Response so catch-side formatters can
    // read the body, and count the 429 against the breaker.
    const retryAfter = parseRetryAfter(response.headers.get('Retry-After'))
    const errorMessage = await readErrorMessage(response)
    if (cb) cb.onFailure()
    const error = new Error(errorMessage)
    error.status = 429
    error.retryAfter = retryAfter
    error.response = response
    throw error
  }

  if (!response.ok) {
    const errorMessage = await readErrorMessage(response)
    const error = new Error(errorMessage)
    error.status = response.status
    error.response = response
    return retryOrThrow(error)
  }

  // Success path: the backend answered cleanly → close the breaker.
  if (cb) cb.onSuccess()

  // Explicit raw bypass: return the unparsed 2xx Response (PDF/CSV downloads,
  // tolerant-parse callers) before the JSON sniff/validation below.
  if (raw) return response

  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    let data = await response.json()
    // Strict boundary: drop malformed/tampered shapes before they reach React.
    data = validateAtBoundary(data, validate)
    // Cryptographic integrity: verify provenance/attestation when required.
    if (typeof attestVerify === 'function') {
      data = await attestVerify(data)
    }
    return data
  }

  return response
}

export const api = {
  get: (url, options = {}) => apiFetch(url, { ...options, method: 'GET' }),
  post: (url, body, options = {}) => apiFetch(url, { ...options, method: 'POST', body }),
  put: (url, body, options = {}) => apiFetch(url, { ...options, method: 'PUT', body }),
  patch: (url, body, options = {}) => apiFetch(url, { ...options, method: 'PATCH', body }),
  delete: (url, options = {}) => apiFetch(url, { ...options, method: 'DELETE' }),
}

export default apiFetch
