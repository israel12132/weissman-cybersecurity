/**
 * Step-up assertion token cache (in-memory, short-lived).
 *
 * A step-up token proves the operator re-authenticated *recently* (fresh TOTP) and is
 * presented in the `X-Weissman-StepUp` header on privileged operations, where the backend
 * verifies it via `crate::auth_stepup::require_step_up`. It is minted by
 * `POST /api/auth/step-up` and lives only ~5 minutes.
 *
 * Blast-radius policy: this is a re-auth assertion, so — like the access token's primary
 * store in lib/apiBase — it is kept ONLY in memory. It is deliberately never written to
 * sessionStorage/localStorage: it must not survive a tab reload (a fresh privileged action
 * should re-prompt) and must not be an XSS-exfiltration target. It is cleared eagerly once
 * expired so a stale token is never attached to a request.
 */

/** HTTP header the backend reads the step-up assertion from (auth_stepup::STEP_UP_HEADER). */
export const STEP_UP_HEADER = 'X-Weissman-StepUp'

/**
 * Skew guard: treat the token as expired this many seconds BEFORE the server's stated
 * expiry, so we never present a token the server will reject for a clock skew of a few
 * seconds (which would surface as a spurious second step-up prompt).
 */
const EXPIRY_SKEW_SECONDS = 15

let token = null
let expiresAtMs = 0

/**
 * Store a freshly minted step-up token.
 * @param {string} value the `step_up_token` from POST /api/auth/step-up
 * @param {number} [expiresInSeconds] the response `expires_in` (defaults to 300s)
 */
export function setStepUpToken(value, expiresInSeconds) {
  const v = typeof value === 'string' ? value.trim() : ''
  if (!v) {
    clearStepUpToken()
    return
  }
  const ttl = Number.isFinite(expiresInSeconds) && expiresInSeconds > 0 ? expiresInSeconds : 300
  token = v
  expiresAtMs = Date.now() + Math.max(0, ttl - EXPIRY_SKEW_SECONDS) * 1000
}

/**
 * Return a still-valid cached step-up token, or null. Clears the cache once expired so the
 * next privileged action re-prompts rather than sending a token the server will reject.
 * @returns {string|null}
 */
export function getStepUpToken() {
  if (!token) return null
  if (Date.now() >= expiresAtMs) {
    clearStepUpToken()
    return null
  }
  return token
}

/** Forget any cached step-up token (e.g. on logout, or after a rejected assertion). */
export function clearStepUpToken() {
  token = null
  expiresAtMs = 0
}

/**
 * Header object attaching the cached step-up token, or `{}` when none is valid. Spread into
 * a fetch/apiFetch `headers` to proactively satisfy a step-up gate without a round-trip.
 * @returns {Record<string,string>}
 */
export function stepUpHeaders() {
  const t = getStepUpToken()
  return t ? { [STEP_UP_HEADER]: t } : {}
}
