import { apiFetch } from './apiBase'

// Transparent retry for scan-intake POSTs.
//
// The platform sheds NEW scan intake transiently with two self-protecting codes, both advertising
// Retry-After so a correct client backs off and retries instead of surfacing a hard failure to the
// operator:
//   * 429 `rate_limited` — per-tenant / per-IP burst limit.
//   * 503 `load_shed`    — self-heal recovery, engaged under genuine saturation (DB pool exhausted
//                          or async backlog past its critical threshold); auto-clears on a TTL.
// A brief automatic back-off is the correct UX for a heavyweight scan launch: the operator's click
// lands once the platform drains rather than erroring on a condition that resolves itself in
// seconds. Scoped to scan dispatch only — the global apiFetch still fails fast for every other
// request — and bounded so a persistently-shedding platform still returns control to the caller.
const SHED_STATUS = new Set([429, 503])
const MAX_RETRIES = 3
const WAIT_CAP_MS = 15000

function shedWaitMs(response, attempt) {
  const header = response?.headers?.get?.('Retry-After')
  const secs = header ? parseInt(header, 10) : NaN
  if (Number.isFinite(secs) && secs > 0) return Math.min(secs * 1000, WAIT_CAP_MS)
  return Math.min(1500 * attempt, WAIT_CAP_MS)
}

/**
 * apiFetch for a scan-intake POST that rides out transient shedding (429/503), honoring
 * Retry-After. `init.body` must be a reusable value (e.g. a JSON string) — the request is
 * re-issued verbatim on each retry. Returns the final Response with its body unconsumed, so
 * the caller still owns `.json()` / `.ok` / `.status` exactly as with a bare apiFetch.
 */
export async function apiFetchScanIntake(path, init) {
  let response = await apiFetch(path, init)
  for (let attempt = 1; attempt <= MAX_RETRIES && SHED_STATUS.has(response.status); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, shedWaitMs(response, attempt)))
    response = await apiFetch(path, init)
  }
  return response
}
