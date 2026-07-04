import { apiFetch } from './apiBase'

let cachedSummary = null
let fetchPromise = null

/**
 * Latest job per engine in one request (GET /api/engines/history-summary).
 * Replaces N parallel /api/engines/history/:id calls on Engine Matrix.
 */
export async function fetchEngineHistorySummary({ force = false } = {}) {
  if (!force && cachedSummary) return cachedSummary
  if (!fetchPromise || force) {
    fetchPromise = apiFetch('/api/engines/history-summary')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        const engines = data?.engines && typeof data.engines === 'object' ? data.engines : {}
        cachedSummary = engines
        return engines
      })
      .catch(() => cachedSummary || {})
      .finally(() => {
        fetchPromise = null
      })
  }
  return fetchPromise
}

export function invalidateEngineHistorySummary() {
  cachedSummary = null
  fetchPromise = null
}
