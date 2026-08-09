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
        if (data?.engines && typeof data.engines === 'object') {
          cachedSummary = data.engines
          return cachedSummary
        }
        // Do NOT cache an empty/failed response: caching `{}` pinned "no run
        // history" for every engine card for the tab's lifetime, indistinguishable
        // from a platform that has genuinely never run a scan. Return last-known
        // (or {}) for this call only and leave the cache untouched to allow retry.
        return cachedSummary || {}
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
