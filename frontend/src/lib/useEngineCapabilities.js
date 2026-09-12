import { useCallback, useEffect, useMemo, useState } from 'react'
import { apiFetch } from './apiBase'

// Singleton cache so many cards/pages share one fetch of /api/engines/capabilities.
let cachedPayload = null
let fetchPromise = null

function buildMaps(payload) {
  const byId = {}
  const kindById = {}
  if (Array.isArray(payload?.engines)) {
    for (const e of payload.engines) {
      if (!e || typeof e.id !== 'string') continue
      byId[e.id] = e
      kindById[e.id] = e.kind
    }
  }
  return { byId, kindById }
}

function markUnavailable(err, fallbackMessage) {
  const wrapped = err instanceof Error ? err : new Error(fallbackMessage)
  wrapped.unavailable = true
  return wrapped
}

async function fetchCapabilities(force = false) {
  if (!force && cachedPayload) return cachedPayload
  if (!fetchPromise || force) {
    fetchPromise = apiFetch('/api/engines/capabilities')
      .then(async (r) => {
        if (!r || typeof r.ok !== 'boolean') {
          // utils-style clients may already return parsed JSON.
          if (r && typeof r === 'object' && Array.isArray(r.engines)) {
            cachedPayload = r
            return cachedPayload
          }
          throw markUnavailable(new Error('capabilities manifest missing'), 'capabilities manifest missing')
        }
        if (!r.ok) {
          const err = new Error(`capabilities HTTP ${r.status}`)
          err.status = r.status
          throw markUnavailable(err, 'capabilities unavailable')
        }
        const data = await r.json()
        if (!data || typeof data !== 'object' || !Array.isArray(data.engines)) {
          throw markUnavailable(new Error('capabilities manifest missing'), 'capabilities manifest missing')
        }
        cachedPayload = data
        return cachedPayload
      })
      .catch((err) => {
        throw markUnavailable(err, 'Failed to load engine capabilities')
      })
      .finally(() => {
        fetchPromise = null
      })
  }
  return fetchPromise
}

/** Clear the singleton cache (e.g. after deploy or manual refresh). */
export function invalidateEngineCapabilitiesCache() {
  cachedPayload = null
  fetchPromise = null
}

/**
 * Full capabilities payload from GET /api/engines/capabilities:
 * engines (id, kind, canonical?, remote_detection), summary counts, total, legend.
 */
export function useEngineCapabilities() {
  const [payload, setPayload] = useState(cachedPayload)
  const [loading, setLoading] = useState(!cachedPayload)
  const [error, setError] = useState(null)
  const [unavailable, setUnavailable] = useState(false)

  const load = useCallback(async (force = false) => {
    if (!force && cachedPayload) {
      setPayload(cachedPayload)
      setLoading(false)
      setUnavailable(false)
      setError(null)
      return cachedPayload
    }
    setLoading(true)
    setError(null)
    try {
      const data = await fetchCapabilities(force)
      setUnavailable(false)
      setPayload(data)
      return data
    } catch (e) {
      setError(e?.message || 'Failed to load engine capabilities')
      setUnavailable(true)
      return cachedPayload
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(false)
  }, [load])

  const { byId, kindById } = useMemo(() => buildMaps(payload), [payload])

  const summary = payload?.summary ?? {}
  const total = payload?.total ?? 0
  const legend = payload?.legend ?? {}

  const remoteDetectionCount = useMemo(
    () => Object.values(byId).filter((e) => e?.remote_detection).length,
    [byId],
  )

  const getEngine = useCallback((engineId) => byId[engineId] ?? null, [byId])

  return {
    /** Full API payload including cryptographic `provenance` manifest. */
    payload,
    /** @deprecated prefer `byId` — kept for existing callers */
    kindById,
    byId,
    summary,
    total,
    legend,
    remoteDetectionCount,
    getEngine,
    loading,
    error,
    unavailable,
    refresh: () => load(true),
  }
}
