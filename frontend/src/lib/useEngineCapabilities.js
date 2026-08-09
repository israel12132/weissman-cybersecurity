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

async function fetchCapabilities(force = false) {
  if (!force && cachedPayload) return cachedPayload
  if (!fetchPromise || force) {
    fetchPromise = apiFetch('/api/engines/capabilities')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (data && typeof data === 'object') {
          cachedPayload = data
          return cachedPayload
        }
        // A non-OK/empty response must NOT be cached as data: doing so pinned an
        // empty manifest for the whole session (and tripped the forensic badge's
        // false "capabilities manifest empty — cannot verify" tamper alarm).
        // Return a transient empty payload for this call only and leave the cache
        // untouched so the next mount retries.
        return cachedPayload || { engines: [], summary: {}, total: 0, legend: {} }
      })
      .catch(() => cachedPayload || { engines: [], summary: {}, total: 0, legend: {} })
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

  const load = useCallback(async (force = false) => {
    if (!force && cachedPayload) {
      setPayload(cachedPayload)
      setLoading(false)
      return cachedPayload
    }
    setLoading(true)
    setError(null)
    try {
      const data = await fetchCapabilities(force)
      setPayload(data)
      return data
    } catch (e) {
      setError(e?.message || 'Failed to load engine capabilities')
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
    refresh: () => load(true),
  }
}
