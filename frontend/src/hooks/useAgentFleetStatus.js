import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../utils/apiFetch'

let cachedPayload = null
let cachedAt = 0
let fetchPromise = null
// The fleet gates agent-required engine surfaces; a stale snapshot leaves an
// operator either blocked after enrolling an agent or dispatching scans at an
// offline fleet. Re-fetch after this window rather than pinning it for the tab.
const CACHE_TTL_MS = 30_000

function fleetCacheValid() {
  return cachedPayload != null && Date.now() - cachedAt < CACHE_TTL_MS
}

async function fetchAgentStatus(force = false) {
  if (!force && fleetCacheValid()) return cachedPayload
  if (!fetchPromise || force) {
    fetchPromise = apiFetch('/api/agents/status')
      .then((data) => {
        cachedPayload = data || { agents: [], online_count: 0 }
        cachedAt = Date.now()
        return cachedPayload
      })
      .catch(() => {
        // Do NOT cache the empty fallback: a single transient boot failure must
        // not pin an empty fleet (and thus block agent surfaces) for the session.
        // Leave the cache untouched so the next load retries.
        return cachedPayload || { agents: [], online_count: 0 }
      })
      .finally(() => {
        fetchPromise = null
      })
  }
  return fetchPromise
}

export function invalidateAgentFleetCache() {
  cachedPayload = null
  cachedAt = 0
  fetchPromise = null
}

/** Live endpoint-agent fleet from GET /api/agents/status (singleton cache). */
export function useAgentFleetStatus() {
  const [payload, setPayload] = useState(cachedPayload)
  const [loading, setLoading] = useState(!cachedPayload)
  const [error, setError] = useState(null)

  const load = useCallback(async (force = false) => {
    if (!force && fleetCacheValid()) {
      setPayload(cachedPayload)
      setLoading(false)
      return cachedPayload
    }
    setLoading(true)
    setError(null)
    try {
      const data = await fetchAgentStatus(force)
      setPayload(data)
      return data
    } catch (e) {
      setError(e?.message || 'Failed to load agent fleet status')
      return cachedPayload
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(false)
  }, [load])

  const agents = Array.isArray(payload?.agents) ? payload.agents : []
  const onlineCount =
    typeof payload?.online_count === 'number'
      ? payload.online_count
      : agents.filter((a) => a?.online).length

  return {
    agents,
    onlineCount,
    hasOnlineAgent: onlineCount > 0,
    loading,
    error,
    refresh: () => load(true),
  }
}
