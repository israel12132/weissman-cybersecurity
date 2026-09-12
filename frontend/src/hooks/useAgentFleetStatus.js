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

function markUnavailable(err, fallbackMessage) {
  const wrapped = err instanceof Error ? err : new Error(fallbackMessage)
  wrapped.unavailable = true
  return wrapped
}

async function fetchAgentStatus(force = false) {
  if (!force && fleetCacheValid()) return cachedPayload
  if (!fetchPromise || force) {
    fetchPromise = apiFetch('/api/agents/status')
      .then((data) => {
        if (data instanceof Response) {
          throw markUnavailable(new Error('agent fleet status was not JSON'), 'agent fleet status was not JSON')
        }
        if (data?.unavailable === true || data?.ok === false) {
          throw markUnavailable(
            new Error(data?.detail || data?.message || 'agent fleet unavailable'),
            'agent fleet unavailable',
          )
        }
        const agents = Array.isArray(data?.agents) ? data.agents : []
        const onlineCount =
          typeof data?.online_count === 'number'
            ? data.online_count
            : agents.filter((a) => a?.online).length
        cachedPayload = { agents, online_count: onlineCount }
        cachedAt = Date.now()
        return cachedPayload
      })
      .catch((err) => {
        // Do NOT cache a failure as an empty fleet. A transport/5xx/404 miss
        // must not look like "zero agents enrolled" and block 58 engines.
        throw markUnavailable(err, 'Failed to load agent fleet status')
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
  const [unavailable, setUnavailable] = useState(false)

  const load = useCallback(async (force = false) => {
    if (!force && fleetCacheValid()) {
      setPayload(cachedPayload)
      setLoading(false)
      setUnavailable(false)
      setError(null)
      return cachedPayload
    }
    setLoading(true)
    setError(null)
    try {
      const data = await fetchAgentStatus(force)
      setUnavailable(false)
      setPayload(data)
      return data
    } catch (e) {
      setError(e?.message || 'Failed to load agent fleet status')
      setUnavailable(true)
      // Keep the last *successful* snapshot if we have one; never replace it
      // with a synthetic empty fleet.
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
    unavailable,
    refresh: () => load(true),
  }
}
