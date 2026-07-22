import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../utils/apiFetch'

let cachedPayload = null
let fetchPromise = null

async function fetchAgentStatus(force = false) {
  if (!force && cachedPayload) return cachedPayload
  if (!fetchPromise || force) {
    fetchPromise = apiFetch('/api/agents/status')
      .then((data) => {
        cachedPayload = data || { agents: [], online_count: 0 }
        return cachedPayload
      })
      .catch(() => {
        const empty = { agents: [], online_count: 0 }
        if (!cachedPayload) cachedPayload = empty
        return cachedPayload
      })
      .finally(() => {
        fetchPromise = null
      })
  }
  return fetchPromise
}

export function invalidateAgentFleetCache() {
  cachedPayload = null
  fetchPromise = null
}

/** Live endpoint-agent fleet from GET /api/agents/status (singleton cache). */
export function useAgentFleetStatus() {
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
