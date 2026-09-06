import { useCallback, useEffect, useState } from 'react'
import { apiFetch } from '../utils/apiFetch'

/**
 * Live GET /api/agents/queue — pending/running host tasks for agent-required engines.
 */
export function useAgentQueue({ clientId, engineId, intervalMs = 5000, enabled = true } = {}) {
  const [payload, setPayload] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!enabled) return null
    const qs = new URLSearchParams({ limit: '100' })
    if (clientId) qs.set('client_id', String(clientId))
    if (engineId) qs.set('engine', String(engineId))
    try {
      const data = await apiFetch(`/api/agents/queue?${qs}`)
      setPayload(data)
      setError(null)
      return data
    } catch (e) {
      setError(e?.message || 'Failed to load agent queue')
      return null
    } finally {
      setLoading(false)
    }
  }, [clientId, engineId, enabled])

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return undefined
    }
    let cancelled = false
    load().then(() => {
      if (cancelled) return
    })
    const iv = setInterval(() => {
      if (!cancelled) load()
    }, intervalMs)
    return () => {
      cancelled = true
      clearInterval(iv)
    }
  }, [enabled, intervalMs, load])

  const tasks = Array.isArray(payload?.tasks) ? payload.tasks : []
  const pending = Number(payload?.pending) || 0
  const running = Number(payload?.running) || 0
  const waiting = Number(payload?.waiting) || pending + running

  return {
    payload,
    tasks,
    pending,
    running,
    waiting,
    done: Number(payload?.done) || 0,
    failed: Number(payload?.failed) || 0,
    expired: Number(payload?.expired) || 0,
    loading,
    error,
    refresh: load,
  }
}
