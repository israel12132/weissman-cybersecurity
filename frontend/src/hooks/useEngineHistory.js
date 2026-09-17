import { useState, useCallback } from 'react'
import { apiFetch } from '../utils/apiFetch'

/**
 * Classify GET /api/engines/history/:id JSON.
 * Confirmed empty `jobs` / `runs` is never-run (ok). A missing list, `ok: false`,
 * or `unavailable` is a store-down — never indistinguishable from never-run.
 */
export function classifyEngineHistory(d) {
  if (d == null || typeof d !== 'object' || d.ok === false || d.unavailable) {
    return { kind: 'unavailable' }
  }
  const runs = Array.isArray(d.jobs) ? d.jobs : Array.isArray(d) ? d : Array.isArray(d.runs) ? d.runs : null
  if (!Array.isArray(runs)) return { kind: 'unavailable' }
  const last = runs[0] || null
  const findings = Array.isArray(d.findings)
    ? d.findings
    : Array.isArray(last?.findings)
      ? last.findings
      : []
  return { kind: 'ok', runs, last, findings }
}

/**
 * Load the most recent engine run from GET /api/engines/history/:engineId.
 * Returns live findings only — never seeds demo data.
 * On transport / malformed payload, returns `{ unavailable: true }` instead of null
 * so callers cannot paint never-run / ready / clean.
 */
export function useEngineHistory(engineId) {
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [lastJobId, setLastJobId] = useState(null)
  const [historyUnavailable, setHistoryUnavailable] = useState(false)

  const loadLastRun = useCallback(async () => {
    if (!engineId) return null
    setLoading(true)
    try {
      const d = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=1`)
      const classified = classifyEngineHistory(d)
      if (classified.kind === 'unavailable') {
        setHistoryUnavailable(true)
        return { unavailable: true }
      }
      setHistoryUnavailable(false)
      const last = classified.last
      if (!last) return null
      const findings = classified.findings
      const ts = last.completed_at || last.updated_at || last.created_at || null
      setLastUpdated(ts)
      setLastJobId(last.job_id ?? last.id ?? null)
      return { findings, jobId: last.job_id ?? last.id, status: last.status, completedAt: ts, raw: last }
    } catch {
      setHistoryUnavailable(true)
      return { unavailable: true }
    } finally {
      setLoading(false)
    }
  }, [engineId])

  return {
    loadLastRun,
    historyLoading: loading,
    lastUpdated,
    lastJobId,
    setLastUpdated,
    setLastJobId,
    historyUnavailable,
    setHistoryUnavailable,
  }
}
