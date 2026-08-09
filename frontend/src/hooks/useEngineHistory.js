import { useState, useCallback } from 'react'
import { apiFetch } from '../utils/apiFetch'

/**
 * Load the most recent engine run from GET /api/engines/history/:engineId.
 * Returns live findings only — never seeds demo data.
 */
export function useEngineHistory(engineId) {
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [lastJobId, setLastJobId] = useState(null)

  const loadLastRun = useCallback(async () => {
    if (!engineId) return null
    setLoading(true)
    try {
      const d = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=1`)
      // Backend (collect_engine_history_json) returns
      // { engine_id, canonical_engine, jobs:[...], findings:[...], ... } — the runs live under
      // `jobs`, and findings are a separate top-level array (not nested per job).
      const runs = Array.isArray(d?.jobs) ? d.jobs : Array.isArray(d) ? d : Array.isArray(d?.runs) ? d.runs : []
      const last = runs[0]
      if (!last) return null
      const findings = Array.isArray(d?.findings)
        ? d.findings
        : Array.isArray(last.findings)
          ? last.findings
          : []
      const ts = last.completed_at || last.updated_at || last.created_at || null
      setLastUpdated(ts)
      setLastJobId(last.job_id ?? last.id ?? null)
      return { findings, jobId: last.job_id ?? last.id, status: last.status, completedAt: ts, raw: last }
    } catch {
      return null
    } finally {
      setLoading(false)
    }
  }, [engineId])

  return { loadLastRun, historyLoading: loading, lastUpdated, lastJobId, setLastUpdated, setLastJobId }
}
