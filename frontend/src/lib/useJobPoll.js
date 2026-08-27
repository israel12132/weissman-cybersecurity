import { useEffect, useRef } from 'react'
import { apiFetch } from './apiBase'

const TERMINAL = new Set(['completed', 'failed', 'dead', 'cancelled', 'blocked'])

export function isTerminalJobStatus(status) {
  return TERMINAL.has(String(status || '').toLowerCase())
}

/**
 * Poll GET /api/jobs/:id until the job reaches a terminal status.
 */
export function useJobPoll(jobId, { onUpdate, onComplete, intervalMs = 2000, enabled = true } = {}) {
  const onUpdateRef = useRef(onUpdate)
  const onCompleteRef = useRef(onComplete)
  onUpdateRef.current = onUpdate
  onCompleteRef.current = onComplete

  useEffect(() => {
    if (!enabled || !jobId) return undefined

    let cancelled = false
    let iv = null

    async function poll() {
      try {
        const r = await apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`)
        const job = await r.json().catch(() => null)
        if (cancelled || !r.ok || !job) return
        onUpdateRef.current?.(job)
        const status = (job.status || '').toLowerCase()
        if (isTerminalJobStatus(status)) {
          onCompleteRef.current?.(job)
          // Job is finished — stop hitting the endpoint (the hook contract is
          // "poll until terminal"; without this it polls forever once done).
          cancelled = true
          if (iv) clearInterval(iv)
        }
      } catch (_) {
        // apiFetch rejects on transport failure / circuit-open BEFORE the !r.ok
        // guard above. Swallow it so the rejection can't escape as an
        // unhandledrejection every tick; the next interval simply retries.
      }
    }

    poll()
    iv = setInterval(poll, intervalMs)
    return () => {
      cancelled = true
      if (iv) clearInterval(iv)
    }
  }, [jobId, enabled, intervalMs])
}

/** Normalize backend job status for UI display (pending → queued). */
export function normalizeJobStatus(status) {
  const s = (status || '').toLowerCase()
  return s === 'pending' ? 'queued' : s
}

/** Extract findings array from a completed job payload. */
export function extractFindingsFromJob(job) {
  const payload = job?.result ?? job?.result_json ?? {}
  if (Array.isArray(payload?.findings)) return payload.findings
  if (Array.isArray(job?.findings)) return job.findings
  const raw = job?.findings_json
  if (typeof raw === 'string' && raw.trim()) {
    try {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed)) return parsed
      if (Array.isArray(parsed?.findings)) return parsed.findings
    } catch {
      /* ignore */
    }
  }
  if (Array.isArray(raw)) return raw
  return []
}

/** Fetch recent findings filtered by engine source. */
export async function fetchFindingsForEngine(engineId, clientId) {
  const params = new URLSearchParams({ limit: '30' })
  if (clientId) params.set('client_id', String(clientId))
  const r = await apiFetch(`/api/findings?${params}`)
  const data = await r.json().catch(() => ({}))
  const list = Array.isArray(data) ? data : (data.findings || data.items || [])
  const needle = (engineId || '').toLowerCase()
  return list.filter((f) => {
    const src = String(f.source || f.engine || f.type || '').toLowerCase()
    return src.includes(needle) || needle.includes(src)
  })
}

/** Prefer job result; fall back to findings API. */
export async function resolveJobFindings(job, engineId, clientId) {
  const fromJob = extractFindingsFromJob(job)
  if (fromJob.length) return fromJob
  return fetchFindingsForEngine(engineId, clientId)
}

/** Map backend job status to UI card status. */
export function uiJobStatus(backendStatus) {
  const s = normalizeJobStatus(backendStatus)
  if (s === 'completed') return 'completed'
  if (s === 'blocked') return 'blocked'
  if (s === 'failed' || s === 'dead' || s === 'cancelled') return 'error'
  if (s === 'running' || s === 'queued') return 'running'
  return 'idle'
}
