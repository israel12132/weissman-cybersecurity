import { useEffect, useRef } from 'react'
import { apiFetch } from './apiBase'

const TERMINAL = new Set(['completed', 'failed', 'dead', 'cancelled'])

/**
 * Poll GET /api/jobs/:id until the job reaches a terminal status.
 * @param {string|null} jobId
 * @param {{ onUpdate?: (job: object) => void, onComplete?: (job: object) => void, intervalMs?: number, enabled?: boolean }} opts
 */
export function useJobPoll(jobId, { onUpdate, onComplete, intervalMs = 2000, enabled = true } = {}) {
  const onUpdateRef = useRef(onUpdate)
  const onCompleteRef = useRef(onComplete)
  onUpdateRef.current = onUpdate
  onCompleteRef.current = onComplete

  useEffect(() => {
    if (!enabled || !jobId) return undefined

    let cancelled = false

    async function poll() {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`)
      const job = await r.json().catch(() => null)
      if (cancelled || !r.ok || !job) return
      onUpdateRef.current?.(job)
      const status = (job.status || '').toLowerCase()
      if (TERMINAL.has(status)) {
        onCompleteRef.current?.(job)
      }
    }

    poll()
    const iv = setInterval(poll, intervalMs)
    return () => {
      cancelled = true
      clearInterval(iv)
    }
  }, [jobId, enabled, intervalMs])
}

/** Normalize backend job status for UI display (pending → queued). */
export function normalizeJobStatus(status) {
  const s = (status || '').toLowerCase()
  return s === 'pending' ? 'queued' : s
}
