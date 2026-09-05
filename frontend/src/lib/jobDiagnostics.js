/**
 * Operator-state helpers for the Jobs dashboard.
 * Prefer live `operator_state` from GET /api/jobs (and /diagnostics). Never invent
 * stuck/lease truth on the client when the API omitted it.
 */

import { jobIsRoeBlocked } from './roeBlocked.js'

/** Same contract keys as `job_diagnostics::DIAGNOSTICS_REQUIRED_FIELDS`. */
export const DIAGNOSTICS_REQUIRED_FIELDS = [
  'redis',
  'workers',
  'pending_no_envelope',
  'stuck_reason',
]

export const OPERATOR_STATES = [
  'queued',
  'running',
  'stuck',
  'blocked_by_agent',
  'roe_blocked',
  'completed',
  'error',
  'cancelled',
]

export const TILE_STATES = [
  'queued',
  'running',
  'stuck',
  'blocked_by_agent',
  'roe_blocked',
  'completed',
  'failed',
  'cancelled',
]

export const OPERATOR_COLORS = {
  queued: 'text-yellow-400 bg-yellow-900/20 border-yellow-500/30',
  running: 'text-blue-400 bg-blue-900/20 border-blue-500/30',
  stuck: 'text-orange-300 bg-orange-950/50 border-orange-500/50',
  blocked_by_agent: 'text-amber-300 bg-amber-950/40 border-amber-500/45',
  roe_blocked: 'text-fuchsia-300 bg-fuchsia-950/40 border-fuchsia-500/45',
  completed: 'text-green-400 bg-green-900/20 border-green-500/30',
  failed: 'text-red-400 bg-red-900/20 border-red-500/30',
  error: 'text-red-400 bg-red-900/20 border-red-500/30',
  cancelled: 'text-[var(--text-tertiary)] bg-[var(--bg-1)]/20 border-[var(--border-strong)]/30',
  dead: 'text-red-400 bg-red-900/20 border-red-500/30',
}

export function operatorState(job) {
  if (!job) return 'queued'
  if (jobIsRoeBlocked(job)) return 'roe_blocked'
  const live = String(job.operator_state || '').toLowerCase()
  if (live) {
    if (live === 'failed' || live === 'dead') return 'error'
    return live
  }
  const st = String(job.status || '').toLowerCase()
  if (st === 'pending') return 'queued'
  if (st === 'failed' || st === 'dead') return 'error'
  return st || 'queued'
}

/**
 * Live GET /api/jobs/diagnostics census. Incomplete payloads fail closed —
 * the dashboard must not paint redis/workers as healthy from missing keys.
 */
export function parseDiagnosticsCensus(diag) {
  if (!diag || typeof diag !== 'object') {
    return { ok: false, reason: 'missing' }
  }
  for (const field of DIAGNOSTICS_REQUIRED_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(diag, field)) {
      return { ok: false, reason: 'incomplete', field }
    }
  }
  return {
    ok: true,
    redisConfigured: Boolean(diag.redis?.configured),
    redisInspectOk: Boolean(diag.redis?.inspect_ok),
    workersAlive: Number(diag.workers?.alive ?? 0),
    workersInspected: Number(diag.workers?.inspected ?? 0),
    workerIds: Array.isArray(diag.workers?.ids) ? diag.workers.ids : [],
    pendingNoEnvelope: Number(diag.pending_no_envelope ?? 0),
    stuck: Array.isArray(diag.stuck_reason) ? diag.stuck_reason : [],
  }
}

export function operatorBadgeClass(jobOrState) {
  const s = typeof jobOrState === 'string' ? jobOrState : operatorState(jobOrState)
  return OPERATOR_COLORS[s] || OPERATOR_COLORS.queued
}

export function matchesOperatorFilter(job, filter) {
  if (!filter || filter === 'all') return true
  const s = operatorState(job)
  if (filter === 'failed') return s === 'error' || s === 'failed'
  if (filter === 'queued') return s === 'queued'
  return s === filter
}

export function operatorStateCounts(jobs) {
  const counts = {
    queued: 0,
    running: 0,
    stuck: 0,
    blocked_by_agent: 0,
    roe_blocked: 0,
    completed: 0,
    failed: 0,
    cancelled: 0,
    error: 0,
  }
  for (const j of jobs || []) {
    const s = operatorState(j)
    if (s === 'error' || s === 'failed' || s === 'dead') {
      counts.failed += 1
      counts.error += 1
    } else if (counts[s] != null) {
      counts[s] += 1
    }
  }
  return counts
}

export function remapLabel(job) {
  const remap = job?.remap
  if (!remap || typeof remap !== 'object') return null
  const requested = remap.requested_engine || remap.requested
  const canonical = remap.canonical_engine || remap.canonical
  if (!requested || !canonical) return null
  if (remap.was_remapped) return { requested, canonical, wasRemapped: true }
  return { requested, canonical, wasRemapped: false }
}

export function leaseOwner(job) {
  return job?.lease_owner || job?.worker_id || null
}

export function diagnosticsHaystack(job) {
  const remap = remapLabel(job)
  return [
    job?.id,
    job?.job_id,
    job?.kind,
    job?.type,
    job?.status,
    job?.operator_state,
    job?.stuck_reason,
    job?.target,
    job?.engine,
    job?.client_id != null ? String(job.client_id) : '',
    job?.last_error,
    job?.lease_owner,
    job?.worker_id,
    remap?.requested,
    remap?.canonical,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
}

export const JOBS_CSV_HEADER = [
  'id',
  'kind',
  'status',
  'operator_state',
  'stuck_reason',
  'target',
  'engine',
  'canonical_engine',
  'client_id',
  'created_at',
  'updated_at',
  'attempt_count',
  'last_error',
  'lease_owner',
  'lease_present',
  'lease_ttl_secs',
  'heartbeat_at',
  'heartbeat_stale_secs',
]

export function jobToCsvRow(j) {
  const remap = remapLabel(j)
  return [
    j.id || j.job_id,
    j.kind || j.type,
    j.status,
    operatorState(j),
    j.stuck_reason,
    j.target,
    j.engine,
    remap?.canonical || '',
    j.client_id,
    j.created_at,
    j.updated_at || j.completed_at,
    j.attempt_count ?? j.retries,
    j.last_error,
    leaseOwner(j),
    j.lease_present,
    j.lease_ttl_secs,
    j.heartbeat_at,
    j.heartbeat_stale_secs,
  ]
}

export function mergeJobDiagnostics(job, diag) {
  if (!job) return diag || null
  if (!diag || typeof diag !== 'object') return job
  return { ...job, ...diag }
}

export function overlayStuckReasons(jobs, stuckRows) {
  if (!Array.isArray(jobs) || !Array.isArray(stuckRows) || stuckRows.length === 0) {
    return jobs || []
  }
  const overlay = new Map(stuckRows.map((row) => [String(row.id), row]))
  return jobs.map((job) => {
    const extra = overlay.get(String(job.id || job.job_id))
    return extra ? mergeJobDiagnostics(job, extra) : job
  })
}
