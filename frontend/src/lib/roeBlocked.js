/** Detect a fail-closed RoE block (not green success, not a fake empty scan). */
export function jobIsRoeBlocked(job) {
  if (!job || typeof job !== 'object') return false
  if (job.roe_blocked === true) return true
  const payload = job.result ?? job.result_json ?? null
  if (payload && typeof payload === 'object') {
    if (payload.roe_blocked === true) return true
    if (payload.status === 'roe_blocked') return true
  }
  return String(job.status || '').toLowerCase() === 'roe_blocked'
}

export function extractRoeDetails(job) {
  if (!job || typeof job !== 'object') return null
  if (job.roe && typeof job.roe === 'object') return job.roe
  const payload = job.result ?? job.result_json ?? null
  if (payload && typeof payload === 'object' && payload.roe && typeof payload.roe === 'object') {
    return payload.roe
  }
  if (jobIsRoeBlocked(job)) {
    return {
      control: 'industrial_ot_enabled',
      never_auto_enabled: true,
      who_must_enable: 'tenant_admin',
    }
  }
  return null
}

export function displayJobStatus(job) {
  if (jobIsRoeBlocked(job)) return 'roe_blocked'
  const s = String(job?.status || '').toLowerCase()
  return s === 'pending' ? 'queued' : s
}
