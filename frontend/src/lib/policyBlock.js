/**
 * First-class RoE / policy-block signals.
 * OT/ICS probes denied by Rules of Engagement must never look like "0 findings = healthy".
 */

export function isPolicyBlockFinding(f) {
  if (!f || typeof f !== 'object') return false
  if (f.policy_block === true || f.roe_denied === true) return true
  const cat = String(f.category || '').toLowerCase()
  const type = String(f.type || '').toLowerCase()
  const code = String(f.error_code || '').toLowerCase()
  return cat === 'roe_denied' || cat === 'policy_block' || type === 'policy_block' || code === 'roe_denied'
}

export function isRoeDeniedJob(job) {
  if (!job || typeof job !== 'object') return false
  const status = String(job.status || '').toLowerCase()
  if (status === 'blocked') return true
  const result = job.result ?? job.result_json ?? {}
  if (result && typeof result === 'object') {
    if (String(result.status || '').toLowerCase() === 'blocked') return true
    if (result.policy_block === true) return true
    if (String(result.error_code || '').toLowerCase() === 'roe_denied') return true
  }
  return false
}

export function policyBlockReason(job, findings = []) {
  const result = job?.result ?? job?.result_json ?? {}
  const fromResult = result?.reason || result?.message
  if (typeof fromResult === 'string' && fromResult.trim()) return fromResult.trim()
  const hit = (Array.isArray(findings) ? findings : []).find(isPolicyBlockFinding)
  const desc = hit?.description || hit?.title
  if (typeof desc === 'string' && desc.trim()) return desc.trim()
  return ''
}
