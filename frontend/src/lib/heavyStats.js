/**
 * Pure, worker-safe aggregation helpers for large finding/telemetry sets. Kept
 * dependency-free and side-effect-free so the exact same code runs on the main
 * thread (fallback) and inside the Web Worker (see workers/computeStats.worker.js).
 */

const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0.5 }

/** Nearest-rank percentile of a numeric array (0..100). */
export function percentile(values, p) {
  const nums = (values || []).map(Number).filter((n) => Number.isFinite(n)).sort((a, b) => a - b)
  if (nums.length === 0) return 0
  const rank = Math.ceil((Math.min(100, Math.max(0, p)) / 100) * nums.length)
  return nums[Math.max(0, rank - 1)]
}

/** Count occurrences of `key` across items. */
export function countBy(items, key) {
  const out = {}
  for (const it of items || []) {
    const k = String(it?.[key] ?? 'unknown')
    out[k] = (out[k] || 0) + 1
  }
  return out
}

/**
 * Aggregate a finding set into a risk summary — the kind of O(n) reduction worth
 * offloading when n is large (tens of thousands of findings).
 * @returns {{total:number,bySeverity:object,riskScore:number,openRatio:number}}
 */
export function computeRiskSummary(findings) {
  const list = Array.isArray(findings) ? findings : []
  const bySeverity = countBy(list, 'severity')
  let weighted = 0
  let open = 0
  for (const f of list) {
    weighted += SEVERITY_WEIGHT[String(f?.severity).toLowerCase()] ?? 0
    if (f?.status !== 'resolved' && f?.status !== 'closed') open += 1
  }
  const total = list.length
  // Normalize to 0..100 against a critical-everything ceiling.
  const ceiling = total * SEVERITY_WEIGHT.critical || 1
  return {
    total,
    bySeverity,
    riskScore: Math.round((weighted / ceiling) * 100),
    openRatio: total ? Math.round((open / total) * 100) / 100 : 0,
  }
}

/** Dispatch table so the worker can run any exported task by name. */
export const STATS_TASKS = {
  computeRiskSummary,
  percentile: (args) => percentile(args?.values, args?.p),
  countBy: (args) => countBy(args?.items, args?.key),
}
