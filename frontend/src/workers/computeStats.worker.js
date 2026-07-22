/**
 * Heavy-stats Web Worker. Offloads large O(n) aggregations off the main thread
 * so the UI stays at 60fps while summarizing tens of thousands of findings.
 * Message in:  { id, task, args }
 * Message out: { id, ok, result } | { id, ok:false, error }
 */
import { STATS_TASKS } from '../lib/heavyStats.js'

self.onmessage = (e) => {
  const { id, task, args } = e.data || {}
  const fn = STATS_TASKS[task]
  if (typeof fn !== 'function') {
    self.postMessage({ id, ok: false, error: `Unknown task: ${task}` })
    return
  }
  try {
    self.postMessage({ id, ok: true, result: fn(args) })
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message || err) })
  }
}
