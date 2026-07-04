/**
 * @typedef {object} ForensicVerifyResult
 * @property {'verified'|'tamper'|'error'|'pending'} status
 * @property {string} [detail]
 * @property {string} [layer]
 */

let worker = null
let seq = 0
/** @type {Map<number, { resolve: Function, reject: Function }>} */
const pending = new Map()

/**
 * @returns {Worker}
 */
function getWorker() {
  if (worker) return worker
  worker = new Worker(new URL('./forensicProvenanceWorker.js', import.meta.url), {
    type: 'module',
  })
  worker.onmessage = (ev) => {
    const { id, ok, result, error } = ev.data || {}
    const entry = pending.get(id)
    if (!entry) return
    pending.delete(id)
    if (ok) entry.resolve(result)
    else entry.reject(new Error(error || 'forensic worker error'))
  }
  worker.onerror = (ev) => {
    for (const [, entry] of pending) {
      entry.reject(new Error(ev.message || 'forensic worker crashed'))
    }
    pending.clear()
    worker = null
  }
  return worker
}

/**
 * @param {string} type
 * @param {object} payload
 * @returns {Promise<ForensicVerifyResult>}
 */
export function forensicWorkerRequest(type, payload) {
  const id = ++seq
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    getWorker().postMessage({ id, type, payload })
  })
}

/**
 * Fetch ephemeral HMAC verify material for authenticated sessions.
 * @returns {Promise<string|null>}
 */
export async function fetchProvenanceVerifyKey() {
  try {
    const { apiFetch } = await import('../lib/apiBase.js')
    const res = await apiFetch('/api/forensic/provenance-key')
    if (!res.ok) return null
    const data = await res.json()
    return data?.verify_key?.trim() || null
  } catch {
    return null
  }
}
