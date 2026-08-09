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
    // Release the crashed instance (and its WASM memory) before dropping the
    // reference, so a crash-and-recreate cycle does not leak Worker threads.
    try {
      worker?.terminate()
    } catch {
      /* worker already gone */
    }
    worker = null
  }
  return worker
}

const REQUEST_TIMEOUT_MS = 10_000

/**
 * @param {string} type
 * @param {object} payload
 * @returns {Promise<ForensicVerifyResult>}
 */
export function forensicWorkerRequest(type, payload) {
  const id = ++seq
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (pending.delete(id)) reject(new Error('forensic worker timeout'))
    }, REQUEST_TIMEOUT_MS)
    pending.set(id, {
      resolve: (v) => {
        clearTimeout(timer)
        resolve(v)
      },
      reject: (e) => {
        clearTimeout(timer)
        reject(e)
      },
    })
    // Worker construction (or a CSP worker-src violation) can throw synchronously;
    // don't leak the pending entry if it does.
    try {
      getWorker().postMessage({ id, type, payload })
    } catch (err) {
      clearTimeout(timer)
      pending.delete(id)
      reject(err instanceof Error ? err : new Error(String(err)))
    }
  })
}

/** @type {Promise<string|null> | null} */
let keyPromise = null

/**
 * Fetch ephemeral HMAC verify material for authenticated sessions.
 *
 * Memoised for the tab's lifetime: the value is stable within a session, and
 * the badge remounts on every engine-route navigation — refetching signing
 * material each time needlessly multiplies its exposure over the wire.
 * @returns {Promise<string|null>}
 */
export async function fetchProvenanceVerifyKey() {
  if (keyPromise) return keyPromise
  keyPromise = (async () => {
    try {
      const { apiFetch } = await import('../utils/apiFetch.js')
      const data = await apiFetch('/api/forensic/provenance-key')
      return data?.verify_key?.trim() || null
    } catch {
      return null
    }
  })()
  const resolved = await keyPromise
  // Don't cache a failed/empty result permanently — allow a later retry.
  if (resolved == null) keyPromise = null
  return resolved
}
