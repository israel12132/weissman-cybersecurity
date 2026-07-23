import { useCallback, useEffect, useRef, useState } from 'react'
import { STATS_TASKS } from '../lib/heavyStats.js'

/**
 * useComputeWorker — offload heavy O(n) aggregations to a Web Worker, keeping the
 * main thread free for a smooth UI. Falls back to running the identical pure
 * function on the main thread when Workers are unavailable (SSR / jsdom / old
 * browsers), so callers get a Promise-based API either way.
 *
 * Usage: const { run } = useComputeWorker();
 *        const summary = await run('computeRiskSummary', findings)
 */
export function useComputeWorker() {
  const workerRef = useRef(null)
  const pending = useRef(new Map())
  const idRef = useRef(0)
  const [supported] = useState(() => typeof Worker !== 'undefined')

  useEffect(() => {
    if (!supported) return undefined
    let worker
    try {
      worker = new Worker(new URL('../workers/computeStats.worker.js', import.meta.url), {
        type: 'module',
      })
    } catch {
      return undefined
    }
    worker.onmessage = (e) => {
      const { id, ok, result, error } = e.data || {}
      const p = pending.current.get(id)
      if (!p) return
      pending.current.delete(id)
      if (ok) p.resolve(result)
      else p.reject(new Error(error))
    }
    worker.onerror = () => {
      // Reject everything in flight; future calls fall back to the main thread.
      for (const p of pending.current.values()) p.reject(new Error('worker error'))
      pending.current.clear()
    }
    workerRef.current = worker
    return () => {
      worker.terminate()
      workerRef.current = null
    }
  }, [supported])

  const run = useCallback((task, args) => {
    if (!workerRef.current) {
      // Main-thread fallback — identical computation, just not offloaded.
      return Promise.resolve().then(() => {
        const fn = STATS_TASKS[task]
        if (typeof fn !== 'function') throw new Error(`Unknown task: ${task}`)
        return fn(args)
      })
    }
    const id = (idRef.current += 1)
    return new Promise((resolve, reject) => {
      pending.current.set(id, { resolve, reject })
      workerRef.current.postMessage({ id, task, args })
    })
  }, [])

  return { run, supported }
}

export default useComputeWorker
