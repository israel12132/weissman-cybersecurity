import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Optional auto-refresh for live list pages — pauses when tab hidden.
 */
export function usePageAutoRefresh(callback, intervalMs = 30_000, enabled = true) {
  const [lastSync, setLastSync] = useState(null)
  const [syncing, setSyncing] = useState(false)
  const cbRef = useRef(callback)
  cbRef.current = callback

  const refresh = useCallback(async () => {
    setSyncing(true)
    try {
      await cbRef.current?.()
      setLastSync(new Date())
    } finally {
      setSyncing(false)
    }
  }, [])

  useEffect(() => {
    if (!enabled || !intervalMs) return undefined
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') refresh()
    }, intervalMs)
    return () => clearInterval(id)
  }, [enabled, intervalMs, refresh])

  return { refresh, lastSync, syncing, setLastSync }
}
