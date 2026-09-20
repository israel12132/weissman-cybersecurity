import { useCallback, useEffect, useState } from 'react'
import { setMaintenanceCallback } from '../lib/apiBase'
import { queryClient } from '../lib/queryClient'
import MaintenanceOverlay from './MaintenanceOverlay'

/**
 * Registers the global maintenance signal for every API client (lib/apiBase and
 * utils/apiFetch both report a branded gateway 502/503/504 through
 * setMaintenanceCallback) and mounts the full-screen MaintenanceOverlay while
 * the origin is being updated.
 *
 * Idempotent on purpose: during an update every in-flight query fails at once,
 * so the callback fires many times — the first signal opens the overlay and the
 * rest are no-ops. The overlay itself decides when the origin is back (a genuine
 * 200 from /api/health) and calls `onRestored`, which closes it and refetches the
 * active queries so the screen the operator was on picks up where it left off.
 */
export default function MaintenanceProvider({ children }) {
  const [signal, setSignal] = useState(null) // { status, retryAfter } | null

  const onMaintenance = useCallback(({ status, retryAfter } = {}) => {
    setSignal((current) => current || { status, retryAfter })
  }, [])

  useEffect(() => {
    setMaintenanceCallback(onMaintenance)
    return () => setMaintenanceCallback(null)
  }, [onMaintenance])

  const onRestored = useCallback(() => {
    setSignal(null)
    try {
      // Active queries errored while the origin was away; refresh them now so
      // "your session resumes automatically" is true without a manual reload.
      void queryClient.refetchQueries({ type: 'active' })
    } catch {
      /* the overlay is already gone; the dashboards' own polling takes over */
    }
  }, [])

  return (
    <>
      {children}
      {signal ? (
        <MaintenanceOverlay
          status={signal.status}
          retryAfter={signal.retryAfter}
          onRestored={onRestored}
        />
      ) : null}
    </>
  )
}
