import { useEffect, useRef, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useAuth } from '../../context/AuthContext'
import { useToast } from '../ui/Toaster'

/** Idle before the warning shows (ms). */
const IDLE_LIMIT_MS = 15 * 60 * 1000
/** Grace period after the warning before auto-logout (ms). */
const WARNING_GRACE_MS = 60 * 1000
/** Activity events that reset the idle timer (throttled). */
const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'visibilitychange']

/**
 * Auto-logout after inactivity, with a warning + "stay signed in" grace toast.
 * Mount once inside the authenticated provider tree. Renders nothing.
 */
export default function IdleTimeoutWatcher() {
  const { isAuthenticated, logout } = useAuth()
  const { toast } = useToast()
  const { t } = useTranslation()

  const idleTimerRef = useRef(null)
  const graceTimerRef = useRef(null)
  const warnedRef = useRef(false)
  const lastResetRef = useRef(0)

  const clearTimers = useCallback(() => {
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current)
    if (graceTimerRef.current) clearTimeout(graceTimerRef.current)
    idleTimerRef.current = null
    graceTimerRef.current = null
  }, [])

  const triggerLogout = useCallback(() => {
    clearTimers()
    warnedRef.current = false
    logout()
  }, [clearTimers, logout])

  const showWarning = useCallback(() => {
    warnedRef.current = true
    toast.warning(t('session.idle_warning'), {
      ttl: WARNING_GRACE_MS,
      actionLabel: t('session.stay_signed_in'),
      onAction: () => {
        // handled by the activity listener resetting the timer; the button
        // press itself is activity, so scheduleIdle() runs on the next event.
      },
    })
    graceTimerRef.current = setTimeout(triggerLogout, WARNING_GRACE_MS)
  }, [toast, t, triggerLogout])

  const scheduleIdle = useCallback(() => {
    clearTimers()
    warnedRef.current = false
    idleTimerRef.current = setTimeout(showWarning, IDLE_LIMIT_MS)
  }, [clearTimers, showWarning])

  useEffect(() => {
    if (!isAuthenticated) {
      clearTimers()
      return undefined
    }

    scheduleIdle()

    const onActivity = () => {
      // Ignore the tab-hidden visibility flip; only reset on real interaction.
      if (document.visibilityState === 'hidden') return
      const now = Date.now()
      // Throttle: don't reschedule more than once per second under a flood of
      // mousemove events. But if we're already in the warning window, any
      // activity should immediately cancel the pending logout.
      if (!warnedRef.current && now - lastResetRef.current < 1000) return
      lastResetRef.current = now
      scheduleIdle()
    }

    ACTIVITY_EVENTS.forEach((evt) =>
      window.addEventListener(evt, onActivity, { passive: true }),
    )
    return () => {
      ACTIVITY_EVENTS.forEach((evt) => window.removeEventListener(evt, onActivity))
      clearTimers()
    }
  }, [isAuthenticated, scheduleIdle, clearTimers])

  return null
}
