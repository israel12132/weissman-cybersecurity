import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useMemo,
  useRef,
} from 'react'
import { useTelemetry } from './TelemetryContext'
import { encodeFindingsFilters } from '../lib/findingsUrlState'

const NotificationContext = createContext(null)

const MAX_NOTIFICATIONS = 100
const STORAGE_KEY = 'weissman_notifications'

/** Severities that surface as a durable notification (vs. transient feed noise). */
const NOTEWORTHY_SEVERITY = new Set(['error', 'critical', 'high'])
/** Event kinds that always surface regardless of severity. */
const NOTEWORTHY_KIND = new Set(['finding', 'error'])

function isNoteworthy(evt) {
  const sev = (evt?.severity || '').toLowerCase()
  const kind = (evt?.kind || '').toLowerCase()
  return NOTEWORTHY_SEVERITY.has(sev) || NOTEWORTHY_KIND.has(kind)
}

/**
 * Best-effort deep link for a notification, based on its event shape.
 * Finding events deep-link to the findings console pre-filtered by severity
 * (via the shared URL-filter encoder), so a click lands on the relevant rows.
 * @param {object} evt
 * @returns {string|null}
 */
export function deriveLink(evt) {
  const kind = (evt?.kind || '').toLowerCase()
  if (kind === 'finding') {
    const sev = (evt?.severity || '').toLowerCase()
    const params = encodeFindingsFilters({ severityFilter: sev })
    const qs = new URLSearchParams(params).toString()
    return qs ? `/findings?${qs}` : '/findings'
  }
  if (evt?.job_id) return '/jobs'
  return null
}

function loadPersisted() {
  if (typeof sessionStorage === 'undefined') return []
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr.slice(0, MAX_NOTIFICATIONS) : []
  } catch {
    return []
  }
}

/**
 * Durable notification inbox. Transient toasts vanish; this keeps a bounded,
 * read/unread-tracked history of noteworthy telemetry events so an analyst who
 * steps away doesn't miss a critical finding. Sourced from the single existing
 * telemetry SSE stream via TelemetryProvider.subscribe — no extra connection.
 */
export function NotificationProvider({ children }) {
  const { subscribe } = useTelemetry()
  const [notifications, setNotifications] = useState(loadPersisted)
  const seqRef = useRef(0)

  // Persist to sessionStorage (tab-scoped) so a reload keeps recent history.
  useEffect(() => {
    if (typeof sessionStorage === 'undefined') return
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(notifications.slice(0, MAX_NOTIFICATIONS)))
    } catch {
      /* quota / privacy mode — non-fatal */
    }
  }, [notifications])

  const add = useCallback((evt) => {
    seqRef.current += 1
    const n = {
      id: `ntf-${Date.now()}-${seqRef.current}`,
      severity: (evt.severity || 'info').toLowerCase(),
      message: evt.message || '',
      engine: evt.engine || '',
      target: evt.target || '',
      job_id: evt.job_id || '',
      kind: (evt.kind || 'info').toLowerCase(),
      link: deriveLink(evt),
      ts: Date.now(),
      read: false,
    }
    setNotifications((prev) => [n, ...prev].slice(0, MAX_NOTIFICATIONS))
  }, [])

  useEffect(() => {
    const unsub = subscribe((data) => {
      if (isNoteworthy(data)) add(data)
    })
    return unsub
  }, [subscribe, add])

  const markRead = useCallback((id) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)))
  }, [])

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => (n.read ? n : { ...n, read: true })))
  }, [])

  const clearAll = useCallback(() => setNotifications([]), [])

  const unreadCount = useMemo(() => notifications.filter((n) => !n.read).length, [notifications])

  const value = useMemo(
    () => ({ notifications, unreadCount, markRead, markAllRead, clearAll }),
    [notifications, unreadCount, markRead, markAllRead, clearAll],
  )

  return <NotificationContext.Provider value={value}>{children}</NotificationContext.Provider>
}

export function useNotifications() {
  const ctx = useContext(NotificationContext)
  if (!ctx) {
    // Safe fallback so a bell rendered outside the provider (e.g. tests) no-ops.
    return {
      notifications: [],
      unreadCount: 0,
      markRead: () => {},
      markAllRead: () => {},
      clearAll: () => {},
    }
  }
  return ctx
}
