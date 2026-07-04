import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { openSseStream } from '../lib/sseStream'

const TelemetryContext = createContext(null)

const TOAST_TTL_MS = 8000
const MAX_PROGRESS_LINES_PER_ENGINE = 80
const MAX_ACTIVITY_EVENTS = 200

export function TelemetryProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const [progressByEngine, setProgressByEngine] = useState({})
  // Rolling buffer of all telemetry events — consumed by `LiveActivityFeed` for the
  // Datadog/Falcon-style scrolling event panel. Bounded to keep memory predictable.
  const [activity, setActivity] = useState([])
  const [connected, setConnected] = useState(false)
  const esRef = useRef(null)
  const eventSeqRef = useRef(0)
  // Fan-out registry so additional consumers (e.g. WarRoomContext) can react to every
  // raw telemetry event WITHOUT opening a second stream to the same endpoint.
  const listenersRef = useRef(new Set())

  const subscribe = useCallback((fn) => {
    if (typeof fn !== 'function') return () => {}
    listenersRef.current.add(fn)
    return () => listenersRef.current.delete(fn)
  }, [])

  const pushActivity = useCallback((entry) => {
    eventSeqRef.current += 1
    const e = { ...entry, id: eventSeqRef.current, t: Date.now() }
    setActivity((prev) => {
      const next = [e, ...prev]
      return next.length > MAX_ACTIVITY_EVENTS ? next.slice(0, MAX_ACTIVITY_EVENTS) : next
    })
  }, [])

  const addToast = useCallback((severity, message, engine = '') => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`
    const payload = { id, severity, message, engine }
    setToasts((prev) => [...prev.slice(-14), payload])
    const t = setTimeout(() => {
      setToasts((prev) => prev.filter((x) => x.id !== id))
    }, TOAST_TTL_MS)
    return () => clearTimeout(t)
  }, [])

  const addProgress = useCallback((clientId, engineId, line) => {
    if (!engineId) return
    const key = clientId ? `${clientId}_${engineId}` : `_global_${engineId}`
    setProgressByEngine((prev) => {
      const arr = [...(prev[key] || []), `> ${line}`].slice(-MAX_PROGRESS_LINES_PER_ENGINE)
      return { ...prev, [key]: arr }
    })
  }, [])

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((x) => x.id !== id))
  }, [])

  useEffect(() => {
    let isMounted = true
    const es = openSseStream('/api/telemetry/stream')
    esRef.current = es

    es.onopen = () => { if (isMounted) setConnected(true) }

    es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data || '{}')
          // Fan the raw event out to any registered consumers first.
          listenersRef.current.forEach((fn) => {
            try {
              fn(data)
            } catch (_) {
              /* a misbehaving listener must not break the telemetry stream */
            }
          })
          const severity = data.severity || 'info'
          const message = data.message || 'Unknown event'
          const engine = data.engine || ''
          const clientId = data.client_id || ''
          addProgress(clientId, engine, message)
          // Heuristic classification — orchestrator emits free-form messages and we
          // tag them so the activity feed can colour-code without a schema change.
          const kind = classifyEvent(data, message)
          pushActivity({
            severity,
            message,
            engine,
            client_id: clientId,
            kind,
            job_id: data.job_id || data.run_id || '',
            target: data.target || data.url || '',
            raw: data,
          })
          if (severity === 'error') addToast(severity, message, engine)
        } catch (_) {
          pushActivity({ severity: 'warn', message: String(e.data || ''), kind: 'raw' })
          addToast('error', e.data || 'Telemetry event')
        }
      }

    es.onerror = () => {
      if (isMounted) setConnected(false)
    }

    return () => {
      isMounted = false
      if (esRef.current) {
        esRef.current.close()
        esRef.current = null
      }
    }
  }, [addToast, addProgress, pushActivity])

  const clearActivity = useCallback(() => setActivity([]), [])

  const value = {
    toasts, addToast, removeToast,
    progressByEngine, addProgress,
    activity, clearActivity, connected,
    subscribe,
  }
  return (
    <TelemetryContext.Provider value={value}>
      {children}
    </TelemetryContext.Provider>
  )
}

/**
 * Tag a telemetry event with a coarse `kind` so the activity feed can colour-code
 * (scan/finding/agent/error/heartbeat). Heuristic — keeps the SSE schema unchanged.
 */
function classifyEvent(data, message) {
  const m = (message || '').toLowerCase()
  if (data.kind) return String(data.kind)
  if (m.includes('finding') || m.includes('vulnerability')) return 'finding'
  if (m.includes('engine') && (m.includes('start') || m.includes('running'))) return 'scan_start'
  if (m.includes('engine') && (m.includes('finish') || m.includes('completed') || m.includes('done'))) return 'scan_done'
  if (m.includes('agent') && (m.includes('enrol') || m.includes('online') || m.includes('connect'))) return 'agent'
  if (m.includes('heartbeat') || m.includes('alive') || m.includes('ping')) return 'heartbeat'
  if (m.includes('error') || m.includes('fail') || m.includes('denied')) return 'error'
  if (m.includes('cycle') || m.includes('orchestrator')) return 'orchestrator'
  return 'info'
}

export function useTelemetry() {
  const ctx = useContext(TelemetryContext)
  if (!ctx) throw new Error('useTelemetry must be used within TelemetryProvider')
  return ctx
}
