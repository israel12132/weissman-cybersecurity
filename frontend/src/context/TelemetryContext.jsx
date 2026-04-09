import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react'
import { apiEventSourceUrl } from '../lib/apiBase'

const TelemetryContext = createContext(null)

const TOAST_TTL_MS = 8000
const MAX_PROGRESS_LINES_PER_ENGINE = 80

export function TelemetryProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const [progressByEngine, setProgressByEngine] = useState({})
  const esRef = useRef(null)

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
    let retryTimer = null
    let retryDelay = 2000

    function connect() {
      if (!isMounted) return
      const url = apiEventSourceUrl('/api/telemetry/stream')
      const es = new EventSource(url, { withCredentials: true })
      esRef.current = es

      es.onmessage = (e) => {
        retryDelay = 2000 // reset backoff on successful message
        try {
          const data = JSON.parse(e.data || '{}')
          const severity = data.severity || 'error'
          const message = data.message || 'Unknown error'
          const engine = data.engine || ''
          const clientId = data.client_id || ''
          addProgress(clientId, engine, message)
          if (severity === 'error') addToast(severity, message, engine)
        } catch (_) {
          addToast('error', e.data || 'Telemetry event')
        }
      }

      es.onerror = () => {
        es.close()
        esRef.current = null
        if (!isMounted) return
        // Exponential backoff reconnect (max 30 s)
        retryTimer = setTimeout(() => {
          retryDelay = Math.min(retryDelay * 1.5, 30_000)
          connect()
        }, retryDelay)
      }
    }

    connect()

    return () => {
      isMounted = false
      if (retryTimer) clearTimeout(retryTimer)
      if (esRef.current) {
        esRef.current.close()
        esRef.current = null
      }
    }
  }, [addToast, addProgress])

  const value = { toasts, addToast, removeToast, progressByEngine, addProgress }
  return (
    <TelemetryContext.Provider value={value}>
      {children}
    </TelemetryContext.Provider>
  )
}

export function useTelemetry() {
  const ctx = useContext(TelemetryContext)
  if (!ctx) throw new Error('useTelemetry must be used within TelemetryProvider')
  return ctx
}
