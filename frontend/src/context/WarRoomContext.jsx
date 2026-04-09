import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react'
import { apiEventSourceUrl } from '../lib/apiBase'

const WarRoomContext = createContext(null)

const LATENCY_HISTORY_MAX = 60
const US_CENTER = [37.09, -95.71]
const ENGINE_ACTIVITY_WINDOW_MS = 3000

export function WarRoomProvider({ children }) {
  const [redTeamActive, setRedTeamActive] = useState(false)
  const [commandConfirmed, setCommandConfirmed] = useState(null)
  const [commandRefused, setCommandRefused] = useState(false)
  const [latencyHistory, setLatencyHistory] = useState(() => Array(LATENCY_HISTORY_MAX).fill(null).map((_, i) => ({ t: i, ms: null })))
  const [suggestedWidget, setSuggestedWidget] = useState(null)
  const [targetsWithGeo, setTargetsWithGeo] = useState([])
  const [vulnMarkers, setVulnMarkers] = useState([])
  const [mapZoomComplete, setMapZoomComplete] = useState(false)
  const [lastNewTarget, setLastNewTarget] = useState(null)
  const [lastFinding, setLastFinding] = useState(null)
  const [lastHarvestedToken, setLastHarvestedToken] = useState(null)
  const [engineActivityCount, setEngineActivityCount] = useState({})
  const [lastLatencyMs, setLastLatencyMsState] = useState(null)
  const [discoveredTargets, setDiscoveredTargets] = useState([])
  const [lastTelemetry, setLastTelemetry] = useState(null)
  const latencyIndexRef = useRef(0)
  const activityTsRef = useRef({})

  const setLastLatencyMs = useCallback((ms) => setLastLatencyMsState(ms), [])

  const confirmCommand = useCallback((source, meta = null) => {
    setCommandRefused(false)
    setCommandConfirmed({ source, meta })
    const t = setTimeout(() => setCommandConfirmed(null), 2200)
    return () => clearTimeout(t)
  }, [])

  const refuseCommand = useCallback(() => {
    setCommandConfirmed(null)
    setCommandRefused(true)
    const t = setTimeout(() => setCommandRefused(false), 2500)
    return () => clearTimeout(t)
  }, [])

  const addLatency = useCallback((ms) => {
    setLatencyHistory((prev) => {
      const next = [...prev]
      const i = latencyIndexRef.current % LATENCY_HISTORY_MAX
      next[i] = { t: Date.now(), ms: ms == null || ms === Infinity ? null : ms }
      latencyIndexRef.current += 1
      return next
    })
  }, [])

  const resetLatencyHistory = useCallback(() => {
    latencyIndexRef.current = 0
    setLatencyHistory(
      Array(LATENCY_HISTORY_MAX)
        .fill(null)
        .map((_, i) => ({ t: i, ms: null })),
    )
  }, [])

  const setMapZoomDone = useCallback((done) => {
    setMapZoomComplete(done)
  }, [])

  useEffect(() => {
    const url = apiEventSourceUrl('/api/telemetry/stream')
    const es = new EventSource(url, { withCredentials: true })
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data || '{}')
        setLastTelemetry(data)
        const ev = data.event || 'progress'
        if (ev === 'new_target') {
          setLastNewTarget({ client_id: data.client_id, host: data.host })
          setDiscoveredTargets((prev) => {
            const next = [...prev, { host: data.host, client_id: data.client_id }]
            return next.slice(-24)
          })
        } else if (ev === 'finding_created') {
          const poc = data.poc_exploit
          const sealed =
            Boolean(data.poc_sealed) ||
            (typeof poc === 'string' && poc.includes('[SEALED'))
          setLastFinding({
            client_id: data.client_id,
            finding_id: data.finding_id,
            title: data.title,
            severity: data.severity,
            description: data.description,
            poc_exploit: poc,
            poc_sealed: sealed,
          })
        } else if (ev === 'harvested_token') {
          setLastHarvestedToken({
            client_id: data.client_id,
            role_name: data.role_name,
            context_id: data.context_id,
          })
        } else if (ev === 'progress' && data.engine) {
          const now = Date.now()
          setEngineActivityCount((prev) => {
            const key = data.client_id ? `${data.client_id}_${data.engine}` : `_${data.engine}`
            const last = activityTsRef.current[key] || 0
            if (now - last < 500) return prev
            activityTsRef.current[key] = now
            const next = { ...prev }
            next[key] = (next[key] || 0) + 1
            return next
          })
        }
      } catch (_) {}
    }
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) return; es.close() }
    return () => { es.close() }
  }, [])

  useEffect(() => {
    const t = setInterval(() => {
      setEngineActivityCount((prev) => {
        const next = {}
        for (const k of Object.keys(prev)) {
          const v = (prev[k] || 0) * 0.85
          if (v >= 0.5) next[k] = v
        }
        return Object.keys(next).length ? next : {}
      })
    }, 1000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    if (!lastFinding) return
    const tid = setTimeout(() => setLastFinding(null), 12000)
    return () => clearTimeout(tid)
  }, [lastFinding])

  const value = {
    redTeamActive,
    setRedTeamActive,
    commandConfirmed,
    commandRefused,
    confirmCommand,
    refuseCommand,
    latencyHistory,
    addLatency,
    resetLatencyHistory,
    suggestedWidget,
    setSuggestedWidget,
    targetsWithGeo,
    setTargetsWithGeo,
    vulnMarkers,
    setVulnMarkers,
    mapZoomComplete,
    setMapZoomComplete: setMapZoomDone,
    lastNewTarget,
    setLastNewTarget,
    lastFinding,
    setLastFinding,
    lastHarvestedToken,
    setLastHarvestedToken,
    engineActivityCount,
    lastLatencyMs,
    setLastLatencyMs,
    discoveredTargets,
    setDiscoveredTargets,
    lastTelemetry,
    US_CENTER,
  }

  return (
    <WarRoomContext.Provider value={value}>
      {children}
    </WarRoomContext.Provider>
  )
}

export function useWarRoom() {
  const ctx = useContext(WarRoomContext)
  return ctx || {}
}
