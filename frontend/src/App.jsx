import { useEffect, useState, useRef } from 'react'
import { Link } from 'react-router-dom'
import CinematicBackground from './components/CinematicBackground'
import EmergencyAlert from './components/EmergencyAlert'
import Globe from './components/Globe'
import SecurityScoreGauge from './components/SecurityScoreGauge'
import LiveIntelTerminal from './components/LiveIntelTerminal'
import KillChainVisualizer from './components/KillChainVisualizer'
import AssetHexGrid from './components/AssetHexGrid'
import CyberRadar from './components/CyberRadar'
import GlobalThreatTicker from './components/GlobalThreatTicker'
import CommandBar from './components/CommandBar'
import { apiFetch } from './lib/apiBase'

const WS_BASE = typeof window !== 'undefined'
  ? (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host
  : ''

const DEBOUNCE_SAME_EVENT_MS = 5000
const ARC_EVENT_KINDS = new Set(['scan_pulse', 'critical_cve', 'darkweb', 'fuzzer_anomaly', 'new_source_discovered', 'github_exploit_repo', 'emergency_alert'])
const HIGHLIGHT_DURATION_MS = 4000
const ARC_MAX_AGE_MS = 4000

function resolveTargetToLatLon(globeData, targetName) {
  const name = (targetName || '').toString().trim().toLowerCase()
  if (!name || !globeData) return null
  for (const p of globeData.scanPulses || []) {
    if ((p.name || '').toString().toLowerCase() === name) return { lat: p.lat, lon: p.lon }
  }
  for (const v of globeData.criticalVulns || []) {
    if ((v.client_name || '').toString().toLowerCase() === name) return { lat: v.lat, lon: v.lon }
  }
  return null
}

export default function App() {
  const [globeData, setGlobeData] = useState(null)
  const [scoreData, setScoreData] = useState(null)
  const [tickerEvents, setTickerEvents] = useState([])
  const [realtimeArcs, setRealtimeArcs] = useState([])
  const [realtimePulses, setRealtimePulses] = useState([])
  const [highlightedEventId, setHighlightedEventId] = useState(null)
  const [emergencyMessage, setEmergencyMessage] = useState('')
  const [connectionStatus, setConnectionStatus] = useState('offline')
  const [commandBarError, setCommandBarError] = useState('')
  const wsRef = useRef(null)
  const lastTickerKeyRef = useRef({ key: '', t: 0 })
  const initialTickerFetchedRef = useRef(false)
  const eventIdRef = useRef(0)
  const arcTimeoutsRef = useRef([])
  const [now, setNow] = useState(() => new Date())
  const globeDataRef = useRef(null)
  globeDataRef.current = globeData

  // Single WebSocket stream: no polling. Phase 2: automatic reconnection on drop.
  const reconnectDelayRef = useRef(2000)
  const reconnectTimeoutRef = useRef(null)

  useEffect(() => {
    if (!WS_BASE) return
    const url = `${WS_BASE}/ws/command-center`
    let ws
    function connect() {
      try {
        ws = new WebSocket(url)
        wsRef.current = ws
        ws.onopen = () => {
          setConnectionStatus('online')
          reconnectDelayRef.current = 2000
        }
        ws.onclose = () => {
          setConnectionStatus('offline')
          setRealtimeArcs([])
          setRealtimePulses([])
          setEmergencyMessage('')
          reconnectTimeoutRef.current = setTimeout(() => connect(), reconnectDelayRef.current)
          reconnectDelayRef.current = Math.min(reconnectDelayRef.current + 1000, 15000)
        }
        ws.onerror = () => {
          setConnectionStatus('offline')
          setRealtimeArcs([])
          setRealtimePulses([])
          setEmergencyMessage('')
        }
      ws.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data)
          if (data.type === 'init' || data.type === 'refresh') {
            if (data.globe) setGlobeData(data.globe)
            if (data.score) setScoreData(data.score)
            setConnectionStatus('online')
            return
          }
          const kind = data.kind || 'audit'
          const payload = data.payload || {}
          const now = new Date()
          const time = now.toTimeString().slice(0, 8)
          let severity = (payload.severity || (kind === 'critical_cve' ? 'high' : 'info')).toLowerCase()
          let message
          if (kind === 'new_source_discovered') {
            message = payload.message || `NEW SOURCE DISCOVERED: ${(payload.url || '').slice(0, 50)}... (${payload.risk_level || 'high'})`
            severity = (payload.risk_level || 'high').toLowerCase()
          } else if (kind === 'github_exploit_repo') {
            message = payload.message || `Exploit-like repo: ${payload.full_name || '—'}`
            severity = (payload.severity || 'high').toLowerCase()
          } else if (kind === 'emergency_alert') {
            message = payload.message || 'WARNING: VERIFIED THREAT DETECTED.'
            severity = 'critical'
            setEmergencyMessage(payload.message || message)
          } else if (kind === 'audit') {
            message = (payload.action || '').replace(/_/g, ' ')
          } else {
            message = `[${kind}] ${(payload.message || JSON.stringify(payload)).slice(0, 80)}`
          }
          const targetLabel = payload.target || payload.client_name || payload.target_name || payload.url || payload.full_name || '—'
          const key = `${message}|${targetLabel}`
          const t = Date.now()
          if (lastTickerKeyRef.current.key === key && t - lastTickerKeyRef.current.t < DEBOUNCE_SAME_EVENT_MS) {
            return
          }
          lastTickerKeyRef.current = { key, t }
          eventIdRef.current += 1
          const eventId = `ev-${eventIdRef.current}-${t}`
          const event = {
            id: eventId,
            time,
            target: targetLabel,
            target_ip: payload.target_ip || payload.target || '—',
            agentId: payload.user_email || payload.agentId || 'Discovery',
            severity,
            message: message || '—',
          }
          setTickerEvents((prev) => [...prev, event])

          // Arc ↔ Live Intel: when event triggers arc, add arc and highlight row; emergency_alert also adds Red Pulse
          const currentGlobe = globeDataRef.current
          if (ARC_EVENT_KINDS.has(kind) && currentGlobe) {
            const to = resolveTargetToLatLon(currentGlobe, targetLabel)
            const intelNodes = currentGlobe.intelNodes || [{ lat: 37.77, lon: -122.42 }, { lat: 52.52, lon: 13.4 }]
            const from = intelNodes[0] || { lat: 37.77, lon: -122.42 }
            if (to) {
              const arcId = `arc-${eventId}`
              setRealtimeArcs((prev) => [...prev, { id: arcId, from, to, label: message.slice(0, 12), severity: severity === 'critical' ? 'critical' : 'high', eventId }])
              const arcTimer = setTimeout(() => {
                setRealtimeArcs((a) => a.filter((x) => x.id !== arcId))
              }, ARC_MAX_AGE_MS)
              arcTimeoutsRef.current = [...arcTimeoutsRef.current.slice(-100), arcTimer]
              if (kind === 'emergency_alert') {
                const pulseId = `pulse-${eventId}`
                setRealtimePulses((prev) => [...prev, { id: pulseId, lat: to.lat, lon: to.lon }])
                setTimeout(() => setRealtimePulses((p) => p.filter((x) => x.id !== pulseId)), 3500)
              }
              setHighlightedEventId(eventId)
              setTimeout(() => setHighlightedEventId((h) => (h === eventId ? null : h)), HIGHLIGHT_DURATION_MS)
            }
          }
        } catch (_) {
          setTickerEvents((prev) => [...prev, { id: `ev-err-${Date.now()}`, time: new Date().toTimeString().slice(0, 8), target: '—', target_ip: '—', agentId: 'system', severity: 'info', message: 'Event' }])
        }
      }
      } catch (_) {
        setConnectionStatus('offline')
      }
    }
    connect()
    return () => {
      arcTimeoutsRef.current.forEach(clearTimeout)
      arcTimeoutsRef.current = []
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) wsRef.current.close()
      wsRef.current = null
      setConnectionStatus('offline')
    }
  }, [])

  // One-time initial ticker load: add ids to events for highlight/arc mapping
  useEffect(() => {
    if (initialTickerFetchedRef.current) return
    initialTickerFetchedRef.current = true
    const load = async () => {
      try {
        const r = await apiFetch('/api/command-center/ticker?page=1&per_page=500')
        if (r.ok) {
          const d = await r.json()
          const events = (d.events || []).map((e, i) => ({ ...e, id: e.id || `ev-init-${i}-${Date.now()}` }))
          setTickerEvents((prev) => (prev.length ? prev : events))
        }
      } catch (_) {}
    }
    load()
  }, [])

  useEffect(() => {
    if (connectionStatus !== 'online') return
    const iv = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(iv)
  }, [connectionStatus])

  return (
    <div className="soc-2100-root">
      <CinematicBackground />
      <EmergencyAlert message={emergencyMessage} onComplete={() => setEmergencyMessage('')} />

      <header className="soc-header">
        <nav className="flex gap-6 text-sm font-mono flex-wrap">
          <a href="/" className="nav-link">Dashboard</a>
          <a href="/clients" className="nav-link">Clients</a>
          <Link to="/engines" className="nav-link nav-link-active">Engine Matrix</Link>
          <Link to="/threat-emulation" className="nav-link">APT Emulation</Link>
          <Link to="/cloud" className="nav-link">Cloud</Link>
          <Link to="/supply-chain" className="nav-link">Supply Chain</Link>
          <Link to="/network" className="nav-link">Network</Link>
          <Link to="/pqc-radar" className="nav-link">PQC Radar</Link>
          <Link to="/oast" className="nav-link">OAST</Link>
          <Link to="/digital-twin" className="nav-link">Digital Twin</Link>
          <Link to="/zero-day-radar" className="nav-link">Zero-Day</Link>
          <Link to="/findings" className="nav-link nav-link-findings">Findings C2</Link>
          <Link to="/system-core" className="nav-link">System Core</Link>
          <a href="/api/export/findings" className="nav-link" download>Export CSV</a>
          <a href="/logout" className="nav-link nav-link-danger">Logout</a>
        </nav>
      </header>

      <CommandBar
        onError={(msg) => setCommandBarError(msg)}
        onScanLaunched={() => setCommandBarError('')}
      />
      {commandBarError && (
        <div className="soc-header-error" role="alert">
          {commandBarError}
        </div>
      )}

      <div className="soc-branding soc-branding-frame">
        <div className="soc-branding-corner soc-branding-tl" />
        <div className="soc-branding-corner soc-branding-tr" />
        <div className="soc-branding-corner soc-branding-bl" />
        <div className="soc-branding-corner soc-branding-br" />
        <span className="soc-branding-status soc-branding-status-tl">
          {connectionStatus === 'online' ? now.toISOString().slice(11, 23) : 'CONNECTION LOST'}
        </span>
        <span className="soc-branding-status soc-branding-status-tr">
          {connectionStatus === 'online' ? 'Scanning...' : '—'}
        </span>
        <h1 className="soc-title soc-title-ultimate">WEISSMAN | ADVANCED OFFENSIVE INTELLIGENCE</h1>
        <GlobalThreatTicker scoreData={scoreData} globeData={globeData} intelCount={tickerEvents.length} />
      </div>

      <div className="soc-grid">
        <aside className="soc-left">
          <div className="soc-panel soc-panel-killchain">
            <KillChainVisualizer />
          </div>
          <div className="soc-panel soc-panel-hex">
            <AssetHexGrid />
          </div>
          <div className="soc-panel soc-panel-score">
            <SecurityScoreGauge data={scoreData} />
          </div>
        </aside>

        <main className="soc-center">
          <Globe data={globeData} realtimeArcs={realtimeArcs} realtimePulses={realtimePulses} connectionStatus={connectionStatus} />
        </main>

        <aside className="soc-right">
          <div className="soc-panel soc-panel-radar">
            <CyberRadar />
          </div>
          <div className="soc-panel soc-panel-terminal">
            <LiveIntelTerminal events={tickerEvents} highlightedEventId={highlightedEventId} connectionStatus={connectionStatus} matrixStyle />
          </div>
        </aside>
      </div>
    </div>
  )
}
