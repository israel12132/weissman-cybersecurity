import { useEffect, useState, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
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
import { apiFetch, apiUrl } from './lib/apiBase'
import { useWeissmanSocket } from './hooks/useWeissmanSocket'

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
  const { t } = useTranslation()
  // Use the robust WebSocket hook
  const {
    events: tickerEvents,
    scoreData,
    globeData,
    connectionStatus,
    emergencyMessage,
    setEmergencyMessage,
    arcEventKinds: ARC_EVENT_KINDS,
  } = useWeissmanSocket()

  const [realtimeArcs, setRealtimeArcs] = useState([])
  const [realtimePulses, setRealtimePulses] = useState([])
  const [highlightedEventId, setHighlightedEventId] = useState(null)
  const [commandBarError, setCommandBarError] = useState('')
  const initialTickerFetchedRef = useRef(false)
  const arcTimeoutsRef = useRef([])
  const [now, setNow] = useState(() => new Date())
  const globeDataRef = useRef(null)
  globeDataRef.current = globeData

  // Handle arc creation for new events
  useEffect(() => {
    if (tickerEvents.length === 0) return

    const latestEvent = tickerEvents[tickerEvents.length - 1]
    const { kind, id: eventId, target, message, severity } = latestEvent

    // Check if this event type should create an arc
    if (!ARC_EVENT_KINDS.has(kind) || !globeData) return

    const to = resolveTargetToLatLon(globeData, target)
    if (!to) return

    const intelNodes = globeData.intelNodes || [{ lat: 37.77, lon: -122.42 }, { lat: 52.52, lon: 13.4 }]
    const from = intelNodes[0] || { lat: 37.77, lon: -122.42 }

    // Create arc
    const arcId = `arc-${eventId}`
    setRealtimeArcs((prev) => [
      ...prev,
      {
        id: arcId,
        from,
        to,
        label: (message || '').slice(0, 12),
        severity: severity === 'critical' ? 'critical' : 'high',
        eventId,
      },
    ])

    // Remove arc after ARC_MAX_AGE_MS
    const arcTimer = setTimeout(() => {
      setRealtimeArcs((a) => a.filter((x) => x.id !== arcId))
    }, ARC_MAX_AGE_MS)
    arcTimeoutsRef.current = [...arcTimeoutsRef.current.slice(-100), arcTimer]

    // Create red pulse for emergency alerts
    if (kind === 'emergency_alert') {
      const pulseId = `pulse-${eventId}`
      setRealtimePulses((prev) => [...prev, { id: pulseId, lat: to.lat, lon: to.lon }])
      setTimeout(() => setRealtimePulses((p) => p.filter((x) => x.id !== pulseId)), 3500)
    }

    // Highlight the event row
    setHighlightedEventId(eventId)
    setTimeout(() => setHighlightedEventId((h) => (h === eventId ? null : h)), HIGHLIGHT_DURATION_MS)
  }, [tickerEvents, globeData, ARC_EVENT_KINDS])

  // Cleanup arc timeouts on unmount
  useEffect(() => {
    return () => {
      arcTimeoutsRef.current.forEach(clearTimeout)
      arcTimeoutsRef.current = []
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
          // Initial events don't trigger arcs, just populate the ticker
          // The hook handles live events
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
    <div className="soc-intel-map-root">
      <CinematicBackground />
      <EmergencyAlert message={emergencyMessage} onComplete={() => setEmergencyMessage('')} />

      <header className="soc-header">
        <nav className="flex gap-4 text-sm font-mono flex-wrap items-center">
          <a href="/" className="nav-link">{t('components.intelMap.dashboard')}</a>
          <a href="/clients" className="nav-link">{t('components.intelMap.clients')}</a>
          <Link to="/engines" className="nav-link nav-link-active">{t('components.intelMap.engine_matrix')}</Link>
          <Link to="/threat-intel" className="nav-link" style={{ color: 'rgba(139,92,246,0.85)' }}>{t('components.intelMap.threat_intel')}</Link>
          <Link to="/threat-emulation" className="nav-link">{t('components.intelMap.apt_emulation')}</Link>
          <Link to="/cloud" className="nav-link">{t('components.intelMap.cloud')}</Link>
          <Link to="/supply-chain" className="nav-link">{t('components.intelMap.supply_chain')}</Link>
          <Link to="/network" className="nav-link">{t('components.intelMap.network')}</Link>
          <Link to="/domain-discovery" className="nav-link">{t('components.intelMap.discovery')}</Link>
          <Link to="/pqc-radar" className="nav-link">{t('components.intelMap.pqc_radar')}</Link>
          <Link to="/oast" className="nav-link">{t('components.intelMap.oast')}</Link>
          <Link to="/digital-twin" className="nav-link">{t('components.intelMap.digital_twin')}</Link>
          <Link to="/zero-day-radar" className="nav-link">{t('components.intelMap.zero_day')}</Link>
          <span className="text-white/10">|</span>
          <Link to="/findings" className="nav-link nav-link-findings">{t('components.intelMap.findings_c2')}</Link>
          <Link to="/incident-response" className="nav-link" style={{ color: 'rgba(239,68,68,0.85)' }}>{t('components.intelMap.ir_center')}</Link>
          <Link to="/vuln-intel" className="nav-link" style={{ color: 'rgba(249,115,22,0.85)' }}>{t('components.intelMap.vuln_intel')}</Link>
          <Link to="/dark-web" className="nav-link" style={{ color: 'rgba(167,139,250,0.85)' }}>{t('components.intelMap.dark_web')}</Link>
          <Link to="/threat-hunting" className="nav-link" style={{ color: 'rgba(139,92,246,0.85)' }}>{t('components.intelMap.threat_hunt')}</Link>
          <span className="text-white/10">|</span>
          <Link to="/council-queue" className="nav-link" style={{ color: 'rgba(251,191,36,0.7)' }}>{t('components.intelMap.council')}</Link>
          <Link to="/sso-config" className="nav-link" style={{ color: 'rgba(168,85,247,0.7)' }}>{t('components.intelMap.sso')}</Link>
          <Link to="/admin" className="nav-link" style={{ color: 'rgba(251,191,36,0.9)' }}>{t('components.intelMap.admin')}</Link>
          <Link to="/system-core" className="nav-link">{t('components.intelMap.system_core')}</Link>
          <span className="text-white/10">|</span>
          <a href={apiUrl('/api/export/findings')} className="nav-link" download>{t('components.intelMap.export_csv')}</a>
          <a href="/logout" className="nav-link nav-link-danger">{t('components.intelMap.logout')}</a>
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
          {connectionStatus === 'online' ? now.toISOString().slice(11, 23) : t('components.intelMap.connection_lost')}
        </span>
        <span className="soc-branding-status soc-branding-status-tr">
          {connectionStatus === 'online' ? t('components.intelMap.scanning') : '—'}
        </span>
        <h1 className="soc-title soc-title-ultimate">{t('components.intelMap.title')}</h1>
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
