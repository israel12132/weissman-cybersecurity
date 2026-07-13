import { Fragment, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { INTEL_MAP_QUICKNAV } from './lib/appNav'
import { useTranslation } from 'react-i18next'
import CinematicBackground from './components/CinematicBackground'
import EmergencyAlert from './components/EmergencyAlert'
import BattlespaceTopology from './battlespace/BattlespaceTopology'
import SecurityScoreGauge from './components/SecurityScoreGauge'
import LiveIntelTerminal from './components/LiveIntelTerminal'
import KillChainVisualizer from './components/KillChainVisualizer'
import AssetHexGrid from './components/AssetHexGrid'
import CyberRadar from './components/CyberRadar'
import GlobalThreatTicker from './components/GlobalThreatTicker'
import CommandBar from './components/CommandBar'
import { apiUrl } from './lib/apiBase'
import { useWeissmanSocket } from './hooks/useWeissmanSocket'
import { useAuth } from './context/AuthContext'
import LabForensicEvidence from './components/ui/LabForensicEvidence'
import Button from './components/ui/Button'

const HIGHLIGHT_DURATION_MS = 4000

export default function App() {
  const { t } = useTranslation()
  const { logout } = useAuth()
  const {
    events: tickerEvents,
    scoreData,
    connectionStatus,
    emergencyMessage,
    setEmergencyMessage,
  } = useWeissmanSocket()

  const [highlightedEventId, setHighlightedEventId] = useState(null)
  const [commandBarError, setCommandBarError] = useState('')
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    if (tickerEvents.length === 0) return
    const latestEvent = tickerEvents[tickerEvents.length - 1]
    const eventId = latestEvent.id
    setHighlightedEventId(eventId)
    const timer = setTimeout(() => setHighlightedEventId((h) => (h === eventId ? null : h)), HIGHLIGHT_DURATION_MS)
    return () => clearTimeout(timer)
  }, [tickerEvents])

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
        <nav
          aria-label={t('components.intelMap.dashboard')}
          className="flex gap-4 text-sm font-mono flex-wrap items-center"
        >
          {/* Single-sourced from lib/appNav.js (INTEL_MAP_QUICKNAV) — no hardcoded drift. */}
          {INTEL_MAP_QUICKNAV.map((item) => (
            <Fragment key={item.to}>
              {item.separatorBefore && <span className="text-white/10" aria-hidden="true">|</span>}
              <Link
                to={item.to}
                className={`nav-link${item.className ? ` ${item.className}` : ''}`}
                style={item.color ? { color: item.color } : undefined}
              >
                {t(item.labelKey)}
              </Link>
            </Fragment>
          ))}
          <span className="text-white/10" aria-hidden="true">|</span>
          <a href={apiUrl('/api/export/findings')} className="nav-link" download>{t('components.intelMap.export_csv')}</a>
          <Button variant="unstyled" type="button" onClick={() => logout()} className="nav-link nav-link-danger">{t('components.intelMap.logout')}</Button>
        </nav>
      </header>

      <div className="soc-evidence-banner px-4 py-2 max-w-[1600px] mx-auto w-full">
        <LabForensicEvidence />
      </div>

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
          {connectionStatus === 'online' ? t('battlespace.topology_live') : '—'}
        </span>
        <h1 className="soc-title soc-title-ultimate">
          {t('battlespace.title')}
        </h1>
        <GlobalThreatTicker scoreData={scoreData} intelCount={tickerEvents.length} />
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

        <main className="soc-center battlespace-center">
          <BattlespaceTopology connectionStatus={connectionStatus} />
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
