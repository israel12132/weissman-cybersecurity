import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { motion } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import OverviewTab from './OverviewTab'
import EngineRoomTab from './EngineRoomTab'
import FindingsTab from './FindingsTab'
import IdentityMatrixTab from './IdentityMatrixTab'
import RiskGraphTab from './RiskGraphTab'
import AutoHealTab from './AutoHealTab'
import DeceptionGridTab from './DeceptionGridTab'
import LivePipelineMonitor from './LivePipelineMonitor'
import AuditTrailTab from './AuditTrailTab'
import SettingsAlertsTab from './SettingsAlertsTab'
import ComplianceDashboardTab from './ComplianceDashboardTab'
import SwarmMindTab from './SwarmMindTab'
import ContainmentRulesTab from './ContainmentRulesTab'
import AIModelRiskTab from './AIModelRiskTab'
import GlobalEdgeSwarmMap from './GlobalEdgeSwarmMap'
import SatelliteDroneMap from '../warroom/SatelliteDroneMap'
import NeuralEngineWeb from '../warroom/NeuralEngineWeb'
import SystemPulseEKG from '../warroom/SystemPulseEKG'
import TacticalFindingOverlay from '../warroom/TacticalFindingOverlay'
import WarRoomSoundscape from '../warroom/WarRoomSoundscape'
import CockpitTabErrorBoundary from './CockpitTabErrorBoundary'
import CeoMissionControlTab from './CeoMissionControlTab'
import { useContainerChartSize } from '../../hooks/useViewportChartSize'
import { apiFetch } from '../../lib/apiBase'

const TABS = [
  { id: 'overview', label: 'Overview', Component: OverviewTab },
  { id: 'engine-room', label: 'Engine Room', Component: EngineRoomTab },
  { id: 'findings', label: 'Findings & Reports', Component: FindingsTab },
  { id: 'identity-matrix', label: 'Identity Matrix', Component: IdentityMatrixTab },
  { id: 'risk-graph', label: 'Risk Graph', Component: RiskGraphTab },
  { id: 'auto-heal', label: 'Auto-Heal', Component: AutoHealTab },
  { id: 'deception', label: 'Deception Grid', Component: DeceptionGridTab },
  { id: 'pipeline', label: 'Pipeline Monitor', Component: LivePipelineMonitor },
  { id: 'audit-trail', label: 'Audit Trail', Component: AuditTrailTab },
  { id: 'settings-alerts', label: 'Settings & Alerts', Component: SettingsAlertsTab },
  { id: 'compliance', label: 'Compliance', Component: ComplianceDashboardTab },
  { id: 'swarm-mind', label: 'Swarm Mind', Component: SwarmMindTab },
  { id: 'containment', label: 'Auto-Containment', Component: ContainmentRulesTab },
  { id: 'ai-model-risk', label: 'AI Model Risk', Component: AIModelRiskTab },
  { id: 'edge-swarm', label: 'Edge Swarm Map', Component: GlobalEdgeSwarmMap },
]

function targetUrlFromClient(client) {
  if (!client) return ''
  let domains = client.domains
  if (typeof domains === 'string') {
    try {
      const arr = JSON.parse(domains)
      domains = Array.isArray(arr) ? arr : []
    } catch (_) {
      domains = []
    }
  }
  const first = Array.isArray(domains) && domains.length > 0 ? domains[0] : null
  if (!first || typeof first !== 'string') return ''
  const host = first.startsWith('http') ? first : `https://${first}`
  return host
}

export default function ClientCockpit({ ceoIntegrated = false }) {
  const [neuralWrapRef, neuralSize] = useContainerChartSize(120)
  const { selectedClient, selectedClientId, refreshClients, setPoeJobId } = useClient()
  const [activeTab, setActiveTab] = useState(() =>
    ceoIntegrated ? 'mission-control' : 'overview',
  )

  const tabs = useMemo(() => {
    if (!ceoIntegrated) return TABS
    return [
      { id: 'mission-control', label: 'Mission Control', Component: CeoMissionControlTab },
      ...TABS,
    ]
  }, [ceoIntegrated])
  const [engageLoading, setEngageLoading] = useState(false)
  const [healthSummary, setHealthSummary] = useState(null)
  const [safeMode, setSafeMode] = useState(false)
  const [safeSaving, setSafeSaving] = useState(false)
  const [boardReportLoading, setBoardReportLoading] = useState(false)
  const { redTeamActive } = useWarRoom()

  useEffect(() => {
    const loadHealth = () => {
      apiFetch('/api/health')
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => d && setHealthSummary(d))
        .catch(() => {})
    }
    loadHealth()
    const t = setInterval(loadHealth, 30000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    apiFetch('/api/enterprise/settings')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setSafeMode(!!d.global_safe_mode))
      .catch(() => {})
  }, [])

  const toggleSafeMode = useCallback(async () => {
    setSafeSaving(true)
    const next = !safeMode
    try {
      const r = await apiFetch('/api/enterprise/settings', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global_safe_mode: next }),
      })
      if (r.ok) setSafeMode(next)
    } catch (_) {}
    setSafeSaving(false)
  }, [safeMode])

  const downloadBoardReport = async () => {
    setBoardReportLoading(true)
    try {
      const q = selectedClientId ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''
      const r = await apiFetch(`/api/reports/executive${q}`)
      if (!r.ok) {
        const err = await r.json().catch(() => ({}))
        window.alert(err.detail || err.error || 'Board report failed')
        return
      }
      const blob = await r.blob()
      const dispo = r.headers.get('Content-Disposition')
      let filename = 'Weissman_Board_Report.pdf'
      if (dispo) {
        const m = dispo.match(/filename="([^"]+)"/)
        if (m) filename = m[1]
      }
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.rel = 'noopener'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch {
      window.alert('Network error generating board report')
    }
    setBoardReportLoading(false)
  }

  const runFullScan = async () => {
    setEngageLoading(true)
    try {
      const r = await apiFetch('/api/scan/run-all', { method: 'POST' })
      if (r.ok) {
        const d = await r.json().catch(() => ({}))
        if (d && d.message) refreshClients()
      }
      const targetUrl = targetUrlFromClient(selectedClient)
      if (targetUrl && selectedClientId) {
        const pr = await apiFetch('/api/poe-scan/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ client_id: String(selectedClientId), target_url: targetUrl }),
        })
        if (pr.ok) {
          const pd = await pr.json().catch(() => ({}))
          if (pd && pd.job_id) setPoeJobId(pd.job_id)
        }
      }
    } catch (_) {}
    setEngageLoading(false)
  }

  if (!selectedClientId) {
    if (ceoIntegrated) {
      return (
        <main className="flex-1 flex flex-col min-h-0 min-w-0 w-full bg-black/20 backdrop-blur-sm relative isolate overflow-hidden">
          <WarRoomSoundscape />
          <header className="shrink-0 bg-black/40 backdrop-blur-md border-b border-white/10 px-4 sm:px-6 py-3 z-10">
            <h1 className="text-sm font-semibold text-white tracking-tight">CEO secured cockpit</h1>
            <p className="text-[10px] text-slate-500 font-mono uppercase tracking-widest mt-1">
              Mission control below · pick a client in Global Nexus for target-scoped tabs
            </p>
          </header>
          <div className="flex-1 min-h-0 overflow-auto z-10">
            <CeoMissionControlTab />
          </div>
        </main>
      )
    }
    return (
      <main className="flex-1 flex items-center justify-center min-h-0 min-w-0 w-full px-4 bg-black/20 backdrop-blur-sm overflow-auto">
        <div className="text-center px-6 py-8 rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 shadow-xl">
          <p className="text-sm font-medium text-white/90 mb-1 tracking-wide">No client selected</p>
          <p className="text-xs text-white/50 uppercase tracking-widest">Select a client from the sidebar</p>
        </div>
      </main>
    )
  }

  const activeTabMeta = tabs.find((t) => t.id === activeTab)
  const ActiveComponent = activeTabMeta?.Component ?? OverviewTab

  return (
    <main
      className="flex-1 flex flex-col min-h-0 min-w-0 w-full max-w-full bg-black/20 backdrop-blur-sm relative isolate overflow-hidden"
      style={{ mixBlendMode: 'normal' }}
    >
      <WarRoomSoundscape />
      {/* Holographic scanline overlay */}
      <div
        className="absolute inset-0 pointer-events-none z-[5] opacity-[0.03]"
        style={{
          background: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255,255,255,0.03) 2px, rgba(255,255,255,0.03) 4px)',
        }}
        aria-hidden
      />
      {redTeamActive && (
        <div
          className="absolute inset-0 pointer-events-none z-10"
          style={{
            background: 'radial-gradient(ellipse 80% 50% at 50% 0%, rgba(239,68,68,0.1) 0%, transparent 60%)',
          }}
        />
      )}
      {redTeamActive && (
        <motion.div
          animate={{ opacity: [1, 0.6, 1] }}
          transition={{ repeat: Infinity, duration: 1.2 }}
          className="absolute top-2 left-1/2 -translate-x-1/2 z-20 px-4 py-1.5 rounded-lg border border-red-500/60 bg-red-950/90 backdrop-blur text-xs font-bold text-red-400 tracking-widest"
        >
          SYSTEM EXPLOITATION ACTIVE — ROE OVERRIDDEN
        </motion.div>
      )}
      <TacticalFindingOverlay />
      {/* Header: glass */}
      <header className="shrink-0 bg-black/40 backdrop-blur-md border-b border-white/10 shadow-lg relative z-10 max-w-full">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between px-4 sm:px-6 py-4 max-w-full">
          <div className="flex flex-col sm:flex-row sm:items-center sm:flex-wrap gap-3 sm:gap-6 min-w-0">
            <h1 className="text-base sm:text-lg font-semibold text-white tracking-tight truncate min-w-0 max-w-full">
              {selectedClient?.name || `Client ${selectedClientId}`}
            </h1>
            <span
              className="px-3 py-1 rounded-lg text-xs font-mono font-medium border border-[#22d3ee]/30 max-w-full sm:max-w-[280px] truncate"
              style={{ background: 'rgba(34, 211, 238, 0.12)', color: '#22d3ee' }}
              title={healthSummary ? JSON.stringify(healthSummary) : ''}
            >
              {healthSummary
                ? `Health: ${Math.floor((healthSummary.uptime_secs || 0) / 60)}m · DB ${(
                    (healthSummary.db_bytes || 0) /
                    (1024 * 1024)
                  ).toFixed(1)}MB${healthSummary.scanning_active ? ' · SCAN' : ''}`
                : 'Health: —'}
            </span>
            <button
              type="button"
              disabled={safeSaving}
              onClick={toggleSafeMode}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider border transition-colors ${
                safeMode
                  ? 'border-emerald-500/70 bg-emerald-950/80 text-emerald-300'
                  : 'border-white/25 bg-white/5 text-white/60 hover:text-white/90'
              } disabled:opacity-50`}
            >
              {safeMode ? 'Safe mode ON' : 'Safe mode OFF'}
            </button>
          </div>
          <div className="flex flex-wrap items-stretch sm:items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={downloadBoardReport}
              disabled={boardReportLoading}
              className="px-3 sm:px-4 py-2 sm:py-2.5 rounded-xl font-semibold text-[10px] sm:text-xs uppercase tracking-wider border border-white/20 bg-white/5 text-white/85 hover:bg-white/10 hover:border-white/30 disabled:opacity-50"
            >
              {boardReportLoading ? 'PDF…' : 'Board report'}
            </button>
            <button
              type="button"
              onClick={runFullScan}
              disabled={engageLoading}
              className="px-4 sm:px-5 py-2 sm:py-2.5 rounded-xl font-semibold text-xs sm:text-sm tracking-wide transition-all border border-[#22d3ee]/50 bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 hover:shadow-[0_0_20px_rgba(34,211,238,0.2)] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {engageLoading ? 'ENGAGING…' : 'ENGAGE'}
            </button>
          </div>
        </div>

        {/* Tab nav */}
        <nav className="flex gap-0 px-3 sm:px-6 border-t border-white/10 overflow-x-auto max-w-full [-webkit-overflow-scrolling:touch]">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-3 sm:px-5 py-2.5 sm:py-3.5 text-xs sm:text-sm font-medium border-b-2 transition-all uppercase tracking-widest whitespace-nowrap shrink-0 ${
                activeTab === tab.id
                  ? 'border-[#22d3ee] text-white'
                  : 'border-transparent text-white/50 hover:text-white/80'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </header>

      {/* War Room: Satellite Map + Neural Web */}
      <div className="shrink-0 grid grid-cols-1 lg:grid-cols-12 gap-3 px-3 sm:px-4 py-3 border-b border-white/10 relative z-10 w-full max-w-full min-w-0">
        <motion.div
          className="lg:col-span-4 h-36 sm:h-40 lg:h-52 rounded-xl overflow-hidden border border-white/10 bg-slate-950/90 w-full max-w-full min-w-0"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <SatelliteDroneMap />
        </motion.div>
        <motion.div
          ref={neuralWrapRef}
          className="lg:col-span-8 h-36 sm:h-40 lg:h-52 rounded-xl overflow-hidden border border-white/10 bg-slate-950/80 flex items-center justify-center w-full max-w-full min-w-0"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3, delay: 0.05 }}
        >
          <NeuralEngineWeb width={neuralSize.width} height={neuralSize.height} />
        </motion.div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden relative z-10 min-w-0 max-w-full">
        <CockpitTabErrorBoundary key={activeTab} tabId={activeTab} tabLabel={activeTabMeta?.label}>
          <ActiveComponent />
        </CockpitTabErrorBoundary>
      </div>

      {/* System Pulse EKG */}
      <div className="shrink-0 px-4 py-3 border-t border-white/10 relative z-10">
        <SystemPulseEKG />
      </div>
    </main>
  )
}
