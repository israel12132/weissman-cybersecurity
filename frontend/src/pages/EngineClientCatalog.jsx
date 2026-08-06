/**
 * Engine Client Catalog
 *
 * Organizes all 482 attack engines by client type / industry vertical.
 * Each client profile shows the relevant engine groups and individual engines,
 * with descriptions, MITRE technique badges, and per-profile or global Run All buttons.
 *
 * Route: /engine-catalog
 */
import { firstClientTarget } from '../lib/clientTarget'
import { useState, useMemo, useCallback, useEffect } from 'react'
import { Link } from 'react-router'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { ENGINE_GROUP_DEFS, getEnginesByGroup } from '../lib/enginesRegistry'
import { apiFetch } from '../utils/apiFetch'
import { useProductionEngines } from '../lib/useProductionEngines'
import { useEngineCapabilities } from '../lib/useEngineCapabilities'
import { useJobPoll, normalizeJobStatus } from '../lib/useJobPoll'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { normalizeIntegrations } from '../lib/engineClientPrefill'
import { useRegisterHubClient } from '../context/EngineHubContext'
import { useLaunchEngineScan } from '../hooks/useLaunchEngineScan'
import Button from '../components/ui/Button'

// ─── Client Profiles ─────────────────────────────────────────────────────────
// Each profile declares which engine *groups* are relevant for that client type.
// Engines belonging to those groups will be displayed under the profile.

const CLIENT_PROFILES = [
  {
    id: 'enterprise',
    label: 'Enterprise / Corporate',
    icon: '🏢',
    color: '#3b82f6',
    description:
      'Large organizations with complex multi-cloud infrastructure, broad external attack surface, and compliance obligations (SOC2, ISO 27001).',
    groups: ['recon', 'web', 'cloud', 'network', 'crypto', 'stealth', 'supply_chain', 'apt', 'data'],
  },
  {
    id: 'healthcare',
    label: 'Healthcare / HIPAA',
    icon: '🏥',
    color: '#10b981',
    description:
      'Medical and life-science organizations requiring strict ePHI data protection, HIPAA compliance, and resilience against ransomware targeting clinical systems.',
    groups: ['recon', 'web', 'data', 'crypto', 'cloud', 'network', 'malware'],
  },
  {
    id: 'government',
    label: 'Government / Defense',
    icon: '🏛️',
    color: '#6366f1',
    description:
      'Public-sector and defense agencies facing nation-state APT threats, requiring deep supply-chain integrity checks and classified-network posture validation.',
    groups: ['apt', 'recon', 'crypto', 'network', 'stealth', 'cloud', 'ot', 'supply_chain'],
  },
  {
    id: 'fintech',
    label: 'Fintech / Financial',
    icon: '💳',
    color: '#f59e0b',
    description:
      'Banks, payment processors, and trading platforms with PCI-DSS obligations, high-value transaction APIs, and fraud-prevention requirements.',
    groups: ['web', 'crypto', 'data', 'recon', 'network', 'apt', 'mobile'],
  },
  {
    id: 'smb',
    label: 'SMB / Startup',
    icon: '🚀',
    color: '#22d3ee',
    description:
      'Small-to-medium businesses and early-stage startups with limited security budgets — prioritizing the highest-impact, fastest-to-exploit attack vectors.',
    groups: ['recon', 'web', 'social', 'mobile', 'data'],
  },
  {
    id: 'ecommerce',
    label: 'E-Commerce / Retail',
    icon: '🛒',
    color: '#ec4899',
    description:
      'Online retailers and marketplace platforms focused on customer PII protection, payment-flow security, and mobile-app integrity.',
    groups: ['web', 'mobile', 'social', 'data', 'recon', 'crypto'],
  },
  {
    id: 'ot',
    label: 'OT / ICS / Manufacturing',
    icon: '🏭',
    color: '#f97316',
    description:
      'Operational technology environments — factories, utilities, and critical infrastructure — where Purdue model boundaries and legacy protocols must be validated.',
    groups: ['ot', 'network', 'recon', 'stealth', 'apt'],
  },
  {
    id: 'saas',
    label: 'SaaS / Cloud-Native',
    icon: '☁️',
    color: '#84cc16',
    description:
      'Cloud-first SaaS products built on Kubernetes, microservices, and CI/CD pipelines — requiring container-escape, supply-chain, and AI-model attack coverage.',
    groups: ['cloud', 'web', 'supply_chain', 'ai', 'recon', 'data', 'network'],
  },
  {
    id: 'ai_ml',
    label: 'AI / ML Products',
    icon: '🤖',
    color: '#d946ef',
    description:
      'Companies deploying LLMs, ML pipelines, or AI-driven products — needing prompt-injection, model-poisoning, and training-data-exfiltration validation.',
    groups: ['ai', 'web', 'data', 'cloud', 'supply_chain'],
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const GROUP_ICONS = {
  recon: '🔍',
  web: '🌐',
  ai: '🤖',
  cloud: '☁️',
  ot: '⚙️',
  stealth: '👤',
  crypto: '🔐',
  network: '📡',
  supply_chain: '📦',
  apt: '🎯',
  malware: '🦠',
  social: '📣',
  mobile: '📱',
  data: '💾',
}

function getGroupDef(groupId) {
  return ENGINE_GROUP_DEFS.find((g) => g.id === groupId)
}


/** All engines belonging to a client profile (deduplicated, stable order) */
function profileEngines(profile) {
  const seen = new Set()
  const result = []
  for (const gId of profile.groups) {
    for (const e of getEnginesByGroup(gId)) {
      if (!seen.has(e.id)) {
        seen.add(e.id)
        result.push(e)
      }
    }
  }
  return result
}

// ─── Components ───────────────────────────────────────────────────────────────

function MitreBadge({ id }) {
  if (!id) return null
  return (
    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-muted)] tracking-wider">
      {id}
    </span>
  )
}

function StatusDot({ status }) {
  const map = {
    running: '#22d3ee',
    completed: '#4ade80',
    error: '#ef4444',
    idle: '#374151',
  }
  const color = map[status] ?? map.idle
  return (
    <span className="relative inline-flex items-center justify-center w-2.5 h-2.5">
      {status === 'running' && (
        <span
          className="absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping"
          style={{ backgroundColor: color }}
        />
      )}
      <span className="relative inline-flex rounded-full w-2 h-2" style={{ backgroundColor: color }} />
    </span>
  )
}

function EngineRow({ engine, status, selected, onSelect, onRun, runDisabled, isProductionEngine, capability, telemetry, t }) {
  const gDef = getGroupDef(engine.group)
  const groupColor = gDef?.color ?? '#6b7280'
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      className={`flex items-start gap-3 px-3 py-2.5 rounded-lg border transition-all cursor-pointer ${
        selected ? 'border-[var(--border-strong)] bg-[var(--row-hover-bg)]' : 'border-transparent hover:border-[var(--border-default)] hover:bg-white/3'
      }`}
      onClick={() => onSelect(engine.id)}
    >
      {/* Checkbox */}
      <div className="mt-0.5 shrink-0">
        <div
          className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
            selected ? 'border-cyan-400/60 bg-cyan-500/20' : 'border-[var(--border-strong)]'
          }`}
        >
          {selected && <span className="text-cyan-400 text-[10px]">✓</span>}
        </div>
      </div>

      {/* Status */}
      <div className="mt-1 shrink-0">
        <StatusDot status={status ?? 'idle'} />
      </div>

      {/* Info */}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-[var(--text-primary)]">{engine.label}</span>
          <MitreBadge id={engine.mitre} />
          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
            style={{ color: groupColor, borderColor: `${groupColor}40`, background: `${groupColor}10` }}
          >
            {GROUP_ICONS[engine.group] ?? '◆'} {gDef?.label ?? engine.group}
          </span>
          {!engine.requiresTarget && (
            <span className="text-[9px] font-mono text-emerald-400/70 border border-emerald-500/20 px-1.5 py-0.5 rounded">
              GLOBAL
            </span>
          )}
          {!isProductionEngine && (
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-[0.12em] font-semibold"
              style={{
                color: '#9ca3af',
                borderColor: 'rgba(156,163,175,0.25)',
                background: 'rgba(156,163,175,0.06)',
              }}
            >
              {t('engines.tier_badge_catalog')}
            </span>
          )}
          {capability?.remote_detection && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-cyan-500/25 text-cyan-300/70">
              {t('engines.catalog_remote_detection')}
            </span>
          )}
          {telemetry?.last_status && (
            <span className="text-[9px] font-mono text-[var(--text-muted)]" title={telemetry.last_error || ''}>
              {telemetry.last_status} · {telemetry.total_runs ?? 0} runs
            </span>
          )}
          <Link
            to={`/engines/${engine.id}`}
            onClick={(e) => e.stopPropagation()}
            className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-cyan-500/25 text-cyan-300/70 hover:text-cyan-200 hover:border-cyan-400/45 transition-colors"
          >
            Profile
          </Link>
          {isProductionEngine && onRun && (
            <Button variant="unstyled"
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun(engine.id) }}
              disabled={runDisabled || status === 'running'}
              title={t('engines.catalog_run_single', 'Run this engine now')}
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/30 text-emerald-300/80 hover:text-emerald-200 hover:border-emerald-400/50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors inline-flex items-center gap-1"
            >
              {status === 'running' ? (
                <span className="w-2.5 h-2.5 border border-emerald-400/40 border-t-emerald-400 rounded-full animate-spin" />
              ) : '▶'}
              {t('engines.catalog_run_single_label', 'Run')}
            </Button>
          )}
        </div>
        <p className="text-[10px] text-[var(--text-muted)] mt-0.5 leading-relaxed">{engine.description}</p>
      </div>
    </motion.div>
  )
}

function ProfileCard({ profile, active, onClick, enginesLabel }) {
  return (
    <motion.button
      type="button"
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className="w-full text-left rounded-2xl border p-4 transition-all duration-300 hover:shadow-[0_8px_28px_rgba(0,0,0,0.35)]"
      style={{
        borderColor: active ? `${profile.color}55` : 'rgba(255,255,255,0.07)',
        background: active
          ? `linear-gradient(135deg, ${profile.color}14, rgba(0,0,0,0.45))`
          : 'linear-gradient(135deg, rgba(255,255,255,0.04), rgba(0,0,0,0.35))',
        boxShadow: active ? `0 0 20px ${profile.color}18, inset 0 1px 0 ${profile.color}25` : undefined,
      }}
    >
      <div className="flex items-center gap-2.5 mb-2">
        <span className="text-2xl">{profile.icon}</span>
        <div className="min-w-0">
          <div className="text-xs font-bold truncate tracking-tight" style={{ color: profile.color }}>
            {profile.label}
          </div>
          <div className="text-[10px] font-mono mt-0.5" style={{ color: `${profile.color}90` }}>
            {enginesLabel}
          </div>
        </div>
      </div>
      <p className="text-[10px] text-[var(--text-muted)] leading-relaxed line-clamp-2">{profile.description}</p>
    </motion.button>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EngineClientCatalog() {
  const { t } = useTranslation()
  const { productionCount, isProduction } = useProductionEngines()
  const { byId: capabilityById, summary: capSummary, loading: capLoading, refresh: refreshCapabilities } = useEngineCapabilities()
  const [telemetryById, setTelemetryById] = useState({})
  const [activeProfileId, setActiveProfileId] = useState('enterprise')
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [engineStates, setEngineStates] = useState({})
  const [selectedEngines, setSelectedEngines] = useState(new Set())
  const [search, setSearch] = useState('')
  const [productionOnly, setProductionOnly] = useState(false)
  const [remoteOnly, setRemoteOnly] = useState(false)
  const [runAllLoading, setRunAllLoading] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [pendingEngineIds, setPendingEngineIds] = useState([])
  const [toast, setToast] = useState(null)
  const [capsRefreshing, setCapsRefreshing] = useState(false)
  const [clientReadiness, setClientReadiness] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)

  useRegisterHubClient(selectedClientId)
  const launchScan = useLaunchEngineScan(selectedClientId)

  useEffect(() => {
    if (!selectedClientId) {
      setClientReadiness(null)
      setClientIntegrations(null)
      return
    }
    let cancelled = false
    apiFetch(`/api/clients/${selectedClientId}/readiness`)
      .then((d) => { if (!cancelled) setClientReadiness(d?.readiness || null) })
      .catch(() => { if (!cancelled) setClientReadiness(null) })
    apiFetch(`/api/clients/${selectedClientId}/integrations`)
      .then((d) => { if (!cancelled) setClientIntegrations(normalizeIntegrations(d)) })
      .catch(() => { if (!cancelled) setClientIntegrations(null) })
    return () => { cancelled = true }
  }, [selectedClientId])
  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch((err) => { if (import.meta.env.DEV) console.warn('[EngineClientCatalog] clients load failed:', err) })
  }, [])

  useEffect(() => {
    apiFetch('/api/engines/telemetry')
      .then((data) => {
        if (!data?.engines) return
        const map = {}
        for (const row of data.engines) {
          if (row.engine_id) map[row.engine_id] = row
        }
        setTelemetryById(map)
      })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [])

  const activeProfile = useMemo(
    () => CLIENT_PROFILES.find((p) => p.id === activeProfileId) ?? CLIENT_PROFILES[0],
    [activeProfileId],
  )

  const profileEngineList = useMemo(() => profileEngines(activeProfile), [activeProfile])

  // When profile changes, default-select all engines in that profile.
  // `activeProfile` is a stable derived value from `activeProfileId` — the
  // effect intentionally only re-runs when the profile ID changes.
  useEffect(() => {
    const profile = CLIENT_PROFILES.find((p) => p.id === activeProfileId) ?? CLIENT_PROFILES[0]
    setSelectedEngines(new Set(profileEngines(profile).map((e) => e.id)))
    setSearch('')
  }, [activeProfileId])

  const filteredEngines = useMemo(() => {
    let list = profileEngineList
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (e) =>
          e.label.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          (e.mitre || '').toLowerCase().includes(q) ||
          e.id.toLowerCase().includes(q) ||
          e.group.toLowerCase().includes(q),
      )
    }
    if (productionOnly) list = list.filter((e) => isProduction(e.id))
    if (remoteOnly) list = list.filter((e) => capabilityById[e.id]?.remote_detection)
    return list
  }, [profileEngineList, search, productionOnly, remoteOnly, isProduction, capabilityById])

  const engineFindings = useMemo(() => filteredEngines.map((e) => ({
    title: e.id,
    type: e.group,
    severity: isProduction(e.id) ? 'info' : 'low',
    description: e.label,
    remediation: e.description,
    framework: e.mitre || '',
    component: capabilityById[e.id]?.remote_detection ? 'remote_detection' : '',
  })), [filteredEngines, isProduction, capabilityById])

  const {
    filteredFindings: exportableFindings,
    exportCsv,
  } = useFindingsWorkbench(engineFindings, { csvPrefix: 'weissman-engine-catalog' })

  const handleCatalogRefresh = useCallback(async () => {
    setCapsRefreshing(true)
    try {
      await refreshCapabilities()
      const data = await apiFetch('/api/engines/telemetry')
      if (data?.engines) {
        const map = {}
        for (const row of data.engines) {
          if (row.engine_id) map[row.engine_id] = row
        }
        setTelemetryById(map)
      }
    } catch { /* keep prior telemetry on transient refresh failure */ } finally {
      setCapsRefreshing(false)
    }
  }, [refreshCapabilities])

  const showToast = useCallback((severity, message) => {
    const id = Date.now()
    setToast({ id, severity, message })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const applyJobEngineResults = useCallback((job, engineIds, terminal = false) => {
    const payload = job?.result ?? job?.result_json ?? {}
    const rows = Array.isArray(payload?.results) ? payload.results : []
    const jobStatus = normalizeJobStatus(job?.status)
    const fallbackStatus = jobStatus === 'completed' ? 'completed' : jobStatus === 'failed' || jobStatus === 'dead' ? 'error' : 'running'
    const lastRun = terminal ? new Date().toLocaleString() : 'just now'

    setEngineStates((prev) => {
      const next = { ...prev }
      if (rows.length) {
        for (const row of rows) {
          const eid = row.engine
          if (!eid) continue
          next[eid] = {
            ...next[eid],
            status: row.success ? 'completed' : 'error',
            lastRun,
            findingsDelta: row.findings_count ?? 0,
          }
        }
      } else {
        for (const id of engineIds) {
          next[id] = {
            ...next[id],
            status: fallbackStatus === 'running' ? 'running' : fallbackStatus,
            lastRun: terminal ? lastRun : next[id]?.lastRun ?? 'just now',
          }
        }
      }
      return next
    })
  }, [])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onUpdate: (job) => applyJobEngineResults(job, pendingEngineIds, false),
    onComplete: (job) => {
      applyJobEngineResults(job, pendingEngineIds, true)
      setPendingJobId(null)
      setPendingEngineIds([])
      setRunAllLoading(false)
    },
  })

  const handleToggleEngine = useCallback((engineId) => {
    setSelectedEngines((prev) => {
      const next = new Set(prev)
      if (next.has(engineId)) next.delete(engineId)
      else next.add(engineId)
      return next
    })
  }, [])

  const handleSelectAll = useCallback(() => {
    setSelectedEngines(new Set(filteredEngines.map((e) => e.id)))
  }, [filteredEngines])

  const handleDeselectAll = useCallback(() => {
    setSelectedEngines(new Set())
  }, [])

  const runEngine = useCallback(async (engineId) => {
    setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'running' } }))
    try {
      const selectedClient = clients.find((c) => String(c.id) === String(selectedClientId))
      const clientTarget = firstClientTarget(selectedClient)
      const { ok, data, status } = await launchScan({
        engineId,
        clientId: selectedClientId,
        target: clientTarget,
        integrations: clientIntegrations,
      })
      if (!ok) {
        setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'error' } }))
        return { ok: false, msg: data.detail || data.error || `HTTP ${status}` }
      }
      setEngineStates((prev) => ({
        ...prev,
        [engineId]: { ...prev[engineId], status: 'running', lastRun: 'just now' },
      }))
      return { ok: true, jobId: data.job_id }
    } catch (e) {
      setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'error' } }))
      return { ok: false, msg: e?.message ?? 'Network error' }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, clients, clientIntegrations])

  const handleRunAll = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', 'Select a client first')
      return
    }
    if (clientReadiness && !clientReadiness.ready) {
      showToast('error', t('pages.engineClientCatalog.readiness_blocked', {
        pct: clientReadiness.percent,
      }))
      return
    }
    const runnable = Array.from(selectedEngines).filter(isProduction)
    if (runnable.length === 0) {
      showToast('error', t('engines.catalog_only_run_disabled'))
      return
    }
    setRunAllLoading(true)
    try {
      const d = await apiFetch('/api/scan/all-engines', {
        method: 'POST',
        body: {
          client_id: Number(selectedClientId),
          engines: runnable,
        },
      })
      showToast('info', `✅ Queued ${d.engines_queued ?? runnable.length} engines (Job: ${d.job_id ?? '—'})`)
      setEngineStates((prev) => {
        const next = { ...prev }
        for (const id of runnable) next[id] = { ...next[id], status: 'running', lastRun: 'just now' }
        return next
      })
      if (d.job_id) {
        setPendingJobId(String(d.job_id))
        setPendingEngineIds(runnable)
      } else {
        setRunAllLoading(false)
      }
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      setRunAllLoading(false)
    }
  }, [selectedClientId, selectedEngines, showToast, isProduction, t, clientReadiness])

  const handleRunEngine = useCallback(async (engineId) => {
    if (!selectedClientId) {
      showToast('error', t('engines.catalog_select_client_bottom'))
      return
    }
    if (!isProduction(engineId)) {
      showToast('error', t('engines.catalog_only_run_disabled'))
      return
    }
    const res = await runEngine(engineId)
    if (res?.ok) {
      showToast('info', t('pages.engineClientCatalog.engine_queued', { jobId: res.jobId ?? '—' }))
    } else {
      showToast('error', res?.msg ?? t('common.error'))
    }
  }, [selectedClientId, isProduction, runEngine, showToast, t])

  // Group engines by their group for display
  const groupedEngines = useMemo(() => {
    const map = new Map()
    for (const e of filteredEngines) {
      if (!map.has(e.group)) map.set(e.group, [])
      map.get(e.group).push(e)
    }
    // Preserve the profile's group order
    const result = []
    for (const gId of activeProfile.groups) {
      if (map.has(gId)) result.push({ gId, engines: map.get(gId) })
    }
    return result
  }, [filteredEngines, activeProfile.groups])

  const totalSelected = selectedEngines.size
  const totalRunnable = useMemo(
    () => Array.from(selectedEngines).filter(isProduction).length,
    [selectedEngines, isProduction],
  )
  const totalProfileEngines = profileEngineList.length
  const runDisabled = runAllLoading || !selectedClientId || totalRunnable === 0
  const runDisabledTooltip = totalRunnable === 0 && totalSelected > 0
    ? t('engines.catalog_only_run_disabled')
    : undefined

  const liveCount = productionCount || profileEngineList.length

  return (
    <PageShell
      title={t('engines.catalog_title')}
      subtitle={t('engines.catalog_subtitle', { live: liveCount, profiles: CLIENT_PROFILES.length })}
      badge="CATALOG"
      badgeColor={activeProfile.color}
      actions={(
        <ShellScanActions
          onRefresh={handleCatalogRefresh}
          onExport={exportCsv}
          refreshLoading={capsRefreshing || capLoading}
          exportDisabled={!exportableFindings.length}
        />
      )}
    >
      <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 px-4 py-3 text-xs text-cyan-100/70 mb-4 leading-relaxed">
        {t('engines.catalog_lens_notice', {
          production: productionCount,
          capabilities: capSummary?.production ?? capLoading ? '…' : Object.keys(capabilityById).length,
        })}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 mb-6 p-4 rounded-2xl border border-white/[0.08] bg-gradient-to-r from-black/40 to-black/20">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('engines.client_label')}:</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl px-3 py-1.5 text-xs text-[var(--text-primary)] font-mono focus:outline-none focus:border-cyan-500/40"
          >
            <option value="">{t('engines.select_client')}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          {!selectedClientId && (
            <span className="text-[10px] font-mono text-amber-400/70">
              ⚠ {t('engines.catalog_select_client_warn')}
            </span>
          )}
          {selectedClientId && clientReadiness && !clientReadiness.ready && (
            <Link to={`/clients/${selectedClientId}/integrations`} className="text-[10px] font-mono text-amber-300 hover:text-amber-200">
              ⚠ {t('pages.engineClientCatalog.readiness_pct', { pct: clientReadiness.percent })}
            </Link>
          )}
        </div>

        <Button variant="unstyled"
          id="run-all-engines-btn"
          type="button"
          onClick={handleRunAll}
          disabled={runDisabled}
          title={runDisabledTooltip}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-[12px] font-mono font-semibold bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          style={
            !runDisabled
              ? { boxShadow: '0 0 20px rgba(16,185,129,0.2)' }
              : {}
          }
        >
          {runAllLoading ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-emerald-400/40 border-t-emerald-400 rounded-full animate-spin" />
              {t('engines.catalog_running')}
            </>
          ) : (
            <>🚀 {t('engines.catalog_run_selected', { count: totalRunnable })}</>
          )}
        </Button>
      </div>

      {/* ── Toast ────────────────────────────────────────────────────────── */}
      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`fixed top-4 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
              toast.severity === 'error'
                ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
                : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>

      <div className="grid xl:grid-cols-[300px_1fr] gap-6">
        {/* ── Left: Client Profile Cards ─────────────────────────────── */}
        <div className="space-y-2.5">
          <h2 className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3 px-1">
            {t('engines.catalog_profiles')}
          </h2>
          {CLIENT_PROFILES.map((profile) => (
            <ProfileCard
              key={profile.id}
              profile={profile}
              enginesLabel={t('engines.catalog_engines_count', { count: profileEngines(profile).length })}
              active={profile.id === activeProfileId}
              onClick={() => setActiveProfileId(profile.id)}
            />
          ))}

          <div className="pt-4 space-y-2 px-1">
            <Link
              to="/engines"
              className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-muted)] hover:text-cyan-300 transition-colors"
            >
              ⚡ {t('engines.catalog_matrix_link')}
            </Link>
            <Link
              to="/threat-intel"
              className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-muted)] hover:text-cyan-300 transition-colors"
            >
              🗺️ {t('engines.catalog_threat_intel_link')}
            </Link>
          </div>
        </div>

        {/* ── Right: Engine List for Active Profile ────────────────── */}
        <div className="min-w-0 space-y-4">
          {/* Profile header */}
          <div
            className="rounded-2xl border p-5 md:p-6 relative overflow-hidden"
            style={{
              borderColor: `${activeProfile.color}35`,
              background: `linear-gradient(135deg, ${activeProfile.color}10, rgba(0,0,0,0.4))`,
              boxShadow: `inset 0 1px 0 ${activeProfile.color}20`,
            }}
          >
            <div
              className="absolute inset-x-0 top-0 h-px"
              style={{ background: `linear-gradient(90deg, transparent, ${activeProfile.color}60, transparent)` }}
            />
            <div className="flex items-center gap-3 mb-2">
              <span className="text-3xl">{activeProfile.icon}</span>
              <div>
                <h2 className="text-base font-bold" style={{ color: activeProfile.color }}>
                  {activeProfile.label}
                </h2>
                <p className="text-xs text-[var(--text-muted)] mt-0.5 max-w-lg">{activeProfile.description}</p>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 mt-3">
              {activeProfile.groups.map((gId) => {
                const g = getGroupDef(gId)
                if (!g) return null
                const cnt = getEnginesByGroup(gId).length
                return (
                  <span
                    key={gId}
                    className="text-[10px] font-mono px-2 py-0.5 rounded border"
                    style={{ color: g.color, borderColor: `${g.color}40`, background: `${g.color}10` }}
                  >
                    {GROUP_ICONS[gId] ?? '◆'} {g.label} ({cnt})
                  </span>
                )
              })}
            </div>
          </div>

          {/* Search + bulk controls */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex-1 min-w-[200px] relative">
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t('engines.catalog_search_placeholder')}
                className="w-full bg-[var(--bg-2)] border border-white/[0.08] rounded-xl px-4 py-2.5 text-xs text-[var(--text-primary)] placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/35 focus:ring-1 focus:ring-cyan-500/15"
              />
              {search && (
                <Button variant="unstyled"
                  type="button"
                  onClick={() => setSearch('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] text-xs"
                >
                  ✕
                </Button>
              )}
            </div>
            <span className="text-[10px] font-mono text-[var(--text-muted)] whitespace-nowrap px-2 py-1 rounded-md bg-[var(--row-hover-bg)] border border-white/[0.06]">
              {t('engines.catalog_shown', { shown: filteredEngines.length, total: totalProfileEngines, selected: totalSelected })}
            </span>
            <Button variant="unstyled"
              type="button"
              onClick={handleSelectAll}
              className="px-2.5 py-1 rounded-lg text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
            >
              {t('engines.catalog_select_all')}
            </Button>
            <Button variant="unstyled"
              type="button"
              onClick={handleDeselectAll}
              className="px-2.5 py-1 rounded-lg text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
            >
              {t('engines.catalog_clear_selection')}
            </Button>
            <Button variant="unstyled"
              type="button"
              onClick={() => setProductionOnly((v) => !v)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-mono border transition-colors ${
                productionOnly ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10' : 'border-[var(--border-default)] text-[var(--text-muted)]'
              }`}
            >
              {t('engines.catalog_production_only')}
            </Button>
            <Button variant="unstyled"
              type="button"
              onClick={() => setRemoteOnly((v) => !v)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-mono border transition-colors ${
                remoteOnly ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10' : 'border-[var(--border-default)] text-[var(--text-muted)]'
              }`}
            >
              {t('engines.catalog_remote_only')}
            </Button>
          </div>

          {/* Engines grouped by group */}
          <div className="space-y-6 max-h-[70vh] overflow-y-auto pr-1">
            <AnimatePresence mode="wait">
              {groupedEngines.length === 0 ? (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="py-12 text-center text-[var(--text-disabled)] text-xs font-mono"
                >
                  {t('engines.catalog_no_match')}
                </motion.div>
              ) : (
                <motion.div key={`${activeProfileId}-${search}`} className="space-y-6">
                  {groupedEngines.map(({ gId, engines }) => {
                    const gDef = getGroupDef(gId)
                    const selectedCount = engines.filter((e) => selectedEngines.has(e.id)).length
                    return (
                      <section key={gId}>
                        {/* Group header */}
                        <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-[var(--border-subtle)]">
                          <div className="flex items-center gap-2">
                            <span
                              className="w-2 h-2 rounded-full shrink-0"
                              style={{
                                backgroundColor: gDef?.color ?? '#6b7280',
                                boxShadow: `0 0 6px ${gDef?.color ?? '#6b7280'}70`,
                              }}
                            />
                            <span
                              className="text-[11px] font-bold uppercase tracking-widest"
                              style={{ color: gDef?.color ?? '#6b7280' }}
                            >
                              {GROUP_ICONS[gId] ?? '◆'} {gDef?.label ?? gId}
                            </span>
                            <span className="text-[10px] font-mono text-[var(--text-muted)]">
                              {t('engines.catalog_group_selected', { selected: selectedCount, total: engines.length })}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button variant="unstyled"
                              type="button"
                              onClick={() => {
                                setSelectedEngines((prev) => {
                                  const next = new Set(prev)
                                  engines.forEach((e) => next.add(e.id))
                                  return next
                                })
                              }}
                              className="px-2 py-0.5 rounded text-[9px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-tertiary)] hover:border-[var(--border-strong)] transition-colors"
                            >
                              All
                            </Button>
                            <Button variant="unstyled"
                              type="button"
                              onClick={() => {
                                setSelectedEngines((prev) => {
                                  const next = new Set(prev)
                                  engines.forEach((e) => next.delete(e.id))
                                  return next
                                })
                              }}
                              className="px-2 py-0.5 rounded text-[9px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-tertiary)] hover:border-[var(--border-strong)] transition-colors"
                            >
                              None
                            </Button>
                          </div>
                        </div>

                        {/* Engine rows */}
                        <div className="space-y-0.5">
                          {engines.map((engine) => (
                            <EngineRow
                              key={engine.id}
                              engine={engine}
                              status={engineStates[engine.id]?.status}
                              selected={selectedEngines.has(engine.id)}
                              onSelect={handleToggleEngine}
                              onRun={handleRunEngine}
                              runDisabled={!selectedClientId}
                              isProductionEngine={isProduction(engine.id)}
                              capability={capabilityById[engine.id]}
                              telemetry={telemetryById[engine.id]}
                              t={t}
                            />
                          ))}
                        </div>
                      </section>
                    )
                  })}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Bottom Run All CTA */}
          <div className="sticky bottom-0 pt-3 pb-1">
            <Button variant="unstyled"
              id="run-all-engines-bottom-btn"
              type="button"
              onClick={handleRunAll}
              disabled={runDisabled}
              title={runDisabledTooltip}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-[13px] font-mono font-semibold bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              style={
                !runDisabled
                  ? { boxShadow: '0 0 20px rgba(34,197,94,0.2)' }
                  : {}
              }
            >
              {runAllLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-emerald-400/40 border-t-emerald-400 rounded-full animate-spin" />
                  {t('engines.catalog_running_all')}
                </>
              ) : (
                <>
                  🚀 {t('engines.catalog_run_all_bottom', { count: totalRunnable })}
                  {activeProfile && (
                    <span className="text-emerald-400/60 font-normal">
                      · {activeProfile.icon} {activeProfile.label}
                    </span>
                  )}
                </>
              )}
            </Button>
            {!selectedClientId && (
              <p className="text-center text-[10px] font-mono text-amber-400/55 mt-1.5">
                {t('engines.catalog_select_client_bottom')}
              </p>
            )}
          </div>
        </div>
      </div>
    </PageShell>
  )
}
