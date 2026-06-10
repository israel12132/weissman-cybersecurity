import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import {
  ENGINES_REGISTRY,
  ENGINE_GROUP_DEFS,
  ENGINE_GROUPS,
  ENGINES_BY_ID,
} from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import { useProductionEngines } from '../lib/useProductionEngines'
import { isTopTierEngine } from '../lib/topTierEngineProfiles'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

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

const TIER_FILTERS = ['all', 'live', 'top_tier', 'catalog']

function severityColor(s) {
  return SEVERITY_COLOR[(s || '').toLowerCase()] ?? '#6b7280'
}

function firstClientTarget(client) {
  if (!client) return ''
  let domains = client.domains
  if (typeof domains === 'string') {
    try { domains = JSON.parse(domains) } catch { domains = [] }
  }
  const first = Array.isArray(domains) ? domains.find((d) => typeof d === 'string' && d.trim()) : ''
  if (!first) return ''
  return first.startsWith('http://') || first.startsWith('https://') ? first : `https://${first}`
}

function engineMatchesSearch(engine, q) {
  const hay = `${engine.id} ${engine.label || ''} ${engine.description || ''} ${engine.mitre || ''} ${engine.group || ''}`.toLowerCase()
  return hay.includes(q)
}

function getEngineTier(engineId, isProduction) {
  if (isTopTierEngine(engineId)) return 'top_tier'
  if (isProduction(engineId)) return 'live'
  return 'catalog'
}

// ─── UI Components ───────────────────────────────────────────────────────────

function StatusDot({ status }) {
  const map = {
    running: { color: '#22d3ee', pulse: true },
    completed: { color: '#4ade80', pulse: false },
    error: { color: '#ef4444', pulse: false },
    idle: { color: '#4b5563', pulse: false },
  }
  const { color, pulse } = map[status] ?? map.idle
  return (
    <span className="relative inline-flex items-center justify-center w-2.5 h-2.5 shrink-0" title={status}>
      {pulse && (
        <span
          className="absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping"
          style={{ backgroundColor: color }}
        />
      )}
      <span className="relative inline-flex rounded-full w-2 h-2" style={{ backgroundColor: color }} />
    </span>
  )
}

function CategoryBadge({ groupId }) {
  const gDef = ENGINE_GROUPS[groupId]
  const color = gDef?.color ?? '#6b7280'
  return (
    <span
      className="text-[9px] font-mono px-1.5 py-0.5 rounded-md border uppercase tracking-wider"
      style={{ color, borderColor: `${color}45`, backgroundColor: `${color}12` }}
    >
      {GROUP_ICONS[groupId] ?? '◆'} {gDef?.label ?? groupId}
    </span>
  )
}

function TierBadge({ tier, t }) {
  const styles = {
    live: { color: '#22d3ee', border: 'rgba(34,211,238,0.35)', bg: 'rgba(34,211,238,0.08)', label: t('engines.tier_badge_live') },
    top_tier: { color: '#f43f5e', border: 'rgba(244,63,94,0.35)', bg: 'rgba(244,63,94,0.08)', label: t('engines.tier_badge_top_tier') },
    catalog: { color: '#9ca3af', border: 'rgba(156,163,175,0.25)', bg: 'rgba(156,163,175,0.06)', label: t('engines.tier_badge_catalog') },
  }
  const s = styles[tier] ?? styles.catalog
  return (
    <span
      className="text-[8px] font-mono px-1.5 py-0.5 rounded-md border uppercase tracking-[0.14em] font-semibold"
      style={{ color: s.color, borderColor: s.border, backgroundColor: s.bg }}
    >
      {s.label}
    </span>
  )
}

function EngineMatrixCard({
  engine,
  enabled,
  status,
  lastRun,
  findingsDelta,
  onToggle,
  onRun,
  loading,
  groupColor,
  tier,
  t,
}) {
  const navigate = useNavigate()
  const [runBusy, setRunBusy] = useState(false)

  const handleRun = useCallback(async (e) => {
    e.stopPropagation()
    if (runBusy || !onRun || !enabled) return
    setRunBusy(true)
    try {
      await onRun(engine.id)
    } finally {
      setRunBusy(false)
    }
  }, [runBusy, onRun, engine.id, enabled])

  const handleToggle = useCallback((e) => {
    e.stopPropagation()
    if (onToggle) onToggle(engine.id, !enabled)
  }, [onToggle, engine.id, enabled])

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.98 }}
      transition={{ duration: 0.2 }}
      className="group relative rounded-2xl bg-gradient-to-br from-white/[0.07] via-black/40 to-black/60 backdrop-blur-xl border border-white/[0.08] p-4 cursor-pointer transition-all duration-300 hover:-translate-y-1 hover:border-cyan-400/25 hover:shadow-[0_12px_40px_rgba(0,0,0,0.45),0_0_24px_rgba(34,211,238,0.08)]"
      style={enabled ? { boxShadow: `inset 0 1px 0 ${groupColor}18` } : {}}
      onClick={() => navigate(`/engines/${engine.id}`)}
    >
      <div
        className="absolute inset-x-0 top-0 h-px rounded-t-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{ background: `linear-gradient(90deg, transparent, ${groupColor}60, transparent)` }}
      />

      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <StatusDot status={status} />
          <h3 className="text-sm font-semibold text-white/95 truncate tracking-tight">{engine.label}</h3>
        </div>
        <div className="flex items-center gap-1.5 shrink-0 opacity-90 group-hover:opacity-100">
          <button
            id={`engine-${engine.id}-toggle`}
            type="button"
            role="switch"
            aria-checked={enabled}
            disabled={loading}
            onClick={handleToggle}
            className={`relative shrink-0 w-9 h-5 rounded-full transition-all duration-300 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed ${
              enabled ? 'bg-cyan-500/30 shadow-[inset_0_0_8px_rgba(34,211,238,0.2)]' : 'bg-black/60 border border-white/10'
            }`}
          >
            <span
              className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all duration-300 ${
                enabled ? 'left-[18px]' : 'left-0.5'
              }`}
              style={enabled ? { boxShadow: `0 0 8px ${groupColor}90` } : {}}
            />
          </button>
          <button
            id={`engine-${engine.id}-run-btn`}
            type="button"
            disabled={loading || runBusy || !enabled}
            title={!enabled ? t('engines.enable_engine_first') : t('engines.queue_scan')}
            onClick={handleRun}
            className="px-2 py-0.5 rounded-md text-[9px] font-mono uppercase tracking-wider border border-cyan-500/30 text-cyan-300/80 hover:bg-cyan-950/50 hover:text-cyan-200 hover:border-cyan-400/50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {runBusy ? '…' : 'Run'}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5 mb-2.5">
        <CategoryBadge groupId={engine.group} />
        <TierBadge tier={tier} t={t} />
      </div>

      <p className="text-[11px] text-white/50 leading-relaxed line-clamp-2 min-h-[2.5rem]">
        {engine.description}
      </p>

      <div className="flex items-center justify-between mt-3 pt-2.5 border-t border-white/[0.06]">
        <span className="text-[10px] font-mono text-white/30">
          {lastRun ? t('engines.last_run_label', { time: lastRun }) : t('engines.never_run')}
        </span>
        {findingsDelta > 0 && (
          <span
            className="text-[10px] font-mono px-1.5 py-0.5 rounded-md"
            style={{ backgroundColor: `${severityColor('high')}18`, color: severityColor('high') }}
          >
            {t('engines.findings_delta', { count: findingsDelta })}
          </span>
        )}
      </div>
    </motion.div>
  )
}

function GroupSection({
  groupDef,
  engines,
  engineStates,
  enabledSet,
  loading,
  onToggle,
  onRun,
  onEnableAll,
  onDisableAll,
  onRunGroup,
  isProduction,
  t,
}) {
  const enabledCount = engines.filter((e) => enabledSet.has(e.id)).length
  const runningCount = engines.filter((e) => engineStates[e.id]?.status === 'running').length

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ backgroundColor: groupDef.color, boxShadow: `0 0 10px ${groupDef.color}80` }}
          />
          <h2
            className="text-[11px] font-bold uppercase tracking-[0.22em]"
            style={{ color: groupDef.color }}
          >
            {GROUP_ICONS[groupDef.id] ?? '◆'} {groupDef.label}
          </h2>
          <span className="text-[10px] font-mono text-white/35 px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/[0.06]">
            {enabledCount}/{engines.length}
            {runningCount > 0 && ` · ${runningCount} ${t('engines.status_running').toLowerCase()}`}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            id={`engine-group-${groupDef.id}-run-btn`}
            type="button"
            onClick={() => onRunGroup(engines.map((e) => e.id))}
            disabled={loading || enabledCount === 0}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono uppercase tracking-wide border border-cyan-500/30 text-cyan-300/80 hover:bg-cyan-950/40 hover:border-cyan-400/40 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {t('engines.run_group')}
          </button>
          <button
            id={`engine-group-${groupDef.id}-enable-all-btn`}
            type="button"
            onClick={() => onEnableAll(engines.map((e) => e.id))}
            disabled={loading}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {t('engines.enable_all')}
          </button>
          <button
            id={`engine-group-${groupDef.id}-disable-all-btn`}
            type="button"
            onClick={() => onDisableAll(engines.map((e) => e.id))}
            disabled={loading}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {t('engines.disable_all')}
          </button>
        </div>
      </div>
      <AnimatePresence mode="popLayout">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {engines.map((engine) => {
            const state = engineStates[engine.id] ?? {}
            return (
              <EngineMatrixCard
                key={engine.id}
                engine={engine}
                enabled={enabledSet.has(engine.id)}
                status={state.status ?? 'idle'}
                lastRun={state.lastRun ?? null}
                findingsDelta={state.findingsDelta ?? 0}
                onToggle={onToggle}
                onRun={onRun}
                loading={loading}
                groupColor={groupDef.color}
                tier={getEngineTier(engine.id, isProduction)}
                t={t}
              />
            )
          })}
        </div>
      </AnimatePresence>
    </section>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EngineMatrix() {
  const { t } = useTranslation()
  const {
    engines: productionEngines,
    productionCount,
    catalogCount,
    loading: productionLoading,
    isProduction,
  } = useProductionEngines()

  const [activeGroup, setActiveGroup] = useState('all')
  const [tierFilter, setTierFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [clientConfig, setClientConfig] = useState(null)
  const [configLoading, setConfigLoading] = useState(false)
  const [engineStates, setEngineStates] = useState({})
  const [toast, setToast] = useState(null)
  const [runAllLoading, setRunAllLoading] = useState(false)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (Array.isArray(d)) setClients(d)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (selectedClientId == null) {
      setClientConfig(null)
      return
    }
    setConfigLoading(true)
    apiFetch(`/api/clients/${selectedClientId}/config`)
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setClientConfig(d))
      .catch(() => {})
      .finally(() => setConfigLoading(false))
  }, [selectedClientId])

  const showToast = useCallback((severity, message) => {
    const id = Date.now()
    setToast({ id, severity, message })
    setTimeout(() => setToast((prev) => (prev?.id === id ? null : prev)), 5000)
  }, [])

  const enabledSet = useMemo(
    () => new Set(Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []),
    [clientConfig?.enabled_engines],
  )

  const baseRegistry = useMemo(() => {
    if (tierFilter === 'catalog') {
      return ENGINES_REGISTRY.filter((e) => !isProduction(e.id))
    }
    return productionEngines
  }, [tierFilter, productionEngines, isProduction])

  const filteredEngines = useMemo(() => {
    const q = search.trim().toLowerCase()
    return baseRegistry.filter((e) => {
      if (activeGroup !== 'all' && e.group !== activeGroup) return false
      if (tierFilter === 'live' && !isProduction(e.id)) return false
      if (tierFilter === 'top_tier' && !isTopTierEngine(e.id)) return false
      if (q && !engineMatchesSearch(e, q)) return false
      return true
    })
  }, [baseRegistry, activeGroup, tierFilter, search, isProduction])

  const enginesByGroup = useCallback(
    (groupId) => filteredEngines.filter((e) => e.group === groupId),
    [filteredEngines],
  )

  const visibleGroups = useMemo(() => {
    if (activeGroup !== 'all') {
      const g = ENGINE_GROUP_DEFS.find((gd) => gd.id === activeGroup)
      return g ? [g] : []
    }
    return ENGINE_GROUP_DEFS.filter((g) => enginesByGroup(g.id).length > 0)
  }, [activeGroup, enginesByGroup])

  const patchEngines = useCallback(async (nextList) => {
    if (selectedClientId == null) {
      showToast('error', t('engines.select_client_warning'))
      return false
    }
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/config`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled_engines: nextList }),
      })
      if (r.ok) {
        const d = await r.json().catch(() => ({}))
        setClientConfig((prev) => ({ ...prev, enabled_engines: d.enabled_engines ?? nextList }))
        return true
      }
      showToast('error', `Config update failed (${r.status})`)
      return false
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      return false
    }
  }, [selectedClientId, showToast, t])

  const handleToggle = useCallback(async (engineId, nextEnabled) => {
    const current = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []
    const next = nextEnabled
      ? [...current.filter((e) => e !== engineId), engineId]
      : current.filter((e) => e !== engineId)
    await patchEngines(next)
  }, [clientConfig?.enabled_engines, patchEngines])

  const handleEnableAll = useCallback(async (engineIds) => {
    const current = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []
    const s = new Set(current)
    engineIds.forEach((id) => s.add(id))
    await patchEngines([...s])
  }, [clientConfig?.enabled_engines, patchEngines])

  const handleDisableAll = useCallback(async (engineIds) => {
    const current = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []
    const disableSet = new Set(engineIds)
    await patchEngines(current.filter((e) => !disableSet.has(e)))
  }, [clientConfig?.enabled_engines, patchEngines])

  const handleRun = useCallback(async (engineId) => {
    if (selectedClientId == null) {
      showToast('error', t('engines.select_client_warning'))
      return
    }
    const engine = ENGINES_BY_ID[engineId]
    const selectedClient = clients.find((c) => String(c.id) === String(selectedClientId))
    const clientTarget = firstClientTarget(selectedClient)
    setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'running' } }))
    try {
      const body = { engine: engineId, client_id: Number(selectedClientId) }
      if (clientTarget) body.target = clientTarget
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        const msg = d.detail || d.error || r.statusText || 'Scan failed'
        showToast('error', `${engine?.label ?? engineId}: ${msg}`)
        setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'error' } }))
        return
      }
      showToast('info', `${engine?.label ?? engineId}: queued job ${d.job_id ?? ''}`)
      setEngineStates((prev) => ({
        ...prev,
        [engineId]: { ...prev[engineId], status: 'running', lastRun: 'just now' },
      }))
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
      setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'error' } }))
    }
  }, [selectedClientId, clients, showToast, t])

  const handleRunGroup = useCallback(async (engineIds) => {
    if (selectedClientId == null) {
      showToast('error', t('engines.select_client_warning'))
      return
    }
    await Promise.allSettled(
      engineIds.filter((id) => enabledSet.has(id)).map((id) => handleRun(id)),
    )
  }, [selectedClientId, enabledSet, handleRun, showToast, t])

  const handleRunAllEngines = useCallback(async () => {
    if (selectedClientId == null) {
      showToast('error', t('engines.select_client_warning'))
      return
    }
    if (enabledSet.size === 0) {
      showToast('error', 'No engines enabled for this client')
      return
    }
    setRunAllLoading(true)
    try {
      const r = await apiFetch('/api/scan/all-engines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: Number(selectedClientId),
          engines: Array.from(enabledSet),
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || `Scan failed (${r.status})`)
        return
      }
      showToast('info', `Queued ${d.engines_queued} engines (Job: ${d.job_id})`)
      setEngineStates((prev) => {
        const next = { ...prev }
        for (const id of enabledSet) {
          next[id] = { ...next[id], status: 'running' }
        }
        return next
      })
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setRunAllLoading(false)
    }
  }, [selectedClientId, enabledSet, showToast, t])

  const totalEnabled = enabledSet.size
  const liveCount = productionCount || productionEngines.length
  const tierCounts = useMemo(() => ({
    all: baseRegistry.length,
    live: productionEngines.filter((e) => isProduction(e.id)).length,
    top_tier: productionEngines.filter((e) => isTopTierEngine(e.id)).length,
    catalog: ENGINES_REGISTRY.filter((e) => !isProduction(e.id)).length,
  }), [baseRegistry.length, productionEngines, isProduction])

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{
        background: 'radial-gradient(ellipse 130% 90% at 50% -10%, #1e293b 0%, #0f172a 35%, #020617 65%, #000 100%)',
      }}
    >
      <header className="sticky top-0 z-20 border-b border-white/[0.08] bg-black/60 backdrop-blur-xl">
        <div className="max-w-screen-2xl mx-auto px-4 py-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-white/35">
                <Link to="/" className="hover:text-white/60 transition-colors">← Dashboard</Link>
                <span className="text-white/15">|</span>
                <Link to="/engine-catalog" className="text-emerald-400/70 hover:text-emerald-300 transition-colors">
                  Client Catalog
                </Link>
                <span className="text-white/15">|</span>
                <Link to="/engines/top-tier" className="text-rose-400/70 hover:text-rose-300 transition-colors">
                  Top-Tier Hub
                </Link>
              </div>
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-lg font-bold tracking-tight text-white">{t('engines.matrix_title')}</h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-cyan-500/25 text-cyan-300/80 bg-cyan-500/[0.06]">
                  {t('engines.live_engines', { count: liveCount })}
                </span>
              </div>
              <p className="text-[11px] font-mono text-white/40">
                {t('engines.matrix_subtitle', {
                  live: liveCount,
                  catalog: catalogCount,
                  groups: ENGINE_GROUP_DEFS.length,
                })}
              </p>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[11px] font-mono text-white/40">{t('engines.client_label')}:</span>
              <select
                value={selectedClientId ?? ''}
                onChange={(e) => setSelectedClientId(e.target.value || null)}
                className="bg-black/50 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-white/85 font-mono focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/20"
              >
                <option value="">{t('engines.select_client')}</option>
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              {(configLoading || productionLoading) && (
                <div className="w-3.5 h-3.5 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
              )}
              {selectedClientId && (
                <span className="text-[10px] font-mono text-white/40">
                  {t('engines.enabled_short', { count: totalEnabled })}
                </span>
              )}
              <button
                type="button"
                onClick={handleRunAllEngines}
                disabled={runAllLoading || configLoading || !selectedClientId || totalEnabled === 0}
                className="px-4 py-2 rounded-xl text-[11px] font-mono font-semibold bg-emerald-500/15 border border-emerald-500/35 text-emerald-300 hover:bg-emerald-500/25 hover:shadow-[0_0_20px_rgba(16,185,129,0.15)] disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                {runAllLoading ? t('engines.running') : t('engines.run_all_engines', { count: totalEnabled })}
              </button>
            </div>
          </div>
        </div>
      </header>

      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`fixed top-20 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl backdrop-blur-md ${
              toast.severity === 'error'
                ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
                : 'bg-black/85 border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-screen-2xl mx-auto px-4 py-6 space-y-5">
        <div className="flex flex-col lg:flex-row gap-3">
          <div className="relative flex-1 min-w-[220px]">
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('engines.search_placeholder')}
              className="w-full bg-black/40 border border-white/[0.08] rounded-xl px-4 py-2.5 text-sm font-mono text-white/85 placeholder-white/25 focus:outline-none focus:border-cyan-500/35 focus:ring-1 focus:ring-cyan-500/15 transition-all"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 text-xs"
              >
                ✕
              </button>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {TIER_FILTERS.map((tier) => (
              <button
                key={tier}
                type="button"
                onClick={() => setTierFilter(tier)}
                className={`px-3 py-1.5 rounded-xl text-[10px] font-mono uppercase tracking-wider transition-all border ${
                  tierFilter === tier
                    ? 'bg-white/12 text-white border-white/25 shadow-[0_0_12px_rgba(255,255,255,0.04)]'
                    : 'text-white/45 border-white/[0.08] hover:border-white/18 hover:text-white/65'
                }`}
              >
                {t(`engines.tier_${tier}`)} ({tierCounts[tier] ?? 0})
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap gap-1.5 pb-1">
          <button
            type="button"
            onClick={() => setActiveGroup('all')}
            className={`px-3 py-1.5 rounded-xl text-[11px] font-mono transition-all ${
              activeGroup === 'all'
                ? 'bg-white/12 text-white border border-white/25'
                : 'text-white/50 border border-white/[0.08] hover:border-white/18 hover:text-white/70'
            }`}
          >
            {t('engines.all_engines', { count: filteredEngines.length })}
          </button>
          {ENGINE_GROUP_DEFS.map((g) => {
            const count = enginesByGroup(g.id).length
            if (tierFilter !== 'catalog' && activeGroup === 'all' && count === 0) return null
            return (
              <button
                key={g.id}
                type="button"
                onClick={() => setActiveGroup(g.id)}
                className={`px-3 py-1.5 rounded-xl text-[11px] font-mono transition-all border ${
                  activeGroup === g.id
                    ? 'text-white'
                    : 'text-white/50 border-white/[0.08] hover:border-white/18 hover:text-white/70'
                }`}
                style={
                  activeGroup === g.id
                    ? { backgroundColor: `${g.color}18`, borderColor: `${g.color}45`, color: g.color }
                    : {}
                }
              >
                {GROUP_ICONS[g.id] ?? '◆'} {g.label} ({count})
              </button>
            )
          })}
        </div>

        {!selectedClientId && (
          <div className="rounded-2xl border border-amber-500/20 bg-gradient-to-r from-amber-950/25 to-black/30 px-4 py-3 text-sm text-amber-200/85 font-mono">
            {t('engines.select_client_warning')}
          </div>
        )}

        {productionLoading ? (
          <div className="flex items-center justify-center py-20">
            <div className="text-center space-y-3">
              <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-cyan-400/30 border-t-cyan-400" />
              <p className="text-sm font-mono text-white/50">{t('engines.loading_engines')}</p>
            </div>
          </div>
        ) : filteredEngines.length === 0 ? (
          <div className="rounded-2xl border border-white/[0.08] bg-black/30 px-6 py-16 text-center">
            <p className="text-sm font-mono text-white/35">{t('engines.no_results')}</p>
          </div>
        ) : (
          <div className="space-y-14">
            {visibleGroups.map((groupDef) => {
              const engines = enginesByGroup(groupDef.id)
              if (!engines.length) return null
              return (
                <GroupSection
                  key={groupDef.id}
                  groupDef={groupDef}
                  engines={engines}
                  engineStates={engineStates}
                  enabledSet={enabledSet}
                  loading={configLoading || !selectedClientId}
                  onToggle={handleToggle}
                  onRun={handleRun}
                  onEnableAll={handleEnableAll}
                  onDisableAll={handleDisableAll}
                  onRunGroup={handleRunGroup}
                  isProduction={isProduction}
                  t={t}
                />
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}
