/**
 * Engine Client Catalog
 *
 * Organizes all 482 attack engines by client type / industry vertical.
 * Each client profile shows the relevant engine groups and individual engines,
 * with descriptions, MITRE technique badges, and per-profile or global Run All buttons.
 *
 * Route: /engine-catalog
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { ENGINE_GROUP_DEFS, getEnginesByGroup } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import { useProductionEngines } from '../lib/useProductionEngines'
import PageShell from './PageShell'

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
    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/5 border border-white/10 text-white/45 tracking-wider">
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

function EngineRow({ engine, status, selected, onSelect, isProductionEngine, t }) {
  const gDef = getGroupDef(engine.group)
  const groupColor = gDef?.color ?? '#6b7280'
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      className={`flex items-start gap-3 px-3 py-2.5 rounded-lg border transition-all cursor-pointer ${
        selected ? 'border-white/20 bg-white/5' : 'border-transparent hover:border-white/10 hover:bg-white/3'
      }`}
      onClick={() => onSelect(engine.id)}
    >
      {/* Checkbox */}
      <div className="mt-0.5 shrink-0">
        <div
          className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
            selected ? 'border-cyan-400/60 bg-cyan-500/20' : 'border-white/15'
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
          <span className="text-xs font-semibold text-white/85">{engine.label}</span>
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
        </div>
        <p className="text-[10px] text-white/35 mt-0.5 leading-relaxed">{engine.description}</p>
      </div>
    </motion.div>
  )
}

function ProfileCard({ profile, count, active, onClick, enginesLabel }) {
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
      <p className="text-[10px] text-white/40 leading-relaxed line-clamp-2">{profile.description}</p>
    </motion.button>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EngineClientCatalog() {
  const { t } = useTranslation()
  const { productionCount, isProduction } = useProductionEngines()
  const [activeProfileId, setActiveProfileId] = useState('enterprise')
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [engineStates, setEngineStates] = useState({})
  const [selectedEngines, setSelectedEngines] = useState(new Set())
  const [search, setSearch] = useState('')
  const [runAllLoading, setRunAllLoading] = useState(false)
  const [toast, setToast] = useState(null)

  // Load clients from API
  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch((err) => { if (import.meta.env.DEV) console.warn('[EngineClientCatalog] clients load failed:', err) })
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
    if (!search.trim()) return profileEngineList
    const q = search.toLowerCase()
    return profileEngineList.filter(
      (e) =>
        e.label.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        (e.mitre || '').toLowerCase().includes(q) ||
        e.id.toLowerCase().includes(q) ||
        e.group.toLowerCase().includes(q),
    )
  }, [profileEngineList, search])

  const showToast = useCallback((severity, message) => {
    const id = Date.now()
    setToast({ id, severity, message })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

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
      const body = { engine: engineId, client_id: Number(selectedClientId) }
      const selectedClient = clients.find((c) => String(c.id) === String(selectedClientId))
      const clientTarget = firstClientTarget(selectedClient)
      if (clientTarget) body.target = clientTarget
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'error' } }))
        return { ok: false, msg: d.detail || d.error || r.statusText }
      }
      setEngineStates((prev) => ({
        ...prev,
        [engineId]: { ...prev[engineId], status: 'running', lastRun: 'just now' },
      }))
      return { ok: true, jobId: d.job_id }
    } catch (e) {
      setEngineStates((prev) => ({ ...prev, [engineId]: { ...prev[engineId], status: 'error' } }))
      return { ok: false, msg: e?.message ?? 'Network error' }
    }
  }, [selectedClientId, clients])

  const handleRunAll = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', 'Select a client first')
      return
    }
    const runnable = Array.from(selectedEngines).filter(isProduction)
    if (runnable.length === 0) {
      showToast('error', t('engines.catalog_only_run_disabled'))
      return
    }
    setRunAllLoading(true)
    try {
      const r = await apiFetch('/api/scan/all-engines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: Number(selectedClientId),
          engines: runnable,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || `Scan failed (${r.status})`)
        return
      }
      showToast('info', `✅ Queued ${d.engines_queued ?? runnable.length} engines (Job: ${d.job_id ?? '—'})`)
      setEngineStates((prev) => {
        const next = { ...prev }
        for (const id of runnable) next[id] = { ...next[id], status: 'running' }
        return next
      })
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setRunAllLoading(false)
    }
  }, [selectedClientId, selectedEngines, showToast, isProduction, t])

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
    >
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6 p-4 rounded-2xl border border-white/[0.08] bg-gradient-to-r from-black/40 to-black/20">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-mono text-white/40">{t('engines.client_label')}:</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-black/50 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-white/85 font-mono focus:outline-none focus:border-cyan-500/40"
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
        </div>

        <button
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
        </button>
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
                : 'bg-black/80 border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>

      <div className="grid xl:grid-cols-[300px_1fr] gap-6">
        {/* ── Left: Client Profile Cards ─────────────────────────────── */}
        <div className="space-y-2.5">
          <h2 className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/35 mb-3 px-1">
            {t('engines.catalog_profiles')}
          </h2>
          {CLIENT_PROFILES.map((profile) => (
            <ProfileCard
              key={profile.id}
              profile={profile}
              count={profileEngines(profile).length}
              enginesLabel={t('engines.catalog_engines_count', { count: profileEngines(profile).length })}
              active={profile.id === activeProfileId}
              onClick={() => setActiveProfileId(profile.id)}
            />
          ))}

          <div className="pt-4 space-y-2 px-1">
            <Link
              to="/engines"
              className="flex items-center gap-2 text-[11px] font-mono text-white/40 hover:text-cyan-300 transition-colors"
            >
              ⚡ {t('engines.catalog_matrix_link')}
            </Link>
            <Link
              to="/threat-intel"
              className="flex items-center gap-2 text-[11px] font-mono text-white/40 hover:text-cyan-300 transition-colors"
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
                <p className="text-xs text-white/45 mt-0.5 max-w-lg">{activeProfile.description}</p>
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
                className="w-full bg-black/40 border border-white/[0.08] rounded-xl px-4 py-2.5 text-xs text-white/85 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/35 focus:ring-1 focus:ring-cyan-500/15"
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
            <span className="text-[10px] font-mono text-white/35 whitespace-nowrap px-2 py-1 rounded-md bg-white/[0.03] border border-white/[0.06]">
              {t('engines.catalog_shown', { shown: filteredEngines.length, total: totalProfileEngines, selected: totalSelected })}
            </span>
            <button
              type="button"
              onClick={handleSelectAll}
              className="px-2.5 py-1 rounded-lg text-[10px] font-mono border border-white/10 text-white/45 hover:text-white/75 hover:border-white/20 transition-colors"
            >
              {t('engines.catalog_select_all')}
            </button>
            <button
              type="button"
              onClick={handleDeselectAll}
              className="px-2.5 py-1 rounded-lg text-[10px] font-mono border border-white/10 text-white/45 hover:text-white/75 hover:border-white/20 transition-colors"
            >
              {t('engines.catalog_clear_selection')}
            </button>
          </div>

          {/* Engines grouped by group */}
          <div className="space-y-6 max-h-[70vh] overflow-y-auto pr-1">
            <AnimatePresence mode="wait">
              {groupedEngines.length === 0 ? (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="py-12 text-center text-white/25 text-xs font-mono"
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
                        <div className="flex items-center justify-between mb-2 pb-1.5 border-b border-white/5">
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
                            <span className="text-[10px] font-mono text-white/35">
                              {t('engines.catalog_group_selected', { selected: selectedCount, total: engines.length })}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedEngines((prev) => {
                                  const next = new Set(prev)
                                  engines.forEach((e) => next.add(e.id))
                                  return next
                                })
                              }}
                              className="px-2 py-0.5 rounded text-[9px] font-mono border border-white/10 text-white/35 hover:text-white/60 hover:border-white/20 transition-colors"
                            >
                              All
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                setSelectedEngines((prev) => {
                                  const next = new Set(prev)
                                  engines.forEach((e) => next.delete(e.id))
                                  return next
                                })
                              }}
                              className="px-2 py-0.5 rounded text-[9px] font-mono border border-white/10 text-white/35 hover:text-white/60 hover:border-white/20 transition-colors"
                            >
                              None
                            </button>
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
                              isProductionEngine={isProduction(engine.id)}
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
            <button
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
            </button>
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
