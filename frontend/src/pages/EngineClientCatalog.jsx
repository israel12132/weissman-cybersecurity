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
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS, getEnginesByGroup } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
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

function EngineRow({ engine, status, selected, onSelect }) {
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
        </div>
        <p className="text-[10px] text-white/35 mt-0.5 leading-relaxed">{engine.description}</p>
      </div>
    </motion.div>
  )
}

function ProfileCard({ profile, count, active, onClick }) {
  return (
    <motion.button
      type="button"
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className="w-full text-left rounded-xl border p-4 transition-all"
      style={{
        borderColor: active ? `${profile.color}50` : 'rgba(255,255,255,0.06)',
        background: active ? `${profile.color}12` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-2xl">{profile.icon}</span>
        <div className="min-w-0">
          <div className="text-xs font-bold truncate" style={{ color: profile.color }}>
            {profile.label}
          </div>
          <div className="text-[10px] font-mono" style={{ color: `${profile.color}80` }}>
            {count} engines
          </div>
        </div>
      </div>
      <p className="text-[10px] text-white/35 leading-relaxed line-clamp-2">{profile.description}</p>
    </motion.button>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function EngineClientCatalog() {
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
  }, [selectedClientId])

  const handleRunAll = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', 'Select a client first')
      return
    }
    if (selectedEngines.size === 0) {
      showToast('error', 'No engines selected')
      return
    }
    setRunAllLoading(true)
    try {
      const r = await apiFetch('/api/scan/all-engines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: Number(selectedClientId),
          engines: Array.from(selectedEngines),
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        showToast('error', d.detail || `Scan failed (${r.status})`)
        return
      }
      showToast('info', `✅ Queued ${d.engines_queued ?? selectedEngines.size} engines (Job: ${d.job_id ?? '—'})`)
      setEngineStates((prev) => {
        const next = { ...prev }
        for (const id of selectedEngines) next[id] = { ...next[id], status: 'running' }
        return next
      })
    } catch (e) {
      showToast('error', e?.message ?? 'Network error')
    } finally {
      setRunAllLoading(false)
    }
  }, [selectedClientId, selectedEngines, showToast])

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
  const totalProfileEngines = profileEngineList.length

  return (
    <PageShell
      title="Engine Client Catalog"
      subtitle={`${ENGINES_REGISTRY.length} engines · ${CLIENT_PROFILES.length} client profiles`}
      badge="CATALOG"
      badgeColor={activeProfile.color}
    >
      {/* ── Top bar: client selector + Run All ─────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-white/40">Client:</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-black/60 border border-white/10 rounded-lg px-2 py-1 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
          >
            <option value="">— Select client —</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          {!selectedClientId && (
            <span className="text-[10px] font-mono text-amber-400/60">
              ⚠ Select a client to run engines
            </span>
          )}
        </div>

        <button
          id="run-all-engines-btn"
          type="button"
          onClick={handleRunAll}
          disabled={runAllLoading || !selectedClientId || totalSelected === 0}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-[12px] font-mono font-semibold bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          style={
            !runAllLoading && selectedClientId && totalSelected > 0
              ? { boxShadow: '0 0 16px rgba(34,197,94,0.25)' }
              : {}
          }
        >
          {runAllLoading ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-green-400/40 border-t-green-400 rounded-full animate-spin" />
              Running…
            </>
          ) : (
            <>
              🚀 Run All Selected Engines ({totalSelected})
            </>
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
        <div className="space-y-2">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">
            Client Profiles
          </h2>
          {CLIENT_PROFILES.map((profile) => (
            <ProfileCard
              key={profile.id}
              profile={profile}
              count={profileEngines(profile).length}
              active={profile.id === activeProfileId}
              onClick={() => setActiveProfileId(profile.id)}
            />
          ))}

          {/* Quick links */}
          <div className="pt-4 space-y-1.5">
            <Link
              to="/engines"
              className="flex items-center gap-2 text-[11px] font-mono text-white/35 hover:text-cyan-300 transition-colors"
            >
              ⚡ Engine Matrix (full view)
            </Link>
            <Link
              to="/threat-intel"
              className="flex items-center gap-2 text-[11px] font-mono text-white/35 hover:text-cyan-300 transition-colors"
            >
              🗺️ Threat Intel Hub (MITRE map)
            </Link>
          </div>
        </div>

        {/* ── Right: Engine List for Active Profile ────────────────── */}
        <div className="min-w-0 space-y-4">
          {/* Profile header */}
          <div
            className="rounded-xl border p-5"
            style={{
              borderColor: `${activeProfile.color}30`,
              background: `${activeProfile.color}08`,
            }}
          >
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
                placeholder="Search engines, MITRE IDs, descriptions…"
                className="w-full bg-black/40 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/80 placeholder-white/20 font-mono focus:outline-none focus:border-cyan-500/40"
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
            <span className="text-[10px] font-mono text-white/30 whitespace-nowrap">
              {filteredEngines.length}/{totalProfileEngines} · {totalSelected} selected
            </span>
            <button
              type="button"
              onClick={handleSelectAll}
              className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 transition-colors"
            >
              Select All
            </button>
            <button
              type="button"
              onClick={handleDeselectAll}
              className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 transition-colors"
            >
              Clear
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
                  No engines match your search.
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
                            <span className="text-[10px] font-mono text-white/30">
                              {selectedCount}/{engines.length} selected
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
              disabled={runAllLoading || !selectedClientId || totalSelected === 0}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl text-[13px] font-mono font-semibold bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              style={
                !runAllLoading && selectedClientId && totalSelected > 0
                  ? { boxShadow: '0 0 20px rgba(34,197,94,0.2)' }
                  : {}
              }
            >
              {runAllLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-green-400/40 border-t-green-400 rounded-full animate-spin" />
                  Running all engines…
                </>
              ) : (
                <>
                  🚀 Run All {totalSelected} Selected Engines
                  {activeProfile && (
                    <span className="text-green-400/60 font-normal">
                      · {activeProfile.icon} {activeProfile.label}
                    </span>
                  )}
                </>
              )}
            </button>
            {!selectedClientId && (
              <p className="text-center text-[10px] font-mono text-amber-400/50 mt-1.5">
                Select a client above to enable scanning
              </p>
            )}
          </div>
        </div>
      </div>
    </PageShell>
  )
}
