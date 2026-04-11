import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS, getEnginesByGroup, ENGINES_BY_ID } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

function severityColor(s) {
  return SEVERITY_COLOR[(s || '').toLowerCase()] ?? '#6b7280'
}

function MitreBadge({ id }) {
  if (!id) return null
  return (
    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/5 border border-white/10 text-white/50 tracking-wider">
      {id}
    </span>
  )
}

function StatusDot({ status }) {
  const map = {
    running: { color: '#22d3ee', pulse: true },
    completed: { color: '#4ade80', pulse: false },
    error: { color: '#ef4444', pulse: false },
    idle: { color: '#374151', pulse: false },
  }
  const { color, pulse } = map[status] ?? map.idle
  return (
    <span className="relative inline-flex items-center justify-center w-2.5 h-2.5">
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

// ─── Engine Card ─────────────────────────────────────────────────────────────

function EngineMatrixCard({ engine, enabled, status, lastRun, findingsDelta, onToggle, onRun, loading, groupColor }) {
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
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      transition={{ duration: 0.15 }}
      className="rounded-xl bg-black/40 backdrop-blur-md border border-white/10 p-4 cursor-pointer transition-all duration-200 hover:border-white/20 hover:shadow-[0_0_20px_rgba(0,0,0,0.3)] group"
      style={enabled ? { borderColor: `${groupColor}30` } : {}}
      onClick={() => navigate(`/engines/${engine.id}`)}
    >
      {/* Top row */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <StatusDot status={status} />
          <span className="text-sm font-semibold text-white truncate">{engine.label}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {/* Toggle */}
          <button
            id={`engine-${engine.id}-toggle`}
            type="button"
            role="switch"
            aria-checked={enabled}
            disabled={loading}
            onClick={handleToggle}
            className={`relative shrink-0 w-9 h-5 rounded-full transition-all duration-300 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed ${
              enabled ? 'bg-[#22d3ee]/40 shadow-inner' : 'bg-black/60 border border-white/10'
            }`}
          >
            <span
              className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all duration-300 ${
                enabled ? 'left-[18px]' : 'left-0.5'
              }`}
              style={enabled ? { boxShadow: `0 0 6px ${groupColor}80` } : {}}
            />
          </button>
          {/* Run */}
          <button
            id={`engine-${engine.id}-run-btn`}
            type="button"
            disabled={loading || runBusy || !enabled}
            title={!enabled ? 'Enable engine first' : 'Queue engine scan'}
            onClick={handleRun}
            className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wide border border-cyan-500/30 text-cyan-300/70 hover:bg-cyan-950/40 hover:text-cyan-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            {runBusy ? '…' : 'Run'}
          </button>
        </div>
      </div>

      {/* MITRE + description */}
      <div className="flex items-center gap-1.5 mb-2">
        <MitreBadge id={engine.mitre} />
      </div>
      <p className="text-[11px] text-white/45 leading-relaxed line-clamp-2">{engine.description}</p>

      {/* Footer */}
      <div className="flex items-center justify-between mt-3 pt-2 border-t border-white/5">
        <span className="text-[10px] font-mono text-white/30">
          {lastRun ? `Last: ${lastRun}` : 'Never run'}
        </span>
        {findingsDelta > 0 && (
          <span
            className="text-[10px] font-mono px-1.5 py-0.5 rounded"
            style={{ backgroundColor: `${severityColor('high')}20`, color: severityColor('high') }}
          >
            +{findingsDelta} findings
          </span>
        )}
      </div>
    </motion.div>
  )
}

// ─── Group Section ────────────────────────────────────────────────────────────

function GroupSection({ groupDef, engines, engineStates, enabledSet, loading, onToggle, onRun, onEnableAll, onDisableAll, onRunGroup }) {
  const groupEngines = engines
  const enabledCount = groupEngines.filter((e) => enabledSet.has(e.id)).length
  const runningCount = groupEngines.filter((e) => (engineStates[e.id]?.status === 'running')).length

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: groupDef.color, boxShadow: `0 0 6px ${groupDef.color}70` }}
          />
          <h2
            className="text-xs font-bold uppercase tracking-[0.2em]"
            style={{ color: groupDef.color }}
          >
            {groupDef.label}
          </h2>
          <span className="text-[10px] font-mono text-white/35">
            {enabledCount}/{groupEngines.length} enabled
            {runningCount > 0 && ` · ${runningCount} running`}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            id={`engine-group-${groupDef.id}-run-btn`}
            type="button"
            onClick={() => onRunGroup(groupEngines.map((e) => e.id))}
            disabled={loading || enabledCount === 0}
            className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wide border border-cyan-500/30 text-cyan-300/70 hover:bg-cyan-950/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Run Group
          </button>
          <button
            id={`engine-group-${groupDef.id}-enable-all-btn`}
            type="button"
            onClick={() => onEnableAll(groupEngines.map((e) => e.id))}
            disabled={loading}
            className="px-2 py-0.5 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Enable All
          </button>
          <button
            id={`engine-group-${groupDef.id}-disable-all-btn`}
            type="button"
            onClick={() => onDisableAll(groupEngines.map((e) => e.id))}
            disabled={loading}
            className="px-2 py-0.5 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Disable All
          </button>
        </div>
      </div>
      <AnimatePresence mode="popLayout">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {groupEngines.map((engine) => {
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
  const [activeGroup, setActiveGroup] = useState('all')
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [clientConfig, setClientConfig] = useState(null)
  const [configLoading, setConfigLoading] = useState(false)
  const [engineStates, setEngineStates] = useState({})
  const [toast, setToast] = useState(null)
  const [runAllLoading, setRunAllLoading] = useState(false)

  // Load clients
  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (Array.isArray(d)) setClients(d)
      })
      .catch(() => {})
  }, [])

  // Load config when client changes
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
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const enabledSet = useMemo(
    () => new Set(Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []),
    [clientConfig?.enabled_engines],
  )

  const patchEngines = useCallback(async (nextList) => {
    if (selectedClientId == null) {
      showToast('error', 'Select a client first')
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
  }, [selectedClientId, showToast])

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
      showToast('error', 'Select a client first')
      return
    }
    const engine = ENGINES_BY_ID[engineId]
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
  }, [selectedClientId, showToast])

  const handleRunGroup = useCallback(async (engineIds) => {
    if (selectedClientId == null) {
      showToast('error', 'Select a client first')
      return
    }
    // Run all enabled engines in the group in parallel
    await Promise.allSettled(
      engineIds.filter((id) => enabledSet.has(id)).map((id) => handleRun(id)),
    )
  }, [selectedClientId, enabledSet, handleRun, showToast])

  const handleRunAllEngines = useCallback(async () => {
    if (selectedClientId == null) {
      showToast('error', 'Select a client first')
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
      // Mark all enabled engines as running
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
  }, [selectedClientId, enabledSet, showToast])

  const visibleGroups = activeGroup === 'all'
    ? ENGINE_GROUP_DEFS
    : ENGINE_GROUP_DEFS.filter((g) => g.id === activeGroup)

  const totalEnabled = enabledSet.size

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{
        background: 'radial-gradient(ellipse 120% 80% at 50% 0%, #0f172a 0%, #020617 55%, #000 100%)',
      }}
    >
      {/* Header */}
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/50 backdrop-blur-md">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link to="/" className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors">
              ← Dashboard
            </Link>
            <span className="text-white/20 text-xs">|</span>
            <h1 className="text-sm font-bold tracking-tight text-white">Engine Matrix</h1>
            <span className="text-[10px] font-mono text-white/30 uppercase tracking-widest">
              {ENGINES_REGISTRY.length} engines · {ENGINE_GROUP_DEFS.length} groups
            </span>
          </div>

          {/* Client selector */}
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
            {configLoading && (
              <div className="w-3 h-3 border-2 border-[#22d3ee]/40 border-t-[#22d3ee] rounded-full animate-spin" />
            )}
            {selectedClientId && (
              <span className="text-[10px] font-mono text-white/40">
                {totalEnabled} enabled
              </span>
            )}
            {/* Run All Engines Button */}
            <button
              type="button"
              onClick={handleRunAllEngines}
              disabled={runAllLoading || configLoading || !selectedClientId || totalEnabled === 0}
              className="px-3 py-1.5 rounded-lg text-[11px] font-mono font-semibold bg-green-500/20 border border-green-500/40 text-green-300 hover:bg-green-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
            >
              {runAllLoading ? '⟳ Running…' : `🚀 Run All Engines (${totalEnabled})`}
            </button>
          </div>
        </div>
      </header>

      {/* Toast */}
      <AnimatePresence>
        {toast && (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
              toast.severity === 'error'
                ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
                : 'bg-black/80 border-cyan-500/30 text-cyan-200'
            }`}
          >
            {toast.message}
          </motion.div>
        )}
      </AnimatePresence>

      <main className="max-w-screen-2xl mx-auto px-4 py-6 space-y-6">
        {/* Group filter tabs */}
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setActiveGroup('all')}
            className={`px-3 py-1 rounded-lg text-[11px] font-mono transition-all ${
              activeGroup === 'all'
                ? 'bg-white/15 text-white border border-white/30'
                : 'text-white/50 border border-white/10 hover:border-white/20 hover:text-white/70'
            }`}
          >
            All ({ENGINES_REGISTRY.length})
          </button>
          {ENGINE_GROUP_DEFS.map((g) => {
            const count = getEnginesByGroup(g.id).length
            return (
              <button
                key={g.id}
                type="button"
                onClick={() => setActiveGroup(g.id)}
                className={`px-3 py-1 rounded-lg text-[11px] font-mono transition-all ${
                  activeGroup === g.id
                    ? 'border text-white'
                    : 'text-white/50 border border-white/10 hover:border-white/20 hover:text-white/70'
                }`}
                style={
                  activeGroup === g.id
                    ? { backgroundColor: `${g.color}20`, borderColor: `${g.color}50`, color: g.color }
                    : {}
                }
              >
                {g.label} ({count})
              </button>
            )
          })}
        </div>

        {/* No client warning */}
        {!selectedClientId && (
          <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono">
            Select a client above to enable toggle controls and run engines. Browse is available without a client.
          </div>
        )}

        {/* Group sections */}
        <div className="space-y-12">
          {visibleGroups.map((groupDef) => {
            const engines = getEnginesByGroup(groupDef.id)
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
              />
            )
          })}
        </div>
      </main>
    </div>
  )
}
