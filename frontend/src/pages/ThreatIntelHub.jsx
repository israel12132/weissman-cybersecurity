/**
 * Threat Intelligence Hub
 *
 * Unified view of all 150 engines, MITRE ATT&CK coverage heatmap, engine group
 * statistics, and a live threat feed.  Accessible at /threat-intel.
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS, getEnginesByGroup } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import PageShell from './PageShell'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const GROUP_ICONS = {
  recon:        '🔍',
  web:          '🌐',
  ai:           '🤖',
  cloud:        '☁️',
  ot:           '⚙️',
  stealth:      '👤',
  crypto:       '🔐',
  network:      '📡',
  supply_chain: '📦',
  apt:          '🎯',
}

function severityColor(s) {
  const MAP = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee', info: '#6b7280' }
  return MAP[(s || '').toLowerCase()] ?? '#6b7280'
}

// ─── Stat Card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color = '#22d3ee', icon }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl bg-black/40 backdrop-blur border border-white/8 p-4 flex flex-col gap-1"
    >
      <div className="flex items-center gap-2">
        {icon && <span className="text-lg">{icon}</span>}
        <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${color}99` }}>{label}</span>
      </div>
      <div className="text-3xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-white/30 font-mono">{sub}</div>}
    </motion.div>
  )
}

// ─── Group Breakdown Bar ─────────────────────────────────────────────────────

function GroupBar({ group, engines, total, onClick, active }) {
  const pct = (engines.length / total) * 100
  return (
    <motion.button
      type="button"
      whileHover={{ scale: 1.01 }}
      onClick={onClick}
      className="w-full text-left rounded-lg border p-3 transition-all"
      style={{
        borderColor: active ? `${group.color}60` : 'rgba(255,255,255,0.06)',
        background: active ? `${group.color}10` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-semibold text-white/80">
          {GROUP_ICONS[group.id] ?? '◆'} {group.label}
        </span>
        <span className="text-[10px] font-mono" style={{ color: group.color }}>{engines.length} engines</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="h-full rounded-full"
          style={{ background: group.color }}
        />
      </div>
    </motion.button>
  )
}

// ─── MITRE Coverage Badge ─────────────────────────────────────────────────────

function MitreBadge({ id }) {
  if (!id) return null
  return (
    <span
      className="inline-block px-1.5 py-0.5 rounded text-[9px] font-mono border"
      style={{ color: '#94a3b8', borderColor: 'rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.04)' }}
    >
      {id}
    </span>
  )
}

// ─── Engine List ─────────────────────────────────────────────────────────────

function EngineListItem({ engine, groupColor, index }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.02, duration: 0.15 }}
      className="flex items-start gap-3 py-2.5 border-b border-white/5 group"
    >
      <span
        className="mt-0.5 w-1.5 h-1.5 rounded-full flex-shrink-0"
        style={{ background: groupColor, boxShadow: `0 0 6px ${groupColor}80` }}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-white/85">{engine.label}</span>
          <MitreBadge id={engine.mitre} />
          {!engine.requiresTarget && (
            <span className="text-[9px] font-mono text-emerald-400/70 border border-emerald-500/20 px-1.5 rounded">
              GLOBAL
            </span>
          )}
        </div>
        <p className="text-[10px] text-white/35 mt-0.5 leading-relaxed">{engine.description}</p>
      </div>
    </motion.div>
  )
}

// ─── MITRE Technique Coverage ────────────────────────────────────────────────

function MitreCoverage({ engines }) {
  const techniqueMap = useMemo(() => {
    const map = {}
    for (const e of engines) {
      if (!e.mitre) continue
      if (!map[e.mitre]) map[e.mitre] = { id: e.mitre, engines: [] }
      map[e.mitre].engines.push(e)
    }
    return Object.values(map).sort((a, b) => b.engines.length - a.engines.length)
  }, [engines])

  return (
    <div className="flex flex-wrap gap-1.5">
      {techniqueMap.map((t) => {
        const intensity = Math.min(1, t.engines.length / 4)
        const alpha = Math.round(20 + intensity * 80)
        return (
          <span
            key={t.id}
            title={`${t.id}: ${t.engines.map((e) => e.label).join(', ')}`}
            className="px-2 py-0.5 rounded text-[9px] font-mono cursor-default transition-all hover:scale-105"
            style={{
              background: `rgba(34, 211, 238, ${intensity * 0.2})`,
              border: `1px solid rgba(34, 211, 238, ${intensity * 0.4 + 0.1})`,
              color: `rgba(34, 211, 238, ${0.4 + intensity * 0.6})`,
            }}
          >
            {t.id} {t.engines.length > 1 ? `×${t.engines.length}` : ''}
          </span>
        )
      })}
    </div>
  )
}

// ─── Live Findings Stats ──────────────────────────────────────────────────────

function useFindingsStats() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const r = await apiFetch('/api/findings?page=1&per_page=1')
        if (r.ok) {
          const d = await r.json()
          const total = d.total ?? 0
          // Compute severity breakdown from summary if available, else use totals
          const summary = d.summary ?? {}
          setStats({ total, summary })
        }
      } catch (_) {
        // Non-critical: stats widget degrades gracefully when the API is unavailable
      } finally { setLoading(false) }
    }
    load()
  }, [])

  return { stats, loading }
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ThreatIntelHub() {
  const [activeGroup, setActiveGroup] = useState(null)
  const [search, setSearch] = useState('')
  const { stats, loading: statsLoading } = useFindingsStats()

  const filteredEngines = useMemo(() => {
    let list = activeGroup ? getEnginesByGroup(activeGroup) : ENGINES_REGISTRY
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(
        (e) =>
          e.label.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q) ||
          (e.mitre || '').toLowerCase().includes(q) ||
          e.id.toLowerCase().includes(q),
      )
    }
    return list
  }, [activeGroup, search])

  const handleGroupClick = useCallback(
    (groupId) => setActiveGroup((prev) => (prev === groupId ? null : groupId)),
    [],
  )

  const uniqueMitre = useMemo(() => {
    return new Set(ENGINES_REGISTRY.map((e) => e.mitre).filter(Boolean)).size
  }, [])

  const globalEngines = useMemo(() => ENGINES_REGISTRY.filter((e) => !e.requiresTarget).length, [])
  const targetEngines = ENGINES_REGISTRY.length - globalEngines

  return (
    <PageShell
      title="Threat Intelligence Hub"
      subtitle={`${ENGINES_REGISTRY.length} engines · ${uniqueMitre} MITRE techniques`}
      badge="LIVE"
      badgeColor="#22d3ee"
    >
      {/* ── Top Stats ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
        <StatCard
          label="Attack Engines"
          value={ENGINES_REGISTRY.length}
          sub={`${globalEngines} global · ${targetEngines} target-based`}
          color="#22d3ee"
          icon="⚡"
        />
        <StatCard
          label="MITRE Techniques"
          value={uniqueMitre}
          sub="ATT&CK technique coverage"
          color="#8b5cf6"
          icon="🗺️"
        />
        <StatCard
          label="Engine Groups"
          value={ENGINE_GROUP_DEFS.length}
          sub="Tactical domains covered"
          color="#f97316"
          icon="🏹"
        />
        <StatCard
          label="Live Findings"
          value={statsLoading ? '—' : (stats?.total ?? '—')}
          sub="Verified & potential"
          color="#ef4444"
          icon="🚨"
        />
      </div>

      <div className="grid lg:grid-cols-[320px_1fr] gap-6">
        {/* ── Left: Group Breakdown ─────────────────────────────────────── */}
        <div className="space-y-2">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">Engine Groups</h2>
          {ENGINE_GROUP_DEFS.map((group) => (
            <GroupBar
              key={group.id}
              group={group}
              engines={getEnginesByGroup(group.id)}
              total={ENGINES_REGISTRY.length}
              onClick={() => handleGroupClick(group.id)}
              active={activeGroup === group.id}
            />
          ))}
          {activeGroup && (
            <button
              type="button"
              onClick={() => setActiveGroup(null)}
              className="w-full text-center text-[10px] font-mono text-white/30 hover:text-white/60 mt-2 transition-colors"
            >
              ✕ clear filter
            </button>
          )}

          {/* MITRE Coverage */}
          <div className="mt-6">
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">
              MITRE ATT&amp;CK Coverage
            </h2>
            <MitreCoverage engines={ENGINES_REGISTRY} />
          </div>
        </div>

        {/* ── Right: Engine List ────────────────────────────────────────── */}
        <div className="min-w-0">
          <div className="flex items-center gap-3 mb-4">
            <div className="flex-1 relative">
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
              {filteredEngines.length} engines
            </span>
          </div>

          <div className="rounded-xl bg-black/30 border border-white/6 px-4 max-h-[70vh] overflow-y-auto">
            <AnimatePresence mode="wait">
              {filteredEngines.length === 0 ? (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="py-12 text-center text-white/25 text-xs font-mono"
                >
                  No engines match your search.
                </motion.div>
              ) : (
                <motion.div key={`${activeGroup}-${search}`}>
                  {filteredEngines.map((engine, i) => {
                    const groupDef = ENGINE_GROUP_DEFS.find((g) => g.id === engine.group)
                    return (
                      <EngineListItem
                        key={engine.id}
                        engine={engine}
                        groupColor={groupDef?.color ?? '#6b7280'}
                        index={i}
                      />
                    )
                  })}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* ── Quick Links ───────────────────────────────────────────────────── */}
      <div className="mt-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { to: '/engines',         label: 'Engine Matrix',     color: '#22d3ee', desc: 'Run & manage all engines' },
          { to: '/engine-catalog',  label: 'Client Catalog',    color: '#10b981', desc: 'Engines by client type' },
          { to: '/threat-emulation',label: 'APT Emulation',     color: '#ef4444', desc: 'Nation-state TTP simulation' },
          { to: '/domain-discovery',label: 'Domain Discovery',  color: '#8b5cf6', desc: 'Enumerate attack surface' },
        ].map((link) => (
          <Link
            key={link.to}
            to={link.to}
            className="rounded-xl border p-4 transition-all hover:scale-[1.02] group block"
            style={{ borderColor: `${link.color}25`, background: `${link.color}08` }}
          >
            <div className="text-xs font-semibold mb-1" style={{ color: link.color }}>
              {link.label} →
            </div>
            <div className="text-[10px] text-white/35">{link.desc}</div>
          </Link>
        ))}
      </div>
    </PageShell>
  )
}
