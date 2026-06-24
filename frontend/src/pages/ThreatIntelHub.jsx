/**
 * Threat Intelligence Hub — /threat-intel
 *
 * Real intelligence only:
 *   • Live CVE feed from the National Vulnerability Database via GET /api/threat-intel/feed
 *     (last 7 days; empty when NVD_API_KEY is not configured — rendered as an honest empty state).
 *   • Environment correlation from GET /api/dashboard/exec-kpis (open-finding severity counts,
 *     24h deltas, most-detected CVEs, top MITRE ATT&CK techniques, weighted security score).
 *   • A detection-capability catalog derived from the engine registry — clearly labelled as
 *     platform capability, not live telemetry.
 *
 * No fabricated rows. Every number on this page is sourced from a backend response.
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  ChevronDown,
  Crosshair,
  ExternalLink,
  Gauge,
  Layers,
  RadioTower,
  Search,
  ShieldAlert,
  Target,
  X,
} from 'lucide-react'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS, getEnginesByGroup } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'

// ── Severity model ────────────────────────────────────────────────────────────

const SEVERITY_META = {
  critical: { color: '#f43f5e', rank: 5 },
  high: { color: '#fb923c', rank: 4 },
  medium: { color: '#fbbf24', rank: 3 },
  low: { color: '#38bdf8', rank: 2 },
  info: { color: '#94a3b8', rank: 1 },
}
const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'info']

function normSev(s) {
  const k = String(s || '').toLowerCase()
  return SEVERITY_META[k] ? k : 'info'
}

function sevColor(s) {
  return SEVERITY_META[normSev(s)].color
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
}

// ── Data hook (real backend, optional polling) ─────────────────────────────────

function useApiResource(path, autoRefreshMs) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [updatedAt, setUpdatedAt] = useState(null)

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true)
      setError(null)
      try {
        const r = await apiFetch(path)
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        setData(d)
        setUpdatedAt(Date.now())
      } catch (e) {
        setError(e?.message || 'Request failed')
      } finally {
        setLoading(false)
      }
    },
    [path],
  )

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!autoRefreshMs) return undefined
    const id = setInterval(() => load(true), autoRefreshMs)
    return () => clearInterval(id)
  }, [autoRefreshMs, load])

  return { data, loading, error, reload: load, updatedAt }
}

// ── Presentational primitives ──────────────────────────────────────────────────

function StatTile({ label, value, hint, color = 'var(--accent-strong)', icon: Icon, loading }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-white/10 bg-[var(--card-bg)]/80 backdrop-blur-md p-5"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
            {label}
          </div>
          <div
            className="mt-2 text-3xl font-bold tabular-nums tracking-tight"
            style={{ color }}
          >
            {loading ? '—' : value}
          </div>
          {hint && <p className="text-[11px] text-white/40 mt-1.5 leading-snug">{hint}</p>}
        </div>
        {Icon && (
          <span
            className="shrink-0 w-9 h-9 rounded-xl border border-white/10 bg-white/[0.03] grid place-items-center"
            style={{ color }}
          >
            <Icon className="w-4 h-4" strokeWidth={1.9} />
          </span>
        )}
      </div>
    </motion.div>
  )
}

function DeltaPill({ delta }) {
  if (delta == null || delta === 0) {
    return <span className="text-[10px] font-mono text-white/30">±0</span>
  }
  const up = delta > 0
  return (
    <span
      className={`text-[10px] font-mono ${up ? 'text-rose-300' : 'text-emerald-300'}`}
      title="Δ vs 24h ago"
    >
      {up ? '▲' : '▼'} {Math.abs(delta)}
    </span>
  )
}

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

// ── Live CVE feed ───────────────────────────────────────────────────────────────

function nvdUrl(id) {
  const clean = String(id || '').trim()
  return clean ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(clean)}` : null
}

function fmtDate(s) {
  if (!s) return ''
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString()
}

function FeedRow({ item, expanded, onToggle, t }) {
  const sev = normSev(item.severity)
  const color = SEVERITY_META[sev].color
  const id = item.external_id || ''
  const url = nvdUrl(id)
  return (
    <div className="border-b border-white/5 last:border-0">
      <button
        type="button"
        onClick={onToggle}
        className="w-full text-left flex items-start gap-3 py-3 group"
      >
        <span
          className="mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0"
          style={{ background: color, boxShadow: `0 0 7px ${color}90` }}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs font-semibold text-white/90">{id || '—'}</span>
            <span
              className="px-1.5 py-0.5 rounded text-[9px] font-mono uppercase tracking-wider border"
              style={{ color, borderColor: `${color}55`, background: `${color}14` }}
            >
              {sev}
            </span>
            <span className="text-[10px] font-mono text-white/30">{item.source || 'NVD'}</span>
            {item.published_at && (
              <span className="text-[10px] font-mono text-white/30">
                {t('pages.threatIntelHub.published', { date: fmtDate(item.published_at) })}
              </span>
            )}
          </div>
          <p
            className={`text-[11px] text-white/45 mt-1 leading-relaxed ${expanded ? '' : 'line-clamp-2'}`}
          >
            {item.description || '—'}
          </p>
        </div>
        <ChevronDown
          className={`w-4 h-4 text-white/25 shrink-0 mt-1 transition-transform ${expanded ? 'rotate-180' : ''}`}
        />
      </button>
      <AnimatePresence initial={false}>
        {expanded && url && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="pb-3 pl-5">
              <a
                href={url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 hover:text-cyan-200"
              >
                <ExternalLink className="w-3 h-3" /> {t('pages.threatIntelHub.view_on_nvd')}
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function LiveFeed({ feed, t, workbench }) {
  const [expanded, setExpanded] = useState(() => new Set())
  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    total,
  } = workbench

  const itemById = useMemo(() => {
    const m = {}
    for (const item of feed.data?.items || []) {
      if (item.external_id) m[item.external_id] = item
    }
    return m
  }, [feed.data])

  const toggle = useCallback((id) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  if (feed.error) {
    return (
      <EmptyState
        icon="alert"
        title={t('pages.threatIntelHub.feed_error')}
        body={feed.error}
        cta={{ label: t('pages.threatIntelHub.retry'), onClick: () => feed.reload() }}
      />
    )
  }

  if (feed.loading && !total) {
    return (
      <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
        <SkeletonWidgetGrid count={4} />
      </div>
    )
  }

  if (total === 0 && !feed.loading) {
    return (
      <EmptyState
        icon="radar"
        title={t('pages.threatIntelHub.feed_empty_title')}
        body={t('pages.threatIntelHub.feed_empty_body')}
        cta={{ label: t('pages.threatIntelHub.retry'), onClick: () => feed.reload() }}
      />
    )
  }

  return (
    <WeissmanFindingsPanel
      findings={workbench.sortedFindings}
      filteredFindings={filteredFindings}
      counts={counts}
      total={total}
      searchQuery={searchQuery}
      onSearchChange={setSearchQuery}
      severityFilter={severityFilter}
      onSeverityChange={setSeverityFilter}
      loading={feed.loading && !total}
      accent="#22d3ee"
      title={t('pages.threatIntelHub.feed_heading')}
      emptyTitle={t('pages.threatIntelHub.feed_empty_title')}
      emptyBody={t('pages.threatIntelHub.feed_empty_body')}
      renderFinding={(f) => {
        const item = itemById[f.id] || {
          external_id: f.title,
          severity: f.severity,
          description: f.description,
          source: f.type,
        }
        const key = item.external_id || f.id
        return (
          <FeedRow
            key={key}
            item={item}
            expanded={expanded.has(key)}
            onToggle={() => toggle(key)}
            t={t}
          />
        )
      }}
    />
  )
}

// ── Environment correlation (real exec-kpis) ────────────────────────────────────

function SeverityDistribution({ kpis, t }) {
  const sev = kpis.data?.severity || {}
  const delta = kpis.data?.severity_delta_24h || {}
  const max = Math.max(1, ...SEVERITY_KEYS.map((k) => Number(sev[k] || 0)))

  return (
    <div className="rounded-2xl border border-white/10 bg-[var(--card-bg)]/70 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-white/80">
          {t('pages.threatIntelHub.severity_distribution')}
        </h3>
        <span className="text-[10px] font-mono text-white/30">
          {t('pages.threatIntelHub.severity_distribution_hint')}
        </span>
      </div>
      {kpis.loading ? (
        <SkeletonTable rows={5} cols={2} />
      ) : (
        <div className="space-y-2.5">
          {SEVERITY_KEYS.map((k) => {
            const v = Number(sev[k] || 0)
            const pct = (v / max) * 100
            const color = SEVERITY_META[k].color
            return (
              <div key={k} className="flex items-center gap-3">
                <span className="w-16 text-[10px] font-mono uppercase tracking-wider text-white/55">
                  {t(`pages.threatIntelHub.sev_${k}`)}
                </span>
                <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.5 }}
                    className="h-full rounded-full"
                    style={{ background: color }}
                  />
                </div>
                <span className="w-10 text-right text-xs font-mono tabular-nums" style={{ color }}>
                  {v}
                </span>
                <span className="w-12 text-right">
                  <DeltaPill delta={Number(delta[k] ?? 0)} />
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function TopList({ title, hint, emptyLabel, rows, loading, renderRow }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-[var(--card-bg)]/70 p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-white/80">{title}</h3>
        {hint && <span className="text-[10px] font-mono text-white/30">{hint}</span>}
      </div>
      {loading ? (
        <SkeletonTable rows={5} cols={2} />
      ) : rows.length === 0 ? (
        <div className="py-6 text-center text-white/25 text-[11px] font-mono">{emptyLabel}</div>
      ) : (
        <div className="space-y-1.5">{rows.map(renderRow)}</div>
      )}
    </div>
  )
}

// ── Detection capability catalog (engine registry) ──────────────────────────────

function GroupBar({ group, engines, total, onClick, active }) {
  const pct = total ? (engines.length / total) * 100 : 0
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
        <span className="text-[10px] font-mono" style={{ color: group.color }}>
          {engines.length}
        </span>
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

function EngineListItem({ engine, groupColor, index, t }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: Math.min(index * 0.015, 0.4), duration: 0.15 }}
      className="flex items-start gap-3 py-2.5 border-b border-white/5"
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
              {t('pages.threatIntelHub.global_badge')}
            </span>
          )}
        </div>
        <p className="text-[10px] text-white/35 mt-0.5 leading-relaxed">{engine.description}</p>
      </div>
    </motion.div>
  )
}

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
      {techniqueMap.map((tech) => {
        const intensity = Math.min(1, tech.engines.length / 4)
        return (
          <span
            key={tech.id}
            title={`${tech.id}: ${tech.engines.map((e) => e.label).join(', ')}`}
            className="px-2 py-0.5 rounded text-[9px] font-mono cursor-default transition-all hover:scale-105"
            style={{
              background: `rgba(34, 211, 238, ${intensity * 0.2})`,
              border: `1px solid rgba(34, 211, 238, ${intensity * 0.4 + 0.1})`,
              color: `rgba(34, 211, 238, ${0.4 + intensity * 0.6})`,
            }}
          >
            {tech.id} {tech.engines.length > 1 ? `×${tech.engines.length}` : ''}
          </span>
        )
      })}
    </div>
  )
}

function CoveragePanel({ t }) {
  const [activeGroup, setActiveGroup] = useState(null)
  const [search, setSearch] = useState('')

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

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-cyan-500/15 bg-cyan-500/[0.04] px-4 py-2.5 text-[11px] text-cyan-200/70 font-mono">
        {t('pages.threatIntelHub.coverage_intro')}
      </div>

      <div className="grid lg:grid-cols-[320px_1fr] gap-6">
        <div className="space-y-2">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">
            {t('pages.threatIntelHub.groups_heading')}
          </h2>
          {ENGINE_GROUP_DEFS.map((group) => (
            <GroupBar
              key={group.id}
              group={group}
              engines={getEnginesByGroup(group.id)}
              total={ENGINES_REGISTRY.length}
              onClick={() => setActiveGroup((prev) => (prev === group.id ? null : group.id))}
              active={activeGroup === group.id}
            />
          ))}
          {activeGroup && (
            <button
              type="button"
              onClick={() => setActiveGroup(null)}
              className="w-full text-center text-[10px] font-mono text-white/30 hover:text-white/60 mt-2 transition-colors"
            >
              ✕ {t('pages.threatIntelHub.clear_filter')}
            </button>
          )}

          <div className="mt-6">
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-white/30 mb-3">
              {t('pages.threatIntelHub.mitre_coverage_heading')}
            </h2>
            <MitreCoverage engines={ENGINES_REGISTRY} />
          </div>
        </div>

        <div className="min-w-0">
          <div className="flex items-center gap-3 mb-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/25" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t('pages.threatIntelHub.search_placeholder')}
                className="w-full bg-black/40 border border-white/10 rounded-lg pl-9 pr-8 py-2 text-xs text-white/80 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/40"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
            <span className="text-[10px] font-mono text-white/30 whitespace-nowrap">
              {t('pages.threatIntelHub.engines_count', { count: filteredEngines.length })}
            </span>
          </div>

          <div className="rounded-xl bg-black/30 border border-white/6 px-4 max-h-[62vh] overflow-y-auto">
            {filteredEngines.length === 0 ? (
              <div className="py-12 text-center text-white/25 text-xs font-mono">
                {t('pages.threatIntelHub.no_match')}
              </div>
            ) : (
              filteredEngines.map((engine, i) => {
                const groupDef = ENGINE_GROUP_DEFS.find((g) => g.id === engine.group)
                return (
                  <EngineListItem
                    key={engine.id}
                    engine={engine}
                    groupColor={groupDef?.color ?? '#6b7280'}
                    index={i}
                    t={t}
                  />
                )
              })
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Page ────────────────────────────────────────────────────────────────────────

const QUICK_LINKS = [
  { to: '/findings', key: 'link_findings', desc: 'link_findings_desc', color: '#22d3ee' },
  { to: '/threat-emulation', key: 'link_apt_emulation', desc: 'link_apt_emulation_desc', color: '#ef4444' },
  { to: '/engines', key: 'link_engine_matrix', desc: 'link_engine_matrix_desc', color: '#10b981' },
  { to: '/domain-discovery', key: 'link_domain_discovery', desc: 'link_domain_discovery_desc', color: '#8b5cf6' },
]

export default function ThreatIntelHub() {
  const { t } = useTranslation()
  const [tab, setTab] = useState('feed')
  const [auto, setAuto] = useState(false)

  const refreshMs = auto ? 60000 : 0
  const feed = useApiResource('/api/threat-intel/feed', refreshMs)
  const kpis = useApiResource('/api/dashboard/exec-kpis', refreshMs)

  const feedItems = useMemo(() => (Array.isArray(feed.data?.items) ? feed.data.items : []), [feed.data])
  const feedListFindings = useMemo(
    () => feedItems.map((item) => ({
      id: item.external_id || item.id,
      severity: normSev(item.severity),
      title: item.external_id || 'CVE',
      description: item.description || '',
      type: item.source || 'NVD',
      published_at: item.published_at,
    })),
    [feedItems],
  )
  const feedWorkbench = useFindingsWorkbench(feedListFindings, {
    csvPrefix: 'threat-intel-feed',
    haystackFn: (f) => `${f.title} ${f.description} ${f.type} ${f.published_at || ''}`,
  })
  const feedSevereCount = useMemo(
    () => feedItems.filter((i) => ['critical', 'high'].includes(normSev(i.severity))).length,
    [feedItems],
  )

  const openFindings = kpis.data?.open_vs_resolved?.open ?? null
  const score = kpis.data?.security_score
  const cvesTop = Array.isArray(kpis.data?.cves_top) ? kpis.data.cves_top : []
  const mitreTop = Array.isArray(kpis.data?.mitre_top) ? kpis.data.mitre_top : []

  const uniqueMitre = useMemo(
    () => new Set(ENGINES_REGISTRY.map((e) => e.mitre).filter(Boolean)).size,
    [],
  )

  const reloadAll = useCallback(() => {
    feed.reload()
    kpis.reload()
  }, [feed, kpis])

  const updatedAt = Math.max(feed.updatedAt || 0, kpis.updatedAt || 0)
  const busy = feed.loading || kpis.loading

  const actions = (
    <div className="flex items-center gap-2 flex-wrap">
      {updatedAt > 0 && (
        <span className="text-[10px] font-mono text-white/35 hidden sm:inline">
          {t('pages.threatIntelHub.last_updated', {
            time: new Date(updatedAt).toLocaleTimeString(),
          })}
        </span>
      )}
      <button
        type="button"
        onClick={() => setAuto((v) => !v)}
        className={`px-2.5 py-1.5 rounded-lg text-[11px] font-mono border transition-colors ${
          auto
            ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
            : 'border-white/10 text-white/50 hover:text-white/80'
        }`}
        title={t('pages.threatIntelHub.auto_refresh_hint')}
      >
        {auto ? '◉' : '◯'} {t('pages.threatIntelHub.auto_refresh')}
      </button>
      <ShellScanActions
        onRefresh={reloadAll}
        onExport={feedWorkbench.exportCsv}
        refreshLoading={busy}
        exportDisabled={tab !== 'feed' || !feedWorkbench.filteredFindings.length}
      />
    </div>
  )

  return (
    <PageShell
      title={t('pages.threatIntelHub.title')}
      subtitle={t('pages.threatIntelHub.page_subtitle')}
      badge={t('pages.threatIntelHub.badge')}
      badgeColor="#22d3ee"
      actions={actions}
    >
      {/* Hero KPI row — every value sourced from the backend */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <StatTile
          label={t('pages.threatIntelHub.stat_live_cves')}
          value={feedItems.length}
          hint={t('pages.threatIntelHub.stat_live_cves_hint')}
          color="#22d3ee"
          icon={RadioTower}
          loading={feed.loading}
        />
        <StatTile
          label={t('pages.threatIntelHub.stat_crit_high_cves')}
          value={feedSevereCount}
          hint={t('pages.threatIntelHub.stat_crit_high_hint')}
          color="#f43f5e"
          icon={ShieldAlert}
          loading={feed.loading}
        />
        <StatTile
          label={t('pages.threatIntelHub.stat_open_findings')}
          value={openFindings ?? '—'}
          hint={t('pages.threatIntelHub.stat_open_findings_hint')}
          color="#fb923c"
          icon={Activity}
          loading={kpis.loading}
        />
        <StatTile
          label={t('pages.threatIntelHub.stat_security_score')}
          value={score == null ? '—' : `${score}/100`}
          hint={t('pages.threatIntelHub.stat_security_score_hint')}
          color="#34d399"
          icon={Gauge}
          loading={kpis.loading}
        />
      </div>

      {/* Environment correlation — real exec-kpis */}
      <div className="grid lg:grid-cols-3 gap-4 mb-6">
        <SeverityDistribution kpis={kpis} t={t} />
        <TopList
          title={t('pages.threatIntelHub.top_cves_env')}
          hint={t('pages.threatIntelHub.top_cves_env_hint')}
          emptyLabel={t('pages.threatIntelHub.top_cves_empty')}
          rows={cvesTop}
          loading={kpis.loading}
          renderRow={(c) => {
            const url = nvdUrl(c.cve)
            return (
              <div key={c.cve} className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0">
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sevColor(c.severity) }} />
                {url ? (
                  <a
                    href={url}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-[11px] text-white/80 hover:text-cyan-300 truncate flex-1"
                  >
                    {c.cve}
                  </a>
                ) : (
                  <span className="font-mono text-[11px] text-white/80 truncate flex-1">{c.cve}</span>
                )}
                <span className="text-[10px] font-mono text-white/35">
                  {t('pages.threatIntelHub.hits', { count: c.hits })}
                </span>
              </div>
            )
          }}
        />
        <TopList
          title={t('pages.threatIntelHub.top_mitre')}
          hint={t('pages.threatIntelHub.top_mitre_hint')}
          emptyLabel={t('pages.threatIntelHub.top_mitre_empty')}
          rows={mitreTop}
          loading={kpis.loading}
          renderRow={(m) => (
            <div key={m.id} className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0">
              <Crosshair className="w-3 h-3 text-cyan-400/60 shrink-0" />
              <span className="font-mono text-[11px] text-white/80">{m.id}</span>
              <span className="text-[10px] font-mono text-white/35 truncate flex-1">
                {String(m.tactic || '').replace(/_/g, ' ')}
              </span>
              <span className="text-[10px] font-mono text-white/35">
                {t('pages.threatIntelHub.hits', { count: m.hits })}
              </span>
            </div>
          )}
        />
      </div>

      {/* Tabs: live feed vs detection capability */}
      <div className="flex items-center gap-1 mb-5 border-b border-white/8">
        <TabButton active={tab === 'feed'} onClick={() => setTab('feed')} icon={Target}>
          {t('pages.threatIntelHub.tab_feed')}
        </TabButton>
        <TabButton active={tab === 'coverage'} onClick={() => setTab('coverage')} icon={Layers}>
          {t('pages.threatIntelHub.tab_coverage')}
        </TabButton>
        {tab === 'coverage' && (
          <span className="ml-auto text-[10px] font-mono text-white/30">
            {t('pages.threatIntelHub.subtitle', { engines: ENGINES_REGISTRY.length, mitre: uniqueMitre })}
          </span>
        )}
      </div>

      {tab === 'feed' ? <LiveFeed feed={feed} t={t} workbench={feedWorkbench} /> : <CoveragePanel t={t} />}

      {/* Quick links */}
      <div className="mt-8 grid grid-cols-2 sm:grid-cols-4 gap-3">
        {QUICK_LINKS.map((link) => (
          <Link
            key={link.to}
            to={link.to}
            className="rounded-xl border p-4 transition-all hover:scale-[1.02] block"
            style={{ borderColor: `${link.color}25`, background: `${link.color}08` }}
          >
            <div className="text-xs font-semibold mb-1" style={{ color: link.color }}>
              {t(`pages.threatIntelHub.${link.key}`)} →
            </div>
            <div className="text-[10px] text-white/35">{t(`pages.threatIntelHub.${link.desc}`)}</div>
          </Link>
        ))}
      </div>
    </PageShell>
  )
}

function TabButton({ active, onClick, icon: Icon, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold border-b-2 -mb-px transition-colors ${
        active
          ? 'border-cyan-400 text-cyan-300'
          : 'border-transparent text-white/45 hover:text-white/75'
      }`}
    >
      {Icon && <Icon className="w-3.5 h-3.5" />}
      {children}
    </button>
  )
}
