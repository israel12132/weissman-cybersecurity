/**
 * Threat Hunting Workbench
 *
 * World-class threat hunting: hunt campaigns, IOC management,
 * hypothesis-driven hunting with YARA-like queries, hunt results.
 * Route: /threat-hunting
 */
import React, { useState, useMemo, useCallback, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { Download } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid, SkeletonCard } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'

const NS = 'pages.threatHuntingWorkbench'

const HUNT_STATUS_META = {
  active:    { labelKey: `${NS}.status_active`,    color: '#22d3ee' },
  completed: { labelKey: `${NS}.status_completed`, color: '#4ade80' },
  paused:    { labelKey: `${NS}.status_paused`,    color: '#f59e0b' },
  queued:    { labelKey: `${NS}.status_queued`,    color: '#8b5cf6' },
}

function severityLabel(severity, t, prefix = 'severity') {
  const s = String(severity ?? 'medium').toLowerCase()
  return t(`${NS}.${prefix}_${s}`, { defaultValue: s.toUpperCase() })
}

function normalizeCampaign(raw, t) {
  return {
    id: raw.id ?? '',
    title: raw.title ?? t(`${NS}.untitled_hunt`),
    hypothesis: raw.hypothesis ?? '',
    status: raw.status ?? 'queued',
    analyst: raw.analyst ?? t(`${NS}.unassigned`),
    started: raw.started ?? '—',
    mitre: Array.isArray(raw.mitre) ? raw.mitre : [],
    hitsFound: Number(raw.hitsFound) || 0,
    dataSources: Array.isArray(raw.dataSources) ? raw.dataSources : [],
    priority: raw.priority ?? 'medium',
    color: raw.color ?? '#22d3ee',
  }
}

function normalizeIoc(raw, index) {
  const tags = Array.isArray(raw.tags) ? raw.tags : (raw.source ? [raw.source] : [])
  return {
    id: raw.id ?? `ioc-${index}`,
    type: raw.type ?? 'domain',
    value: raw.value ?? raw.indicator ?? '',
    source: raw.source ?? 'Findings',
    severity: String(raw.severity ?? 'medium').toLowerCase(),
    tags,
    added: raw.added ?? (raw.last_seen ? String(raw.last_seen).slice(0, 10) : '—'),
  }
}

function normalizeQuery(raw, index, t) {
  return {
    id: raw.id ?? `q-${index}`,
    name: raw.name ?? t(`${NS}.untitled_query`),
    datasource: raw.datasource ?? raw.dataSources?.[0] ?? 'Findings',
    language: raw.language ?? 'KQL',
    query: raw.query ?? '',
    mitre: raw.mitre ?? '—',
    hits: Number(raw.hits ?? raw.hitsFound) || 0,
  }
}

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee', info: '#6b7280' }
const IOC_TYPE_ICON = { ip: '🌐', domain: '🔗', hash: '#️⃣', email: '✉️', url: '🔍' }

function exportIocsCsv(iocs, t) {
  const header = ['type', 'value', 'source', 'severity', 'added', 'tags']
  const rows = iocs.map((ioc) => [
    ioc.type,
    (ioc.value || '').replace(/"/g, '""'),
    ioc.source,
    ioc.severity,
    ioc.added,
    (ioc.tags || []).join(';'),
  ])
  const csv = [header.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `threat-hunting-iocs-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color, icon }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl bg-[var(--bg-2)] backdrop-blur border border-[var(--border-subtle)] p-4 flex flex-col gap-1"
    >
      <div className="flex items-center gap-2">
        {icon && <span className="text-lg">{icon}</span>}
        <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${color}99` }}>{label}</span>
      </div>
      <div className="text-3xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-[var(--text-disabled)] font-mono">{sub}</div>}
    </motion.div>
  )
}

function CampaignCard({ campaign, selected, onSelect, t }) {
  const sm = HUNT_STATUS_META[campaign.status] ?? { labelKey: null, color: '#6b7280' }
  const sc = SEV_COLOR[campaign.priority] ?? '#6b7280'
  const statusLabel = sm.labelKey ? t(sm.labelKey) : campaign.status.toUpperCase()
  return (
    <motion.button
      type="button"
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      onClick={() => onSelect(campaign.id === selected ? null : campaign.id)}
      className="w-full text-left rounded-xl border p-4 transition-all hover:scale-[1.003]"
      style={{
        borderColor: selected === campaign.id ? `${campaign.color}50` : 'rgba(255,255,255,0.07)',
        background: selected === campaign.id ? `${campaign.color}08` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-[10px] font-mono text-[var(--text-disabled)]">{campaign.id}</span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sm.color, borderColor: `${sm.color}40`, background: `${sm.color}10` }}
            >
              {statusLabel}
            </span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sc, borderColor: `${sc}40`, background: `${sc}10` }}
            >
              {severityLabel(campaign.priority, t, 'priority')}
            </span>
          </div>
          <p className="text-xs font-semibold text-[var(--text-primary)] leading-snug">{campaign.title}</p>
        </div>
        <div className="text-right shrink-0">
          <div className="text-xl font-bold font-mono" style={{ color: campaign.hitsFound > 0 ? '#ef4444' : '#4ade80' }}>
            {campaign.hitsFound}
          </div>
          <div className="text-[9px] font-mono text-[var(--text-disabled)]">{t(`${NS}.hits`)}</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {campaign.mitre.map((m) => (
          <span key={m} className="text-[9px] font-mono px-1.5 py-0.5 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded text-[var(--text-disabled)]">{m}</span>
        ))}
      </div>
    </motion.button>
  )
}

function CampaignDetail({ campaign, t }) {
  if (!campaign) return null
  const sm = HUNT_STATUS_META[campaign.status] ?? { labelKey: null, color: '#6b7280' }
  const statusLabel = sm.labelKey ? t(sm.labelKey) : campaign.status.toUpperCase()
  return (
    <motion.div
      key={campaign.id}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur border border-[var(--border-default)] p-6 space-y-4"
    >
      <div>
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className="text-[10px] font-mono text-[var(--text-disabled)]">{campaign.id}</span>
          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
            style={{ color: sm.color, borderColor: `${sm.color}40`, background: `${sm.color}10` }}
          >
            {statusLabel}
          </span>
        </div>
        <h3 className="text-sm font-bold text-white mb-2">{campaign.title}</h3>
        <p className="text-xs text-[var(--text-tertiary)] leading-relaxed italic">"{campaign.hypothesis}"</p>
      </div>
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: t(`${NS}.analyst`), value: campaign.analyst },
          { label: t(`${NS}.started`), value: campaign.started },
          { label: t(`${NS}.hits_found`), value: campaign.hitsFound > 0 ? `🔴 ${campaign.hitsFound}` : '✅ 0' },
          { label: t(`${NS}.data_sources`), value: campaign.dataSources.join(', ') },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-lg bg-[var(--table-surface)] border border-[var(--border-subtle)] p-3">
            <div className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-0.5">{label}</div>
            <div className="text-xs font-semibold text-[var(--text-secondary)]">{value}</div>
          </div>
        ))}
      </div>
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-2">{t(`${NS}.mitre_techniques`)}</div>
        <div className="flex flex-wrap gap-1.5">
          {campaign.mitre.map((m) => (
            <span
              key={m}
              className="px-2 py-1 rounded text-[10px] font-mono border"
              style={{ background: 'rgba(34,211,238,0.05)', border: '1px solid rgba(34,211,238,0.2)', color: 'rgba(34,211,238,0.7)' }}
            >
              {m}
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  )
}

function QueryCard({ query, t }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <motion.div
      layout
      className="rounded-xl bg-[var(--bg-2)] backdrop-blur border border-[var(--border-default)] overflow-hidden"
    >
      <button
        type="button"
        onClick={() => setExpanded((p) => !p)}
        className="w-full text-left p-4 flex items-start justify-between gap-3 hover:bg-white/3 transition-colors"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border text-cyan-400 border-cyan-500/30 bg-cyan-950/20 uppercase tracking-widest">
              {query.language}
            </span>
            <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-1.5 py-0.5 rounded">{query.mitre}</span>
          </div>
          <p className="text-xs font-semibold text-[var(--text-secondary)]">{query.name}</p>
          <div className="text-[10px] font-mono text-[var(--text-disabled)] mt-0.5">{query.datasource}</div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-lg font-bold font-mono" style={{ color: query.hits > 0 ? '#ef4444' : '#4ade80' }}>{query.hits}</div>
          <div className="text-[9px] font-mono text-[var(--text-disabled)]">{t(`${NS}.hits`)}</div>
        </div>
      </button>
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4">
              <pre className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg p-3 text-[10px] font-mono text-green-400/80 overflow-x-auto leading-relaxed whitespace-pre-wrap">
                {query.query}
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

function IocTable({ iocs, t, onExport }) {
  if (!iocs.length) {
    return (
      <EmptyState
        icon="search"
        title={t(`${NS}.ioc_empty_title`)}
        body={t(`${NS}.ioc_empty_body`)}
        cta={{ label: t(`${NS}.ioc_view_findings`), to: '/findings' }}
      />
    )
  }
  return (
    <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur border border-[var(--border-default)] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-subtle)]">
        <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)]">{t(`${NS}.ioc_heading`)}</span>
        <button
          type="button"
          onClick={onExport}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-cyan-500/30 text-[10px] font-mono text-cyan-300/80 hover:bg-cyan-500/10"
        >
          <Download className="w-3 h-3" />
          {t(`${NS}.export_csv`)}
        </button>
      </div>
      <div className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-4 px-4 py-2 border-b border-[var(--border-subtle)] text-[9px] font-mono uppercase tracking-widest text-[var(--text-disabled)]">
        <span>{t(`${NS}.col_type`)}</span>
        <span>{t(`${NS}.col_indicator`)}</span>
        <span>{t(`${NS}.col_source`)}</span>
        <span>{t(`${NS}.col_severity`)}</span>
        <span>{t(`${NS}.col_added`)}</span>
      </div>
      {iocs.map((ioc, i) => {
        const sc = SEV_COLOR[ioc.severity] ?? '#6b7280'
        return (
          <motion.div
            key={ioc.id}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: i * 0.03 }}
            className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-x-4 px-4 py-2.5 border-b border-[var(--border-subtle)] hover:bg-white/2 transition-colors items-center"
          >
            <span className="text-sm">{IOC_TYPE_ICON[ioc.type] ?? '?'}</span>
            <div className="min-w-0">
              <code className="text-[11px] font-mono text-[var(--text-secondary)] block truncate">{ioc.value}</code>
              <div className="flex gap-1 mt-0.5 flex-wrap">
                {ioc.tags.map((tag) => (
                  <span key={tag} className="text-[8px] font-mono bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-1 py-0.5 rounded text-[var(--text-disabled)]">{tag}</span>
                ))}
              </div>
            </div>
            <span className="text-[10px] font-mono text-[var(--text-disabled)] whitespace-nowrap">{ioc.source}</span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest whitespace-nowrap"
              style={{ color: sc, borderColor: `${sc}40`, background: `${sc}10` }}
            >
              {severityLabel(ioc.severity, t)}
            </span>
            <span className="text-[10px] font-mono text-[var(--text-disabled)] whitespace-nowrap">{ioc.added}</span>
          </motion.div>
        )
      })}
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ThreatHuntingWorkbench() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState('campaigns')
  const [campaigns, setCampaigns] = useState([])
  const [iocs, setIocs] = useState([])
  const [queries, setQueries] = useState([])
  const [campaignsLoading, setCampaignsLoading] = useState(true)
  const [campaignsError, setCampaignsError] = useState(null)
  const [selectedCampaign, setSelectedCampaign] = useState(null)

  const loadHuntData = useCallback(async () => {
    try {
      const r = await apiFetch('/api/soc/hunts')
      if (!r.ok) {
        setCampaigns([])
        setIocs([])
        setQueries([])
        setCampaignsError(t(`${NS}.load_error`, { status: r.status }))
        return
      }
      const data = await r.json().catch(() => ({}))
      const list = (Array.isArray(data.campaigns) ? data.campaigns : []).map((raw) => normalizeCampaign(raw, t))
      const iocList = (Array.isArray(data.iocs) ? data.iocs : []).map(normalizeIoc)
      const queryList = (Array.isArray(data.queries) ? data.queries : []).map((raw, i) => normalizeQuery(raw, i, t))
      setCampaigns(list)
      setIocs(iocList)
      setQueries(queryList)
      setCampaignsError(null)
      setSelectedCampaign((prev) => {
        if (prev && list.some((c) => c.id === prev)) return prev
        return list[0]?.id ?? null
      })
    } catch (e) {
      setCampaigns([])
      setIocs([])
      setQueries([])
      setCampaignsError(e.message || String(e))
    } finally {
      setCampaignsLoading(false)
    }
  }, [t])

  useEffect(() => {
    loadHuntData()
  }, [loadHuntData])

  const selectedCampaignObj = useMemo(
    () => campaigns.find((c) => c.id === selectedCampaign),
    [campaigns, selectedCampaign],
  )

  const metrics = useMemo(() => {
    const active = campaigns.filter((c) => c.status === 'active').length
    const totalHits = campaigns.reduce((s, c) => s + c.hitsFound, 0)
    const totalIOCs = iocs.length
    const critIOCs = iocs.filter((i) => i.severity === 'critical').length
    return { active, totalHits, totalIOCs, critIOCs }
  }, [campaigns, iocs])

  const tabs = [
    { id: 'campaigns', label: t(`${NS}.tab_campaigns`), count: campaigns.length },
    { id: 'queries',   label: t(`${NS}.tab_queries`),   count: queries.length },
    { id: 'iocs',      label: t(`${NS}.tab_iocs`),    count: iocs.length },
  ]

  const listFindings = useMemo(() => {
    if (activeTab === 'iocs') {
      return iocs.map((ioc) => ({
        id: ioc.id,
        severity: ioc.severity || 'medium',
        title: ioc.value || ioc.type,
        type: ioc.type || 'ioc',
        description: ioc.source || '',
      }))
    }
    return campaigns.map((c) => ({
      id: c.id,
      severity: c.severity || 'medium',
      title: c.name || c.id,
      type: c.status || 'campaign',
      description: String(c.hitsFound ?? 0),
    }))
  }, [activeTab, iocs, campaigns])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-threat-hunting',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  const visibleCampaigns = useMemo(() => {
    if (!searchQuery.trim()) return campaigns
    const ids = new Set(filteredFindings.map((f) => f.id))
    return campaigns.filter((c) => ids.has(c.id))
  }, [campaigns, filteredFindings, searchQuery])

  const visibleIocs = useMemo(() => {
    if (!searchQuery.trim()) return iocs
    const ids = new Set(filteredFindings.map((f) => f.id))
    return iocs.filter((ioc) => ids.has(ioc.id))
  }, [iocs, filteredFindings, searchQuery])

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#8b5cf6"
      actions={(
        <ShellScanActions
          onRefresh={loadHuntData}
          onExport={() => { if (activeTab === 'iocs') exportIocsCsv(iocs); else exportCsv() }}
          refreshLoading={campaignsLoading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="mb-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      </div>

      {campaignsLoading ? (
        <>
          <SkeletonWidgetGrid count={4} className="mb-8" />
          <SkeletonCard lines={6} />
        </>
      ) : (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
            <MetricCard label={t(`${NS}.metric_active_hunts`)} value={metrics.active} sub={t(`${NS}.metric_active_hunts_sub`)} color="#22d3ee" icon="🎯" />
            <MetricCard label={t(`${NS}.metric_total_hits`)} value={metrics.totalHits} sub={t(`${NS}.metric_total_hits_sub`)} color="#ef4444" icon="🔴" />
            <MetricCard label={t(`${NS}.metric_iocs_tracked`)} value={metrics.totalIOCs} sub={t(`${NS}.metric_iocs_tracked_sub`)} color="#8b5cf6" icon="🧲" />
            <MetricCard label={t(`${NS}.metric_critical_iocs`)} value={metrics.critIOCs} sub={t(`${NS}.metric_critical_iocs_sub`)} color="#f97316" icon="⚡" />
          </div>

          <div className="flex gap-2 mb-6 flex-wrap">
            {tabs.map((tab) => (
              <button
                key={tab.id} type="button" onClick={() => setActiveTab(tab.id)}
                className="px-4 py-2 rounded-xl text-xs font-mono border transition-all"
                style={{
                  color: activeTab === tab.id ? '#8b5cf6' : 'rgba(255,255,255,0.35)',
                  borderColor: activeTab === tab.id ? 'rgba(139,92,246,0.4)' : 'rgba(255,255,255,0.1)',
                  background: activeTab === tab.id ? 'rgba(139,92,246,0.1)' : 'transparent',
                }}
              >
                {tab.label}
                <span className="ml-2 text-[9px] opacity-60">({tab.count})</span>
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {activeTab === 'campaigns' && (
              <motion.div key="campaigns" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                <h2 className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-3">{t(`${NS}.campaigns_heading`)}</h2>
                {campaigns.length === 0 ? (
                  <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-8 text-center">
                    <p className="text-sm text-[var(--text-muted)] font-mono">{t(`${NS}.no_campaigns`)}</p>
                    {campaignsError ? (
                      <p className="text-[11px] text-rose-400/70 font-mono mt-2">{campaignsError}</p>
                    ) : (
                      <p className="text-[11px] text-[var(--text-disabled)] font-mono mt-2">
                        {t(`${NS}.no_campaigns_hint`)}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="grid lg:grid-cols-[360px_1fr] gap-6">
                    <div className="space-y-2">
                      <WeissmanListToolbar
                        searchQuery={searchQuery}
                        onSearchChange={setSearchQuery}
                        resultCount={visibleCampaigns.length}
                        totalCount={campaigns.length}
                      />
                      {visibleCampaigns.length === 0 ? (
                        <div className="text-center py-8 text-slate-500">{t('weissmanFindings.filtered_title')}</div>
                      ) : visibleCampaigns.map((c) => (
                        <CampaignCard key={c.id} campaign={c} selected={selectedCampaign} onSelect={setSelectedCampaign} t={t} />
                      ))}
                    </div>
                    <AnimatePresence mode="wait">
                      {selectedCampaignObj && <CampaignDetail key={selectedCampaignObj.id} campaign={selectedCampaignObj} t={t} />}
                    </AnimatePresence>
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'queries' && (
              <motion.div key="queries" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
                <h2 className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-3">{t(`${NS}.detection_queries_heading`)}</h2>
                {queries.length === 0 ? (
                  <EmptyState
                    icon="search"
                    title={t(`${NS}.no_queries_title`)}
                    body={t(`${NS}.no_queries_body`)}
                  />
                ) : (
                  queries.map((q) => (
                    <QueryCard key={q.id} query={q} t={t} />
                  ))
                )}
              </motion.div>
            )}

            {activeTab === 'iocs' && (
              <motion.div key="iocs" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-3">
                <WeissmanListToolbar
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  resultCount={visibleIocs.length}
                  totalCount={iocs.length}
                />
                {iocs.length > 0 && visibleIocs.length === 0 ? (
                  <div className="text-center py-8 text-slate-500">{t('weissmanFindings.filtered_title')}</div>
                ) : (
                  <IocTable iocs={visibleIocs} t={t} onExport={() => exportIocsCsv(iocs, t)} />
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </>
      )}
    </PageShell>
  )
}
